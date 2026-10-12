// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 downstream relay with a swappable upstream — the SV2 analogue of the
//! SV1 [`crate::proto::relay`].
//!
//! Full proxy: the proxy is the Noise responder to the miner and the Noise
//! initiator to each upstream pool. It mirrors the miner's channel type
//! (Standard or Extended) onto the upstream, assigns the miner a stable
//! downstream `channel_id`, and maps it to the upstream's `channel_id` on every
//! frame. Most traffic (jobs, prev-hash, shares, set-target, set-extranonce) is
//! forwarded by rewriting just the `channel_id` (see [`crate::proto::sv2::wire`]).
//!
//! An upstream swap ([`crate::proto::sv2::relay::Sv2Session::swap_upstream`]) opens every channel afresh
//! on the new pool and re-points the miners with `SetExtranoncePrefix` +
//! `SetTarget`. Pool changes the miners did not start are followed by a forced
//! reconnect ([`crate::proto::sv2::relay::Sv2Session::force_reconnect`]), so the miners get the new pool
//! through a fresh handshake; the swap keeps the rig's shared upstream current
//! for the members that come back.
//!
//! Multiple mining channels per connection are supported. Every `OpenMiningChannel`
//! — the miner's first as well as any additional one — is forwarded to the
//! upstream as a `pending` open and finalized by the steady reader when its
//! success arrives (assign a stable downstream id, map it, reply to the miner).
//! Each channel maps its own downstream↔upstream `channel_id`. The only
//! synchronous open is the switch re-open (see [`crate::proto::sv2::relay::open_on`]),
//! which must stage the new upstream before the atomic swap.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use stratum_core::bitcoin::hashes::hex::FromHex;

use crate::proto::sv1::{self, RpcMessage};
use crate::proto::translate;

use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_apps::network_helpers::{accept_noise_connection, connect_with_noise};
use stratum_core::binary_sv2::{Str0255, U32AsRef, B032, U256};
use stratum_core::common_messages_sv2 as common;
use stratum_core::common_messages_sv2::{Protocol, SetupConnection, SetupConnectionSuccess};
use stratum_core::mining_sv2 as mining;
use stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess, OpenMiningChannelError,
    OpenStandardMiningChannel, OpenStandardMiningChannelSuccess, SetExtranoncePrefix, SetTarget,
};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};

use super::keys::NoiseKeys;
use super::wire::{self, EitherFrame, Msg, Sv2Frame};
use crate::control::{AnySession, SessionStatus};
use crate::orders::OrderStore;
use crate::proto::ProxyContext;
use crate::session::{Delivery, Routing, UpstreamTarget};

/// SV2 frame builders/parsers (split out for navigability).
pub(crate) mod codec;
use codec::*;

/// Same-rig bundle registry + idle reaper (split out for navigability).
mod registry;
use registry::reap_idle_rig;
pub use registry::Sv2RigRegistry;

/// How long the proxy's Noise certificate (responder side) is valid, seconds.
const CERT_VALIDITY: u64 = 3600;
/// SV2 protocol version the proxy speaks.
const SV2_VERSION: u16 = 2;
/// After this many failed rental switches in a row the retry logs at ERROR
/// once (roughly 90 s in), so a rig quietly mining for its seller while an
/// order runs shows up in the journal as more than a WARN per attempt.
const SWITCH_RETRY_ESCALATE_AFTER: u32 = 8;

/// Default window to keep a rig's upstream warm after its last member leaves, so
/// a quick reconnect re-attaches without a fresh Noise handshake + channel reopen.
const DEFAULT_IDLE_GRACE: Duration = Duration::from_secs(30);

pub(crate) type Read = NoiseTcpReadHalf<Msg>;
pub(crate) type Write = NoiseTcpWriteHalf<Msg>;

/// The miner's channel-open request, captured to re-open against each upstream.
#[derive(Clone)]
pub(crate) enum OpenSpec {
    Standard {
        request_id: u32,
        nominal_hash_rate: f32,
        max_target: Vec<u8>,
    },
    Extended {
        request_id: u32,
        nominal_hash_rate: f32,
        max_target: Vec<u8>,
        min_extranonce_size: u16,
    },
}

impl OpenSpec {
    fn request_id(&self) -> u32 {
        match self {
            OpenSpec::Standard { request_id, .. } | OpenSpec::Extended { request_id, .. } => {
                *request_id
            }
        }
    }
    fn is_extended(&self) -> bool {
        matches!(self, OpenSpec::Extended { .. })
    }
}

/// The miner's open + the worker name it authenticated with.
struct MinerOpen {
    spec: OpenSpec,
    worker: String,
}

/// An upstream's channel-open result (success), copied out as owned bytes.
pub(crate) struct ChannelInfo {
    pub(crate) request_id: u32,
    pub(crate) up_channel_id: u32,
    pub(crate) extranonce_prefix: Vec<u8>,
    pub(crate) target: Vec<u8>,
    pub(crate) extranonce_size: u16,
    pub(crate) group_channel_id: u32,
}

// ── transport helpers ───────────────────────────────────────────────

async fn read_one(read: &mut Read) -> anyhow::Result<Sv2Frame> {
    let frame = read
        .read_frame()
        .await
        .map_err(|e| anyhow!("read frame: {e:?}"))?;
    wire::into_sv2(frame).ok_or_else(|| anyhow!("unexpected handshake frame post-handshake"))
}

/// Why an SV2 probe did not produce an upstream — and the distinction is the
/// whole point.
///
/// The probe answers two different questions at once, and only one of them is
/// about protocols. Collapsing them would make a pool RESTART look like a pool
/// that speaks SV1: the downgrade to translation is permanent (nothing
/// re-probes SV2), so a rig that retried inside the restart window would stay
/// translated for the rest of its session.
pub(crate) enum ProbeFailure {
    /// No TCP connection could be established. The pool is down, restarting or
    /// unroutable, and it has said NOTHING about which protocol it speaks.
    /// Answering that with a protocol downgrade is a category error — the
    /// caller must keep retrying instead.
    Unreachable(anyhow::Error),
    /// The pool accepted the connection but did not complete the SV2 setup: no
    /// Noise handshake, a refusal, or silence until the probe timeout. That IS
    /// a statement about the protocol, so translation is the right answer.
    NotSv2(anyhow::Error),
}

impl ProbeFailure {
    /// The single place a failed probe is judged. `Err` = propagate, the pool is
    /// not there and must not buy the miner a protocol downgrade; `Ok` = the pool
    /// answered and did not speak SV2, so the caller may translate.
    ///
    /// Both probe sites (initial connect and upstream swap) ask this question.
    /// With the judgement here, a third failure class forces a change in
    /// exactly one exhaustive match, and the sites keep only what legitimately
    /// differs — what they DO to translate.
    fn allow_translation(self, url: &str) -> anyhow::Result<()> {
        match self {
            ProbeFailure::Unreachable(e) => {
                Err(e.context("upstream unreachable; not downgrading to SV1"))
            }
            ProbeFailure::NotSv2(e) => {
                debug!(url = %url, error = %e, "upstream not SV2; using SV1 translation");
                Ok(())
            }
        }
    }
}

/// Probe `target` for SV2, classifying a failure by [`ProbeFailure`].
///
/// The timeout lives inside so a pool that accepts TCP and then goes quiet is
/// judged on what it already told us (it answered) rather than on which layer
/// happened to run out of time.
pub(crate) async fn probe_sv2(target: &UpstreamTarget) -> Result<(Read, Write), ProbeFailure> {
    let connected = tokio::time::timeout(
        translate::UPSTREAM_PROBE_TIMEOUT,
        TcpStream::connect(&target.url),
    )
    .await;
    let tcp = match connected {
        Ok(Ok(tcp)) => tcp,
        // Refused, unroutable, or not even accepting inside the probe window:
        // the pool is not there. Not a protocol verdict.
        Ok(Err(e)) => {
            return Err(ProbeFailure::Unreachable(
                anyhow::Error::new(e).context(format!("connect upstream {}", target.url)),
            ))
        }
        Err(_) => {
            return Err(ProbeFailure::Unreachable(anyhow!(
                "connect upstream {} timed out",
                target.url
            )))
        }
    };
    let _ = tcp.set_nodelay(true);
    // Past the TCP connect every failure IS a protocol statement: the pool is
    // there, and it did not speak SV2.
    match tokio::time::timeout(translate::UPSTREAM_PROBE_TIMEOUT, setup_over(tcp, target)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(ProbeFailure::NotSv2(e)),
        Err(_) => Err(ProbeFailure::NotSv2(anyhow!(
            "upstream {} accepted the connection but did not complete the SV2 setup",
            target.url
        ))),
    }
}

/// Connect an upstream and run SetupConnection, returning the post-setup halves.
pub(crate) async fn connect_setup(target: &UpstreamTarget) -> anyhow::Result<(Read, Write)> {
    let tcp = TcpStream::connect(&target.url)
        .await
        .with_context(|| format!("connect upstream {}", target.url))?;
    setup_over(tcp, target).await
}

/// The SV2 setup on an already-connected socket: Noise, then `SetupConnection`
/// until its Success.
async fn setup_over(tcp: TcpStream, target: &UpstreamTarget) -> anyhow::Result<(Read, Write)> {
    let _ = tcp.set_nodelay(true);
    let authority = super::keys::parse_authority(&target.authority_pubkey)?;
    let stream = connect_with_noise::<Msg>(tcp, authority)
        .await
        .map_err(|e| anyhow!("upstream noise handshake: {e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    write
        .write_frame(setup_connection())
        .await
        .map_err(|e| anyhow!("send SetupConnection: {e:?}"))?;
    loop {
        let f = read_one(&mut read).await?;
        match wire::msg_type(&f) {
            Some(common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) => {
                return Ok((read, write));
            }
            Some(common::MESSAGE_TYPE_SETUP_CONNECTION_ERROR) => {
                bail!("upstream rejected SetupConnection")
            }
            _ => continue,
        }
    }
}

/// Synchronously open a channel on an already-setup upstream and read until its
/// success — the staging primitive for a rental switch. The switch must have the
/// new upstream's channels fully open (new `channel_id`s known) *before* it
/// atomically swaps `active`, so miner traffic is never routed to a channel that
/// isn't open yet. The fresh-open path (initial + additional channels) instead
/// finalizes through the steady reader; this is only used by [`Sv2Session::swap_upstream`].
/// Open one channel on an already-set-up upstream connection.
///
/// `deferred` collects every frame that arrives before this channel's
/// `OpenSuccess` and does not belong to the open itself — see the arm below for
/// why those exist and why they must not be dropped. The caller passes the SAME
/// vec through a whole re-open loop, so the frames stay in arrival order, and
/// hands it to the steady reader afterwards.
pub(crate) async fn open_on(
    read: &mut Read,
    write: &mut Write,
    spec: &OpenSpec,
    account: &str,
    deferred: &mut Vec<Sv2Frame>,
) -> anyhow::Result<ChannelInfo> {
    write
        .write_frame(open_channel_upstream(spec, account, spec.request_id())?)
        .await
        .map_err(|e| anyhow!("send OpenMiningChannel: {e:?}"))?;
    loop {
        let mut f = read_one(read).await?;
        match wire::msg_type(&f) {
            Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
            | Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS) => {
                return parse_open_success(&mut f)
                    .ok_or_else(|| anyhow!("malformed OpenMiningChannelSuccess"));
            }
            Some(mining::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR) => {
                let code = parse_open_error(&mut f).map_or_else(String::new, |(_, c)| c);
                return Err(crate::proto::LoginRefused(format!(
                    "OpenMiningChannel refused: {code}"
                ))
                .into());
            }
            _ => {
                // A frame for a channel opened EARLIER on this connection.
                //
                // This function runs once per channel on the SAME connection.
                // The pool sends each channel's first NewExtendedMiningJob (31)
                // + SetNewPrevHash (32) straight after ITS OpenSuccess, which is
                // while we are already waiting for the NEXT channel's success.
                //
                // They cannot be routed yet: the up→down channel map is only
                // complete once every channel is open. So they are buffered here
                // and replayed by the steady reader, which is the same path they
                // would have taken had they arrived a moment later.
                //
                // Dropped, they would leave every channel but the last one
                // without a job: those miners keep hashing a job under an
                // extranonce prefix the pool has since reassigned, and every
                // share comes back job-not-found or difficulty-too-low.
                deferred.push(f);
                continue;
            }
        }
    }
}

fn spawn_writer(mut half: Write, mut rx: mpsc::UnboundedReceiver<EitherFrame>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if half.write_frame(frame).await.is_err() {
                break;
            }
        }
    })
}

/// Spawn the steady reader for an upstream connection.
///
/// `deferred` are frames already read off this connection during the channel
/// re-open loop ([`open_on`]). They are replayed FIRST, before anything still in
/// the socket, so a channel's initial job/prev-hash cannot be overtaken by a
/// later one for the same channel. Replaying them from inside this task (rather
/// than from the swap path) is also what keeps them from being dropped as stale:
/// the task takes `inner` per frame, so its first frame lands only after the
/// caller has released the lock with `active.generation` already set.
fn spawn_upstream_reader(
    session: Arc<Sv2Session>,
    generation: u64,
    mut read: Read,
    deferred: Vec<Sv2Frame>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        for frame in deferred {
            session.on_upstream_frame(generation, frame).await;
        }
        while let Ok(frame) = read.read_frame().await {
            if let Some(sv2) = wire::into_sv2(frame) {
                session.on_upstream_frame(generation, sv2).await;
            }
        }
        // The loop ended = the pool closed/errored (an intentional swap aborts
        // this task before here). Tell the supervisor so it can reconnect/fail over.
        let _ = session.died_tx.send(generation);
    })
}

// ── session ─────────────────────────────────────────────────────────

struct ActiveUpstream {
    generation: u64,
    target: UpstreamTarget,
    to_up: mpsc::UnboundedSender<EitherFrame>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

/// One mining channel: the stable downstream id the miner sees, the current
/// upstream id behind it, and the open spec (to re-open on a switch).
struct Channel {
    down_channel_id: u32,
    up_channel_id: u32,
    spec: OpenSpec,
    /// Current share difficulty (diff-1 units) from the channel's target;
    /// updated by `SetTarget`. Used to weight accepted shares for accounting.
    difficulty: f64,
    /// The rig member (downstream connection) that opened this channel, so the
    /// pool's per-channel frames route back to the right miner when several
    /// same-rig miners share this upstream.
    owner: u32,
    /// The upstream `group_channel_id` this channel was placed in, or 0 when
    /// ungrouped. A pool may run SEVERAL groups on one connection — ours groups
    /// Extended channels by full extranonce size, so miners asking for different
    /// sizes land in different groups. A group-broadcast job is only valid for
    /// the channels of ITS group, which is why this is per channel and not per
    /// connection.
    up_group_id: u32,
    /// The downstream group id the miner was told in its OpenSuccess. Stable
    /// across upstream swaps (the miner cannot be told a new one), so a re-issued
    /// upstream group id is mapped back onto this.
    down_group_id: u32,
}

impl Channel {
    /// The one synthesized channel of a translated SV1 upstream. Its upstream
    /// id is the downstream id (there is no SV2 channel behind it) and it is
    /// ungrouped (there is no SV2 group either).
    fn translated(down_cid: u32, owner: u32, spec: OpenSpec, difficulty: f64) -> Self {
        Self {
            down_channel_id: down_cid,
            up_channel_id: down_cid,
            spec,
            difficulty,
            owner,
            up_group_id: 0,
            down_group_id: 0,
        }
    }
}

struct Inner {
    active: ActiveUpstream,
    generation_counter: u64,
    /// All open channels on this connection (one per rig chain, usually one).
    channels: Vec<Channel>,
    /// upstream channel_id → downstream channel_id, for REAL channels only.
    /// Group ids are deliberately NOT in here: a group frame does not go to one
    /// channel, it goes to every member of that group, and each of those needs
    /// the frame rewritten to ITS own downstream group id. See
    /// [`Inner::group_recipients`].
    up_to_down: std::collections::HashMap<u32, u32>,
    /// upstream `group_channel_id` → the downstream group id we handed the
    /// miners of that group.
    ///
    /// A map, not one id per connection: with same-rig miners sharing one
    /// upstream and mixed firmware asking for different extranonce sizes, the
    /// pool opens a SECOND group on the same connection. Collapsing both onto
    /// one downstream id would hand every member both groups' jobs — a job
    /// built for the wrong extranonce layout, which the miner hashes and the
    /// pool rejects.
    group_down: std::collections::HashMap<u32, u32>,
    /// proxy-assigned upstream request_id → (member, spec) for opens awaiting the
    /// upstream's success. Keyed by the UNIQUE upstream request_id (not the
    /// miner's, which can collide across members on a shared upstream); the member
    /// is the connection that asked and the spec keeps the miner's original
    /// request_id for the downstream OpenSuccess.
    pending: std::collections::HashMap<u32, (u32, OpenSpec)>,
    /// Next downstream channel_id to hand out (proxy-assigned, stable).
    next_down_cid: u32,
    /// Next proxy-assigned upstream request_id, unique across the shared upstream
    /// so concurrent same-rig opens don't collide in `pending`.
    next_up_req: u32,
    /// Downstream miner connections sharing this rig's upstream, keyed by a
    /// rig-local member id; each holds that connection's frame sink. Per-channel
    /// upstream frames route to the owning member; group-broadcast jobs fan out
    /// to all members. Usually one (a 1:1 miner connection); more than one when
    /// several same-rig miners are bundled onto a single upstream.
    members: std::collections::HashMap<u32, mpsc::UnboundedSender<EitherFrame>>,
    /// Next member id to hand out.
    next_member_id: u32,
    routing: Routing,
    /// The seller's idle pool at connect time. `None` for a rig admitted on its
    /// active order alone (seller row deleted mid-rental): it has nowhere to
    /// idle, so [`Sv2Session::revert`] drops its members instead of swapping.
    default_target: Option<UpstreamTarget>,
    delivery: Delivery,
    label: String,
    /// True when the active upstream is an SV1 pool reached via translation (the
    /// buyer pool speaks SV1 behind this SV2 miner). Jobs/shares are converted;
    /// additional channels are not multiplexed over the single SV1 connection.
    translating: bool,
    /// The rig's upstream supervisor task (reconnect/failover). Owned by the rig,
    /// not any one member, so it survives a single member leaving and is aborted
    /// only when the last member disconnects.
    supervisor: Option<JoinHandle<()>>,
    /// Bumped each time the rig goes empty. A scheduled idle reaper only fires if
    /// the token still matches, so a rejoin-then-leave round can't be reaped by a
    /// stale earlier reaper.
    idle_token: u64,
}

impl Inner {
    /// Swap in a new active upstream: abort the outgoing reader/writer and
    /// install the new pair under `generation`.
    ///
    /// Every install path goes through here — SV2 initial, SV2 swap,
    /// SV1-translate initial, SV1-translate swap. They differ in how the reader
    /// is built (native vs translating) and in nothing else.
    ///
    /// Taking `&mut self` is the load-bearing part, not ceremony: it can only be
    /// called with the `inner` lock held. [`Sv2Session::on_upstream_frame`] drops
    /// any frame whose generation != `active.generation`, while a spawned reader
    /// starts pulling immediately — so spawning the reader and installing
    /// `active` under ONE continuous hold of the lock is what keeps the new
    /// pool's first job from being discarded as stale. Callers must therefore
    /// spawn the reader inside the same lock scope as this call.
    fn install_active(
        &mut self,
        generation: u64,
        target: UpstreamTarget,
        to_up: mpsc::UnboundedSender<EitherFrame>,
        reader: JoinHandle<()>,
        writer: JoinHandle<()>,
    ) {
        self.active.reader.abort();
        self.active.writer.abort();
        self.active = ActiveUpstream {
            generation,
            target,
            to_up,
            reader,
            writer,
        };
    }

    /// Ask the active upstream to open a channel for `member`. The open is sent
    /// under a proxy-assigned request_id that is unique on this upstream (the
    /// miners' own ids can collide across bundled members) and is finalized by
    /// the steady reader when the pool answers.
    fn open_upstream_channel(&mut self, member: u32, spec: &OpenSpec) -> anyhow::Result<()> {
        let account = crate::proto::relay::upstream_worker(&self.active.target.user, &self.label);
        let up_req = self.next_up_req;
        self.next_up_req += 1;
        let frame = open_channel_upstream(spec, &account, up_req)?;
        self.pending.insert(up_req, (member, spec.clone()));
        self.active
            .to_up
            .send(frame)
            .map_err(|_| anyhow!("upstream writer gone"))
    }

    /// Drop the opens still pending on the upstream being replaced, returning
    /// `(member, request_id)` for each so the member can be told to reopen.
    fn take_pending_opens(&mut self) -> Vec<(u32, u32)> {
        self.pending
            .drain()
            .map(|(request_id, (member, _))| (member, request_id))
            .collect()
    }

    fn up_for_down(&self, down_cid: u32) -> Option<u32> {
        self.channels
            .iter()
            .find(|c| c.down_channel_id == down_cid)
            .map(|c| c.up_channel_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn register_channel(
        &mut self,
        down_cid: u32,
        up_cid: u32,
        spec: OpenSpec,
        difficulty: f64,
        owner: u32,
        up_group_id: u32,
        down_group_id: u32,
    ) {
        self.up_to_down.insert(up_cid, down_cid);
        self.channels.push(Channel {
            down_channel_id: down_cid,
            up_channel_id: up_cid,
            spec,
            difficulty,
            owner,
            up_group_id,
            down_group_id,
        });
    }

    /// Who a frame addressed to upstream group `up_cid` must reach: one
    /// `(down_group_id, member)` pair per distinct downstream group in that
    /// upstream group, deduplicated so a member holding two channels of the same
    /// group is written to once.
    ///
    /// Empty means `up_cid` is not a group on this connection — the caller then
    /// treats the frame as per-channel. Standard channels are never grouped
    /// (`up_group_id == 0`), so they can't be picked up here.
    fn group_recipients(&self, up_cid: u32) -> Vec<(u32, u32)> {
        if up_cid == 0 {
            return Vec::new();
        }
        let mut out: Vec<(u32, u32)> = Vec::new();
        for c in self
            .channels
            .iter()
            .filter(|c| c.up_group_id == up_cid && c.spec.is_extended())
        {
            let pair = (c.down_group_id, c.owner);
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
        out
    }

    /// Register a downstream miner connection as a member of this rig, returning
    /// its id. Each member has its own sink; per-channel upstream frames route to
    /// the owning member, group-broadcast jobs fan out to all members.
    fn add_member(&mut self, sink: mpsc::UnboundedSender<EitherFrame>) -> u32 {
        let id = self.next_member_id;
        self.next_member_id += 1;
        self.members.insert(id, sink);
        id
    }

    /// The sink of a given member, if still attached.
    fn member_sink(&self, member: u32) -> Option<&mpsc::UnboundedSender<EitherFrame>> {
        self.members.get(&member)
    }

    /// The sink of the member that owns the channel behind `up_cid`, if any.
    fn member_sink_for_up(&self, up_cid: u32) -> Option<&mpsc::UnboundedSender<EitherFrame>> {
        let owner = self
            .channels
            .iter()
            .find(|c| c.up_channel_id == up_cid)?
            .owner;
        self.members.get(&owner)
    }

    /// Map an Extended channel's upstream `group_channel_id` into the downstream
    /// id namespace and return the downstream group id the miner should see in
    /// its OpenSuccess.
    ///
    /// One downstream id PER upstream group: channels the pool put in different
    /// groups must stay in different groups downstream, or their jobs get
    /// crossed. Re-opens of the same upstream group reuse the id the miners of
    /// that group already know. Returns `up_group_id` unchanged for non-Extended
    /// or ungrouped (`group_channel_id == 0`) channels, leaving Standard channels
    /// untouched.
    fn map_group(&mut self, up_group_id: u32, is_extended: bool) -> u32 {
        if !is_extended || up_group_id == 0 {
            return up_group_id;
        }
        if let Some(&down) = self.group_down.get(&up_group_id) {
            return down;
        }
        let id = self.next_down_cid;
        self.next_down_cid += 1;
        self.group_down.insert(up_group_id, id);
        id
    }
}

/// A live SV2 seller rig: one swappable upstream shared by one or more same-rig
/// miner connections (members). Per-channel frames route to the owning member;
/// group-broadcast jobs fan out to every member.
pub struct Sv2Session {
    inner: Mutex<Inner>,
    /// Serializes upstream swaps so two concurrent switches (e.g. an API rent and
    /// the expiry revert) can't interleave their connect/install and leave
    /// `active` pointing at one upstream while `routing` describes another. Always
    /// taken before `inner`, never the reverse, so it can't deadlock.
    switch: Mutex<()>,
    /// An upstream reader sends its generation here when its read loop ends on a
    /// dropped/closed pool (an intentional swap aborts the reader, which doesn't
    /// signal). The supervisor task reconnects / fails over to the fallback.
    died_tx: mpsc::UnboundedSender<u64>,
    /// For crediting measured delivered work to the active rental order.
    orders: Arc<OrderStore>,
    /// Fired by [`Sv2Session::force_reconnect`] to drop the miner connections so
    /// they reconnect and re-resolve their upstream from current state. Used for
    /// every pool change the miners did not start: operator changes (idle-pool
    /// edit, rent start, rent end/cancel), recovery after a dropped upstream
    /// ([`crate::control::supervise_upstream`]) and a completed attach retry.
    ///
    /// A `watch` epoch, not a `Notify`: EVERY bundled member holds its own
    /// receiver, so one signal drops all of them (`notify_one` woke exactly one
    /// member of a multi-miner rig), and the retained epoch means a member busy
    /// processing a frame between selects still sees the bump on its next poll.
    reconnect: watch::Sender<u64>,
    /// Single-flight guard for [`Sv2Session::spawn_switch_retry`]: the task
    /// holds it for its lifetime, so several members attaching in the same
    /// second (one failed switch each) start one retry, not one per member.
    retry_switch: Arc<Mutex<()>>,
}

impl Sv2Session {
    pub async fn switch_to(
        self: &Arc<Self>,
        order_id: String,
        target: UpstreamTarget,
    ) -> anyhow::Result<()> {
        self.swap_upstream(target, Routing::Rented { order_id })
            .await
    }

    /// Switch onto a rental order's pool: its primary target, then its fallback
    /// if the primary is unreachable. Errors only if both fail.
    pub async fn switch_to_order(self: &Arc<Self>, order_id: String) -> anyhow::Result<()> {
        let order = self
            .orders
            .get(&order_id)
            .await
            .ok_or_else(|| anyhow!("order {order_id} not found"))?;
        order
            .connect_with_fallback(|target| self.switch_to(order_id.clone(), target))
            .await
            .map(drop)
    }

    pub async fn revert(self: &Arc<Self>) -> anyhow::Result<()> {
        let default = self.inner.lock().await.default_target.clone();
        match default {
            Some(target) => self.swap_upstream(target, Routing::Idle).await,
            None => {
                // No idle pool to fall back to and the rental is over: staying
                // on the buyer's pool would mine for the buyer unpaid. Drop
                // the members; on reconnect they are refused unless a rig
                // row or a new order exists by then.
                let label = self.inner.lock().await.label.clone();
                warn!(%label, "rig has no idle pool registered; disconnecting its miners instead of reverting");
                self.force_reconnect();
                Ok(())
            }
        }
    }

    /// Drop ALL bundled miner connections so they reconnect and re-resolve
    /// their upstream from current state (the updated idle pool, or an active
    /// rental). The caller must persist the new state (store/order) BEFORE
    /// calling this so the reconnects land on the right pool. Preferred over a
    /// live swap for operator-initiated changes — a fresh handshake gives the
    /// miner the new pool's extranonce/target cleanly instead of relying on a
    /// live re-point.
    pub fn force_reconnect(&self) {
        // The bumped epoch is retained by the watch channel, so a member whose
        // serve loop is between selects (processing a frame) still sees it —
        // and every member has its own receiver, so all of them break.
        self.reconnect
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    /// Per-member reconnect-signal receiver for the serve loop. Subscribe
    /// BEFORE resolving order state: a change that fires after subscription is
    /// seen by `changed()`, and one that fired before was already persisted in
    /// the order store, so the fresh resolve right after subscription sees it.
    fn subscribe_reconnect(&self) -> watch::Receiver<u64> {
        self.reconnect.subscribe()
    }

    /// The rig's routing, if `generation` is still its active upstream.
    pub async fn routing_if_active(&self, generation: u64) -> Option<Routing> {
        let i = self.inner.lock().await;
        (i.active.generation == generation).then(|| i.routing.clone())
    }

    /// The order this rig is routed to, `None` while idle.
    async fn current_order_id(&self) -> Option<String> {
        self.inner
            .lock()
            .await
            .routing
            .order_id()
            .map(str::to_string)
    }

    /// Align the shared upstream with the current order state before bundling
    /// a new member. A live rig can sit on a stale upstream across a rent or
    /// cancel: the other members hold the rig alive while one reconnects, and
    /// an attach bundles onto whatever the rig currently mines — the order
    /// resolve at connect time only ever picked the upstream for FRESH rigs.
    /// No-op when already aligned. If the swap fails the attach proceeds on
    /// the current upstream and [`Sv2Session::spawn_switch_retry`] keeps
    /// trying: nothing else would. The supervisor only wakes when the ACTIVE
    /// upstream dies, and here the active upstream is the seller's healthy
    /// pool, so a rental that failed to connect once would stay unrouted for
    /// the whole order.
    async fn reconcile_routing(self: &Arc<Self>, desired: Option<&crate::orders::Order>) {
        let current = self.current_order_id().await;
        match (desired, current) {
            (Some(o), current) if current.as_deref() != Some(o.id.as_str()) => {
                info!(order = %o.id, "attach: rig on stale upstream — switching to the active rental");
                if let Err(e) = self.switch_to_order(o.id.clone()).await {
                    warn!(order = %o.id, error = %e, "attach: switch to rental failed; bundling on current upstream, retrying in the background");
                    self.spawn_switch_retry(o.worker.clone());
                }
            }
            (None, Some(stale)) => {
                info!(order = %stale, "attach: rig still on an ended rental — reverting to the idle pool");
                if let Err(e) = self.revert().await {
                    warn!(error = %e, "attach: revert to idle failed; bundling on current upstream");
                }
            }
            _ => {}
        }
    }

    /// Keep converging onto the rig's active rental after a failed switch.
    /// Each round re-resolves the order, so a cancel, expiry or exhausted
    /// budget ends the loop, and a switch another path completed meanwhile is
    /// seen on `routing` and not repeated. Holds a `Weak` so a torn-down rig
    /// is not kept alive by its own retry.
    fn spawn_switch_retry(self: &Arc<Self>, worker: String) {
        let Ok(guard) = self.retry_switch.clone().try_lock_owned() else {
            return; // a retry for this rig is already running
        };
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let _guard = guard;
            let mut backoff = Duration::from_millis(500);
            let mut failures = 0u32;
            loop {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                let Some(session) = weak.upgrade() else {
                    return;
                };
                let Some(order) = session
                    .orders
                    .active_for_worker(&worker, crate::orders::now_ms())
                    .await
                else {
                    info!(%worker, "attach retry: no active rental any more; giving up");
                    return;
                };
                let current = session.current_order_id().await;
                if current.as_deref() == Some(order.id.as_str()) {
                    return; // converged elsewhere
                }
                match session.switch_to_order(order.id.clone()).await {
                    Ok(()) => {
                        // Same rule as the supervisor's recovery: the members
                        // were live on the old upstream, so drop them for a
                        // fresh handshake instead of a re-point.
                        session.force_reconnect();
                        info!(order = %order.id, failures, "attach retry: rig switched to the active rental");
                        return;
                    }
                    Err(e) => {
                        failures += 1;
                        if failures == SWITCH_RETRY_ESCALATE_AFTER {
                            error!(order = %order.id, error = %e, failures, "attach retry: rental switch keeps failing; rig still mines for the seller");
                        } else {
                            warn!(order = %order.id, error = %e, failures, "attach retry: rental switch failed; backing off");
                        }
                    }
                }
            }
        });
    }

    async fn swap_upstream(
        self: &Arc<Self>,
        target: UpstreamTarget,
        routing: Routing,
    ) -> anyhow::Result<()> {
        // Hold the switch lock for the whole swap so concurrent switches run
        // strictly one after another (the last to acquire wins). Released on
        // return.
        let _switch = self.switch.lock().await;
        // Snapshot the channels to re-open (down_channel_id + spec) + worker.
        // Each channel carries the downstream group id its miner already knows —
        // the new upstream re-issues its own group ids, and each must be mapped
        // back onto the one the miner of THAT channel was told. Carried per
        // channel rather than once per connection: the pool may run several
        // groups here, and the swap must not merge them.
        let (specs, generation, label, members) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            let specs: Vec<(u32, u32, OpenSpec, u32)> = i
                .channels
                .iter()
                .map(|c| (c.down_channel_id, c.owner, c.spec.clone(), c.down_group_id))
                .collect();
            (
                specs,
                i.generation_counter,
                i.label.clone(),
                // Members don't change across an upstream swap; snapshot their
                // sinks (cheap Sender clones) to re-point each one after.
                i.members.clone(),
            )
        };
        // user_identity on the new pool: its account + the miner's worker, tagged.
        let up_ident = crate::proto::relay::upstream_worker(&target.user, &label);
        // Zero channels is NOT an error: a rig can be swapped while its only
        // member is mid-reconnect — the empty grace-window hull between the last
        // member leaving and the next attaching. We still connect the new upstream
        // and install it as `active` + set `routing` below (the re-open and
        // re-point loops are no-ops on empty `specs`), so the member that attaches
        // next opens its first channel straight on the new pool instead of
        // bundling back onto the old (idle) one.

        // Native first: re-open on SV2; if the new pool doesn't answer as SV2,
        // it's an SV1 buyer pool → translate the switch onto it. But an
        // unreachable pool is NOT an SV1 pool: fail, so the supervisor keeps
        // retrying on SV2 instead of downgrading for the rest of the session.
        let (mut read, mut write) = match probe_sv2(&target).await {
            Ok(c) => c,
            Err(f) => {
                f.allow_translation(&target.url)?;
                return self
                    .swap_to_sv1_translate(target, routing, generation, up_ident)
                    .await;
            }
        };
        let mut new_channels = Vec::with_capacity(specs.len());
        let mut up_to_down = std::collections::HashMap::new();
        let mut group_down = std::collections::HashMap::new();
        let mut repoint = Vec::with_capacity(specs.len());
        // Frames the pool sends for an already-opened channel while we are still
        // opening the next one — its initial job + prev-hash. Accumulated across
        // the whole loop and handed to the steady reader below.
        let mut deferred: Vec<Sv2Frame> = Vec::new();
        for (down_cid, owner, spec, down_group_id) in &specs {
            let info = open_on(&mut read, &mut write, spec, &up_ident, &mut deferred)
                .await
                .map_err(|e| anyhow!("switch reopen channel {down_cid}: {e}"))?;
            up_to_down.insert(info.up_channel_id, *down_cid);
            // Remap the new pool's group id onto the downstream group id THIS
            // channel's miner already knows, so its group-broadcast jobs keep
            // reaching it after the switch. Two channels the old pool had in
            // different groups keep two ids even if the new pool merges them:
            // each miner still only hears about its own.
            let up_group_id = if spec.is_extended() {
                info.group_channel_id
            } else {
                0
            };
            if up_group_id != 0 {
                if *down_group_id == 0 {
                    warn!(
                        worker = %label,
                        down_cid,
                        "extended channel grouped on new upstream but was ungrouped before — group jobs may be dropped"
                    );
                } else {
                    group_down.insert(up_group_id, *down_group_id);
                }
            }
            new_channels.push(Channel {
                down_channel_id: *down_cid,
                up_channel_id: info.up_channel_id,
                spec: spec.clone(),
                difficulty: translate::difficulty_from_target(&info.target),
                owner: *owner,
                up_group_id,
                down_group_id: *down_group_id,
            });
            repoint.push((*down_cid, *owner, info.extranonce_prefix, info.target));
        }

        let (to_up, up_rx) = mpsc::unbounded_channel();

        let abandoned: Vec<(u32, u32)> = {
            let mut i = self.inner.lock().await;
            // Reader spawned inside the lock — see `Inner::install_active` for
            // why that ordering is required.
            let writer = spawn_writer(write, up_rx);
            let reader = spawn_upstream_reader(self.clone(), generation, read, deferred);
            i.install_active(generation, target.clone(), to_up, reader, writer);
            i.channels = new_channels;
            i.up_to_down = up_to_down;
            i.group_down = group_down;
            let abandoned = i.take_pending_opens();
            i.routing = routing;
            // Back on a native SV2 upstream: this rig can multiplex again.
            // Left set, `attach_member` would refuse every same-rig miner and
            // the rig would split into standalone sessions. Reaching here
            // means `probe_sv2` accepted the target: the SV1 case returned
            // through `swap_to_sv1_translate` above.
            i.translating = false;
            abandoned
        };

        // Re-point every channel: new extranonce prefix + target. The new
        // upstream then streams jobs + prev-hash per channel, which the reader
        // forwards. Downstream channel ids are unchanged, so the miner does not
        // reconnect.
        for (down_cid, owner, prefix, tgt) in repoint {
            if let Some(sink) = members.get(&owner) {
                let _ = sink.send(set_extranonce_prefix(down_cid, prefix)?);
                let _ = sink.send(set_target(down_cid, tgt)?);
            }
        }
        refuse_abandoned_opens(&members, abandoned);
        info!(upstream = %target.url, generation, channels = specs.len(), "sv2 upstream switched");
        Ok(())
    }

    /// Forward an upstream frame to the miner (channel-id remapped), crediting
    /// the hashrate window on accepted shares and finalizing additional channel
    /// opens.
    async fn on_upstream_frame(&self, generation: u64, mut frame: Sv2Frame) {
        let Some(mt) = wire::msg_type(&frame) else {
            return;
        };
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return; // stale upstream (already swapped away)
        }

        // An additional channel (opened mid-session) succeeded upstream: assign
        // a downstream id, map it, and tell the miner.
        if mt == mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
            || mt == mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
        {
            if let Some(info) = parse_open_success(&mut frame) {
                if let Some((member, spec)) = i.pending.remove(&info.request_id) {
                    let down_cid = i.next_down_cid;
                    i.next_down_cid += 1;
                    let diff = translate::difficulty_from_target(&info.target);
                    // Group first: the channel records the pair, so a later
                    // group-broadcast can find its members without a second map.
                    let down_group_id = i.map_group(info.group_channel_id, spec.is_extended());
                    let up_group_id = if spec.is_extended() {
                        info.group_channel_id
                    } else {
                        0
                    };
                    i.register_channel(
                        down_cid,
                        info.up_channel_id,
                        spec.clone(),
                        diff,
                        member,
                        up_group_id,
                        down_group_id,
                    );
                    if let Ok(reply) =
                        open_success_downstream(&spec, down_cid, down_group_id, &info)
                    {
                        if let Some(sink) = i.member_sink(member) {
                            let _ = sink.send(reply);
                        }
                    }
                    info!(worker = %i.label, member, down_cid, up_cid = info.up_channel_id, down_group_id, "sv2 additional channel opened");
                }
            }
            return;
        }
        // An additional open was rejected: pass the error back to the member that
        // asked for it (or fan out if the request is unknown, so no miner hangs).
        if mt == mining::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR {
            match parse_open_error(&mut frame).and_then(|(req, _)| i.pending.remove(&req)) {
                Some((member, spec)) => {
                    // Rebuild with the miner's original request_id (the upstream
                    // error echoes the proxy-assigned one the miner won't know).
                    if let Some(sink) = i.member_sink(member) {
                        if let Ok(f) =
                            open_channel_error(spec.request_id(), "upstream rejected channel open")
                        {
                            let _ = sink.send(f);
                        }
                    }
                }
                None => {
                    for sink in i.members.values() {
                        let _ = sink.send(frame.clone().into());
                    }
                }
            }
            return;
        }

        if !wire::is_channel_scoped(mt) {
            debug!(mt, "dropping non-channel-scoped upstream message");
            return;
        }

        let Some(up_cid) = wire::read_channel_id(&mut frame) else {
            debug!(
                mt,
                "channel-scoped upstream frame too short for a channel_id; dropping"
            );
            return;
        };

        // Trace job/prev-hash flow (job_id = bytes 4..8) at debug level: lets us
        // confirm extended jobs + their SetNewPrevHash reach the miner with
        // matching ids + channel mapping (incl. the group_channel_id remap).
        if matches!(
            mt,
            mining::MESSAGE_TYPE_NEW_MINING_JOB
                | mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB
                | mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ) {
            let job_id = {
                let p = frame.payload();
                if p.len() >= 8 {
                    u32::from_le_bytes([p[4], p[5], p[6], p[7]])
                } else {
                    0
                }
            };
            debug!(
                worker = %i.label,
                mt,
                up_cid,
                down_cid = ?i.up_to_down.get(&up_cid),
                job_id,
                "sv2 job/prev-hash upstream→miner"
            );
        }

        // Vardiff: a new target changes this channel's share difficulty.
        if mt == mining::MESSAGE_TYPE_SET_TARGET {
            if let Some(target) = parse_set_target(&mut frame) {
                let diff = translate::difficulty_from_target(&target);
                let mapped = i.up_to_down.get(&up_cid).copied();
                debug!(
                    worker = %i.label,
                    up_cid,
                    down_cid = ?mapped,
                    diff,
                    "sv2 SetTarget from upstream (forwarding to miner)"
                );
                if let Some(c) = i.channels.iter_mut().find(|c| c.up_channel_id == up_cid) {
                    c.difficulty = diff;
                }
            }
        }

        // Accounting: weight accepted shares by the channel's current
        // difficulty (proxy-authoritative) and credit the active rental.
        let mut order_credit: Option<(String, f64, u64)> = None;
        let mut order_reject: Option<(String, String)> = None;
        if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_ERROR {
            if let Some((_, code)) = parse_submit_error(&mut frame) {
                order_reject = i.routing.order_id().map(|o| (o.to_string(), code));
            }
        }
        if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS {
            let count = parse_submit_success(&mut frame).map_or(0, |(_, n)| n);
            let diff = i
                .channels
                .iter()
                .find(|c| c.up_channel_id == up_cid)
                .map(|c| c.difficulty)
                .unwrap_or(0.0);
            let work = diff * count as f64;
            let shares = count as u64;
            let inner = &mut *i;
            if inner.delivery.accepted(work, shares, &inner.label) {
                order_credit = inner
                    .routing
                    .order_id()
                    .map(|o| (o.to_string(), work, shares));
            }
        }

        // Forward with the channel id remapped. A frame addressed to a group id
        // (the pool's group-broadcast job + prev-hash) goes to the members of THAT
        // group; a per-channel frame routes only to its owner.
        let recipients = i.group_recipients(up_cid);
        if !recipients.is_empty() {
            // Group-broadcast job. Only Extended channels are grouped — Standard
            // members are ungrouped, get their work per channel, and must NOT
            // receive a group-addressed NewExtendedMiningJob (a header-only device
            // cannot process it); `group_recipients` filters them out.
            //
            // One write per distinct downstream group, not one per rig: a member
            // whose channel sits in a different group must not see this job at
            // all. It is built for its own group's extranonce layout, so the
            // wrong member would hash a coinbase it reconstructs differently and
            // every share it finds would be rejected.
            for (down_group_id, member) in recipients {
                if let Some(sink) = i.members.get(&member) {
                    let mut f = frame.clone();
                    wire::rewrite_channel_id(&mut f, down_group_id);
                    let _ = sink.send(f.into());
                }
            }
        } else if let Some(&down_cid) = i.up_to_down.get(&up_cid) {
            wire::rewrite_channel_id(&mut frame, down_cid);
            if let Some(sink) = i.member_sink_for_up(up_cid) {
                let _ = sink.send(frame.into());
            } else {
                debug!(up_cid, down_cid, "no member owns this channel; dropping");
            }
        } else {
            debug!(up_cid, "no channel mapping for upstream frame; dropping");
        }
        drop(i);

        if let Some((order_id, work, shares)) = order_credit {
            self.orders.add_work(&order_id, work, shares);
        }
        if let Some((order_id, reason)) = order_reject {
            self.orders.note_rejected(&order_id, reason);
        }
    }

    pub async fn status(&self) -> SessionStatus {
        let i = self.inner.lock().await;
        i.delivery
            .status(&i.label, &i.routing, &i.active.target.url, "sv2")
    }

    async fn worker_label(&self) -> String {
        self.inner.lock().await.label.clone()
    }

    pub(crate) fn orders(&self) -> &OrderStore {
        &self.orders
    }

    /// Whether the rig's upstream is an SV1 pool reached via translation (can't
    /// multiplex extra channels, so it can't take bundled members).
    async fn is_translating(&self) -> bool {
        self.inner.lock().await.translating
    }

    /// Attach a same-rig miner connection as a new member and open its first
    /// channel on the shared upstream. The steady reader finalizes the open and
    /// routes the OpenSuccess back to this member. Returns the member id, or
    /// `None` if the rig can't take more members (SV1-translated upstream).
    async fn attach_member(
        &self,
        sink: mpsc::UnboundedSender<EitherFrame>,
        spec: &OpenSpec,
    ) -> Option<u32> {
        let mut i = self.inner.lock().await;
        if i.translating {
            return None;
        }
        let member = i.add_member(sink);
        if let Err(e) = i.open_upstream_channel(member, spec) {
            warn!(error = %e, "attach: additional channel open failed");
        }
        Some(member)
    }

    /// Detach a member: close its channels on the shared upstream (so the pool
    /// drops just this member from the group) and forget its channels/pending.
    /// Returns true if this was the last member, so the caller tears the rig down.
    async fn detach_member(&self, member: u32) -> bool {
        let mut i = self.inner.lock().await;
        i.members.remove(&member);
        let up_cids: Vec<u32> = i
            .channels
            .iter()
            .filter(|c| c.owner == member)
            .map(|c| c.up_channel_id)
            .collect();
        // A translated upstream has no SV2 channel to close: it is one SV1
        // connection, and `swap_to_sv1_translate` collapsed the rig onto a
        // single channel of its own making. Sending the built CloseChannel
        // there panics the translate writer, which calls `payload()` on
        // everything it is handed — `wire`'s contract is that only handshake
        // and channel-open messages are built rather than re-emitted
        // already-serialized. The two channel-OPEN paths already refuse a
        // translated upstream; this is the same rule for the close.
        let notify_upstream = !i.translating;
        for up in up_cids {
            if notify_upstream {
                if let Ok(f) = close_channel_upstream(up) {
                    let _ = i.active.to_up.send(f);
                }
            }
            i.up_to_down.remove(&up);
        }
        i.channels.retain(|c| c.owner != member);
        i.pending.retain(|_, (m, _)| *m != member);
        i.members.is_empty()
    }
}

// ── SV1 upstream translator (combo 4): SV2 miner ↔ SV1 buyer pool ────
//
// The buyer pool may speak SV1 behind an SV2 miner. The proxy is the SV1 client
// to the pool and synthesizes the miner-facing SV2 channel: the SV1 extranonce1
// becomes the channel's extranonce_prefix, `mining.notify` becomes a future
// `NewExtendedMiningJob` + `SetNewPrevHash` (SV2 §7 order), `mining.set_difficulty`
// becomes `SetTarget`, the miner's `SubmitSharesExtended` becomes a `mining.submit`,
// and the pool's result becomes `SubmitSharesSuccess`/`SubmitSharesError`. One
// Extended channel per SV1 connection (a single extranonce1); Standard channels
// and additional channels are refused (loudly), not silently dropped.

/// An SV1 pool connection for translation, positioned after the handshake.
struct Sv1UpConn {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    extranonce1: Vec<u8>,
    extranonce2_size: u16,
    version_mask: Option<u32>,
    initial_diff: f64,
    /// `set_difficulty`/`notify` notifications seen during the handshake (the
    /// initial difficulty + first job), replayed to the reader on start.
    prelude: Vec<String>,
}

/// Per-job state the proxy must remember to translate the miner's submit back to
/// the pool: the pool's string job id, and (Standard only) the `extranonce2` the
/// proxy chose when it built that job's coinbase (a Standard submit carries none).
#[derive(Clone)]
struct Sv1JobInfo {
    sv1_job_id: String,
    extranonce2: Option<Vec<u8>>,
}

/// Shared state between the two SV1-translate driver tasks.
#[derive(Default)]
struct Sv1UpState {
    version_mask: Option<u32>,
    user_name: String,
    /// Extended channel (miner rolls its own extranonce) vs Standard (the proxy
    /// assembles the coinbase + folds the merkle root and rolls the extranonce2).
    extended: bool,
    /// The SV1 pool's fixed extranonce1 (the coinbase prefix for Standard builds).
    extranonce1: Vec<u8>,
    /// The extranonce2 byte length the SV1 pool allows.
    extranonce2_size: u16,
    /// Rolls a distinct extranonce2 per Standard job → distinct merkle roots.
    next_extranonce2: u64,
    next_job_id: u32,
    job_map: HashMap<u32, Sv1JobInfo>,
    next_submit_id: u64,
    submit_seq: HashMap<u64, u32>,
    first_job_sent: bool,
}

/// Connect an SV1 pool for translation: the shared SV1 handshake with the
/// proxy's own version-rolling `configure`, plus what the translator needs from
/// it (granted version mask, extranonce as bytes, initial difficulty).
async fn connect_sv1_upstream(
    target: &UpstreamTarget,
    user_identity: &str,
) -> anyhow::Result<Sv1UpConn> {
    let conn = sv1::connect_pool(
        target,
        user_identity,
        Some(&RpcMessage::version_rolling_configure()),
    )
    .await?;
    let initial_diff = conn
        .prelude
        .iter()
        .rev()
        .find_map(|l| translate::set_difficulty_from_line(l))
        .unwrap_or(1.0);
    Ok(Sv1UpConn {
        extranonce1: Vec::<u8>::from_hex(&conn.extranonce1)
            .map_err(|e| anyhow!("bad extranonce hex: {e}"))?,
        extranonce2_size: conn.extranonce2_size as u16,
        read: conn.read,
        write: conn.write,
        version_mask: conn.version_mask,
        initial_diff,
        prelude: conn.prelude,
    })
}

/// Writer: the miner's share frames → SV1 `mining.submit` lines. Handles both
/// `SubmitSharesExtended` (extranonce from the share) and `SubmitSharesStandard`
/// (extranonce2 is the one the proxy chose when it built that job).
fn spawn_sv1_translate_writer(
    mut write: OwnedWriteHalf,
    state: Arc<Mutex<Sv1UpState>>,
    mut rx: mpsc::UnboundedReceiver<EitherFrame>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let Some(mut f) = wire::into_sv2(frame) else {
                continue;
            };
            let Some(mt) = wire::msg_type(&f) else {
                continue;
            };
            let payload = f.payload();
            let line = match Mining::try_from((mt, payload)) {
                Ok(Mining::SubmitSharesExtended(submit)) => {
                    let mut s = state.lock().await;
                    let Some(info) = s.job_map.get(&submit.job_id).cloned() else {
                        continue; // share for a job we no longer have
                    };
                    let id = s.next_submit_id;
                    s.next_submit_id = s.next_submit_id.wrapping_add(1);
                    s.submit_seq.insert(id, submit.sequence_number);
                    let (mask, user) = (s.version_mask, s.user_name.clone());
                    drop(s);
                    translate::sv2_submit_to_sv1(&submit, user, info.sv1_job_id, id, mask)
                }
                Ok(Mining::SubmitSharesStandard(submit)) => {
                    let mut s = state.lock().await;
                    let Some(info) = s.job_map.get(&submit.job_id).cloned() else {
                        continue;
                    };
                    // Standard jobs always recorded an extranonce2 at build time.
                    let Some(extranonce2) = info.extranonce2 else {
                        continue;
                    };
                    let id = s.next_submit_id;
                    s.next_submit_id = s.next_submit_id.wrapping_add(1);
                    s.submit_seq.insert(id, submit.sequence_number);
                    let (mask, user) = (s.version_mask, s.user_name.clone());
                    drop(s);
                    translate::sv2_standard_submit_to_sv1(
                        &submit,
                        user,
                        info.sv1_job_id,
                        extranonce2,
                        id,
                        mask,
                    )
                }
                _ => continue, // only shares cross to the SV1 pool
            };
            let sv1 = match line {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "sv2→sv1 submit translation failed");
                    continue;
                }
            };
            if write
                .write_all(translate::submit_to_line(sv1).as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

/// Reader: SV1 pool lines → synthesized SV2 frames for the miner (jobs, target,
/// share results), plus accounting. Processes the handshake `prelude` first.
fn spawn_sv1_translate_reader(
    session: Arc<Sv2Session>,
    generation: u64,
    mut read: BufReader<OwnedReadHalf>,
    state: Arc<Mutex<Sv1UpState>>,
    down_cid: u32,
    prelude: Vec<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        for line in prelude {
            handle_sv1_line(&session, generation, &state, down_cid, line.trim()).await;
        }
        let mut line = String::new();
        let mut last = String::new();
        let reason = loop {
            line.clear();
            match read.read_line(&mut line).await {
                Ok(0) => break "closed by pool".to_string(),
                Err(e) => break e.to_string(),
                Ok(_) => {}
            }
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            last.clear();
            last.extend(l.chars().take(300));
            handle_sv1_line(&session, generation, &state, down_cid, l).await;
        };
        // Pool closed/errored (an intentional swap aborts this task first).
        warn!(gen = generation, %reason, last_line = %last, "sv1 upstream connection ended");
        let _ = session.died_tx.send(generation);
    })
}

async fn handle_sv1_line(
    session: &Arc<Sv2Session>,
    generation: u64,
    state: &Arc<Mutex<Sv1UpState>>,
    down_cid: u32,
    line: &str,
) {
    // mining.notify → a job (+ SetNewPrevHash on a clean/first job). Extended:
    // pass the coinbase parts through (the miner folds). Standard: the proxy
    // chooses an extranonce2, assembles the coinbase + folds the merkle root.
    if let Some(notify) = translate::notify_from_line(line) {
        let (sv2_job_id, as_future, vra, extended, en1, en2) = {
            let mut s = state.lock().await;
            let jid = s.next_job_id;
            s.next_job_id = s.next_job_id.wrapping_add(1);
            if s.job_map.len() >= 64 {
                s.job_map.clear();
            }
            // The first job must be future (the miner has no prev-hash yet).
            let as_future = notify.clean_jobs || !s.first_job_sent;
            s.first_job_sent = true;
            let vra = s.version_mask.is_some();
            if s.extended {
                s.job_map.insert(
                    jid,
                    Sv1JobInfo {
                        sv1_job_id: notify.job_id.clone(),
                        extranonce2: None,
                    },
                );
                (jid, as_future, vra, true, Vec::new(), Vec::new())
            } else {
                let mut e2 = vec![0u8; s.extranonce2_size as usize];
                let counter = s.next_extranonce2.to_le_bytes();
                s.next_extranonce2 = s.next_extranonce2.wrapping_add(1);
                let n = e2.len().min(counter.len());
                e2[..n].copy_from_slice(&counter[..n]);
                let en1 = s.extranonce1.clone();
                s.job_map.insert(
                    jid,
                    Sv1JobInfo {
                        sv1_job_id: notify.job_id.clone(),
                        extranonce2: Some(e2.clone()),
                    },
                );
                (jid, as_future, vra, false, en1, e2)
            }
        };
        let built = if extended {
            translate::sv1_notify_to_sv2_job(&notify, down_cid, sv2_job_id, as_future, vra).map(
                |(j, p)| {
                    (
                        wire::frame_from(AnyMessage::Mining(Mining::NewExtendedMiningJob(j))),
                        p,
                    )
                },
            )
        } else {
            translate::sv1_notify_to_sv2_standard_job(
                &notify, down_cid, sv2_job_id, &en1, &en2, as_future,
            )
            .map(|(j, p)| {
                (
                    wire::frame_from(AnyMessage::Mining(Mining::NewMiningJob(j))),
                    p,
                )
            })
        };
        match built {
            Ok((job_frame, prev)) => {
                session.send_translate_frame(generation, job_frame).await;
                if let Some(p) = prev {
                    let prev_frame =
                        wire::frame_from(AnyMessage::Mining(Mining::SetNewPrevHash(p)));
                    session.send_translate_frame(generation, prev_frame).await;
                }
            }
            Err(e) => warn!(error = %e, "sv1→sv2 job translation failed"),
        }
        return;
    }
    // mining.set_difficulty → SetTarget.
    if let Some(diff) = translate::set_difficulty_from_line(line) {
        session.set_translate_diff(generation, down_cid, diff).await;
        if let Ok(f) = set_target(down_cid, translate::target_from_difficulty(diff).to_vec()) {
            session.send_translate_frame(generation, f).await;
        }
        return;
    }
    // A submit response → SubmitSharesSuccess / SubmitSharesError for the miner.
    if let Ok(m) = RpcMessage::parse(line) {
        if m.method.is_some() {
            return;
        }
        let Some(id) = m.id.as_ref().and_then(|v| v.as_u64()) else {
            return;
        };
        let seq = state.lock().await.submit_seq.remove(&id);
        let Some(seq) = seq else { return };
        if matches!(&m.result, Some(Value::Bool(true))) {
            session.credit_translate(generation, down_cid).await;
            let ok = mining::SubmitSharesSuccess {
                channel_id: down_cid,
                last_sequence_number: seq,
                new_submits_accepted_count: 1,
                new_shares_sum: 1,
            };
            let f = wire::frame_from(AnyMessage::Mining(Mining::SubmitSharesSuccess(ok)));
            session.send_translate_frame(generation, f).await;
        } else {
            let reason = m.reject_reason();
            warn!(error = %reason, "sv1 pool rejected a share");
            session.note_translate_rejected(generation, reason).await;
            if let Ok(error_code) = Str0255::try_from("rejected".to_string()) {
                let err = mining::SubmitSharesError {
                    channel_id: down_cid,
                    sequence_number: seq,
                    error_code,
                };
                let f = wire::frame_from(AnyMessage::Mining(Mining::SubmitSharesError(err)));
                session.send_translate_frame(generation, f).await;
            }
        }
    }
}

impl Sv2Session {
    /// Forward a synthesized frame to the miner if the generation is current.
    async fn send_translate_frame(&self, generation: u64, frame: EitherFrame) {
        let i = self.inner.lock().await;
        if generation != i.active.generation {
            return;
        }
        // SV1 translation carries a single channel/member; deliver to it. (The
        // transport `EitherFrame` isn't `Clone`, so there's no fan-out here — SV1
        // upstreams are never bundled.)
        if let Some(sink) = i.members.values().next() {
            let _ = sink.send(frame);
        }
    }

    /// Record the share difficulty implied by the SV1 pool's `set_difficulty`.
    async fn set_translate_diff(&self, generation: u64, down_cid: u32, diff: f64) {
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return;
        }
        if let Some(c) = i
            .channels
            .iter_mut()
            .find(|c| c.down_channel_id == down_cid)
        {
            c.difficulty = diff;
        }
    }

    /// Credit one accepted share (diff-weighted) to the hashrate window and, when
    /// rented, the order. Generation-guarded.
    async fn credit_translate(&self, generation: u64, down_cid: u32) {
        let credit = {
            let mut guard = self.inner.lock().await;
            let i = &mut *guard;
            if generation != i.active.generation {
                return;
            }
            let work = i
                .channels
                .iter()
                .find(|c| c.down_channel_id == down_cid)
                .map(|c| c.difficulty)
                .unwrap_or(0.0);
            if i.delivery.accepted(work, 1, &i.label) {
                i.routing.order_id().map(|o| (o.to_string(), work, 1))
            } else {
                None
            }
        };
        if let Some((order_id, work, shares)) = credit {
            self.orders.add_work(&order_id, work, shares);
        }
    }

    /// Remember a translated pool's reject reason on the active rental.
    /// Generation-guarded.
    async fn note_translate_rejected(&self, generation: u64, reason: String) {
        let order_id = {
            let i = self.inner.lock().await;
            if generation != i.active.generation {
                return;
            }
            i.routing.order_id().map(str::to_string)
        };
        if let Some(order_id) = order_id {
            self.orders.note_rejected(&order_id, reason);
        }
    }

    /// Connect `target` (protocol auto-detected) and install it as the initial
    /// upstream: SV2 passthrough, or SV1 translation.
    async fn connect_and_install_initial(
        self: &Arc<Self>,
        target: UpstreamTarget,
        spec: OpenSpec,
        worker: &str,
        routing: Routing,
        member: u32,
    ) -> anyhow::Result<()> {
        // Native first: try SV2 (reusing its socket on success); if the pool
        // doesn't answer as SV2, it's an SV1 buyer pool → translate.
        // An unreachable pool says nothing about protocols, so it must not buy
        // the miner a permanent downgrade — fail, and let the connect retry.
        match probe_sv2(&target).await {
            Ok((read, write)) => {
                self.install_sv2_initial(read, write, spec, target, routing, member)
                    .await
            }
            Err(f) => {
                f.allow_translation(&target.url)?;
                let up_ident = crate::proto::relay::upstream_worker(&target.user, worker);
                let conn = connect_sv1_upstream(&target, &up_ident).await?;
                self.install_sv1_translate_initial(conn, spec, up_ident, target, routing, member)
                    .await
            }
        }
    }

    /// Install an SV2 passthrough upstream and forward the miner's open (the
    /// steady reader finalizes it on the pool's OpenSuccess).
    async fn install_sv2_initial(
        self: &Arc<Self>,
        read: Read,
        write: Write,
        spec: OpenSpec,
        target: UpstreamTarget,
        routing: Routing,
        member: u32,
    ) -> anyhow::Result<()> {
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_writer(write, up_rx);
        let mut i = self.inner.lock().await;
        // Nothing to replay: this path installs the FIRST channel of a fresh
        // connection, so no earlier channel exists whose job could have arrived
        // while it was opening. Every later channel is opened by the miner and
        // handled by this reader.
        let reader = spawn_upstream_reader(self.clone(), 0, read, Vec::new());
        i.install_active(0, target, to_up, reader, writer);
        i.routing = routing;
        i.translating = false;
        i.open_upstream_channel(member, &spec)
    }

    /// Install an SV1 translation upstream: open the channel locally (synthesize
    /// the OpenSuccess) and start the driver tasks.
    async fn install_sv1_translate_initial(
        self: &Arc<Self>,
        conn: Sv1UpConn,
        spec: OpenSpec,
        up_ident: String,
        target: UpstreamTarget,
        routing: Routing,
        member: u32,
    ) -> anyhow::Result<()> {
        let (down_cid, sink) = {
            let mut i = self.inner.lock().await;
            let c = i.next_down_cid;
            i.next_down_cid += 1;
            (c, i.member_sink(member).cloned())
        };
        // Reply OpenSuccess to the member before any job (FIFO on its sink): the
        // SV1 extranonce1 is the channel's extranonce_prefix. The builder emits a
        // Standard or Extended success per the channel type the miner opened.
        let info = ChannelInfo {
            request_id: spec.request_id(),
            up_channel_id: down_cid,
            extranonce_prefix: conn.extranonce1.clone(),
            target: translate::target_from_difficulty(conn.initial_diff).to_vec(),
            extranonce_size: conn.extranonce2_size,
            group_channel_id: 0,
        };
        if let Some(sink) = &sink {
            sink.send(open_success_downstream(&spec, down_cid, 0, &info)?)
                .map_err(|_| anyhow!("miner writer gone"))?;
        }
        let channel = Channel::translated(down_cid, member, spec, conn.initial_diff);
        // A fresh session has no earlier upstream, so nothing was pending on it.
        self.install_sv1_translated(conn, up_ident, target, routing, 0, channel)
            .await;
        Ok(())
    }

    /// Switch the (single) channel onto an SV1 buyer pool via translation.
    async fn swap_to_sv1_translate(
        self: &Arc<Self>,
        target: UpstreamTarget,
        routing: Routing,
        generation: u64,
        up_ident: String,
    ) -> anyhow::Result<()> {
        let (down_cid, owner, spec, members) = {
            let i = self.inner.lock().await;
            match i.channels.first() {
                Some(c) => (
                    c.down_channel_id,
                    c.owner,
                    c.spec.clone(),
                    i.members.clone(),
                ),
                None => bail!("no channel to switch"),
            }
        };
        let conn = connect_sv1_upstream(&target, &up_ident)
            .await
            .map_err(|e| anyhow!("switch to {}: {e}", target.url))?;
        let initial_target = translate::target_from_difficulty(conn.initial_diff).to_vec();
        let extranonce1 = conn.extranonce1.clone();
        let channel = Channel::translated(down_cid, owner, spec, conn.initial_diff);
        let abandoned = self
            .install_sv1_translated(conn, up_ident, target.clone(), routing, generation, channel)
            .await;
        // Re-point the channel's owner: new extranonce prefix + target; the reader
        // streams the new pool's first job after.
        if let Some(sink) = members.get(&owner) {
            let _ = sink.send(set_extranonce_prefix(down_cid, extranonce1)?);
            let _ = sink.send(set_target(down_cid, initial_target)?);
        }
        refuse_abandoned_opens(&members, abandoned);
        info!(upstream = %target.url, generation, "sv2→sv1 upstream switched (translated)");
        Ok(())
    }

    /// Make the SV1 pool behind `conn` the active upstream, translated onto the
    /// single `channel`. Returns the opens that were still pending on the
    /// upstream it replaces.
    async fn install_sv1_translated(
        self: &Arc<Self>,
        conn: Sv1UpConn,
        up_ident: String,
        target: UpstreamTarget,
        routing: Routing,
        generation: u64,
        channel: Channel,
    ) -> Vec<(u32, u32)> {
        let state = Arc::new(Mutex::new(Sv1UpState {
            version_mask: conn.version_mask,
            user_name: up_ident,
            extended: channel.spec.is_extended(),
            extranonce1: conn.extranonce1,
            extranonce2_size: conn.extranonce2_size,
            next_job_id: 1,
            next_submit_id: 1,
            ..Default::default()
        }));
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_sv1_translate_writer(conn.write, state.clone(), up_rx);
        let down_cid = channel.down_channel_id;
        let mut i = self.inner.lock().await;
        // Reader spawned inside the lock — see `Inner::install_active`.
        let reader = spawn_sv1_translate_reader(
            self.clone(),
            generation,
            conn.read,
            state,
            down_cid,
            conn.prelude,
        );
        i.install_active(generation, target, to_up, reader, writer);
        i.channels = vec![channel];
        i.up_to_down = HashMap::from([(down_cid, down_cid)]);
        i.group_down.clear();
        i.routing = routing;
        i.translating = true;
        i.take_pending_opens()
    }
}

/// Answer every open that was pending on a replaced upstream with an error,
/// so the member that asked reopens instead of waiting forever.
fn refuse_abandoned_opens(
    members: &HashMap<u32, mpsc::UnboundedSender<EitherFrame>>,
    abandoned: Vec<(u32, u32)>,
) {
    for (member, request_id) in abandoned {
        if let Ok(f) = open_channel_error(request_id, "upstream switched; please reopen") {
            if let Some(sink) = members.get(&member) {
                let _ = sink.send(f);
            }
        }
    }
}

// ── connection handler ──────────────────────────────────────────────

/// Drive one SV2 seller miner end to end.
pub async fn handle_seller_miner_sv2(
    miner: TcpStream,
    peer: String,
    ctx: ProxyContext,
    keys: NoiseKeys,
) -> anyhow::Result<()> {
    let _ = miner.set_nodelay(true);
    let stream = accept_noise_connection::<Msg>(miner, keys.public(), keys.secret(), CERT_VALIDITY)
        .await
        .map_err(|e| anyhow!("downstream noise accept: {e:?}"))?;
    let (mut down_read, down_write) = stream.into_split();

    // 1. Miner SetupConnection.
    let setup = read_one(&mut down_read).await?;
    if wire::msg_type(&setup) != Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
        bail!("expected SetupConnection from miner");
    }

    // 2. Acknowledge setup (flags=0, permissive). Register-only: no upstream is
    //    contacted yet — it is resolved from the worker in the OpenMiningChannel
    //    below, so SV2 needs no bootstrap/fallback pool at all.
    let (to_miner, to_miner_rx) = mpsc::unbounded_channel::<EitherFrame>();
    let miner_writer = spawn_writer(down_write, to_miner_rx);
    to_miner
        .send(setup_success(0))
        .map_err(|_| anyhow!("miner writer gone"))?;

    // 3. Miner OpenMiningChannel → capture spec + worker.
    let mut open_frame = read_one(&mut down_read).await?;
    let MinerOpen { spec, worker } =
        parse_miner_open(&mut open_frame).ok_or_else(|| anyhow!("expected OpenMiningChannel"))?;

    // 4. Register-only: the worker is admitted when it has a registered rig
    //    (its idle pool) OR an active order, the same rule the SV1 relay applies,
    //    so a rented rig is still served while the buyer's order runs.
    let idle_target = ctx.sellers.default_pool(&worker).await;

    // 5. Decide where the first channel opens: straight on the buyer's pool if a
    //    rental is already active (resume on reconnect without an open-then-switch
    //    round-trip), else the rig's idle pool. `default_target` stays the idle
    //    pool, so a release/revert returns there; with none, the revert drops
    //    the members instead.
    let active_order = ctx
        .orders
        .active_for_worker(&worker, crate::orders::now_ms())
        .await;
    let (open_target, routing) = match (&active_order, &idle_target) {
        (Some(o), _) => (
            o.target.clone(),
            Routing::Rented {
                order_id: o.id.clone(),
            },
        ),
        (None, Some(idle)) => (idle.clone(), Routing::Idle),
        (None, None) => {
            warn!(%peer, %worker, "rejected unregistered worker (register-only)");
            bail!("unregistered worker {worker} — register the rig first");
        }
    };

    // 6. Bundle onto this rig's existing SV2 upstream if one is live; else build a
    //    fresh session (which becomes the rig if its upstream ends up SV2). The
    //    per-worker gate serializes create-or-attach so two same-rig miners
    //    connecting at once don't each build an upstream.
    let gate = ctx.sv2_rigs.gate(&worker).await;
    let _hold = gate.lock().await;

    let attached = match ctx.sv2_rigs.get(&worker).await {
        Some(rig) => {
            // Subscribe FIRST: a pool change firing from here on breaks the
            // serve loop below, and one that fired earlier was persisted in the
            // order store before the signal — the reconcile resolve sees it.
            let reconnect_rx = rig.subscribe_reconnect();
            // Re-resolve NOW (the resolve at the top of this function predates
            // the subscription) and align the rig's shared upstream with it, so
            // this member can't bundle onto a stale pre-rent/post-cancel pool.
            let desired = ctx
                .orders
                .active_for_worker(&worker, crate::orders::now_ms())
                .await;
            rig.reconcile_routing(desired.as_ref()).await;
            rig.attach_member(to_miner.clone(), &spec)
                .await
                .map(|member| (rig, member, reconnect_rx))
        }
        None => None,
    };

    let (session, member_id, mut reconnect_rx) = match attached {
        Some((rig, member, reconnect_rx)) => {
            drop(_hold);
            info!(%peer, %worker, member, "sv2 miner bundled onto existing rig");
            (rig, member, reconnect_rx)
        }
        None => {
            // Build the session with a placeholder upstream, then connect +
            // install the real one — SV2 passthrough or SV1 translation,
            // auto-detected. On primary failure, fall back to the order's pool.
            let (died_tx, died_rx) = mpsc::unbounded_channel::<u64>();
            let (placeholder_to_up, _placeholder_rx) = mpsc::unbounded_channel::<EitherFrame>();
            let session = Arc::new(Sv2Session {
                switch: Mutex::new(()),
                died_tx,
                orders: ctx.orders.clone(),
                reconnect: watch::channel(0).0,
                retry_switch: Arc::new(Mutex::new(())),
                inner: Mutex::new(Inner {
                    active: ActiveUpstream {
                        generation: 0,
                        target: open_target.clone(),
                        to_up: placeholder_to_up,
                        reader: tokio::spawn(async {}), // placeholders, installed below
                        writer: tokio::spawn(async {}),
                    },
                    generation_counter: 0,
                    channels: Vec::new(),
                    up_to_down: std::collections::HashMap::new(),
                    group_down: std::collections::HashMap::new(),
                    pending: std::collections::HashMap::new(),
                    next_down_cid: 1,
                    next_up_req: 1,
                    members: std::collections::HashMap::new(),
                    next_member_id: 1,
                    routing: routing.clone(),
                    default_target: idle_target.clone(),
                    delivery: Delivery::new(),
                    label: worker.clone(),
                    translating: false,
                    supervisor: None,
                    idle_token: 0,
                }),
            });

            // Subscribe before the registry insert below: `reconnect_all` can
            // only reach this session once it's registered, so no pool-change
            // signal can slip between registration and our subscription.
            let reconnect_rx = session.subscribe_reconnect();

            // This connection is the rig's first member; its sink owns the
            // initial channel and receives that channel's per-channel frames.
            let member_id = session.inner.lock().await.add_member(to_miner.clone());

            let install = |target| {
                session.connect_and_install_initial(
                    target,
                    spec.clone(),
                    &worker,
                    routing.clone(),
                    member_id,
                )
            };
            let upstream = match &active_order {
                Some(o) => o.connect_with_fallback(install).await?,
                None => {
                    install(open_target.clone()).await?;
                    open_target
                }
            };

            ctx.registry
                .insert(worker.clone(), AnySession::Sv2(session.clone()))
                .await;
            // Supervisor owned by the rig (aborted only on last-member teardown).
            let supervisor = tokio::spawn(crate::control::supervise_upstream(
                AnySession::Sv2(session.clone()),
                died_rx,
            ));
            session.inner.lock().await.supervisor = Some(supervisor);

            // Become the bundle target for this worker only if the upstream is SV2
            // (a translated SV1 rig can't multiplex) and the slot is still free.
            if !session.is_translating().await {
                ctx.sv2_rigs
                    .insert_if_absent(&worker, session.clone())
                    .await;
            }
            drop(_hold);
            match &active_order {
                Some(o) => {
                    info!(%peer, %worker, member = member_id, upstream = %upstream.url, order = %o.id, "sv2 relay established (rented)")
                }
                None => {
                    info!(%peer, %worker, member = member_id, upstream = %upstream.url, "sv2 relay established (idle)")
                }
            }
            (session, member_id, reconnect_rx)
        }
    };

    // 7. Downstream loop: open additional channels and forward shares/updates
    //    upstream (channel-id remapped per channel).
    let result: anyhow::Result<()> = async {
        loop {
            let mut frame = tokio::select! {
                biased;
                // Operator-initiated pool change → close the connection so the
                // miner reconnects and re-handshakes against the new upstream.
                _ = reconnect_rx.changed() => {
                    info!(%peer, %worker, "forcing miner reconnect for pool change");
                    break;
                }
                read = down_read.read_frame() => match read {
                    Ok(f) => match wire::into_sv2(f) {
                        Some(f) => f,
                        None => continue,
                    },
                    Err(_) => break,
                },
            };
            let Some(mt) = wire::msg_type(&frame) else {
                continue;
            };
            if mt == mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL
                || mt == mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL
            {
                // Additional channel: forward to the active upstream (account
                // rewritten); the upstream reader finalizes it on success. A
                // translated SV1 upstream carries a single extranonce1, so it
                // can't multiplex extra channels — refuse them loudly.
                if let Some(open) = parse_miner_open(&mut frame) {
                    let mut i = session.inner.lock().await;
                    if i.translating {
                        drop(i);
                        if let Ok(f) = open_channel_error(
                            open.spec.request_id(),
                            "additional channels are not supported on an SV1 upstream",
                        ) {
                            let _ = to_miner.send(f);
                        }
                        continue;
                    }
                    if let Err(e) = i.open_upstream_channel(member_id, &open.spec) {
                        warn!(%worker, error = %e, "additional channel open failed");
                    }
                }
            } else if wire::is_channel_scoped(mt) {
                let is_submit = matches!(
                    mt,
                    mining::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD
                        | mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED
                );
                let mut submit_order: Option<String> = None;
                {
                    let mut i = session.inner.lock().await;
                    let Some(down_cid) = wire::read_channel_id(&mut frame) else {
                        debug!(
                            "channel-scoped downstream frame too short for a channel_id; dropping"
                        );
                        continue;
                    };
                    if let Some(up_cid) = i.up_for_down(down_cid) {
                        if is_submit {
                            let inner = &mut *i;
                            inner.delivery.submitted(&inner.label);
                            submit_order = inner.routing.order_id().map(str::to_string);
                        }
                        wire::rewrite_channel_id(&mut frame, up_cid);
                        let _ = i.active.to_up.send(frame.into());
                    } else {
                        debug!(
                            down_cid,
                            "no channel mapping for downstream frame; dropping"
                        );
                    }
                }
                if let Some(order_id) = submit_order {
                    session.orders.add_submitted(&order_id, 1);
                }
            } else {
                debug!(mt, "ignoring non-channel-scoped downstream message");
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        debug!(%peer, error = %e, "sv2 downstream ended");
    }

    // Teardown: detach this member (close its channels on the shared upstream so
    // the pool drops it from the group). Only when it was the LAST member do we
    // tear the whole rig down — other bundled members keep mining.
    let was_last = session.detach_member(member_id).await;
    miner_writer.abort();
    if was_last {
        let label = session.worker_label().await;
        if ctx.sv2_rigs.is_target(&label, &session).await {
            // Bundle-target rig: keep the upstream warm for a grace window so a
            // quick reconnect re-attaches without a fresh handshake. A reaper
            // closes it if it's still idle when the window elapses.
            let token = {
                let mut i = session.inner.lock().await;
                i.idle_token += 1;
                i.idle_token
            };
            info!(%peer, %label, "sv2 rig idle (last member left); grace before close");
            tokio::spawn(reap_idle_rig(
                ctx.sv2_rigs.clone(),
                ctx.registry.clone(),
                session.clone(),
                label,
                token,
                ctx.sv2_rigs.idle_grace,
            ));
        } else {
            // Standalone session (not a bundle target): close immediately — a
            // reconnect couldn't re-attach to it anyway.
            ctx.registry
                .remove_if(&label, &AnySession::Sv2(session.clone()))
                .await;
            let i = session.inner.lock().await;
            i.active.reader.abort();
            i.active.writer.abort();
            if let Some(sup) = &i.supervisor {
                sup.abort();
            }
            info!(%peer, %label, "sv2 session closed");
        }
    } else {
        info!(%peer, member = member_id, "sv2 member left; rig keeps running");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
