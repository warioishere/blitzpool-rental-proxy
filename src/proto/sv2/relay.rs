// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 downstream relay with a swappable upstream — the SV2 analogue of the
//! SV1 [`crate::proto::relay`].
//!
//! Full proxy: the proxy is the Noise responder to the miner and the Noise
//! initiator to each upstream pool. It mirrors the miner's channel type
//! (Standard or Extended) onto the upstream, assigns the miner a stable
//! downstream `channel_id`, and maps it to the upstream's `channel_id` on every
//! frame. Most traffic (jobs, prev-hash, shares, set-target, set-extranonce) is
//! forwarded by rewriting just the `channel_id` (see [`super::wire`]).
//!
//! On a rental switch the proxy opens a fresh channel on the buyer's upstream
//! for every channel and re-points the miner with `SetExtranoncePrefix` +
//! `SetTarget` — the downstream `channel_id`s are unchanged, so the miner never
//! reconnects. The new upstream's jobs + prev-hash then stream through.
//!
//! Multiple mining channels per connection are supported. Every `OpenMiningChannel`
//! — the miner's first as well as any additional one — is forwarded to the
//! upstream as a `pending` open and finalized by the steady reader when its
//! success arrives (assign a stable downstream id, map it, reply to the miner).
//! Each channel maps its own downstream↔upstream `channel_id`. The only
//! synchronous open is the switch re-open (see [`open_on`]), which must stage the
//! new upstream before the atomic swap.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use stratum_core::bitcoin::hashes::hex::FromHex;

use crate::proto::sv1::RpcMessage;
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
use crate::proto::adapter::{DownstreamAdapter, ProxyContext};
use crate::session::{HashrateWindow, Routing, UpstreamTarget};

/// How long the proxy's Noise certificate (responder side) is valid, seconds.
const CERT_VALIDITY: u64 = 3600;
/// SV2 protocol version the proxy speaks.
const SV2_VERSION: u16 = 2;
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

// ── message builders ────────────────────────────────────────────────

fn empty_str() -> Str0255<'static> {
    Str0255::try_from(String::new()).expect("empty str")
}

fn setup_connection() -> EitherFrame {
    let sc = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: SV2_VERSION,
        max_version: SV2_VERSION,
        flags: 0,
        endpoint_host: empty_str(),
        endpoint_port: 0,
        // Identify the rental proxy to the upstream pool (the pool surfaces this
        // as the userAgent, e.g. `bp-proxy/sv2`, instead of the `jd-client/sv2`
        // placeholder it uses when the vendor is empty).
        vendor: Str0255::try_from("bp-proxy".to_string()).unwrap_or_else(|_| empty_str()),
        hardware_version: empty_str(),
        firmware: empty_str(),
        device_id: empty_str(),
    };
    wire::frame_from(AnyMessage::Common(CommonMessages::SetupConnection(sc)))
}

fn setup_success(flags: u32) -> EitherFrame {
    let s = SetupConnectionSuccess {
        used_version: SV2_VERSION,
        flags,
    };
    wire::frame_from(AnyMessage::Common(CommonMessages::SetupConnectionSuccess(
        s,
    )))
}

/// Build an upstream `OpenMiningChannel` for `spec` under a caller-supplied
/// `request_id`. Several members of one rig may pick the SAME downstream
/// request_id, so the proxy assigns a unique one per open on the shared upstream
/// (see `Inner::next_up_req`) and maps the reply back to the member; the stored
/// spec keeps the miner's original request_id for the downstream OpenSuccess.
fn open_channel_upstream(
    spec: &OpenSpec,
    account: &str,
    request_id: u32,
) -> anyhow::Result<EitherFrame> {
    let user = Str0255::try_from(account.to_string()).map_err(|_| anyhow!("account too long"))?;
    let msg = match spec {
        OpenSpec::Extended {
            nominal_hash_rate,
            max_target,
            min_extranonce_size,
            ..
        } => Mining::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
            request_id,
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
            min_extranonce_size: *min_extranonce_size,
        }),
        OpenSpec::Standard {
            nominal_hash_rate,
            max_target,
            ..
        } => Mining::OpenStandardMiningChannel(OpenStandardMiningChannel {
            request_id: U32AsRef::from(request_id),
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
        }),
    };
    Ok(wire::frame_from(AnyMessage::Mining(msg)))
}

fn open_success_downstream(
    spec: &OpenSpec,
    down_channel_id: u32,
    down_group_id: u32,
    info: &ChannelInfo,
) -> anyhow::Result<EitherFrame> {
    let target = U256::try_from(info.target.clone()).map_err(|_| anyhow!("bad target"))?;
    let prefix =
        B032::try_from(info.extranonce_prefix.clone()).map_err(|_| anyhow!("bad extranonce"))?;
    let msg = if spec.is_extended() {
        Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
            request_id: spec.request_id(),
            channel_id: down_channel_id,
            target,
            extranonce_size: info.extranonce_size,
            extranonce_prefix: prefix,
            // Remapped into the downstream id namespace so the group-broadcast
            // jobs the pool addresses to this id reach the miner (see
            // `Inner::map_group`). Extended channels are the only grouped ones.
            group_channel_id: down_group_id,
        })
    } else {
        Mining::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
            request_id: U32AsRef::from(spec.request_id()),
            channel_id: down_channel_id,
            target,
            extranonce_prefix: prefix,
            group_channel_id: info.group_channel_id,
        })
    };
    Ok(wire::frame_from(AnyMessage::Mining(msg)))
}

fn set_extranonce_prefix(channel_id: u32, prefix: Vec<u8>) -> anyhow::Result<EitherFrame> {
    let m = SetExtranoncePrefix {
        channel_id,
        extranonce_prefix: B032::try_from(prefix).map_err(|_| anyhow!("bad extranonce"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(
        Mining::SetExtranoncePrefix(m),
    )))
}

fn set_target(channel_id: u32, target: Vec<u8>) -> anyhow::Result<EitherFrame> {
    let m = SetTarget {
        channel_id,
        maximum_target: U256::try_from(target).map_err(|_| anyhow!("bad target"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(Mining::SetTarget(m))))
}

fn open_channel_error(request_id: u32, reason: &str) -> anyhow::Result<EitherFrame> {
    let m = OpenMiningChannelError {
        request_id,
        error_code: Str0255::try_from(reason.to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(
        Mining::OpenMiningChannelError(m),
    )))
}

/// Tell the upstream to close one of our channels — sent when a bundled member
/// disconnects so the pool drops just that member from the rig's group (the
/// other members keep mining on the shared upstream).
fn close_channel_upstream(channel_id: u32) -> anyhow::Result<EitherFrame> {
    let m = mining::CloseChannel {
        channel_id,
        reason_code: Str0255::try_from("member disconnected".to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(Mining::CloseChannel(m))))
}

// ── message parsers (copy fields out as owned) ──────────────────────

fn parse_miner_open(frame: &mut Sv2Frame) -> Option<MinerOpen> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenStandardMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.inner_as_ref()).into_owned(),
            spec: OpenSpec::Standard {
                request_id: m.request_id.as_u32(),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.inner_as_ref().to_vec(),
            },
        }),
        Mining::OpenExtendedMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.inner_as_ref()).into_owned(),
            spec: OpenSpec::Extended {
                request_id: m.request_id,
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.inner_as_ref().to_vec(),
                min_extranonce_size: m.min_extranonce_size,
            },
        }),
        _ => None,
    }
}

pub(crate) fn parse_open_success(frame: &mut Sv2Frame) -> Option<ChannelInfo> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenExtendedMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id,
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.inner_as_ref().to_vec(),
            target: m.target.inner_as_ref().to_vec(),
            extranonce_size: m.extranonce_size,
            group_channel_id: m.group_channel_id,
        }),
        Mining::OpenStandardMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id.as_u32(),
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.inner_as_ref().to_vec(),
            target: m.target.inner_as_ref().to_vec(),
            extranonce_size: 0,
            group_channel_id: m.group_channel_id,
        }),
        _ => None,
    }
}

/// The `request_id` of an `OpenMiningChannelError`, to route the failure back to
/// the member whose pending open it answers.
fn parse_open_error_request_id(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenMiningChannelError(m) => Some(m.request_id),
        _ => None,
    }
}

fn parse_setup_success_flags(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match CommonMessages::try_from((mt, payload)).ok()? {
        CommonMessages::SetupConnectionSuccess(s) => Some(s.flags),
        _ => None,
    }
}

pub(crate) fn parse_accepted_count(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => Some(s.new_submits_accepted_count),
        _ => None,
    }
}

/// `(last_sequence_number, new_submits_accepted_count)` of a `SubmitSharesSuccess`.
pub(crate) fn parse_submit_success(frame: &mut Sv2Frame) -> Option<(u32, u32)> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => {
            Some((s.last_sequence_number, s.new_submits_accepted_count))
        }
        _ => None,
    }
}

pub(crate) fn parse_set_target(frame: &mut Sv2Frame) -> Option<Vec<u8>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetTarget(m) => Some(m.maximum_target.inner_as_ref().to_vec()),
        _ => None,
    }
}

/// Parse a `NewExtendedMiningJob` out of a frame (owned/`'static`).
pub(crate) fn parse_new_extended_job(
    frame: &mut Sv2Frame,
) -> Option<mining::NewExtendedMiningJob<'static>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::NewExtendedMiningJob(m) => Some(m.into_static()),
        _ => None,
    }
}

/// Parse a `SetNewPrevHash` out of a frame (owned/`'static`).
pub(crate) fn parse_set_new_prev_hash(
    frame: &mut Sv2Frame,
) -> Option<mining::SetNewPrevHash<'static>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetNewPrevHash(m) => Some(m.into_static()),
        _ => None,
    }
}

/// The `sequence_number` of a `SubmitSharesError` (the rejected share's id).
pub(crate) fn parse_submit_error_seq(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesError(m) => Some(m.sequence_number),
        _ => None,
    }
}

/// Difficulty implied by a channel `target` (Bitcoin bdiff convention). The
/// single source of truth is [`crate::proto::translate::difficulty_from_target`].
fn difficulty_from_target(target: &[u8]) -> f64 {
    crate::proto::translate::difficulty_from_target(target)
}

// ── transport helpers ───────────────────────────────────────────────

async fn read_one(read: &mut Read) -> anyhow::Result<Sv2Frame> {
    let frame = read
        .read_frame()
        .await
        .map_err(|e| anyhow!("read frame: {e:?}"))?;
    wire::into_sv2(frame).ok_or_else(|| anyhow!("unexpected handshake frame post-handshake"))
}

/// Connect an upstream, run SetupConnection, return the (post-setup) halves and
/// the upstream's negotiated flags.
pub(crate) async fn connect_setup(target: &UpstreamTarget) -> anyhow::Result<(Read, Write, u32)> {
    let tcp = TcpStream::connect(&target.url)
        .await
        .with_context(|| format!("connect upstream {}", target.url))?;
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
        let mut f = read_one(&mut read).await?;
        match wire::msg_type(&f) {
            Some(common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) => {
                return Ok((read, write, parse_setup_success_flags(&mut f).unwrap_or(0)));
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
pub(crate) async fn open_on(
    read: &mut Read,
    write: &mut Write,
    spec: &OpenSpec,
    account: &str,
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
                bail!("upstream rejected OpenMiningChannel")
            }
            other => {
                // Per the SV2 spec the pool assigns the channel in its
                // OpenSuccess before it can address any job/prev-hash to it, so
                // nothing channel-scoped legitimately precedes the success here.
                // The pool's initial NewExtendedMiningJob + SetNewPrevHash arrive
                // *after* it and are read by the steady upstream reader — the same
                // `read` half (with its buffered frames) is handed to it, so they
                // are not lost. A frame before the success is unexpected; skip it.
                tracing::warn!(mt = ?other, "sv2 open_on: unexpected frame before OpenSuccess; skipping");
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

fn spawn_upstream_reader(
    session: Arc<Sv2Session>,
    generation: u64,
    mut read: Read,
) -> JoinHandle<()> {
    tokio::spawn(async move {
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

/// Per-session supervisor: when the active upstream drops while a rental is in
/// effect, reconnect to the order's pool (primary→fallback); when an idle pool
/// drops, reconnect the seller's default. Retries with capped backoff. Each
/// reconnect bumps the generation, so a recovered/superseded session ends the
/// retry loop; stale signals (from an already-swapped reader) are ignored.
async fn supervise_upstream(session: Arc<Sv2Session>, mut died_rx: mpsc::UnboundedReceiver<u64>) {
    while let Some(gen) = died_rx.recv().await {
        if session.inner.lock().await.active.generation != gen {
            continue; // stale (already swapped away)
        }
        warn!(gen, "sv2 upstream dropped — reconnecting/failing over");
        let mut backoff = Duration::from_millis(500);
        loop {
            let order_id = {
                let i = session.inner.lock().await;
                if i.active.generation != gen {
                    None // re-established, or reverted/switched elsewhere
                } else {
                    match &i.routing {
                        Routing::Rented { order_id } => Some(Some(order_id.clone())),
                        Routing::Idle => Some(None),
                    }
                }
            };
            let res = match order_id {
                None => break,
                Some(Some(oid)) => session.switch_to_order(oid).await,
                Some(None) => session.revert().await,
            };
            match res {
                Ok(()) => {
                    info!(gen, "sv2 upstream re-established after drop");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "sv2 reconnect failed; backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
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
}

struct Inner {
    active: ActiveUpstream,
    generation_counter: u64,
    /// All open channels on this connection (one per rig chain, usually one).
    channels: Vec<Channel>,
    /// upstream channel_id → downstream channel_id (for upstream→miner frames).
    /// Holds both real channel ids AND the group_channel_id of grouped Extended
    /// channels, so the pool's group-broadcast jobs (NewExtendedMiningJob +
    /// SetNewPrevHash addressed to the group id) are remapped to the miner too.
    up_to_down: std::collections::HashMap<u32, u32>,
    /// Stable downstream id we assigned to this connection's Extended group, if
    /// any. Only Extended channels are grouped (per the SV2 spec), and a single
    /// 1:1 miner connection has at most one group — every Extended channel/reopen
    /// on it maps its (re-issued) upstream group_channel_id to this one id, which
    /// the miner learned from its OpenExtendedMiningChannelSuccess.
    group_down_id: Option<u32>,
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
    default_target: UpstreamTarget,
    hashrate: HashrateWindow,
    /// Lifetime delivered work (diff-1 share units) + accepted shares.
    delivered_work: f64,
    accepted_shares: u64,
    /// Shares the miner submitted (for the accept-ratio health/fraud signal).
    submitted_shares: u64,
    /// Edge-trigger so the low-accept-ratio warning is logged once.
    accept_low_logged: bool,
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
    fn up_for_down(&self, down_cid: u32) -> Option<u32> {
        self.channels
            .iter()
            .find(|c| c.down_channel_id == down_cid)
            .map(|c| c.up_channel_id)
    }

    fn register_channel(
        &mut self,
        down_cid: u32,
        up_cid: u32,
        spec: OpenSpec,
        difficulty: f64,
        owner: u32,
    ) {
        self.up_to_down.insert(up_cid, down_cid);
        self.channels.push(Channel {
            down_channel_id: down_cid,
            up_channel_id: up_cid,
            spec,
            difficulty,
            owner,
        });
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
    /// its OpenSuccess. The first grouped Extended channel allocates a stable
    /// downstream id; every later channel/reopen on this connection maps its
    /// (re-issued) upstream group id onto that same id. Returns `up_group_id`
    /// unchanged for non-Extended or ungrouped (`group_channel_id == 0`)
    /// channels, leaving Standard channels untouched.
    fn map_group(&mut self, up_group_id: u32, is_extended: bool) -> u32 {
        if !is_extended || up_group_id == 0 {
            return up_group_id;
        }
        let down = match self.group_down_id {
            Some(d) => d,
            None => {
                let id = self.next_down_cid;
                self.next_down_cid += 1;
                self.group_down_id = Some(id);
                id
            }
        };
        self.up_to_down.insert(up_group_id, down);
        down
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
    /// Fired by [`Sv2Session::force_reconnect`] to drop the miner connection so
    /// it reconnects and re-resolves its upstream from current state. Used for
    /// operator-initiated pool changes (idle-pool edit, rent start, rent
    /// end/cancel) where a live re-point would risk the miner mining on a stale
    /// extranonce. Automatic upstream failover does NOT use this (it re-points in
    /// place) so a flapping pool can't storm the miner with reconnects.
    reconnect: Notify,
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

    /// Switch onto a rental order's pool with failover: try the order's primary
    /// target, then its fallback if the primary is unreachable. Errors only if
    /// both fail. Resolves the pools from the order store (same protocol as the
    /// rig — the proxy doesn't translate).
    pub async fn switch_to_order(self: &Arc<Self>, order_id: String) -> anyhow::Result<()> {
        let order = self
            .orders
            .get(&order_id)
            .await
            .ok_or_else(|| anyhow!("order {order_id} not found"))?;
        match self.switch_to(order_id.clone(), order.target).await {
            Ok(()) => Ok(()),
            Err(primary_err) => match order.fallback {
                Some(fb) => {
                    warn!(order = %order_id, error = %primary_err, "primary buyer pool unreachable — using fallback");
                    self.switch_to(order_id, fb).await
                }
                None => Err(primary_err),
            },
        }
    }

    pub async fn revert(self: &Arc<Self>) -> anyhow::Result<()> {
        let default = self.inner.lock().await.default_target.clone();
        self.swap_upstream(default, Routing::Idle).await
    }

    /// Drop the miner connection so it reconnects and re-resolves its upstream
    /// from current state (the updated idle pool, or an active rental). The
    /// caller must persist the new state (store/order) BEFORE calling this so the
    /// reconnect lands on the right pool. Preferred over a live swap for
    /// operator-initiated changes — a fresh handshake gives the miner the new
    /// pool's extranonce/target cleanly instead of relying on a live re-point.
    pub fn force_reconnect(&self) {
        // `notify_one` stores a permit, so a signal fired while the serve loop is
        // between selects (processing a frame) is not lost.
        self.reconnect.notify_one();
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
        // Snapshot the channels to re-open (down_channel_id + spec) + worker +
        // the stable downstream group id (the miner already knows it, so the new
        // upstream's re-issued group id must map back onto it).
        let (specs, generation, label, group_down_id, members) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            let specs: Vec<(u32, u32, OpenSpec)> = i
                .channels
                .iter()
                .map(|c| (c.down_channel_id, c.owner, c.spec.clone()))
                .collect();
            (
                specs,
                i.generation_counter,
                i.label.clone(),
                i.group_down_id,
                // Members don't change across an upstream swap; snapshot their
                // sinks (cheap Sender clones) to re-point each one after.
                i.members.clone(),
            )
        };
        // user_identity on the new pool: its account + the miner's worker, tagged.
        let up_ident = crate::proto::relay::upstream_worker(&target.user, &label);
        if specs.is_empty() {
            bail!("no channels to switch");
        }

        // Native first: re-open on SV2; if the new pool doesn't answer as SV2,
        // it's an SV1 buyer pool → translate the switch onto it.
        let (mut read, mut write, _flags) = match tokio::time::timeout(
            translate::UPSTREAM_PROBE_TIMEOUT,
            connect_setup(&target),
        )
        .await
        {
            Ok(Ok(c)) => c,
            res => {
                if let Ok(Err(e)) = &res {
                    debug!(url = %target.url, error = %e, "upstream not SV2; switching via SV1 translation");
                }
                return self
                    .swap_to_sv1_translate(target, routing, generation, up_ident)
                    .await;
            }
        };
        let mut new_channels = Vec::with_capacity(specs.len());
        let mut up_to_down = std::collections::HashMap::new();
        let mut repoint = Vec::with_capacity(specs.len());
        for (down_cid, owner, spec) in &specs {
            let info = open_on(&mut read, &mut write, spec, &up_ident)
                .await
                .map_err(|e| anyhow!("switch reopen channel {down_cid}: {e}"))?;
            up_to_down.insert(info.up_channel_id, *down_cid);
            // Remap the new pool's group id onto the stable downstream group id
            // so group-broadcast jobs keep reaching the miner after the switch.
            if spec.is_extended() && info.group_channel_id != 0 {
                match group_down_id {
                    Some(g) => {
                        up_to_down.insert(info.group_channel_id, g);
                    }
                    None => warn!(
                        worker = %label,
                        down_cid,
                        "extended channel grouped on new upstream but no stable group id from open — group jobs may be dropped"
                    ),
                }
            }
            new_channels.push(Channel {
                down_channel_id: *down_cid,
                up_channel_id: info.up_channel_id,
                spec: spec.clone(),
                difficulty: difficulty_from_target(&info.target),
                owner: *owner,
            });
            repoint.push((*down_cid, *owner, info.extranonce_prefix, info.target));
        }

        let (to_up, up_rx) = mpsc::unbounded_channel();

        let abandoned: Vec<(u32, u32)> = {
            let mut i = self.inner.lock().await;
            // Spawn the new upstream's reader/writer while holding the lock and
            // install `active` (carrying the new generation) before releasing it.
            // The reader tags each frame with `generation`, and `on_upstream_frame`
            // drops frames whose generation != the active one. Spawning inside the
            // lock means the reader cannot process the new pool's initial job /
            // prev-hash until `active.generation` already equals `generation`, so
            // that first job is never dropped as "stale".
            let writer = spawn_writer(write, up_rx);
            let reader = spawn_upstream_reader(self.clone(), generation, read);
            i.active.reader.abort();
            i.active.writer.abort();
            i.active = ActiveUpstream {
                generation,
                target: target.clone(),
                to_up,
                reader,
                writer,
            };
            i.channels = new_channels;
            i.up_to_down = up_to_down;
            // In-flight opens were sent to the old upstream; abandon them and
            // tell the requesting member so it can reopen (rather than hang).
            let abandoned: Vec<(u32, u32)> = i
                .pending
                .drain()
                .map(|(request_id, (member, _))| (member, request_id))
                .collect();
            i.routing = routing;
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
        for (member, request_id) in abandoned {
            if let Ok(f) = open_channel_error(request_id, "upstream switched; please reopen") {
                if let Some(sink) = members.get(&member) {
                    let _ = sink.send(f);
                }
            }
        }
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
                    let diff = difficulty_from_target(&info.target);
                    i.register_channel(down_cid, info.up_channel_id, spec.clone(), diff, member);
                    let down_group_id = i.map_group(info.group_channel_id, spec.is_extended());
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
            match parse_open_error_request_id(&mut frame).and_then(|req| i.pending.remove(&req)) {
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
                let diff = difficulty_from_target(&target);
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
        if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS {
            let count = parse_accepted_count(&mut frame).unwrap_or(0);
            let diff = i
                .channels
                .iter()
                .find(|c| c.up_channel_id == up_cid)
                .map(|c| c.difficulty)
                .unwrap_or(0.0);
            let work = diff * count as f64;
            if work > 0.0 {
                i.hashrate.record(work);
                i.delivered_work += work;
                i.accepted_shares += count as u64;
                if let Routing::Rented { order_id, .. } = &i.routing {
                    order_credit = Some((order_id.clone(), work, count as u64));
                }
                debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted shares");
            }
            // Accept-ratio health/fraud signal (logged once).
            if !i.accept_low_logged
                && crate::control::accept_ratio_low(i.accepted_shares, i.submitted_shares)
            {
                i.accept_low_logged = true;
                warn!(
                    worker = %i.label,
                    accepted = i.accepted_shares,
                    submitted = i.submitted_shares,
                    ratio = crate::control::accept_ratio(i.accepted_shares, i.submitted_shares),
                    "low accept ratio — possible pool under-reporting or misbehaving miner"
                );
            }
        }

        // Forward with the channel id remapped. A frame addressed to the group id
        // (the pool's group-broadcast job + prev-hash) is fanned out to every
        // member of the rig; a per-channel frame routes only to its owner.
        if let Some(&down_cid) = i.up_to_down.get(&up_cid) {
            wire::rewrite_channel_id(&mut frame, down_cid);
            if Some(down_cid) == i.group_down_id {
                // Group-broadcast job: only members with an Extended channel are in
                // the group. Standard members are ungrouped — their work arrives
                // per channel — and must NOT get a group-addressed NewExtendedMiningJob
                // (a header-only device can't process it). Fan out to grouped members.
                let grouped: std::collections::HashSet<u32> = i
                    .channels
                    .iter()
                    .filter(|c| c.spec.is_extended())
                    .map(|c| c.owner)
                    .collect();
                for m in &grouped {
                    if let Some(sink) = i.members.get(m) {
                        let _ = sink.send(frame.clone().into());
                    }
                }
            } else if let Some(sink) = i.member_sink_for_up(up_cid) {
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
    }

    pub async fn status(&self) -> SessionStatus {
        let i = self.inner.lock().await;
        let (routing, order_id) = match &i.routing {
            Routing::Idle => ("idle".to_string(), None),
            Routing::Rented { order_id, .. } => ("rented".to_string(), Some(order_id.clone())),
        };
        SessionStatus {
            worker: i.label.clone(),
            routing,
            order_id,
            upstream_url: i.active.target.url.clone(),
            hashrate_hs: i.hashrate.hashes_per_second(),
            delivered_work: i.delivered_work,
            accepted_shares: i.accepted_shares,
            submitted_shares: i.submitted_shares,
            accept_ratio: crate::control::accept_ratio(i.accepted_shares, i.submitted_shares),
            accept_ratio_low: crate::control::accept_ratio_low(
                i.accepted_shares,
                i.submitted_shares,
            ),
            protocol: "sv2",
        }
    }

    async fn worker_label(&self) -> String {
        self.inner.lock().await.label.clone()
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
        let account = crate::proto::relay::upstream_worker(&i.active.target.user, &i.label);
        let up_req = i.next_up_req;
        i.next_up_req += 1;
        match open_channel_upstream(spec, &account, up_req) {
            Ok(f) => {
                i.pending.insert(up_req, (member, spec.clone()));
                let _ = i.active.to_up.send(f);
            }
            Err(e) => warn!(error = %e, "attach: additional channel open failed"),
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
        for up in up_cids {
            if let Ok(f) = close_channel_upstream(up) {
                let _ = i.active.to_up.send(f);
            }
            i.up_to_down.remove(&up);
        }
        i.channels.retain(|c| c.owner != member);
        i.pending.retain(|_, (m, _)| *m != member);
        i.members.is_empty()
    }
}

/// The bundle-target SV2 rig for each worker, so several same-rig miners share
/// one upstream (one group of N channels) instead of one upstream each. Holds
/// only non-translating (SV2) sessions; SV1-translated rigs and any parallel
/// standalone sessions are not bundle targets and stay 1:1.
pub struct Sv2RigRegistry {
    rigs: Mutex<HashMap<String, Arc<Sv2Session>>>,
    /// Per-worker create-or-attach gate so two same-rig miners connecting at once
    /// don't both build an upstream; the loser waits, then attaches. The idle
    /// reaper takes the same gate, so an attach and a reap can't interleave.
    /// Distinct workers don't contend. Kept for the proxy's lifetime (bounded by
    /// distinct worker names) so a waiting attach can't race a fresh gate Arc.
    gates: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// How long to keep an emptied rig's upstream warm before reaping it.
    idle_grace: Duration,
}

impl Default for Sv2RigRegistry {
    fn default() -> Self {
        Self {
            rigs: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            idle_grace: DEFAULT_IDLE_GRACE,
        }
    }
}

impl Sv2RigRegistry {
    /// A registry with a custom idle-grace window (tests use a short one).
    #[cfg(test)]
    fn with_grace(idle_grace: Duration) -> Self {
        Self {
            idle_grace,
            ..Default::default()
        }
    }

    /// The serialization gate for one worker's create-or-attach (and reap).
    async fn gate(&self, worker: &str) -> Arc<Mutex<()>> {
        self.gates
            .lock()
            .await
            .entry(worker.to_string())
            .or_default()
            .clone()
    }

    /// The bundle-target rig for a worker, if one is registered.
    async fn get(&self, worker: &str) -> Option<Arc<Sv2Session>> {
        self.rigs.lock().await.get(worker).cloned()
    }

    /// Is `rig` the currently-registered bundle target for `worker`?
    async fn is_target(&self, worker: &str, rig: &Arc<Sv2Session>) -> bool {
        self.rigs
            .lock()
            .await
            .get(worker)
            .is_some_and(|r| Arc::ptr_eq(r, rig))
    }

    /// Register `rig` as the bundle target for `worker`, but only if the slot is
    /// free (a translated rig or a race may already hold it; then this session
    /// runs standalone). Returns whether it became the bundle target.
    async fn insert_if_absent(&self, worker: &str, rig: Arc<Sv2Session>) -> bool {
        let mut m = self.rigs.lock().await;
        if m.contains_key(worker) {
            return false;
        }
        m.insert(worker.to_string(), rig);
        true
    }

    /// Remove `rig` as the bundle target for `worker` — but only if it is still
    /// the registered one (a late teardown must not evict a fresh replacement).
    /// The per-worker gate is intentionally kept.
    async fn remove(&self, worker: &str, rig: &Arc<Sv2Session>) {
        let mut m = self.rigs.lock().await;
        if m.get(worker).is_some_and(|existing| Arc::ptr_eq(existing, rig)) {
            m.remove(worker);
        }
    }
}

/// After the idle-grace window, reap a rig whose last member never came back:
/// drop it from both registries and abort its upstream tasks. No-ops if a member
/// has since (re)attached, or if the rig emptied again under a newer token (a
/// fresh reaper owns that round). Takes the per-worker gate so it can't interleave
/// with a concurrent attach.
async fn reap_idle_rig(
    rigs: Arc<Sv2RigRegistry>,
    registry: Arc<crate::registry::Registry>,
    session: Arc<Sv2Session>,
    worker: String,
    token: u64,
    grace: Duration,
) {
    tokio::time::sleep(grace).await;
    let gate = rigs.gate(&worker).await;
    let _hold = gate.lock().await;
    {
        let i = session.inner.lock().await;
        if !i.members.is_empty() || i.idle_token != token {
            return; // a member rejoined, or a newer idle round owns the reap
        }
    }
    rigs.remove(&worker, &session).await;
    registry
        .remove_if(&worker, &AnySession::Sv2(session.clone()))
        .await;
    let i = session.inner.lock().await;
    i.active.reader.abort();
    i.active.writer.abort();
    if let Some(sup) = &i.supervisor {
        sup.abort();
    }
    info!(%worker, "sv2 rig reaped after idle grace");
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

/// Connect an SV1 pool and run `configure`(version-rolling) → `subscribe` →
/// `authorize`, capturing the extranonce, the negotiated version mask, and the
/// handshake notifications (initial difficulty + first job).
async fn connect_sv1_upstream(
    target: &UpstreamTarget,
    user_identity: &str,
) -> anyhow::Result<Sv1UpConn> {
    let tcp = TcpStream::connect(&target.url)
        .await
        .with_context(|| format!("connect sv1 upstream {}", target.url))?;
    let _ = tcp.set_nodelay(true);
    let (r, mut w) = tcp.into_split();
    let mut read = BufReader::new(r);
    let mut prelude: Vec<String> = Vec::new();

    let cfg = RpcMessage::request(
        json!(1),
        "mining.configure",
        json!([["version-rolling"], {"version-rolling.mask": "1fffe000"}]),
    );
    w.write_all(cfg.to_line().as_bytes()).await?;
    let cfg_resp = sv1_read_response(&mut read, &mut prelude).await?;
    let version_mask = parse_version_mask(&cfg_resp);

    let sub = RpcMessage::request(
        json!(2),
        "mining.subscribe",
        json!(["bp-proxy"]),
    );
    w.write_all(sub.to_line().as_bytes()).await?;
    let sub_resp = sv1_read_response(&mut read, &mut prelude).await?;
    let (en1_hex, extranonce2_size) =
        parse_subscribe_sv1(&sub_resp).ok_or_else(|| anyhow!("bad subscribe result"))?;

    // Authorize with the SAME worker name we submit shares under (see
    // `upstream_worker`). Strict pools (e.g. ckpool) reject submits whose worker
    // differs from the authorized one ("Worker mismatch"); the payout address is
    // the part before the first '.', so this keeps the payout correct.
    let auth = RpcMessage::request(
        json!(3),
        "mining.authorize",
        json!([user_identity, target.password]),
    );
    w.write_all(auth.to_line().as_bytes()).await?;
    let _ = sv1_read_response(&mut read, &mut prelude).await?;

    let initial_diff = prelude
        .iter()
        .rev()
        .find_map(|l| translate::set_difficulty_from_line(l))
        .unwrap_or(1.0);
    Ok(Sv1UpConn {
        read,
        write: w,
        extranonce1: Vec::<u8>::from_hex(&en1_hex)
            .map_err(|e| anyhow!("bad extranonce hex: {e}"))?,
        extranonce2_size,
        version_mask,
        initial_diff,
        prelude,
    })
}

/// Read SV1 lines until a response (no `method`), pushing interleaved
/// notifications to `prelude`.
async fn sv1_read_response(
    read: &mut BufReader<OwnedReadHalf>,
    prelude: &mut Vec<String>,
) -> anyhow::Result<RpcMessage> {
    let mut line = String::new();
    loop {
        line.clear();
        if read.read_line(&mut line).await? == 0 {
            bail!("sv1 upstream closed during handshake");
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(m) = RpcMessage::parse(t) {
            if m.method.is_none() {
                return Ok(m);
            }
            prelude.push(format!("{t}\n"));
        }
    }
}

fn parse_version_mask(resp: &RpcMessage) -> Option<u32> {
    let r = resp.result.as_ref()?;
    if r.get("version-rolling")?.as_bool() != Some(true) {
        return None;
    }
    let mask = r
        .get("version-rolling.mask")
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s, 16).ok());
    Some(mask.unwrap_or(translate::VERSION_ROLLING_MASK))
}

fn parse_subscribe_sv1(resp: &RpcMessage) -> Option<(String, u16)> {
    let arr = resp.result.as_ref()?.as_array()?;
    if arr.len() < 3 {
        return None;
    }
    Some((arr[1].as_str()?.to_string(), arr[2].as_u64()? as u16))
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
        loop {
            line.clear();
            match read.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            handle_sv1_line(&session, generation, &state, down_cid, l).await;
        }
        // Pool closed/errored (an intentional swap aborts this task first).
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
        } else if let Ok(error_code) = Str0255::try_from("rejected".to_string()) {
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
            let mut i = self.inner.lock().await;
            if generation != i.active.generation {
                return;
            }
            let work = i
                .channels
                .iter()
                .find(|c| c.down_channel_id == down_cid)
                .map(|c| c.difficulty)
                .unwrap_or(0.0);
            let mut credit = None;
            if work > 0.0 {
                i.hashrate.record(work);
                i.delivered_work += work;
                i.accepted_shares += 1;
                if let Routing::Rented { order_id, .. } = &i.routing {
                    credit = Some((order_id.clone(), work, 1u64));
                }
                debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted share (translated)");
            }
            if !i.accept_low_logged
                && crate::control::accept_ratio_low(i.accepted_shares, i.submitted_shares)
            {
                i.accept_low_logged = true;
                warn!(
                    worker = %i.label,
                    accepted = i.accepted_shares,
                    submitted = i.submitted_shares,
                    "low accept ratio — possible pool under-reporting or misbehaving miner"
                );
            }
            credit
        };
        if let Some((order_id, work, shares)) = credit {
            self.orders.add_work(&order_id, work, shares);
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
        let up_ident = crate::proto::relay::upstream_worker(&target.user, worker);
        // Native first: try SV2 (reusing its socket on success); if the pool
        // doesn't answer as SV2, it's an SV1 buyer pool → translate.
        match tokio::time::timeout(translate::UPSTREAM_PROBE_TIMEOUT, connect_setup(&target)).await
        {
            Ok(Ok((read, write, _flags))) => {
                self.install_sv2_initial(read, write, spec, up_ident, target, routing, member)
                    .await
            }
            res => {
                if let Ok(Err(e)) = &res {
                    debug!(url = %target.url, error = %e, "upstream not SV2; trying SV1 translation");
                }
                let conn = connect_sv1_upstream(&target, &up_ident).await?;
                self.install_sv1_translate_initial(conn, spec, up_ident, target, routing, member)
                    .await
            }
        }
    }

    /// Install an SV2 passthrough upstream and forward the miner's open (the
    /// steady reader finalizes it on the pool's OpenSuccess).
    #[allow(clippy::too_many_arguments)] // wire-plumbing install path; cohesive args
    async fn install_sv2_initial(
        self: &Arc<Self>,
        read: Read,
        write: Write,
        spec: OpenSpec,
        up_ident: String,
        target: UpstreamTarget,
        routing: Routing,
        member: u32,
    ) -> anyhow::Result<()> {
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_writer(write, up_rx);
        let mut i = self.inner.lock().await;
        let reader = spawn_upstream_reader(self.clone(), 0, read);
        i.active.reader.abort();
        i.active.writer.abort();
        i.active = ActiveUpstream {
            generation: 0,
            target,
            to_up,
            reader,
            writer,
        };
        i.routing = routing;
        i.translating = false;
        let up_req = i.next_up_req;
        i.next_up_req += 1;
        i.pending.insert(up_req, (member, spec.clone()));
        i.active
            .to_up
            .send(open_channel_upstream(&spec, &up_ident, up_req)?)
            .map_err(|_| anyhow!("upstream writer gone"))?;
        Ok(())
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
        let extended = spec.is_extended();
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

        let state = Arc::new(Mutex::new(Sv1UpState {
            version_mask: conn.version_mask,
            user_name: up_ident,
            extended,
            extranonce1: conn.extranonce1,
            extranonce2_size: conn.extranonce2_size,
            next_job_id: 1,
            next_submit_id: 1,
            ..Default::default()
        }));
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_sv1_translate_writer(conn.write, state.clone(), up_rx);
        {
            let mut i = self.inner.lock().await;
            // Spawn the reader inside the lock so the new generation is in place
            // before its first job/diff line is processed.
            let reader = spawn_sv1_translate_reader(
                self.clone(),
                i.active.generation,
                conn.read,
                state,
                down_cid,
                conn.prelude,
            );
            i.active.reader.abort();
            i.active.writer.abort();
            let generation = i.active.generation;
            i.active = ActiveUpstream {
                generation,
                target,
                to_up,
                reader,
                writer,
            };
            i.channels = vec![Channel {
                down_channel_id: down_cid,
                up_channel_id: down_cid,
                spec,
                difficulty: conn.initial_diff,
                owner: member,
            }];
            i.up_to_down = HashMap::from([(down_cid, down_cid)]);
            i.pending.clear();
            i.routing = routing;
            i.translating = true;
        }
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
        let extended = spec.is_extended();
        let conn = connect_sv1_upstream(&target, &up_ident)
            .await
            .map_err(|e| anyhow!("switch to {}: {e}", target.url))?;
        let initial_target = translate::target_from_difficulty(conn.initial_diff).to_vec();
        let extranonce1 = conn.extranonce1.clone();
        let state = Arc::new(Mutex::new(Sv1UpState {
            version_mask: conn.version_mask,
            user_name: up_ident,
            extended,
            extranonce1: conn.extranonce1,
            extranonce2_size: conn.extranonce2_size,
            next_job_id: 1,
            next_submit_id: 1,
            ..Default::default()
        }));
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_sv1_translate_writer(conn.write, state.clone(), up_rx);
        let abandoned: Vec<(u32, u32)> = {
            let mut i = self.inner.lock().await;
            let reader = spawn_sv1_translate_reader(
                self.clone(),
                generation,
                conn.read,
                state,
                down_cid,
                conn.prelude,
            );
            i.active.reader.abort();
            i.active.writer.abort();
            i.active = ActiveUpstream {
                generation,
                target: target.clone(),
                to_up,
                reader,
                writer,
            };
            i.channels = vec![Channel {
                down_channel_id: down_cid,
                up_channel_id: down_cid,
                spec,
                difficulty: conn.initial_diff,
                owner,
            }];
            i.up_to_down = HashMap::from([(down_cid, down_cid)]);
            let abandoned: Vec<(u32, u32)> = i
                .pending
                .drain()
                .map(|(request_id, (member, _))| (member, request_id))
                .collect();
            i.routing = routing;
            i.translating = true;
            abandoned
        };
        // Re-point the channel's owner: new extranonce prefix + target; the reader
        // streams the new pool's first job after.
        if let Some(sink) = members.get(&owner) {
            let _ = sink.send(set_extranonce_prefix(down_cid, extranonce1)?);
            let _ = sink.send(set_target(down_cid, initial_target)?);
        }
        for (member, request_id) in abandoned {
            if let Ok(f) = open_channel_error(request_id, "upstream switched; please reopen") {
                if let Some(sink) = members.get(&member) {
                    let _ = sink.send(f);
                }
            }
        }
        info!(upstream = %target.url, generation, "sv2→sv1 upstream switched (translated)");
        Ok(())
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

    // 4. Register-only: the worker MUST have a registered rig (its idle pool).
    //    No rig → reject and close.
    let idle_target = match ctx.sellers.default_pool(&worker).await {
        Some(t) => t,
        None => {
            warn!(%peer, %worker, "rejected unregistered worker (register-only)");
            bail!("unregistered worker {worker} — register the rig first");
        }
    };

    // 5. Decide where the first channel opens: straight on the buyer's pool if a
    //    rental is already active (resume on reconnect without an open-then-switch
    //    round-trip), else the rig's idle pool. `default_target` stays the idle
    //    pool either way, so a release/revert returns there.
    let active_order = ctx
        .orders
        .active_for_worker(&worker, crate::orders::now_ms())
        .await;
    let (mut open_target, routing) = match &active_order {
        Some(o) => (
            o.target.clone(),
            Routing::Rented {
                order_id: o.id.clone(),
            },
        ),
        None => (idle_target.clone(), Routing::Idle),
    };

    // 6. Bundle onto this rig's existing SV2 upstream if one is live; else build a
    //    fresh session (which becomes the rig if its upstream ends up SV2). The
    //    per-worker gate serializes create-or-attach so two same-rig miners
    //    connecting at once don't each build an upstream.
    let gate = ctx.sv2_rigs.gate(&worker).await;
    let _hold = gate.lock().await;

    let attached = match ctx.sv2_rigs.get(&worker).await {
        Some(rig) => rig
            .attach_member(to_miner.clone(), &spec)
            .await
            .map(|member| (rig, member)),
        None => None,
    };

    let (session, member_id) = match attached {
        Some((rig, member)) => {
            drop(_hold);
            info!(%peer, %worker, member, "sv2 miner bundled onto existing rig");
            (rig, member)
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
                reconnect: Notify::new(),
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
                    group_down_id: None,
                    pending: std::collections::HashMap::new(),
                    next_down_cid: 1,
                    next_up_req: 1,
                    members: std::collections::HashMap::new(),
                    next_member_id: 1,
                    routing: routing.clone(),
                    default_target: idle_target.clone(),
                    hashrate: HashrateWindow::new(Duration::from_secs(600)),
                    delivered_work: 0.0,
                    accepted_shares: 0,
                    submitted_shares: 0,
                    accept_low_logged: false,
                    label: worker.clone(),
                    translating: false,
                    supervisor: None,
                    idle_token: 0,
                }),
            });

            // This connection is the rig's first member; its sink owns the
            // initial channel and receives that channel's per-channel frames.
            let member_id = session.inner.lock().await.add_member(to_miner.clone());

            if let Err(e) = session
                .connect_and_install_initial(
                    open_target.clone(),
                    spec.clone(),
                    &worker,
                    routing.clone(),
                    member_id,
                )
                .await
            {
                match active_order.as_ref().and_then(|o| o.fallback.clone()) {
                    Some(fb) => {
                        warn!(%worker, error = %e, "primary buyer pool unreachable — using fallback");
                        open_target = fb.clone();
                        session
                            .connect_and_install_initial(
                                fb,
                                spec.clone(),
                                &worker,
                                routing.clone(),
                                member_id,
                            )
                            .await?;
                    }
                    None => return Err(e),
                }
            }

            ctx.registry
                .insert(worker.clone(), AnySession::Sv2(session.clone()))
                .await;
            // Supervisor owned by the rig (aborted only on last-member teardown).
            let supervisor = tokio::spawn(supervise_upstream(session.clone(), died_rx));
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
                    info!(%peer, %worker, member = member_id, upstream = %open_target.url, order = %o.id, "sv2 relay established (rented)")
                }
                None => {
                    info!(%peer, %worker, member = member_id, upstream = %open_target.url, "sv2 relay established (idle)")
                }
            }
            (session, member_id)
        }
    };

    // 9. Downstream loop: open additional channels and forward shares/updates
    //    upstream (channel-id remapped per channel).
    let result: anyhow::Result<()> = async {
        loop {
            let mut frame = tokio::select! {
                biased;
                // Operator-initiated pool change → close the connection so the
                // miner reconnects and re-handshakes against the new upstream.
                _ = session.reconnect.notified() => {
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
                    let account =
                        crate::proto::relay::upstream_worker(&i.active.target.user, &i.label);
                    let up_req = i.next_up_req;
                    i.next_up_req += 1;
                    match open_channel_upstream(&open.spec, &account, up_req) {
                        Ok(f) => {
                            i.pending.insert(up_req, (member_id, open.spec.clone()));
                            let _ = i.active.to_up.send(f);
                        }
                        Err(e) => warn!(%worker, error = %e, "additional channel open failed"),
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
                            i.submitted_shares += 1;
                            if let Routing::Rented { order_id, .. } = &i.routing {
                                submit_order = Some(order_id.clone());
                            }
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

// ── adapter ─────────────────────────────────────────────────────────

/// The Stratum V2 downstream adapter (full proxy with a swappable upstream).
#[derive(Clone)]
pub struct Sv2Adapter {
    keys: NoiseKeys,
}

impl Default for Sv2Adapter {
    fn default() -> Self {
        Self {
            keys: NoiseKeys::from_env_or_generate(),
        }
    }
}

impl DownstreamAdapter for Sv2Adapter {
    fn protocol(&self) -> &'static str {
        "sv2"
    }

    async fn serve(&self, miner: TcpStream, peer: String, ctx: ProxyContext) -> anyhow::Result<()> {
        handle_seller_miner_sv2(miner, peer, ctx, self.keys.clone()).await
    }
}

#[cfg(test)]
mod tests;
