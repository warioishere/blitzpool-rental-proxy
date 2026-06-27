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
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::proto::sv1::RpcMessage;
use crate::proto::translate;

use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_apps::network_helpers::{accept_noise_connection, connect_with_noise};
use stratum_core::binary_sv2::{Str0255, B032, U256, U32AsRef};
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
use crate::proto::adapter::{DownstreamAdapter, ProxyContext};
use crate::control::{AnySession, SessionStatus};
use crate::orders::OrderStore;
use crate::session::{HashrateWindow, Routing, UpstreamTarget};

/// How long the proxy's Noise certificate (responder side) is valid, seconds.
const CERT_VALIDITY: u64 = 3600;
/// SV2 protocol version the proxy speaks.
const SV2_VERSION: u16 = 2;

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
    wire::frame_from(AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s)))
}

fn open_channel_upstream(spec: &OpenSpec, account: &str) -> anyhow::Result<EitherFrame> {
    let user = Str0255::try_from(account.to_string()).map_err(|_| anyhow!("account too long"))?;
    let msg = match spec {
        OpenSpec::Extended {
            request_id,
            nominal_hash_rate,
            max_target,
            min_extranonce_size,
        } => Mining::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
            request_id: *request_id,
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone()).map_err(|_| anyhow!("bad max_target"))?,
            min_extranonce_size: *min_extranonce_size,
        }),
        OpenSpec::Standard {
            request_id,
            nominal_hash_rate,
            max_target,
        } => Mining::OpenStandardMiningChannel(OpenStandardMiningChannel {
            request_id: U32AsRef::from(*request_id),
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone()).map_err(|_| anyhow!("bad max_target"))?,
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
        error_code: Str0255::try_from(reason.to_string()).map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(
        Mining::OpenMiningChannelError(m),
    )))
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
        Mining::SubmitSharesSuccess(s) => Some((s.last_sequence_number, s.new_submits_accepted_count)),
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
pub(crate) fn parse_new_extended_job(frame: &mut Sv2Frame) -> Option<mining::NewExtendedMiningJob<'static>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::NewExtendedMiningJob(m) => Some(m.into_static()),
        _ => None,
    }
}

/// Parse a `SetNewPrevHash` out of a frame (owned/`'static`).
pub(crate) fn parse_set_new_prev_hash(frame: &mut Sv2Frame) -> Option<mining::SetNewPrevHash<'static>> {
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

/// Difficulty (in diff-1 share units) implied by a channel `target`. Reuses the
/// upstream stack's authoritative target math so the byte order + diff-1
/// convention match the pools. Returns 0.0 on a zero/invalid target.
fn difficulty_from_target(target: &[u8]) -> f64 {
    let Ok(u) = U256::try_from(target.to_vec()) else {
        return 0.0;
    };
    // hash_rate_from_target(t, 1 share/min) = hashes_per_share / 60;
    // difficulty = hashes_per_share / 2^32.
    match stratum_core::channels_sv2::target::hash_rate_from_target(u, 1.0) {
        Ok(h1) => h1 * 60.0 / 4_294_967_296.0,
        Err(_) => 0.0,
    }
}

// ── transport helpers ───────────────────────────────────────────────

async fn read_one(read: &mut Read) -> anyhow::Result<Sv2Frame> {
    let frame = read.read_frame().await.map_err(|e| anyhow!("read frame: {e:?}"))?;
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
        .write_frame(open_channel_upstream(spec, account)?)
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

fn spawn_upstream_reader(session: Arc<Sv2Session>, generation: u64, mut read: Read) -> JoinHandle<()> {
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
    /// request_id → spec for additional opens awaiting the upstream's success.
    pending: std::collections::HashMap<u32, OpenSpec>,
    /// Next downstream channel_id to hand out (proxy-assigned, stable).
    next_down_cid: u32,
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
}

impl Inner {
    fn up_for_down(&self, down_cid: u32) -> Option<u32> {
        self.channels
            .iter()
            .find(|c| c.down_channel_id == down_cid)
            .map(|c| c.up_channel_id)
    }

    fn register_channel(&mut self, down_cid: u32, up_cid: u32, spec: OpenSpec, difficulty: f64) {
        self.up_to_down.insert(up_cid, down_cid);
        self.channels.push(Channel {
            down_channel_id: down_cid,
            up_channel_id: up_cid,
            spec,
            difficulty,
        });
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

/// A live SV2 seller-miner session.
pub struct Sv2Session {
    to_miner: mpsc::UnboundedSender<EitherFrame>,
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
}

impl Sv2Session {
    pub async fn switch_to(
        self: &Arc<Self>,
        order_id: String,
        target: UpstreamTarget,
    ) -> anyhow::Result<()> {
        self.swap_upstream(target, Routing::Rented { order_id }).await
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

    pub async fn set_default(self: &Arc<Self>, target: UpstreamTarget) -> anyhow::Result<()> {
        {
            self.inner.lock().await.default_target = target.clone();
        }
        self.swap_upstream(target, Routing::Idle).await
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
        let (specs, generation, label, group_down_id) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            let specs: Vec<(u32, OpenSpec)> = i
                .channels
                .iter()
                .map(|c| (c.down_channel_id, c.spec.clone()))
                .collect();
            (specs, i.generation_counter, i.label.clone(), i.group_down_id)
        };
        // user_identity on the new pool: its account + the miner's worker, tagged.
        let up_ident = crate::proto::relay::upstream_worker(&target.user, &label);
        if specs.is_empty() {
            bail!("no channels to switch");
        }

        // Native first: re-open on SV2; if the new pool doesn't answer as SV2,
        // it's an SV1 buyer pool → translate the switch onto it.
        let (mut read, mut write, _flags) =
            match tokio::time::timeout(translate::UPSTREAM_PROBE_TIMEOUT, connect_setup(&target)).await {
                Ok(Ok(c)) => c,
                res => {
                    if let Ok(Err(e)) = &res {
                        debug!(url = %target.url, error = %e, "upstream not SV2; switching via SV1 translation");
                    }
                    return self.swap_to_sv1_translate(target, routing, generation, up_ident).await;
                }
            };
        let mut new_channels = Vec::with_capacity(specs.len());
        let mut up_to_down = std::collections::HashMap::new();
        let mut repoint = Vec::with_capacity(specs.len());
        for (down_cid, spec) in &specs {
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
            });
            repoint.push((*down_cid, info.extranonce_prefix, info.target));
        }

        let (to_up, up_rx) = mpsc::unbounded_channel();

        let abandoned: Vec<u32> = {
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
            // tell the miner so it can reopen (rather than hang).
            let abandoned = i.pending.keys().copied().collect();
            i.pending.clear();
            i.routing = routing;
            abandoned
        };

        // Re-point every channel: new extranonce prefix + target. The new
        // upstream then streams jobs + prev-hash per channel, which the reader
        // forwards. Downstream channel ids are unchanged, so the miner does not
        // reconnect.
        for (down_cid, prefix, tgt) in repoint {
            let _ = self.to_miner.send(set_extranonce_prefix(down_cid, prefix)?);
            let _ = self.to_miner.send(set_target(down_cid, tgt)?);
        }
        for request_id in abandoned {
            if let Ok(f) = open_channel_error(request_id, "upstream switched; please reopen") {
                let _ = self.to_miner.send(f);
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
                if let Some(spec) = i.pending.remove(&info.request_id) {
                    let down_cid = i.next_down_cid;
                    i.next_down_cid += 1;
                    let diff = difficulty_from_target(&info.target);
                    i.register_channel(down_cid, info.up_channel_id, spec.clone(), diff);
                    let down_group_id = i.map_group(info.group_channel_id, spec.is_extended());
                    if let Ok(reply) =
                        open_success_downstream(&spec, down_cid, down_group_id, &info)
                    {
                        let _ = self.to_miner.send(reply);
                    }
                    info!(worker = %i.label, down_cid, up_cid = info.up_channel_id, down_group_id, "sv2 additional channel opened");
                }
            }
            return;
        }
        // An additional open was rejected: pass the error to the miner.
        if mt == mining::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR {
            let _ = self.to_miner.send(frame.into());
            return;
        }

        if !wire::is_channel_scoped(mt) {
            debug!(mt, "dropping non-channel-scoped upstream message");
            return;
        }

        let Some(up_cid) = wire::read_channel_id(&mut frame) else {
            debug!(mt, "channel-scoped upstream frame too short for a channel_id; dropping");
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

        // Forward to the miner with the channel id remapped.
        if let Some(&down_cid) = i.up_to_down.get(&up_cid) {
            wire::rewrite_channel_id(&mut frame, down_cid);
            let _ = self.to_miner.send(frame.into());
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
            accept_ratio_low: crate::control::accept_ratio_low(i.accepted_shares, i.submitted_shares),
            protocol: "sv2",
        }
    }

    async fn worker_label(&self) -> String {
        self.inner.lock().await.label.clone()
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

/// Shared state between the two SV1-translate driver tasks: the SV2↔SV1 job id
/// map, the version-rolling mask, and the submit id → sequence-number map (to
/// translate the pool's result back to the miner's share).
#[derive(Default)]
struct Sv1UpState {
    version_mask: Option<u32>,
    user_name: String,
    next_job_id: u32,
    job_map: HashMap<u32, String>,
    next_submit_id: u64,
    submit_seq: HashMap<u64, u32>,
    first_job_sent: bool,
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// Connect an SV1 pool and run `configure`(version-rolling) → `subscribe` →
/// `authorize`, capturing the extranonce, the negotiated version mask, and the
/// handshake notifications (initial difficulty + first job).
async fn connect_sv1_upstream(target: &UpstreamTarget) -> anyhow::Result<Sv1UpConn> {
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

    let sub = RpcMessage::request(json!(2), "mining.subscribe", json!(["stratum-rental-proxy/0.1"]));
    w.write_all(sub.to_line().as_bytes()).await?;
    let sub_resp = sv1_read_response(&mut read, &mut prelude).await?;
    let (en1_hex, extranonce2_size) =
        parse_subscribe_sv1(&sub_resp).ok_or_else(|| anyhow!("bad subscribe result"))?;

    let auth = RpcMessage::request(json!(3), "mining.authorize", json!([target.user, target.password]));
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
        extranonce1: hex_decode(&en1_hex)?,
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

/// Writer: the miner's `SubmitSharesExtended` frames → SV1 `mining.submit` lines.
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
            if mt != mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED {
                continue; // only shares cross to the SV1 pool
            }
            let payload = f.payload();
            let submit = match Mining::try_from((mt, payload)) {
                Ok(Mining::SubmitSharesExtended(m)) => m,
                _ => continue,
            };
            let mut s = state.lock().await;
            let Some(sv1_job) = s.job_map.get(&submit.job_id).cloned() else {
                continue; // share for a job we no longer have
            };
            let id = s.next_submit_id;
            s.next_submit_id = s.next_submit_id.wrapping_add(1);
            s.submit_seq.insert(id, submit.sequence_number);
            let mask = s.version_mask;
            let user = s.user_name.clone();
            drop(s);
            let sv1 = match translate::sv2_submit_to_sv1(&submit, user, sv1_job, id, mask) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "sv2→sv1 submit translation failed");
                    continue;
                }
            };
            if write.write_all(translate::submit_to_line(sv1).as_bytes()).await.is_err() {
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
    // mining.notify → NewExtendedMiningJob (+ SetNewPrevHash on a clean/first job).
    if let Some(notify) = translate::notify_from_line(line) {
        let (sv2_job_id, as_future, vra) = {
            let mut s = state.lock().await;
            let jid = s.next_job_id;
            s.next_job_id = s.next_job_id.wrapping_add(1);
            if s.job_map.len() >= 64 {
                s.job_map.clear();
            }
            s.job_map.insert(jid, notify.job_id.clone());
            // The first job must be future (the miner has no prev-hash yet).
            let as_future = notify.clean_jobs || !s.first_job_sent;
            s.first_job_sent = true;
            (jid, as_future, s.version_mask.is_some())
        };
        match translate::sv1_notify_to_sv2_job(&notify, down_cid, sv2_job_id, as_future, vra) {
            Ok((job, prev)) => {
                let job_frame = wire::frame_from(AnyMessage::Mining(Mining::NewExtendedMiningJob(job)));
                session.send_translate_frame(generation, job_frame).await;
                if let Some(p) = prev {
                    let prev_frame = wire::frame_from(AnyMessage::Mining(Mining::SetNewPrevHash(p)));
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
        {
            let i = self.inner.lock().await;
            if generation != i.active.generation {
                return;
            }
        }
        let _ = self.to_miner.send(frame);
    }

    /// Record the share difficulty implied by the SV1 pool's `set_difficulty`.
    async fn set_translate_diff(&self, generation: u64, down_cid: u32, diff: f64) {
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return;
        }
        if let Some(c) = i.channels.iter_mut().find(|c| c.down_channel_id == down_cid) {
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
    ) -> anyhow::Result<()> {
        let up_ident = crate::proto::relay::upstream_worker(&target.user, worker);
        // Native first: try SV2 (reusing its socket on success); if the pool
        // doesn't answer as SV2, it's an SV1 buyer pool → translate.
        match tokio::time::timeout(translate::UPSTREAM_PROBE_TIMEOUT, connect_setup(&target)).await {
            Ok(Ok((read, write, _flags))) => {
                self.install_sv2_initial(read, write, spec, up_ident, target, routing).await
            }
            res => {
                if let Ok(Err(e)) = &res {
                    debug!(url = %target.url, error = %e, "upstream not SV2; trying SV1 translation");
                }
                let conn = connect_sv1_upstream(&target).await?;
                self.install_sv1_translate_initial(conn, spec, up_ident, target, routing).await
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
        up_ident: String,
        target: UpstreamTarget,
        routing: Routing,
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
        i.pending.insert(spec.request_id(), spec.clone());
        i.active
            .to_up
            .send(open_channel_upstream(&spec, &up_ident)?)
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
    ) -> anyhow::Result<()> {
        if !spec.is_extended() {
            let _ = self
                .to_miner
                .send(open_channel_error(spec.request_id(), "standard channels are not supported on an SV1 upstream")?);
            bail!("standard channel on an SV1 upstream is not supported");
        }
        let down_cid = {
            let mut i = self.inner.lock().await;
            let c = i.next_down_cid;
            i.next_down_cid += 1;
            c
        };
        // Reply OpenSuccess to the miner before any job (FIFO on to_miner): the
        // SV1 extranonce1 is the channel's extranonce_prefix.
        let success = OpenExtendedMiningChannelSuccess {
            request_id: spec.request_id(),
            channel_id: down_cid,
            target: U256::try_from(translate::target_from_difficulty(conn.initial_diff).to_vec())
                .map_err(|e| anyhow!("target: {e:?}"))?,
            extranonce_size: conn.extranonce2_size,
            extranonce_prefix: B032::try_from(conn.extranonce1.clone())
                .map_err(|e| anyhow!("extranonce: {e:?}"))?,
            group_channel_id: 0,
        };
        self.to_miner
            .send(wire::frame_from(AnyMessage::Mining(
                Mining::OpenExtendedMiningChannelSuccess(success),
            )))
            .map_err(|_| anyhow!("miner writer gone"))?;

        let state = Arc::new(Mutex::new(Sv1UpState {
            version_mask: conn.version_mask,
            user_name: up_ident,
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
        let (down_cid, spec) = {
            let i = self.inner.lock().await;
            match i.channels.first() {
                Some(c) => (c.down_channel_id, c.spec.clone()),
                None => bail!("no channel to switch"),
            }
        };
        if !spec.is_extended() {
            bail!("standard channel cannot be switched onto an SV1 upstream");
        }
        let conn = connect_sv1_upstream(&target)
            .await
            .map_err(|e| anyhow!("switch to {}: {e}", target.url))?;
        let initial_target = translate::target_from_difficulty(conn.initial_diff).to_vec();
        let extranonce1 = conn.extranonce1.clone();
        let state = Arc::new(Mutex::new(Sv1UpState {
            version_mask: conn.version_mask,
            user_name: up_ident,
            next_job_id: 1,
            next_submit_id: 1,
            ..Default::default()
        }));
        let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
        let writer = spawn_sv1_translate_writer(conn.write, state.clone(), up_rx);
        let abandoned: Vec<u32> = {
            let mut i = self.inner.lock().await;
            let reader =
                spawn_sv1_translate_reader(self.clone(), generation, conn.read, state, down_cid, conn.prelude);
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
            }];
            i.up_to_down = HashMap::from([(down_cid, down_cid)]);
            let abandoned = i.pending.keys().copied().collect();
            i.pending.clear();
            i.routing = routing;
            i.translating = true;
            abandoned
        };
        // Re-point the miner: new extranonce prefix + target; the reader streams
        // the new pool's first job after.
        let _ = self.to_miner.send(set_extranonce_prefix(down_cid, extranonce1)?);
        let _ = self.to_miner.send(set_target(down_cid, initial_target)?);
        for request_id in abandoned {
            if let Ok(f) = open_channel_error(request_id, "upstream switched; please reopen") {
                let _ = self.to_miner.send(f);
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
    let stream =
        accept_noise_connection::<Msg>(miner, keys.public(), keys.secret(), CERT_VALIDITY)
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

    // 6. Build the session with a placeholder upstream, then connect + install
    //    the real one — SV2 passthrough or SV1 translation, auto-detected from the
    //    pool. On the primary's failure, fall back to the order's fallback pool.
    let (died_tx, died_rx) = mpsc::unbounded_channel::<u64>();
    let (placeholder_to_up, _placeholder_rx) = mpsc::unbounded_channel::<EitherFrame>();
    let session = Arc::new(Sv2Session {
        to_miner: to_miner.clone(),
        switch: Mutex::new(()),
        died_tx,
        orders: ctx.orders.clone(),
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
            routing: routing.clone(),
            default_target: idle_target.clone(),
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            accept_low_logged: false,
            label: worker.clone(),
            translating: false,
        }),
    });

    if let Err(e) = session
        .connect_and_install_initial(open_target.clone(), spec.clone(), &worker, routing.clone())
        .await
    {
        match active_order.as_ref().and_then(|o| o.fallback.clone()) {
            Some(fb) => {
                warn!(%worker, error = %e, "primary buyer pool unreachable — using fallback");
                open_target = fb.clone();
                session
                    .connect_and_install_initial(fb, spec.clone(), &worker, routing.clone())
                    .await?;
            }
            None => return Err(e),
        }
    }

    ctx.registry
        .insert(worker.clone(), AnySession::Sv2(session.clone()))
        .await;
    // Supervisor: reconnect / fail over to the fallback if the upstream drops.
    let supervisor = tokio::spawn(supervise_upstream(session.clone(), died_rx));
    match &active_order {
        Some(o) => info!(%peer, %worker, upstream = %open_target.url, order = %o.id, "sv2 relay established (rented)"),
        None => info!(%peer, %worker, upstream = %open_target.url, "sv2 relay established (idle)"),
    }

    // 9. Downstream loop: open additional channels and forward shares/updates
    //    upstream (channel-id remapped per channel).
    let result: anyhow::Result<()> = async {
        loop {
            let mut frame = match down_read.read_frame().await {
                Ok(f) => match wire::into_sv2(f) {
                    Some(f) => f,
                    None => continue,
                },
                Err(_) => break,
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
                    match open_channel_upstream(&open.spec, &account) {
                        Ok(f) => {
                            i.pending.insert(open.spec.request_id(), open.spec.clone());
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
                        debug!("channel-scoped downstream frame too short for a channel_id; dropping");
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
                        debug!(down_cid, "no channel mapping for downstream frame; dropping");
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

    // Teardown.
    let label = session.worker_label().await;
    ctx.registry
        .remove_if(&label, &AnySession::Sv2(session.clone()))
        .await;
    supervisor.abort();
    {
        let i = session.inner.lock().await;
        i.active.reader.abort();
        i.active.writer.abort();
    }
    miner_writer.abort();
    info!(%peer, "sv2 relay closed");
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
mod tests {
    //! End-to-end relay test over real loopback Noise sockets: a mock miner
    //! talks to the proxy, which relays to mock pool A; then a rental switch
    //! re-points it to mock pool B without the miner reconnecting.

    use super::*;
    use stratum_core::binary_sv2::B032;
    use stratum_core::mining_sv2::{SubmitSharesExtended, SubmitSharesSuccess, UpdateChannel};
    use tokio::net::TcpListener;

    fn ext_target(url: &str, user: &str) -> UpstreamTarget {
        UpstreamTarget {
            url: url.to_string(),
            user: user.to_string(),
            password: String::new(),
            authority_pubkey: None,
        }
    }

    /// Register a worker's rig (its idle pool) so the register-only relay serves
    /// it — every test miner authorizes as `bc1qSELLER.rig1`.
    async fn register_rig(sellers: &crate::store::SellerStore, worker: &str, idle: UpstreamTarget) {
        sellers
            .set(
                worker.to_string(),
                crate::store::Rig {
                    default_pool: idle,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    /// A channel target (little-endian) of 2^224 ⇒ difficulty ≈ 1, so accepted
    /// shares carry real (non-zero) work. (`[0xff; 32]` is the max target =
    /// difficulty 0, which the accounting correctly ignores.)
    fn diff1_target() -> Vec<u8> {
        let mut t = vec![0u8; 32];
        t[28] = 1;
        t
    }

    /// A mock SV2 pool: one connection, tagging its `extranonce_prefix`. Assigns
    /// each opened channel a distinct id starting at `base_cid`. Reports the
    /// `channel_id` of each received submit on `submits` and replies
    /// `SubmitSharesSuccess` with that channel id (exercising the proxy's
    /// downstream rewrite). Handles multiple channels on the one connection.
    async fn mock_pool(
        listener: TcpListener,
        prefix: Vec<u8>,
        base_cid: u32,
        keys: NoiseKeys,
        submits: mpsc::UnboundedSender<u32>,
    ) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("pool noise: {e:?}"))?;
        let (read, write) = stream.into_split();
        serve_pool_conn(read, write, prefix, base_cid, submits).await
    }

    /// A pool that accepts MANY connections (several miners sharing one rig name,
    /// each its own proxy→pool connection), serving each on its own task with a
    /// distinct base channel id.
    async fn mock_pool_multi(
        listener: TcpListener,
        prefix: Vec<u8>,
        base_cid: u32,
        keys: NoiseKeys,
        submits: mpsc::UnboundedSender<u32>,
    ) -> anyhow::Result<()> {
        let mut n = 0u32;
        loop {
            let (sock, _) = listener.accept().await?;
            let _ = sock.set_nodelay(true);
            let stream =
                accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                    .await
                    .map_err(|e| anyhow!("pool noise: {e:?}"))?;
            let (read, write) = stream.into_split();
            let cid = base_cid + n * 10;
            n += 1;
            tokio::spawn(serve_pool_conn(read, write, prefix.clone(), cid, submits.clone()));
        }
    }

    /// Serve one pool connection: setup handshake, then opens → success (distinct
    /// cid), submits → report + success, UpdateChannel → SetTarget.
    async fn serve_pool_conn(
        mut read: Read,
        mut write: Write,
        prefix: Vec<u8>,
        base_cid: u32,
        submits: mpsc::UnboundedSender<u32>,
    ) -> anyhow::Result<()> {
        // SetupConnection → success.
        loop {
            let f = read_one(&mut read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        write.write_frame(setup_success(0)).await.map_err(|e| anyhow!("{e:?}"))?;

        // Steady loop: opens → success (distinct cid), submits → report + success.
        let mut next_cid = base_cid;
        while let Ok(mut f) = read_one(&mut read).await {
            match wire::msg_type(&f) {
                Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL)
                | Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL) => {
                    let Some(open) = parse_miner_open(&mut f) else {
                        continue;
                    };
                    let cid = next_cid;
                    next_cid += 1;
                    let info = ChannelInfo {
                        request_id: open.spec.request_id(),
                        up_channel_id: cid,
                        extranonce_prefix: prefix.clone(),
                        target: diff1_target(),
                        extranonce_size: 8,
                        group_channel_id: 0,
                    };
                    write
                        .write_frame(open_success_downstream(
                            &open.spec,
                            cid,
                            info.group_channel_id,
                            &info,
                        )?)
                        .await
                        .map_err(|e| anyhow!("{e:?}"))?;
                }
                Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) => {
                    let Some(cid) = wire::read_channel_id(&mut f) else {
                        continue;
                    };
                    let _ = submits.send(cid);
                    let ok = SubmitSharesSuccess {
                        channel_id: cid,
                        last_sequence_number: 0,
                        new_submits_accepted_count: 1,
                        new_shares_sum: 1,
                    };
                    write
                        .write_frame(wire::frame_from(AnyMessage::Mining(
                            Mining::SubmitSharesSuccess(ok),
                        )))
                        .await
                        .map_err(|e| anyhow!("{e:?}"))?;
                }
                Some(mining::MESSAGE_TYPE_UPDATE_CHANNEL) => {
                    // Vardiff: answer the miner's hashrate update with a target.
                    let Some(cid) = wire::read_channel_id(&mut f) else {
                        continue;
                    };
                    let st = SetTarget {
                        channel_id: cid,
                        maximum_target: U256::from([0x33u8; 32]),
                    };
                    write
                        .write_frame(wire::frame_from(AnyMessage::Mining(Mining::SetTarget(st))))
                        .await
                        .map_err(|e| anyhow!("{e:?}"))?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    struct MockMiner {
        read: Read,
        write: Write,
    }

    impl MockMiner {
        async fn connect(addr: std::net::SocketAddr) -> anyhow::Result<Self> {
            let tcp = TcpStream::connect(addr).await?;
            let _ = tcp.set_nodelay(true);
            let stream = connect_with_noise::<Msg>(tcp, None)
                .await
                .map_err(|e| anyhow!("miner noise: {e:?}"))?;
            let (read, write) = stream.into_split();
            Ok(Self { read, write })
        }

        async fn setup(&mut self) -> anyhow::Result<()> {
            self.write.write_frame(setup_connection()).await.map_err(|e| anyhow!("{e:?}"))?;
            loop {
                let f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) {
                    return Ok(());
                }
            }
        }

        /// Send an OpenExtendedMiningChannel without waiting for the success.
        async fn send_open(&mut self, worker: &str, request_id: u32) -> anyhow::Result<()> {
            let spec = OpenSpec::Extended {
                request_id,
                nominal_hash_rate: 1.0e12,
                max_target: vec![0xffu8; 32],
                min_extranonce_size: 8,
            };
            self.write
                .write_frame(open_channel_upstream(&spec, worker)?)
                .await
                .map_err(|e| anyhow!("{e:?}"))
        }

        /// Open an Extended channel; returns `(downstream_channel_id, prefix)`.
        async fn open(&mut self, worker: &str, request_id: u32) -> anyhow::Result<(u32, Vec<u8>)> {
            self.send_open(worker, request_id).await?;
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f)
                    == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
                {
                    let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                    return Ok((info.up_channel_id, info.extranonce_prefix));
                }
            }
        }

        async fn update_channel(&mut self, channel_id: u32) -> anyhow::Result<()> {
            let m = UpdateChannel {
                channel_id,
                nominal_hash_rate: 2.0e12,
                maximum_target: U256::from([0xffu8; 32]),
            };
            self.write
                .write_frame(wire::frame_from(AnyMessage::Mining(Mining::UpdateChannel(m))))
                .await
                .map_err(|e| anyhow!("{e:?}"))
        }

        /// Read until SetTarget; returns `(channel_id, target_bytes)`.
        async fn read_until_set_target(&mut self) -> anyhow::Result<(u32, Vec<u8>)> {
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SET_TARGET) {
                    let mt = wire::msg_type(&f).unwrap();
                    let payload = f.payload();
                    if let Ok(Mining::SetTarget(m)) = Mining::try_from((mt, payload)) {
                        return Ok((m.channel_id, m.maximum_target.inner_as_ref().to_vec()));
                    }
                }
            }
        }

        async fn submit(&mut self, channel_id: u32, seq: u32) -> anyhow::Result<()> {
            let m = SubmitSharesExtended {
                channel_id,
                sequence_number: seq,
                job_id: 1,
                nonce: 0,
                ntime: 0,
                version: 0x2000_0000,
                extranonce: B032::try_from(vec![0u8; 8]).unwrap(),
            };
            self.write
                .write_frame(wire::frame_from(AnyMessage::Mining(
                    Mining::SubmitSharesExtended(m),
                )))
                .await
                .map_err(|e| anyhow!("{e:?}"))
        }

        /// Read until a frame of `want` type; returns its channel_id.
        async fn read_until_cid(&mut self, want: u8) -> anyhow::Result<u32> {
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(want) {
                    if let Some(cid) = wire::read_channel_id(&mut f) {
                        return Ok(cid);
                    }
                }
            }
        }

        /// Open an Extended channel; returns the OpenSuccess `(channel_id,
        /// group_channel_id, prefix)` the miner sees (all already remapped into
        /// the proxy's downstream id namespace).
        async fn open_full(
            &mut self,
            worker: &str,
            request_id: u32,
        ) -> anyhow::Result<(u32, u32, Vec<u8>)> {
            self.send_open(worker, request_id).await?;
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f)
                    == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
                {
                    let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                    return Ok((
                        info.up_channel_id,
                        info.group_channel_id,
                        info.extranonce_prefix,
                    ));
                }
            }
        }

        /// Read until SetExtranoncePrefix; returns `(channel_id, prefix)`.
        async fn read_until_set_extranonce(&mut self) -> anyhow::Result<(u32, Vec<u8>)> {
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX) {
                    let mt = wire::msg_type(&f).unwrap();
                    let payload = f.payload();
                    if let Ok(Mining::SetExtranoncePrefix(m)) = Mining::try_from((mt, payload)) {
                        return Ok((m.channel_id, m.extranonce_prefix.inner_as_ref().to_vec()));
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn relay_forwards_open_share_and_switches_upstream() {
        // Mock pools A (cid 7, prefix AA) and B (cid 99, prefix BB).
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        // Proxy: default upstream = pool A.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        // Miner connects + opens → lands on pool A.
        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, prefix1) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
        assert_eq!(prefix1, vec![0xAA; 8], "idle → seller default pool A");

        // Submit → reaches pool A; success comes back on the stable downstream cid.
        miner.submit(down_cid, 0).await.unwrap();
        assert_eq!(a_rx.recv().await.unwrap(), 7, "submit reached pool A");
        let ok_cid = miner
            .read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS)
            .await
            .unwrap();
        assert_eq!(ok_cid, down_cid, "success remapped to downstream channel id");

        // Rent: switch the session to pool B.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
            .await
            .unwrap();

        // Miner is re-pointed to pool B (new extranonce prefix), same channel id.
        let (re_cid, prefix2) = miner.read_until_set_extranonce().await.unwrap();
        assert_eq!(prefix2, vec![0xBB; 8], "rented → buyer pool B");
        assert_eq!(re_cid, down_cid, "re-point keeps the downstream channel id");

        // Submit again → now reaches pool B; the proxy rewrote down cid → pool B's 99.
        miner.submit(down_cid, 1).await.unwrap();
        assert_eq!(b_rx.recv().await.unwrap(), 99, "submit reached pool B (cid remapped)");
        let ok_cid2 = miner
            .read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS)
            .await
            .unwrap();
        assert_eq!(ok_cid2, down_cid, "success still on stable downstream channel id");
    }

    #[tokio::test]
    async fn relay_supports_multiple_channels_on_one_connection() {
        // Pool A assigns cids 7, 8; pool B assigns 99, 100.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        // First channel (bootstrap, request_id 1) + a second channel (request_id 2).
        let (cid1, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
        let (cid2, _) = miner.open("bc1qSELLER.rig1", 2).await.unwrap();
        assert_ne!(cid1, cid2, "each channel gets a distinct downstream id");

        // Submit on each channel → both reach pool A on distinct upstream cids.
        miner.submit(cid1, 0).await.unwrap();
        miner.submit(cid2, 0).await.unwrap();
        let mut seen = vec![a_rx.recv().await.unwrap(), a_rx.recv().await.unwrap()];
        seen.sort_unstable();
        assert_eq!(seen, vec![7, 8], "both channels' submits reached pool A");

        // Switch both channels to pool B.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
            .await
            .unwrap();

        // Both channels are re-pointed (two SetExtranoncePrefix, same down cids).
        let (rc1, _) = miner.read_until_set_extranonce().await.unwrap();
        let (rc2, _) = miner.read_until_set_extranonce().await.unwrap();
        let mut repointed = vec![rc1, rc2];
        repointed.sort_unstable();
        let mut expected = vec![cid1, cid2];
        expected.sort_unstable();
        assert_eq!(repointed, expected, "both channels re-pointed, ids stable");

        // Submit on both → reach pool B on its distinct cids.
        miner.submit(cid1, 1).await.unwrap();
        miner.submit(cid2, 1).await.unwrap();
        let mut seen_b = vec![b_rx.recv().await.unwrap(), b_rx.recv().await.unwrap()];
        seen_b.sort_unstable();
        assert_eq!(seen_b, vec![99, 100], "both channels' submits reached pool B");
    }

    #[tokio::test]
    async fn vardiff_set_target_forwards_to_miner() {
        // Pool answers the miner's UpdateChannel with a SetTarget; the proxy
        // forwards it back, remapped to the downstream channel id.
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, NoiseKeys::generate(), tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&addr.to_string(), "acct")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        miner.update_channel(down_cid).await.unwrap();
        let (cid, target) = miner.read_until_set_target().await.unwrap();
        assert_eq!(cid, down_cid, "SetTarget remapped to downstream channel id");
        assert_eq!(target, vec![0x33u8; 32], "pool's new target reached the miner");
    }

    /// A pool that completes the first channel open, then signals + ignores any
    /// further opens (leaving them pending at the proxy).
    async fn mock_pool_stall(
        listener: TcpListener,
        keys: NoiseKeys,
        ignored: mpsc::UnboundedSender<u32>,
    ) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
        let (mut read, mut write) = stream.into_split();
        loop {
            let f = read_one(&mut read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        write.write_frame(setup_success(0)).await.map_err(|e| anyhow!("{e:?}"))?;
        let mut opened = 0;
        while let Ok(mut f) = read_one(&mut read).await {
            let is_open = matches!(
                wire::msg_type(&f),
                Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL)
                    | Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL)
            );
            if !is_open {
                continue;
            }
            let Some(open) = parse_miner_open(&mut f) else {
                continue;
            };
            if opened == 0 {
                opened += 1;
                let info = ChannelInfo {
                    request_id: open.spec.request_id(),
                    up_channel_id: 7,
                    extranonce_prefix: vec![0xAA; 8],
                    target: vec![0xffu8; 32],
                    extranonce_size: 8,
                    group_channel_id: 0,
                };
                write
                    .write_frame(open_success_downstream(
                        &open.spec,
                        7,
                        info.group_channel_id,
                        &info,
                    )?)
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            } else {
                let _ = ignored.send(open.spec.request_id()); // stall this open
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn switch_abandons_pending_open_with_error() {
        // Pool A completes the first open then stalls the second; pool B normal.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (ign_tx, mut ign_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool_stall(pool_a, NoiseKeys::generate(), ign_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let _ = miner.open("bc1qSELLER.rig1", 1).await.unwrap(); // first channel ok
        miner.send_open("bc1qSELLER.rig1", 2).await.unwrap(); // second → stalls upstream
        assert_eq!(ign_rx.recv().await.unwrap(), 2, "pool A received + stalled open #2");

        // Switch to pool B: the in-flight open #2 must be abandoned with an error.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
            .await
            .unwrap();

        let err_request_id = miner
            .read_until_cid(mining::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR)
            .await
            .unwrap();
        assert_eq!(err_request_id, 2, "pending open #2 abandoned with an error");
    }

    #[tokio::test]
    async fn delivered_work_is_credited_to_the_rental_order() {
        // Default pool A (idle) + buyer pool B (rented).
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(pool.clone());
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: orders.clone(),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        // Rent: create an order and switch the session onto buyer pool B.
        let order = orders
            .create(
                "bc1qSELLER.rig1".into(),
                ext_target(&b_addr.to_string(), "acctB"),
                None,
                0,
                0.0,
                0.0,
            )
            .await
            .unwrap();
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to(order.id.clone(), ext_target(&b_addr.to_string(), "acctB"))
            .await
            .unwrap();
        let _ = miner.read_until_set_extranonce().await.unwrap();

        // Submit K accepted shares.
        let k = 3u64;
        for seq in 0..k {
            miner.submit(down_cid, seq as u32).await.unwrap();
            b_rx.recv().await.unwrap(); // pool B received the submit
        }

        // Work is buffered as the successes are forwarded; flush each poll to
        // drain it to the DB (bounded, so a regression fails instead of hanging).
        let mut credited = orders.get(&order.id).await.unwrap();
        for _ in 0..100_000 {
            if credited.accepted_shares >= k {
                break;
            }
            tokio::task::yield_now().await;
            orders.flush().await;
            credited = orders.get(&order.id).await.unwrap();
        }
        assert_eq!(credited.accepted_shares, k, "accepted shares credited to order");
        assert_eq!(credited.submitted_shares, k, "submitted shares tracked on order");
        let expected = difficulty_from_target(&diff1_target()) * k as f64;
        assert!(credited.delivered_work > 0.0, "delivered work measured");
        assert!(
            (credited.delivered_work - expected).abs() <= expected * 1e-6 + f64::MIN_POSITIVE,
            "delivered_work {} ~= {} (diff-weighted)",
            credited.delivered_work,
            expected
        );
    }

    #[tokio::test]
    async fn upstream_authenticates_pool_authority() {
        // Pool with a known authority keypair.
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        let pool_keys = NoiseKeys::generate();
        let pool_pubkey = pool_keys.public_b58();
        let (tx, _rx) = mpsc::unbounded_channel();
        tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, pool_keys, tx));

        // Pinning the correct authority key: the upstream handshake succeeds.
        let mut target = ext_target(&addr.to_string(), "acct");
        target.authority_pubkey = Some(pool_pubkey);
        assert!(
            connect_setup(&target).await.is_ok(),
            "correct authority key should authenticate"
        );
    }

    #[tokio::test]
    async fn upstream_rejects_wrong_pool_authority() {
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        let pool_keys = NoiseKeys::generate();
        let (tx, _rx) = mpsc::unbounded_channel();
        tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, pool_keys, tx));

        // Pinning a different authority key: the handshake must fail.
        let mut target = ext_target(&addr.to_string(), "acct");
        target.authority_pubkey = Some(NoiseKeys::generate().public_b58());
        assert!(
            connect_setup(&target).await.is_err(),
            "wrong authority key must be rejected"
        );
    }

    #[tokio::test]
    async fn unregistered_worker_is_rejected() {
        // Register-only: a worker with no rig is refused at channel-open, before
        // any upstream is contacted (no mock pool needed).
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let pool = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
        // No rig registered for the worker.
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        assert!(
            miner.open("bc1qUNREGISTERED", 1).await.is_err(),
            "unregistered worker open must fail (connection closed)"
        );
        assert!(registry.get_all("bc1qUNREGISTERED").await.is_empty());
    }

    /// A mock pool that groups the Extended channel the way the real pool does:
    /// its OpenSuccess carries a distinct `group_channel_id`, and it then
    /// broadcasts ONE `NewExtendedMiningJob` addressed to that GROUP id (not the
    /// channel id). Exercises the proxy's group-id remapping.
    async fn mock_pool_group(listener: TcpListener, keys: NoiseKeys) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("pool noise: {e:?}"))?;
        let (mut read, mut write) = stream.into_split();
        loop {
            let f = read_one(&mut read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        write.write_frame(setup_success(0)).await.map_err(|e| anyhow!("{e:?}"))?;
        while let Ok(mut f) = read_one(&mut read).await {
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                // Channel id 10, a DISTINCT group id 77 (mimics the pool's group).
                let success =
                    Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
                        request_id: open.spec.request_id(),
                        channel_id: 10,
                        target: U256::try_from(diff1_target()).unwrap(),
                        extranonce_size: 8,
                        extranonce_prefix: B032::try_from(vec![0xCC; 8]).unwrap(),
                        group_channel_id: 77,
                    });
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(success)))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
                // The job is broadcast to the GROUP id (77), not the channel (10).
                let empty_path: Vec<U256> = vec![];
                let job = mining::NewExtendedMiningJob {
                    channel_id: 77,
                    job_id: 1,
                    min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path: empty_path.into(),
                    coinbase_tx_prefix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                    coinbase_tx_suffix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::NewExtendedMiningJob(job),
                    )))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn group_broadcast_job_reaches_miner() {
        // Regression: Extended channels are grouped, so the pool broadcasts
        // NewExtendedMiningJob to the group_channel_id — not the channel id. The
        // proxy must remap the group id into its downstream namespace, else the
        // job is dropped (down_cid=None) and the miner never starts real work.
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        tokio::spawn(mock_pool_group(pool, NoiseKeys::generate()));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&addr.to_string(), "acct")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, down_group, prefix) = miner.open_full("bc1qSELLER.rig1", 1).await.unwrap();
        assert_eq!(prefix, vec![0xCC; 8], "miner sees the pool's extranonce prefix");
        assert_ne!(down_group, 0, "Extended OpenSuccess carries a remapped group id");
        assert_ne!(down_group, down_cid, "group id is distinct from the channel id");

        // The group-broadcast job must reach the miner, remapped to the
        // downstream group id (before the fix it was dropped as unmapped).
        let job_cid = tokio::time::timeout(
            Duration::from_secs(5),
            miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
        )
        .await
        .expect("group-broadcast job was dropped (not remapped) — timed out")
        .unwrap();
        assert_eq!(
            job_cid, down_group,
            "group-broadcast job remapped to the downstream group id"
        );
    }

    /// A pool that completes the channel open (cid 99) and then *immediately*
    /// broadcasts a `NewExtendedMiningJob` addressed to that channel — like a real
    /// pool bootstrapping a freshly opened channel right after its OpenSuccess.
    async fn mock_pool_job_after_open(listener: TcpListener, keys: NoiseKeys) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("pool noise: {e:?}"))?;
        let (mut read, mut write) = stream.into_split();
        loop {
            let f = read_one(&mut read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        write.write_frame(setup_success(0)).await.map_err(|e| anyhow!("{e:?}"))?;
        while let Ok(mut f) = read_one(&mut read).await {
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                let info = ChannelInfo {
                    request_id: open.spec.request_id(),
                    up_channel_id: 99,
                    extranonce_prefix: vec![0xBB; 8],
                    target: diff1_target(),
                    extranonce_size: 8,
                    group_channel_id: 0,
                };
                write
                    .write_frame(open_success_downstream(&open.spec, 99, 0, &info)?)
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
                // Bootstrap job, sent right after OpenSuccess to the channel id.
                let empty_path: Vec<U256> = vec![];
                let job = mining::NewExtendedMiningJob {
                    channel_id: 99,
                    job_id: 7,
                    min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path: empty_path.into(),
                    coinbase_tx_prefix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                    coinbase_tx_suffix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::NewExtendedMiningJob(job),
                    )))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn switch_delivers_new_upstream_initial_job() {
        // Regression: on a rental switch the proxy opens a fresh channel on the
        // new upstream, then the steady reader takes over the same socket. The
        // job the new pool broadcasts right after OpenSuccess must reach the miner
        // (remapped to its stable downstream channel id) — i.e. the reader must
        // already be on the new generation when it processes that first frame, and
        // the post-OpenSuccess frames buffered on the socket must not be lost.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool_job_after_open(pool_b, NoiseKeys::generate()));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        // Rent: switch onto pool B, which sends a job right after the reopen.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
            .await
            .unwrap();

        // The new upstream's bootstrap job must reach the miner, remapped to the
        // stable downstream channel id (read_until_cid skips the switch's
        // SetExtranoncePrefix/SetTarget re-point frames).
        let job_cid = tokio::time::timeout(
            Duration::from_secs(5),
            miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
        )
        .await
        .expect("new upstream's post-switch job was dropped — timed out")
        .unwrap();
        assert_eq!(
            job_cid, down_cid,
            "post-switch job remapped to the stable downstream channel id"
        );
    }

    /// A pool that completes one channel open then drops the connection AND its
    /// listener — simulating a pool that goes away mid-rental (reconnects refused).
    async fn mock_pool_drop_once(listener: TcpListener, keys: NoiseKeys) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("pool noise: {e:?}"))?;
        let (mut read, mut write) = stream.into_split();
        loop {
            let f = read_one(&mut read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        write.write_frame(setup_success(0)).await.map_err(|e| anyhow!("{e:?}"))?;
        while let Ok(mut f) = read_one(&mut read).await {
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                let info = ChannelInfo {
                    request_id: open.spec.request_id(),
                    up_channel_id: 99,
                    extranonce_prefix: vec![0xBB; 8],
                    target: diff1_target(),
                    extranonce_size: 8,
                    group_channel_id: 0,
                };
                write
                    .write_frame(open_success_downstream(&open.spec, 99, 0, &info)?)
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
                break;
            }
        }
        // Return → drops the connection (EOF to the proxy) + the listener (port
        // freed), so the proxy's reconnect to the primary is refused → fail over.
        Ok(())
    }

    #[tokio::test]
    async fn mid_rental_failover_to_fallback_on_primary_drop() {
        // Rental primary serves the open then drops; the supervisor must reconnect,
        // find the primary gone, and fail over to the fallback pool.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let pool_fb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = pool_fb.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (fb_tx, _fb_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool_drop_once(primary, NoiseKeys::generate()));
        tokio::spawn(mock_pool(pool_fb, vec![0xCC; 8], 55, NoiseKeys::generate(), fb_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(db.clone());
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (_down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        let order = orders
            .create(
                "bc1qSELLER.rig1".into(),
                ext_target(&primary_addr.to_string(), "acctP"),
                Some(ext_target(&fb_addr.to_string(), "acctFB")),
                0,
                0.0,
                0.0,
            )
            .await
            .unwrap();
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        // Lands on the primary; the primary then drops → supervisor fails over.
        sess.switch_to_order(order.id.clone()).await.unwrap();

        // The miner is eventually re-pointed to the fallback (0xCC) by the supervisor.
        let mut got_fb = false;
        for _ in 0..50 {
            let res = tokio::time::timeout(Duration::from_secs(5), miner.read_until_set_extranonce()).await;
            let Ok(Ok((_, prefix))) = res else { break };
            if prefix == vec![0xCC; 8] {
                got_fb = true;
                break;
            }
        }
        assert!(got_fb, "supervisor failed the dropped primary over to the fallback pool");
    }

    #[tokio::test]
    async fn switch_falls_back_when_primary_pool_is_down() {
        // Rental primary points at a dead port; fallback = a live pool. switch_to_order
        // must try the primary, fail fast, and land on the fallback.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // free the port → connect refused
        let pool_fb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = pool_fb.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (fb_tx, _fb_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_fb, vec![0xCC; 8], 55, NoiseKeys::generate(), fb_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(db.clone());
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        let order = orders
            .create(
                "bc1qSELLER.rig1".into(),
                ext_target(&dead_addr.to_string(), "acctDead"),
                Some(ext_target(&fb_addr.to_string(), "acctFB")),
                0,
                0.0,
                0.0,
            )
            .await
            .unwrap();

        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.switch_to_order(order.id.clone()).await.unwrap();

        // Landed on the fallback: the miner is re-pointed to FB's extranonce prefix.
        let (re_cid, prefix) = miner.read_until_set_extranonce().await.unwrap();
        assert_eq!(prefix, vec![0xCC; 8], "primary down → switched to fallback pool");
        assert_eq!(re_cid, down_cid);
        assert_eq!(sess.status().await.routing, "rented");
    }

    #[tokio::test]
    async fn connect_with_active_rental_opens_on_buyer_directly() {
        // Reconnect-resume: when an order is already active as the miner connects,
        // the first channel opens straight on the buyer's pool (no idle-then-switch
        // round-trip) and the session reads rented immediately.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap(); // rig idle pool
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap(); // buyer pool
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(db.clone());
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        // Rental already active for this worker, targeting buyer pool B.
        let order = orders
            .create("bc1qSELLER.rig1".into(), ext_target(&b_addr.to_string(), "acctB"), None, 0, 0.0, 0.0)
            .await
            .unwrap();

        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (_down_cid, prefix) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
        assert_eq!(prefix, vec![0xBB; 8], "first channel opened directly on the buyer pool");

        let st = loop {
            if let Some(s) = registry.aggregated_status("bc1qSELLER.rig1").await {
                break s;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(st.routing, "rented", "session is rented on connect");
        assert_eq!(st.order_id.as_deref(), Some(order.id.as_str()));
    }

    #[tokio::test]
    async fn concurrent_switches_leave_a_consistent_session() {
        // Two switches fired at once must serialize (the switch lock) and leave the
        // session internally consistent: `routing`/`order_id` agree with the active
        // upstream, and a submit reaches exactly that pool on its remapped cid.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let pool_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c_addr = pool_c.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
        let (c_tx, mut c_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));
        tokio::spawn(mock_pool(pool_c, vec![0xCC; 8], 199, NoiseKeys::generate(), c_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };

        // Fire both switches concurrently; the switch lock serializes them.
        let b_url = b_addr.to_string();
        let c_url = c_addr.to_string();
        let (rb, rc) = tokio::join!(
            sess.switch_to("oB".to_string(), ext_target(&b_url, "acctB")),
            sess.switch_to("oC".to_string(), ext_target(&c_url, "acctC")),
        );
        rb.unwrap();
        rc.unwrap();

        // Whichever won, routing/order and the active upstream must agree, and a
        // submit must reach that same pool (its remapped upstream cid).
        let st = sess.status().await;
        assert_eq!(st.routing, "rented");
        miner.submit(down_cid, 0).await.unwrap();
        match st.order_id.as_deref() {
            Some("oB") => {
                assert_eq!(st.upstream_url, b_url, "active matches the winning order (B)");
                assert_eq!(b_rx.recv().await.unwrap(), 99, "submit reached pool B");
            }
            Some("oC") => {
                assert_eq!(st.upstream_url, c_url, "active matches the winning order (C)");
                assert_eq!(c_rx.recv().await.unwrap(), 199, "submit reached pool C");
            }
            other => panic!("unexpected winning order {other:?}"),
        }
    }

    #[tokio::test]
    async fn same_worker_miners_form_one_rig_switched_together() {
        // MRR model: 2 miners under the SAME worker name = one rig. Each is its
        // own session; renting switches BOTH and the rig status sums them.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
        let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool_multi(pool_a, vec![0xAA; 8], 7, NoiseKeys::generate(), a_tx));
        tokio::spawn(mock_pool_multi(pool_b, vec![0xBB; 8], 99, NoiseKeys::generate(), b_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.farm", ext_target(&a_addr.to_string(), "acctA")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            loop {
                let (sock, peer) = proxy.accept().await.unwrap();
                let ctx = ctx.clone();
                let keys = keys.clone();
                tokio::spawn(async move {
                    let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
                });
            }
        });

        // Two miners, SAME worker name → both land on pool A.
        let mut m1 = MockMiner::connect(proxy_addr).await.unwrap();
        m1.setup().await.unwrap();
        let (cid1, p1) = m1.open("bc1qSELLER.farm", 1).await.unwrap();
        assert_eq!(p1, vec![0xAA; 8], "miner 1 on seller default pool A");
        let mut m2 = MockMiner::connect(proxy_addr).await.unwrap();
        m2.setup().await.unwrap();
        let (_cid2, p2) = m2.open("bc1qSELLER.farm", 1).await.unwrap();
        assert_eq!(p2, vec![0xAA; 8], "miner 2 on seller default pool A");

        // Both registered as ONE rig (two sessions under the shared name).
        let sessions = loop {
            let s = registry.get_all("bc1qSELLER.farm").await;
            if s.len() == 2 {
                break s;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(sessions.len(), 2, "two miners → one rig, two sessions");

        // Rent the whole rig: switch every session to pool B.
        for sess in &sessions {
            sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
                .await
                .unwrap();
        }

        // BOTH miners get re-pointed to pool B (new prefix), same channel id.
        let (rc1, rp1) = m1.read_until_set_extranonce().await.unwrap();
        assert_eq!(rp1, vec![0xBB; 8], "miner 1 switched to pool B");
        assert_eq!(rc1, cid1, "miner 1 keeps its downstream channel id");
        let (_rc2, rp2) = m2.read_until_set_extranonce().await.unwrap();
        assert_eq!(rp2, vec![0xBB; 8], "miner 2 switched to pool B");

        // The rig reads as rented (any session rented ⇒ rig rented).
        let st = registry.aggregated_status("bc1qSELLER.farm").await.unwrap();
        assert_eq!(st.routing, "rented", "the whole rig is rented");
    }

    /// A mock SV1 pool for the translate path: configure(version-rolling) →
    /// subscribe (extranonce1 `deadbeefcafebabe`, en2=8) + a set_difficulty and a
    /// `mining.notify`, then accepts every `mining.submit`. Reports each submit.
    async fn mock_sv1_pool_translate(listener: TcpListener, submits: mpsc::UnboundedSender<()>) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let submits = submits.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    let id = v.get("id").cloned().unwrap_or(Value::Null);
                    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
                        "mining.configure" => {
                            let reply = json!({"id": id, "result": {"version-rolling": true, "version-rolling.mask": "1fffe000"}, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        "mining.subscribe" => {
                            let reply = json!({"id": id, "result": [[["mining.notify", "1"]], "deadbeefcafebabe", 8], "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                            let sd = json!({"id": Value::Null, "method": "mining.set_difficulty", "params": [1024.0]});
                            let _ = w.write_all(format!("{sd}\n").as_bytes()).await;
                            let notify = json!({"id": Value::Null, "method": "mining.notify", "params": ["j1", "0000000000000000000000000000000000000000000000000000000000000000", "01000000", "00000000", [], "20000000", "17072cf6", "65000000", true]});
                            let _ = w.write_all(format!("{notify}\n").as_bytes()).await;
                        }
                        "mining.authorize" => {
                            let reply = json!({"id": id, "result": true, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        "mining.submit" => {
                            let _ = submits.send(());
                            let reply = json!({"id": id, "result": true, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn sv2_miner_rented_onto_sv1_pool_translates_end_to_end() {
        // The rig's idle pool is SV1, so the SV2 miner is served via translation:
        // the proxy is the SV1 client and synthesizes the miner's Extended channel.
        let sv1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sv1_addr = sv1.local_addr().unwrap();
        let (sub_tx, mut sub_rx) = mpsc::unbounded_channel::<()>();
        tokio::spawn(mock_sv1_pool_translate(sv1, sub_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&sv1_addr.to_string(), "acctSV1")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        // The SV2-native connect probe to the SV1 pool must time out before the
        // proxy falls back to SV1 translation, so allow generous time for open().
        let (down_cid, prefix) = tokio::time::timeout(Duration::from_secs(15), miner.open("bc1qSELLER.rig1", 1))
            .await
            .expect("open did not complete")
            .unwrap();
        assert_eq!(
            prefix,
            vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
            "Extended channel prefix = the SV1 extranonce1"
        );

        // The translated job (built from the SV1 mining.notify) reaches the miner.
        let job_cid = tokio::time::timeout(
            Duration::from_secs(5),
            miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
        )
        .await
        .expect("translated job timed out")
        .unwrap();
        assert_eq!(job_cid, down_cid, "job addressed to the miner's channel");

        // Submit → translated to a mining.submit on the SV1 pool.
        miner.submit(down_cid, 0).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), sub_rx.recv())
            .await
            .expect("share never reached the SV1 pool")
            .unwrap();

        // The pool's accept is translated back to a SubmitSharesSuccess.
        let ok_cid = tokio::time::timeout(
            Duration::from_secs(5),
            miner.read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
        )
        .await
        .expect("share result timed out")
        .unwrap();
        assert_eq!(ok_cid, down_cid, "translated share accepted end to end");

        // Accounting credited the delivered work.
        let sess = registry.get_all("bc1qSELLER.rig1").await.into_iter().next().unwrap();
        let st = sess.status().await;
        assert!(st.accepted_shares >= 1, "accepted share counted");
        assert!(st.delivered_work > 0.0, "delivered work credited");
    }

    #[tokio::test]
    async fn rent_sv2_miner_switches_onto_sv1_pool() {
        // Idle on an SV2 pool (passthrough), then rented onto an SV1 buyer pool —
        // the switch must translate (swap_to_sv1_translate) and re-point the miner.
        let sv2_idle = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idle_addr = sv2_idle.local_addr().unwrap();
        let (idle_tx, _idle_rx) = mpsc::unbounded_channel::<u32>();
        tokio::spawn(mock_pool(sv2_idle, vec![0xAA; 8], 7, NoiseKeys::generate(), idle_tx));
        let sv1_buyer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let buyer_addr = sv1_buyer.local_addr().unwrap();
        let (sub_tx, mut sub_rx) = mpsc::unbounded_channel::<()>();
        tokio::spawn(mock_sv1_pool_translate(sv1_buyer, sub_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(db.clone());
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&idle_addr.to_string(), "acctIdle")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, prefix) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
        assert_eq!(prefix, vec![0xAA; 8], "idle on the SV2 pool (passthrough)");

        // Rent onto the SV1 buyer pool → translated switch.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        let buyer = ext_target(&buyer_addr.to_string(), "acctBuyer");
        let order = orders
            .create("bc1qSELLER.rig1".into(), buyer.clone(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        sess.switch_to(order.id.clone(), buyer).await.unwrap();

        // Re-pointed to the SV1 extranonce, then a translated job + accepted share.
        let (re_cid, re_prefix) = tokio::time::timeout(Duration::from_secs(15), miner.read_until_set_extranonce())
            .await
            .expect("set_extranonce after the translated switch")
            .unwrap();
        assert_eq!(re_cid, down_cid, "channel id stable across the switch");
        assert_eq!(re_prefix, vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], "now on the SV1 extranonce1");
        let _ = tokio::time::timeout(Duration::from_secs(5), miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB))
            .await
            .expect("translated job after switch")
            .unwrap();
        miner.submit(down_cid, 0).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), sub_rx.recv())
            .await
            .expect("share reached the SV1 buyer pool")
            .unwrap();
        assert_eq!(sess.status().await.routing, "rented");
    }

    // ── self-validating combo 4: a real mined share, validated by the pool ──

    /// `a <= b` for two 32-byte little-endian numbers (Bitcoin hash vs target).
    fn le_leq(a: &[u8], b: &[u8]) -> bool {
        for i in (0..32).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    /// A legacy coinbase split reserving `en_len` bytes for the extranonce so
    /// `coinb1 + extranonce + coinb2` deserializes as a valid transaction.
    fn legacy_cb_reserving(en_len: usize) -> (Vec<u8>, Vec<u8>) {
        let script_prefix = [0x03u8, 0x33, 0x33, 0x33];
        let ssl = script_prefix.len() + en_len;
        let mut c1 = Vec::new();
        c1.extend_from_slice(&1u32.to_le_bytes());
        c1.push(0x01);
        c1.extend_from_slice(&[0u8; 32]);
        c1.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        c1.push(ssl as u8);
        c1.extend_from_slice(&script_prefix);
        let mut c2 = Vec::new();
        c2.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        c2.push(0x01);
        c2.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        c2.push(0x00);
        c2.extend_from_slice(&0u32.to_le_bytes());
        (c1, c2)
    }

    /// Read the SV2 job/prev-hash/target, mine a real nonce that meets the target,
    /// and submit it — exercising the full coinbase (prefix+extranonce+suffix) and
    /// header reconstruction the SV1 pool will independently re-check.
    async fn mine_and_submit_one(
        miner: &mut MockMiner,
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    ) -> anyhow::Result<()> {
        use stratum_core::bitcoin::hashes::{sha256d, Hash};
        use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;

        let mut job: Option<(u32, u32, Vec<u8>, Vec<u8>)> = None; // job_id, version, cb_prefix, cb_suffix
        let mut prev: Option<([u8; 32], u32, u32)> = None; // prev_hash, min_ntime, nbits
        let mut target: Option<Vec<u8>> = None;
        for _ in 0..50 {
            let mut f = read_one(&mut miner.read).await?;
            match wire::msg_type(&f) {
                Some(mt) if mt == mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB => {
                    if let Some(m) = parse_new_extended_job(&mut f) {
                        job = Some((
                            m.job_id,
                            m.version,
                            m.coinbase_tx_prefix.inner_as_ref().to_vec(),
                            m.coinbase_tx_suffix.inner_as_ref().to_vec(),
                        ));
                    }
                }
                Some(mt) if mt == mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH => {
                    if let Some(m) = parse_set_new_prev_hash(&mut f) {
                        let ph: [u8; 32] = m.prev_hash.inner_as_ref().try_into().unwrap();
                        prev = Some((ph, m.min_ntime, m.nbits));
                    }
                }
                Some(mt) if mt == mining::MESSAGE_TYPE_SET_TARGET => {
                    if let Some(t) = parse_set_target(&mut f) {
                        target = Some(t);
                    }
                }
                _ => {}
            }
            if job.is_some() && prev.is_some() && target.is_some() {
                break;
            }
        }
        let (job_id, version, cb_prefix, cb_suffix) = job.ok_or_else(|| anyhow!("no job"))?;
        let (prev_hash, min_ntime, nbits) = prev.ok_or_else(|| anyhow!("no prev-hash"))?;
        let target = target.ok_or_else(|| anyhow!("no target"))?;

        // Full extranonce = the channel prefix + the miner's rolled part.
        let miner_extranonce = vec![0u8, 0, 0, 1];
        let mut full_en = extranonce_prefix;
        full_en.extend_from_slice(&miner_extranonce);
        let empty: Vec<Vec<u8>> = vec![];
        let merkle_root = merkle_root_from_path(&cb_prefix, &cb_suffix, &full_en, &empty)
            .ok_or_else(|| anyhow!("coinbase did not deserialize"))?;

        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&version.to_le_bytes());
        header.extend_from_slice(&prev_hash);
        header.extend_from_slice(&merkle_root);
        header.extend_from_slice(&min_ntime.to_le_bytes());
        header.extend_from_slice(&nbits.to_le_bytes());
        let noff = header.len();
        header.extend_from_slice(&0u32.to_le_bytes());
        let mut nonce = None;
        for n in 0u32..5_000_000 {
            header[noff..noff + 4].copy_from_slice(&n.to_le_bytes());
            if le_leq(&sha256d::Hash::hash(&header).to_byte_array(), &target) {
                nonce = Some(n);
                break;
            }
        }
        let nonce = nonce.ok_or_else(|| anyhow!("no winning nonce"))?;

        let m = SubmitSharesExtended {
            channel_id,
            sequence_number: 0,
            job_id,
            nonce,
            ntime: min_ntime,
            version,
            extranonce: B032::try_from(miner_extranonce).unwrap(),
        };
        miner
            .write
            .write_frame(wire::frame_from(AnyMessage::Mining(Mining::SubmitSharesExtended(m))))
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(())
    }

    /// A mock SV1 pool that *validates* each submitted share: it reconstructs the
    /// coinbase (`coinb1 + extranonce1 + extranonce2 + coinb2`), the merkle root,
    /// and the 80-byte header, and accepts only if SHA256d ≤ the share target.
    async fn validating_sv1_pool(listener: TcpListener, accepted: mpsc::UnboundedSender<bool>) {
        use stratum_core::bitcoin::hashes::{sha256d, Hash};
        use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;
        use stratum_core::sv1_api::utils::PrevHash as Sv1PrevHash;

        const MASK: u32 = 0x1fff_e000;
        const VERSION: u32 = 0x2000_0000;
        const NBITS: u32 = 0x207f_ffff;
        const NTIME: u32 = 0x6500_0000;
        const DIFFICULTY: f64 = 1e-9;
        let en1: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let (coinb1, coinb2) = legacy_cb_reserving(en1.len() + 4);
        let pv = [0x11u8; 32]; // internal byte order
        let pv_str = String::from(Sv1PrevHash(U256::from(pv)));
        let share_target = translate::target_from_difficulty(DIFFICULTY).to_vec();

        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let accepted = accepted.clone();
            let (en1, coinb1, coinb2, pv_str, share_target) =
                (en1.clone(), coinb1.clone(), coinb2.clone(), pv_str.clone(), share_target.clone());
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    let id = v.get("id").cloned().unwrap_or(Value::Null);
                    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    match method {
                        "mining.configure" => {
                            let reply = json!({"id": id, "result": {"version-rolling": true, "version-rolling.mask": "1fffe000"}, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        "mining.subscribe" => {
                            let reply = json!({"id": id, "result": [[["mining.notify", "1"]], hex_string(&en1), 4], "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                            let sd = json!({"id": Value::Null, "method": "mining.set_difficulty", "params": [DIFFICULTY]});
                            let _ = w.write_all(format!("{sd}\n").as_bytes()).await;
                            let notify = json!({"id": Value::Null, "method": "mining.notify", "params": [
                                "j1", pv_str, hex_string(&coinb1), hex_string(&coinb2), [],
                                format!("{VERSION:08x}"), format!("{NBITS:08x}"), format!("{NTIME:08x}"), true
                            ]});
                            let _ = w.write_all(format!("{notify}\n").as_bytes()).await;
                        }
                        "mining.authorize" => {
                            let reply = json!({"id": id, "result": true, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        "mining.submit" => {
                            let p = v.get("params").and_then(|p| p.as_array()).cloned().unwrap_or_default();
                            let en2 = p.get(2).and_then(|x| x.as_str()).map(hex_bytes).unwrap_or_default();
                            let ntime = p.get(3).and_then(|x| x.as_str()).and_then(|s| u32::from_str_radix(s, 16).ok()).unwrap_or(0);
                            let nonce = p.get(4).and_then(|x| x.as_str()).and_then(|s| u32::from_str_radix(s, 16).ok()).unwrap_or(0);
                            let vbits = p.get(5).and_then(|x| x.as_str()).and_then(|s| u32::from_str_radix(s, 16).ok()).unwrap_or(0);

                            let mut full_en = en1.clone();
                            full_en.extend_from_slice(&en2);
                            let empty: Vec<Vec<u8>> = vec![];
                            let valid = match merkle_root_from_path(&coinb1, &coinb2, &full_en, &empty) {
                                Some(root) => {
                                    let version = (VERSION & !MASK) | (vbits & MASK);
                                    let mut header = Vec::with_capacity(80);
                                    header.extend_from_slice(&version.to_le_bytes());
                                    header.extend_from_slice(&pv);
                                    header.extend_from_slice(&root);
                                    header.extend_from_slice(&ntime.to_le_bytes());
                                    header.extend_from_slice(&NBITS.to_le_bytes());
                                    header.extend_from_slice(&nonce.to_le_bytes());
                                    le_leq(&sha256d::Hash::hash(&header).to_byte_array(), &share_target)
                                }
                                None => false,
                            };
                            let _ = accepted.send(valid);
                            let reply = json!({"id": id, "result": valid, "error": Value::Null});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    }

    fn hex_string(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
    }

    #[tokio::test]
    async fn sv2_to_sv1_translated_share_is_cryptographically_valid() {
        // The end-to-end proof: an SV2 miner mines a real share against the
        // translated job; the SV1 pool independently rebuilds the coinbase +
        // header and confirms SHA256d ≤ target. A wrong extranonce split or
        // endianness anywhere makes the two headers diverge and the pool reject.
        let sv1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sv1_addr = sv1.local_addr().unwrap();
        let (acc_tx, mut acc_rx) = mpsc::unbounded_channel::<bool>();
        tokio::spawn(validating_sv1_pool(sv1, acc_tx));

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let ctx = ProxyContext {
            default_target: None,
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: crate::orders::OrderStore::new(db.clone()),
        };
        register_rig(&ctx.sellers, "bc1qSELLER.rig1", ext_target(&sv1_addr.to_string(), "acctSV1")).await;
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        miner.setup().await.unwrap();
        let (down_cid, prefix) = tokio::time::timeout(Duration::from_secs(15), miner.open("bc1qSELLER.rig1", 1))
            .await
            .expect("open did not complete")
            .unwrap();
        assert_eq!(prefix, vec![0xaa, 0xbb, 0xcc, 0xdd], "channel prefix = SV1 extranonce1");

        // Mine a real share against the translated job and submit it.
        tokio::time::timeout(Duration::from_secs(20), mine_and_submit_one(&mut miner, down_cid, prefix))
            .await
            .expect("mining timed out")
            .unwrap();

        // The pool validated the reconstructed header and accepted it.
        let valid = tokio::time::timeout(Duration::from_secs(5), acc_rx.recv())
            .await
            .expect("pool never saw the share")
            .unwrap();
        assert!(valid, "the translated share must be cryptographically valid at the SV1 pool");

        // The acceptance is translated back to the miner.
        let ok_cid = tokio::time::timeout(Duration::from_secs(5), miner.read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS))
            .await
            .expect("share result timed out")
            .unwrap();
        assert_eq!(ok_cid, down_cid);
    }
}
