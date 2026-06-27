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
//! Multiple mining channels per connection are supported: the first is opened
//! synchronously during the handshake; additional `OpenMiningChannel`s are
//! forwarded to the upstream and finalized asynchronously when its success
//! arrives. Each channel maps its own downstream↔upstream `channel_id`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

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

type Read = NoiseTcpReadHalf<Msg>;
type Write = NoiseTcpWriteHalf<Msg>;

/// The miner's channel-open request, captured to re-open against each upstream.
#[derive(Clone)]
enum OpenSpec {
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
struct ChannelInfo {
    request_id: u32,
    up_channel_id: u32,
    extranonce_prefix: Vec<u8>,
    target: Vec<u8>,
    extranonce_size: u16,
    group_channel_id: u32,
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
        vendor: empty_str(),
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
            group_channel_id: info.group_channel_id,
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

fn parse_open_success(frame: &mut Sv2Frame) -> Option<ChannelInfo> {
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

fn parse_accepted_count(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => Some(s.new_submits_accepted_count),
        _ => None,
    }
}

fn parse_set_target(frame: &mut Sv2Frame) -> Option<Vec<u8>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetTarget(m) => Some(m.maximum_target.inner_as_ref().to_vec()),
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
async fn connect_setup(target: &UpstreamTarget) -> anyhow::Result<(Read, Write, u32)> {
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

/// Open a channel on an already-setup upstream and read until its success.
async fn open_on(
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
            _ => continue,
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
}

struct Inner {
    active: ActiveUpstream,
    generation_counter: u64,
    /// All open channels on this connection (one per rig chain, usually one).
    channels: Vec<Channel>,
    /// upstream channel_id → downstream channel_id (for upstream→miner frames).
    up_to_down: std::collections::HashMap<u32, u32>,
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
}

/// A live SV2 seller-miner session.
pub struct Sv2Session {
    to_miner: mpsc::UnboundedSender<EitherFrame>,
    inner: Mutex<Inner>,
    /// For crediting measured delivered work to the active rental order.
    orders: Arc<OrderStore>,
}

impl Sv2Session {
    pub async fn switch_to(
        self: &Arc<Self>,
        order_id: String,
        target: UpstreamTarget,
    ) -> anyhow::Result<()> {
        self.swap_upstream(
            target.clone(),
            Routing::Rented {
                order_id,
                target,
                until_unix_ms: 0,
            },
        )
        .await
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

    pub async fn default_target(&self) -> UpstreamTarget {
        self.inner.lock().await.default_target.clone()
    }

    async fn swap_upstream(
        self: &Arc<Self>,
        target: UpstreamTarget,
        routing: Routing,
    ) -> anyhow::Result<()> {
        // Snapshot the channels to re-open (down_channel_id + spec).
        let (specs, generation) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            let specs: Vec<(u32, OpenSpec)> = i
                .channels
                .iter()
                .map(|c| (c.down_channel_id, c.spec.clone()))
                .collect();
            (specs, i.generation_counter)
        };
        if specs.is_empty() {
            bail!("no channels to switch");
        }

        // Open all channels on the new upstream before tearing the old one down,
        // so a failed switch leaves the miner mining on the current upstream.
        let (mut read, mut write, _flags) = connect_setup(&target)
            .await
            .map_err(|e| anyhow!("switch to {}: {e}", target.url))?;
        let mut new_channels = Vec::with_capacity(specs.len());
        let mut up_to_down = std::collections::HashMap::new();
        let mut repoint = Vec::with_capacity(specs.len());
        for (down_cid, spec) in &specs {
            let info = open_on(&mut read, &mut write, spec, &target.user)
                .await
                .map_err(|e| anyhow!("switch reopen channel {down_cid}: {e}"))?;
            up_to_down.insert(info.up_channel_id, *down_cid);
            new_channels.push(Channel {
                down_channel_id: *down_cid,
                up_channel_id: info.up_channel_id,
                spec: spec.clone(),
                difficulty: difficulty_from_target(&info.target),
            });
            repoint.push((*down_cid, info.extranonce_prefix, info.target));
        }

        let (to_up, up_rx) = mpsc::unbounded_channel();
        let writer = spawn_writer(write, up_rx);
        let reader = spawn_upstream_reader(self.clone(), generation, read);

        let abandoned: Vec<u32> = {
            let mut i = self.inner.lock().await;
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
                    if let Ok(reply) = open_success_downstream(&spec, down_cid, &info) {
                        let _ = self.to_miner.send(reply);
                    }
                    info!(worker = %i.label, down_cid, up_cid = info.up_channel_id, "sv2 additional channel opened");
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

        let up_cid = wire::read_channel_id(&mut frame);

        // Vardiff: a new target changes this channel's share difficulty.
        if mt == mining::MESSAGE_TYPE_SET_TARGET {
            if let Some(target) = parse_set_target(&mut frame) {
                let diff = difficulty_from_target(&target);
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
            self.orders.add_work(&order_id, work, shares).await;
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

    // 2. Connect the default upstream + SetupConnection; mirror its flags back.
    let default_target = ctx.default_target.clone();
    let (mut up_read, mut up_write, up_flags) = connect_setup(&default_target).await?;

    // 3. Tell the miner setup succeeded.
    let (to_miner, to_miner_rx) = mpsc::unbounded_channel::<EitherFrame>();
    let miner_writer = spawn_writer(down_write, to_miner_rx);
    to_miner
        .send(setup_success(up_flags))
        .map_err(|_| anyhow!("miner writer gone"))?;

    // 4. Miner OpenMiningChannel → capture spec + worker.
    let mut open_frame = read_one(&mut down_read).await?;
    let MinerOpen { spec, worker } =
        parse_miner_open(&mut open_frame).ok_or_else(|| anyhow!("expected OpenMiningChannel"))?;

    // 5. Open the same channel type on the upstream (rewriting the account).
    let info = open_on(&mut up_read, &mut up_write, &spec, &default_target.user).await?;
    // Stable, proxy-assigned downstream channel id for the first channel.
    let down_channel_id = 1u32;

    // 6. Build the session and wire up the initial upstream.
    let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
    let up_writer = spawn_writer(up_write, up_rx);
    let mut up_to_down = std::collections::HashMap::new();
    up_to_down.insert(info.up_channel_id, down_channel_id);
    let session = Arc::new(Sv2Session {
        to_miner: to_miner.clone(),
        orders: ctx.orders.clone(),
        inner: Mutex::new(Inner {
            active: ActiveUpstream {
                generation: 0,
                target: default_target.clone(),
                to_up,
                reader: tokio::spawn(async {}), // placeholder, replaced below
                writer: up_writer,
            },
            generation_counter: 0,
            channels: vec![Channel {
                down_channel_id,
                up_channel_id: info.up_channel_id,
                spec: spec.clone(),
                difficulty: difficulty_from_target(&info.target),
            }],
            up_to_down,
            pending: std::collections::HashMap::new(),
            next_down_cid: 2,
            routing: Routing::Idle,
            default_target: default_target.clone(),
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            accept_low_logged: false,
            label: worker.clone(),
        }),
    });
    {
        let reader = spawn_upstream_reader(session.clone(), 0, up_read);
        let mut i = session.inner.lock().await;
        let old = std::mem::replace(&mut i.active.reader, reader);
        old.abort();
    }

    // 7. Tell the miner its channel is open (downstream channel id + upstream's
    //    extranonce/target). The upstream's jobs + prev-hash then stream through.
    to_miner
        .send(open_success_downstream(&spec, down_channel_id, &info)?)
        .map_err(|_| anyhow!("miner writer gone"))?;

    ctx.registry
        .insert(worker.clone(), AnySession::Sv2(session.clone()))
        .await;
    info!(%peer, %worker, upstream = %default_target.url, "sv2 relay established (idle)");

    // 8. Resume an active rental, else apply the seller's configured default.
    if let Some(order) = ctx.orders.active_for_worker(&worker, crate::orders::now_ms()).await {
        match session.switch_to(order.id.clone(), order.target.clone()).await {
            Ok(()) => info!(%worker, order = %order.id, "resumed active rental"),
            Err(e) => warn!(%worker, error = %e, "resume rental failed"),
        }
    } else if let Some(def) = ctx.sellers.default_pool(&worker).await {
        if session.default_target().await != def {
            match session.set_default(def.clone()).await {
                Ok(()) => info!(%worker, upstream = %def.url, "applied seller default pool"),
                Err(e) => warn!(%worker, error = %e, "apply seller default failed"),
            }
        }
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
                // rewritten); the upstream reader finalizes it on success.
                if let Some(open) = parse_miner_open(&mut frame) {
                    let mut i = session.inner.lock().await;
                    let account = i.active.target.user.clone();
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
                    let down_cid = wire::read_channel_id(&mut frame);
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
                    session.orders.add_submitted(&order_id, 1).await;
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
        let (mut read, mut write) = stream.into_split();

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
                        .write_frame(open_success_downstream(&open.spec, cid, &info)?)
                        .await
                        .map_err(|e| anyhow!("{e:?}"))?;
                }
                Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) => {
                    let cid = wire::read_channel_id(&mut f);
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
                    let cid = wire::read_channel_id(&mut f);
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
                    return Ok(wire::read_channel_id(&mut f));
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
            default_target: ext_target(&a_addr.to_string(), "acctA"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
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
            if let Some(s) = registry.get("bc1qSELLER.rig1").await {
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
            default_target: ext_target(&a_addr.to_string(), "acctA"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
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
            if let Some(s) = registry.get("bc1qSELLER.rig1").await {
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
            default_target: ext_target(&addr.to_string(), "acct"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
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
                    .write_frame(open_success_downstream(&open.spec, 7, &info)?)
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
            default_target: ext_target(&a_addr.to_string(), "acctA"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool.clone()),
        };
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
            if let Some(s) = registry.get("bc1qSELLER.rig1").await {
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
            default_target: ext_target(&a_addr.to_string(), "acctA"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(pool.clone()),
            orders: orders.clone(),
        };
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
                0,
                0.0,
                0.0,
            )
            .await;
        let sess = loop {
            if let Some(s) = registry.get("bc1qSELLER.rig1").await {
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

        // Work is credited just after the success is forwarded; poll the order
        // (bounded, so a regression fails the test instead of hanging).
        let mut credited = orders.get(&order.id).await.unwrap();
        for _ in 0..100_000 {
            if credited.accepted_shares >= k {
                break;
            }
            tokio::task::yield_now().await;
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
}
