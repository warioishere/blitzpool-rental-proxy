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
//! and re-points the miner with `SetExtranoncePrefix` + `SetTarget` — the
//! downstream `channel_id` is unchanged, so the miner never reconnects. The new
//! upstream's jobs + prev-hash then stream through.
//!
//! Scope: one mining channel per connection (the common single-rig case); a
//! second `OpenMiningChannel` on the same connection is logged and ignored.

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
    OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess, OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess, SetExtranoncePrefix, SetTarget,
};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};

use super::keys::NoiseKeys;
use super::wire::{self, EitherFrame, Msg, Sv2Frame};
use crate::proto::adapter::{DownstreamAdapter, ProxyContext};
use crate::control::{AnySession, SessionStatus};
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
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.inner_as_ref().to_vec(),
            target: m.target.inner_as_ref().to_vec(),
            extranonce_size: m.extranonce_size,
            group_channel_id: m.group_channel_id,
        }),
        Mining::OpenStandardMiningChannelSuccess(m) => Some(ChannelInfo {
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

fn parse_shares_sum(frame: &mut Sv2Frame) -> Option<u64> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => Some(s.new_shares_sum),
        _ => None,
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
    let stream = connect_with_noise::<Msg>(tcp, None)
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

/// Full connect + setup + open (used by a rental switch, where the spec is
/// already known).
async fn connect_open(
    target: &UpstreamTarget,
    spec: &OpenSpec,
) -> anyhow::Result<(Read, Write, ChannelInfo)> {
    let (mut read, mut write, _flags) = connect_setup(target).await?;
    let info = open_on(&mut read, &mut write, spec, &target.user).await?;
    Ok((read, write, info))
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
    up_channel_id: u32,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

struct Inner {
    active: ActiveUpstream,
    generation_counter: u64,
    down_channel_id: u32,
    spec: OpenSpec,
    routing: Routing,
    default_target: UpstreamTarget,
    hashrate: HashrateWindow,
    label: String,
}

/// A live SV2 seller-miner session.
pub struct Sv2Session {
    to_miner: mpsc::UnboundedSender<EitherFrame>,
    inner: Mutex<Inner>,
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
        let (spec, generation) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            (i.spec.clone(), i.generation_counter)
        };

        // Open the new channel before tearing the old one down, so a failed
        // switch leaves the miner mining on the current upstream.
        let (read, write, info) = connect_open(&target, &spec)
            .await
            .map_err(|e| anyhow!("switch to {}: {e}", target.url))?;

        let (to_up, up_rx) = mpsc::unbounded_channel();
        let writer = spawn_writer(write, up_rx);
        let reader = spawn_upstream_reader(self.clone(), generation, read);

        let down_channel_id = {
            let mut i = self.inner.lock().await;
            i.active.reader.abort();
            i.active.writer.abort();
            i.active = ActiveUpstream {
                generation,
                target: target.clone(),
                to_up,
                up_channel_id: info.up_channel_id,
                reader,
                writer,
            };
            i.routing = routing;
            i.down_channel_id
        };

        // Re-point the miner: new extranonce prefix + target. The new upstream
        // then streams NewMiningJob/NewExtendedMiningJob + SetNewPrevHash, which
        // the reader forwards. The downstream channel_id is unchanged, so the
        // miner does not reconnect.
        let _ = self
            .to_miner
            .send(set_extranonce_prefix(down_channel_id, info.extranonce_prefix)?);
        let _ = self.to_miner.send(set_target(down_channel_id, info.target)?);
        info!(upstream = %target.url, generation, "sv2 upstream switched");
        Ok(())
    }

    /// Forward an upstream frame to the miner (channel-id remapped), crediting
    /// the hashrate window on accepted shares.
    async fn on_upstream_frame(&self, generation: u64, mut frame: Sv2Frame) {
        let Some(mt) = wire::msg_type(&frame) else {
            return;
        };
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return; // stale upstream (already swapped away)
        }
        if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS {
            if let Some(sum) = parse_shares_sum(&mut frame) {
                i.hashrate.record(sum as f64);
                debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted shares");
            }
        }
        if wire::is_channel_scoped(mt) {
            wire::rewrite_channel_id(&mut frame, i.down_channel_id);
            let _ = self.to_miner.send(frame.into());
        } else {
            debug!(mt, "dropping non-channel-scoped upstream message");
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
    // Stable downstream channel id = the first upstream channel id.
    let down_channel_id = info.up_channel_id;

    // 6. Build the session and wire up the initial upstream.
    let (to_up, up_rx) = mpsc::unbounded_channel::<EitherFrame>();
    let up_writer = spawn_writer(up_write, up_rx);
    let session = Arc::new(Sv2Session {
        to_miner: to_miner.clone(),
        inner: Mutex::new(Inner {
            active: ActiveUpstream {
                generation: 0,
                target: default_target.clone(),
                to_up,
                up_channel_id: info.up_channel_id,
                reader: tokio::spawn(async {}), // placeholder, replaced below
                writer: up_writer,
            },
            generation_counter: 0,
            down_channel_id,
            spec: spec.clone(),
            routing: Routing::Idle,
            default_target: default_target.clone(),
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
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
    } else if let Some(def) = ctx.sellers.get(&worker).await {
        if session.default_target().await != def {
            match session.set_default(def.clone()).await {
                Ok(()) => info!(%worker, upstream = %def.url, "applied seller default pool"),
                Err(e) => warn!(%worker, error = %e, "apply seller default failed"),
            }
        }
    }

    // 9. Downstream loop: forward shares/updates upstream (channel-id remapped).
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
            if wire::is_channel_scoped(mt) {
                let i = session.inner.lock().await;
                let up_cid = i.active.up_channel_id;
                wire::rewrite_channel_id(&mut frame, up_cid);
                let _ = i.active.to_up.send(frame.into());
            } else if mt == mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL
                || mt == mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL
            {
                warn!(%worker, "miner opened a second channel; only one per connection is supported (ignored)");
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
    use stratum_core::mining_sv2::{SubmitSharesExtended, SubmitSharesSuccess};
    use tokio::net::TcpListener;

    fn ext_target(url: &str, user: &str) -> UpstreamTarget {
        UpstreamTarget {
            url: url.to_string(),
            user: user.to_string(),
            password: String::new(),
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("srp_sv2_{}_{}.json", std::process::id(), tag))
    }

    /// A mock SV2 pool: one connection, Extended channel `pool_cid`, tagging its
    /// `extranonce_prefix`. Reports the `channel_id` of each received submit on
    /// `submits` and replies `SubmitSharesSuccess` (with its own `pool_cid`, so
    /// the proxy's downstream rewrite is exercised).
    async fn mock_pool(
        listener: TcpListener,
        prefix: Vec<u8>,
        pool_cid: u32,
        submits: mpsc::UnboundedSender<u32>,
    ) -> anyhow::Result<()> {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let keys = NoiseKeys::generate();
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

        // OpenExtendedMiningChannel → success (echo request_id, our prefix/cid).
        let spec = loop {
            let mut f = read_one(&mut read).await?;
            if let Some(open) = parse_miner_open(&mut f) {
                break open.spec;
            }
        };
        let info = ChannelInfo {
            up_channel_id: pool_cid,
            extranonce_prefix: prefix,
            target: vec![0xffu8; 32],
            extranonce_size: 8,
            group_channel_id: 0,
        };
        write
            .write_frame(open_success_downstream(&spec, pool_cid, &info)?)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;

        // Serve submits: report the channel_id, reply success.
        while let Ok(mut f) = read_one(&mut read).await {
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) {
                let cid = wire::read_channel_id(&mut f);
                let _ = submits.send(cid);
                let ok = SubmitSharesSuccess {
                    channel_id: pool_cid,
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
        }
        Ok(())
    }

    struct MockMiner {
        read: Read,
        write: Write,
        channel_id: u32,
    }

    impl MockMiner {
        async fn connect(addr: std::net::SocketAddr) -> anyhow::Result<Self> {
            let tcp = TcpStream::connect(addr).await?;
            let _ = tcp.set_nodelay(true);
            let stream = connect_with_noise::<Msg>(tcp, None)
                .await
                .map_err(|e| anyhow!("miner noise: {e:?}"))?;
            let (read, write) = stream.into_split();
            Ok(Self {
                read,
                write,
                channel_id: 0,
            })
        }

        /// SetupConnection + OpenExtendedMiningChannel; returns the extranonce
        /// prefix from the success (identifies which pool we landed on).
        async fn open(&mut self, worker: &str) -> anyhow::Result<Vec<u8>> {
            self.write.write_frame(setup_connection()).await.map_err(|e| anyhow!("{e:?}"))?;
            loop {
                let f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) {
                    break;
                }
            }
            let spec = OpenSpec::Extended {
                request_id: 1,
                nominal_hash_rate: 1.0e12,
                max_target: vec![0xffu8; 32],
                min_extranonce_size: 8,
            };
            self.write
                .write_frame(open_channel_upstream(&spec, worker)?)
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f)
                    == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
                {
                    let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                    self.channel_id = info.up_channel_id;
                    return Ok(info.extranonce_prefix);
                }
            }
        }

        async fn submit(&mut self, seq: u32) -> anyhow::Result<()> {
            let m = SubmitSharesExtended {
                channel_id: self.channel_id,
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

        /// Read until SetExtranoncePrefix; returns the new prefix.
        async fn read_until_set_extranonce(&mut self) -> anyhow::Result<Vec<u8>> {
            loop {
                let mut f = read_one(&mut self.read).await?;
                if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX) {
                    let mt = wire::msg_type(&f).unwrap();
                    let payload = f.payload();
                    if let Ok(Mining::SetExtranoncePrefix(m)) = Mining::try_from((mt, payload)) {
                        return Ok(m.extranonce_prefix.inner_as_ref().to_vec());
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
        tokio::spawn(mock_pool(pool_a, vec![0xAA; 8], 7, a_tx));
        tokio::spawn(mock_pool(pool_b, vec![0xBB; 8], 99, b_tx));

        // Proxy: default upstream = pool A.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let registry = crate::registry::Registry::new();
        let ctx = ProxyContext {
            default_target: ext_target(&a_addr.to_string(), "acctA"),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::load(tmp("sellers")).await,
            orders: crate::orders::OrderStore::load(tmp("orders")).await,
        };
        let keys = NoiseKeys::generate();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
        });

        // Miner connects + opens → lands on pool A.
        let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
        let prefix1 = miner.open("bc1qSELLER.rig1").await.unwrap();
        assert_eq!(prefix1, vec![0xAA; 8], "idle → seller default pool A");
        let down_cid = miner.channel_id;

        // Submit → reaches pool A; success comes back on the stable downstream cid.
        miner.submit(0).await.unwrap();
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
        let prefix2 = miner.read_until_set_extranonce().await.unwrap();
        assert_eq!(prefix2, vec![0xBB; 8], "rented → buyer pool B");

        // Submit again → now reaches pool B; the proxy rewrote down cid → pool B's 99.
        miner.submit(1).await.unwrap();
        assert_eq!(b_rx.recv().await.unwrap(), 99, "submit reached pool B (cid remapped)");
        let ok_cid2 = miner
            .read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS)
            .await
            .unwrap();
        assert_eq!(ok_cid2, down_cid, "success still on stable downstream channel id");
    }
}
