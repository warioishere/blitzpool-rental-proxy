//! Per-connection SV1 relay with a **swappable upstream** (the M2 core).
//!
//! Full-proxy model: the proxy drives the upstream handshake itself
//! (`configure`→`subscribe`→`authorize`) and synthesizes the miner-facing
//! handshake (`mining.configure` reply + `mining.subscribe` reply carrying the
//! upstream's extranonce). Because the proxy owns the miner-facing handshake,
//! it can switch the upstream at runtime and just push a `mining.set_extranonce`
//! to the miner — the downstream connection never drops.
//!
//! - **idle**: relay to the seller's default upstream.
//! - **rented**: [`Session::switch_to`] connects the buyer's target, swaps the
//!   active upstream, and pushes `set_extranonce`; [`Session::revert`] goes
//!   back to the default.
//!
//! Submits are rewritten to the active upstream's account; accepted submits
//! feed the per-miner hashrate window. A generation counter tags each upstream
//! so a stale reader (post-swap) is ignored.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::adapter::{DownstreamAdapter, ProxyContext};
use super::sv1::RpcMessage;
use crate::control::{AnySession, SessionStatus};
use crate::session::{HashrateWindow, Routing, UpstreamTarget};

// Translation path (combo 3: SV1 miner ↔ SV2 buyer pool). Only compiled with the
// SV2 stack; without it the relay is SV1 passthrough only.
#[cfg(feature = "sv2")]
use std::collections::VecDeque;
#[cfg(feature = "sv2")]
use stratum_core::bitcoin::hashes::hex::DisplayHex;
#[cfg(feature = "sv2")]
use stratum_core::mining_sv2 as mining;
#[cfg(feature = "sv2")]
use stratum_core::parsers_sv2::{AnyMessage, Mining};
#[cfg(feature = "sv2")]
use stratum_core::sv1_api::{json_rpc as sv1_json, methods::client_to_server, utils::HexU32Be};
#[cfg(feature = "sv2")]
use crate::proto::sv2::wire;
#[cfg(feature = "sv2")]
use crate::proto::translate;

/// Standard BIP320 version-rolling mask we advertise to the miner.
const VERSION_ROLLING_MASK: &str = "1fffe000";

type Tx = mpsc::UnboundedSender<String>;

/// How long a reconnect-hint stays valid (the miner should reconnect at once).
const RECONNECT_HINT_TTL: Duration = Duration::from_secs(120);

/// After authorize, how long to wait for the miner's `mining.extranonce.subscribe`
/// before deciding live-switch vs reconnect. Miners (e.g. BitAxe) send it only
/// after they receive the authorize result, so the proxy must give it a moment.
/// The wait ends as soon as the subscribe arrives — this is only the ceiling for
/// miners that never send it (they then take the reconnect path). The miner can
/// only send it after the authorize result has made the round trip, so this must
/// exceed the link RTT: ~48ms was observed over the public IP/pfSense, so 250ms
/// gives ample margin (50ms is enough only for LAN-local miners).
const EXTRANONCE_GRACE: Duration = Duration::from_millis(250);

/// Per-source-IP reconnect hints. When a miner that can't take a live
/// extranonce change authorizes onto a pool different from its handshake pool,
/// we remember that pool here, send `client.reconnect`, and on the reconnect run
/// the handshake directly against it — so the miner gets the right extranonce
/// from its first job and no mid-session switch is needed. Keyed by source IP;
/// fine for the common one-miner-per-IP case (a NAT farm whose rigs sit on
/// different pools just costs an extra reconnect to converge).
fn reconnect_hints() -> &'static Mutex<HashMap<String, (UpstreamTarget, Instant)>> {
    static HINTS: OnceLock<Mutex<HashMap<String, (UpstreamTarget, Instant)>>> = OnceLock::new();
    HINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Source IP (no port) of a `host:port` peer string — the reconnect-hint key.
fn peer_ip(peer: &str) -> String {
    peer.rsplit_once(':').map(|(ip, _)| ip.to_string()).unwrap_or_else(|| peer.to_string())
}

/// Worker name to send upstream: the upstream account (pool user / buyer) plus
/// the miner's own worker name, tagged `-bp-proxy` so the pool clearly shows the
/// hashrate is coming through the rental proxy. The account part (before the
/// first `.`) stays a valid payout address; the tag rides on the worker suffix.
pub(crate) fn upstream_worker(account: &str, miner_label: &str) -> String {
    match miner_label.split_once('.').map(|(_, s)| s).filter(|s| !s.is_empty()) {
        Some(suffix) => format!("{account}.{suffix}-bp-proxy"),
        None => format!("{account}.bp-proxy"),
    }
}

/// The live upstream for a session (replaced wholesale on a switch).
struct ActiveUpstream {
    generation: u64,
    target: UpstreamTarget,
    to_up: Tx,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

struct Inner {
    active: ActiveUpstream,
    generation_counter: u64,
    current_difficulty: f64,
    /// submit id (serialized) → (generation, difficulty) for hashrate credit.
    pending: HashMap<String, (u64, f64)>,
    hashrate: HashrateWindow,
    /// Lifetime delivered work (diff-1 share units) + accepted shares.
    delivered_work: f64,
    accepted_shares: u64,
    /// Shares the miner submitted (for the accept-ratio health/fraud signal).
    submitted_shares: u64,
    /// Edge-trigger so the low-accept-ratio warning is logged once.
    accept_low_logged: bool,
    routing: Routing,
    default_target: UpstreamTarget,
    /// Miner's `mining.configure` (remembered to replay to each upstream).
    configure: Option<RpcMessage>,
    extranonce_capable: bool,
    label: String,
    /// Upstream handshake notifications (set_difficulty/notify) captured before
    /// the miner subscribed; flushed to the miner right after the subscribe reply.
    pending_prelude: Vec<String>,
    /// Extranonce the active upstream gave us, surfaced to the miner in the
    /// `mining.subscribe` reply and re-pushed via `set_extranonce` on a switch.
    extranonce1: String,
    extranonce2_size: u32,
    /// True when the active upstream is an SV2 pool reached via translation (the
    /// buyer pool speaks SV2 behind this SV1 miner). Then jobs/shares are
    /// converted and per-submit accounting is driven by the translator, not the
    /// id-matched `pending` map.
    translating: bool,
    /// Set once the miner has sent `mining.subscribe` — until then, translated
    /// jobs are stashed as prelude so a job never precedes the subscribe reply.
    subscribed: bool,
}

/// A live seller-miner session. Held by the relay tasks and the registry.
pub struct Session {
    to_miner: Tx,
    inner: Mutex<Inner>,
    /// Serializes upstream swaps so two concurrent switches (e.g. an API rent and
    /// the expiry revert) can't interleave their connect/install and leave
    /// `active` pointing at one upstream while `routing` describes another. Always
    /// taken before `inner`, never the reverse, so it can't deadlock.
    switch: Mutex<()>,
    /// An upstream reader sends its generation here when its read loop ends on a
    /// dropped pool; the supervisor task reconnects / fails over to the fallback.
    died_tx: mpsc::UnboundedSender<u64>,
    /// For crediting measured delivered work to the active rental order.
    orders: Arc<crate::orders::OrderStore>,
}

impl Session {
    /// Switch this session's hashrate to `target` (a rental starts).
    pub async fn switch_to(self: &Arc<Self>, order_id: String, target: UpstreamTarget) -> anyhow::Result<()> {
        self.swap_upstream(target, Routing::Rented { order_id }).await
    }

    /// Switch onto a rental order's pool with failover: try the order's primary
    /// target, then its fallback if the primary is unreachable. Errors only if
    /// both fail (same protocol as the rig — the proxy doesn't translate).
    pub async fn switch_to_order(self: &Arc<Self>, order_id: String) -> anyhow::Result<()> {
        let order = self
            .orders
            .get(&order_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("order {order_id} not found"))?;
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

    /// Switch back to the seller's default upstream (a rental ends).
    pub async fn revert(self: &Arc<Self>) -> anyhow::Result<()> {
        let default = self.inner.lock().await.default_target.clone();
        self.swap_upstream(default, Routing::Idle).await
    }

    /// Set the seller's configured default upstream and use it now (the miner
    /// is idle). Applied when a miner authorizes and the seller store has a
    /// per-worker default that differs from the process-wide default.
    pub async fn set_default(self: &Arc<Self>, target: UpstreamTarget) -> anyhow::Result<()> {
        {
            self.inner.lock().await.default_target = target.clone();
        }
        self.swap_upstream(target, Routing::Idle).await
    }

    /// Current upstream this session relays to (idle pool or rented target).
    pub async fn active_target(&self) -> UpstreamTarget {
        self.inner.lock().await.active.target.clone()
    }

    /// Mark this session as serving `order` WITHOUT reconnecting the upstream —
    /// used when the handshake already connected the rental's target (a resolved
    /// reconnect), so the miner keeps the extranonce it was given.
    pub async fn attach_order(&self, order_id: String) {
        self.inner.lock().await.routing = Routing::Rented { order_id };
    }

    async fn swap_upstream(self: &Arc<Self>, target: UpstreamTarget, routing: Routing) -> anyhow::Result<()> {
        // Hold the switch lock for the whole swap so concurrent switches run
        // strictly one after another (the last to acquire wins). Released on return.
        let _switch = self.switch.lock().await;
        // Snapshot what the handshake needs without holding the lock across IO.
        let (configure, capable, generation, label) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            (i.configure.clone(), i.extranonce_capable, i.generation_counter, i.label.clone())
        };
        let user_identity = upstream_worker(&target.user, &label);

        // Connect + handshake the new upstream BEFORE tearing down the old, so a
        // failed switch leaves the miner mining on the current upstream. Detection
        // picks passthrough (SV1) vs translation (SV2 buyer pool) automatically.
        let raw = connect_raw(&target, configure.as_ref(), &user_identity)
            .await
            .map_err(|e| anyhow::anyhow!("switch: connect {}: {e}", target.url))?;

        // Swap atomically (the reader is spawned inside the lock so the new
        // generation is visible before it can forward — no first-job drop).
        let (en1, en2) = self.install_raw(raw, generation, target.clone(), routing).await;

        // Re-point the miner: new extranonce + the new upstream's initial
        // set_difficulty/notify (else it keeps the old target → every share
        // rejected as "Difficulty too low"). Modern ASICs honor set_extranonce
        // live; non-capable miners take the reconnect path at authorize instead.
        if capable {
            let _ = self.to_miner.send(RpcMessage::set_extranonce(&en1, en2).to_line());
        } else {
            warn!(upstream = %target.url, "miner not extranonce-capable; live switch may need a reconnect");
        }
        let prelude = std::mem::take(&mut self.inner.lock().await.pending_prelude);
        for line in prelude {
            let _ = self.to_miner.send(line);
        }
        info!(upstream = %target.url, generation, capable, "upstream switched");
        Ok(())
    }

    /// Process a line from the upstream tagged `generation`; returns the line
    /// to forward to the miner (or `None` to drop a stale-upstream line).
    async fn on_upstream_msg(&self, generation: u64, msg: RpcMessage) -> Option<String> {
        let mut order_credit: Option<(String, f64)> = None;
        {
            let mut i = self.inner.lock().await;
            if generation != i.active.generation {
                return None; // stale upstream (already swapped away)
            }
            match msg.method.as_deref() {
                Some("mining.set_difficulty") => {
                    if let Some(d) = msg
                        .params
                        .as_ref()
                        .and_then(|p| p.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_f64())
                    {
                        i.current_difficulty = d;
                    }
                }
                None => {
                    // A response — credit accepted submits (diff-weighted).
                    let idk = id_key(&msg.id);
                    if let Some((g, diff)) = i.pending.remove(&idk) {
                        if g == generation && matches!(&msg.result, Some(Value::Bool(true))) {
                            i.hashrate.record(diff);
                            i.delivered_work += diff;
                            i.accepted_shares += 1;
                            if let Routing::Rented { order_id, .. } = &i.routing {
                                order_credit = Some((order_id.clone(), diff));
                            }
                            debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted share");
                        }
                    }
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
                _ => {}
            }
        }
        if let Some((order_id, diff)) = order_credit {
            self.orders.add_work(&order_id, diff, 1);
        }
        Some(msg.to_line())
    }

    /// Process a line from the miner; sends the (possibly rewritten) line to the
    /// active upstream. Authorize is owned by the main handshake loop (which
    /// registers the session and answers it locally) and is never handled here.
    async fn on_miner_msg(self: &Arc<Self>, mut msg: RpcMessage) {
        let mut submit_order: Option<String> = None;
        {
            let mut i = self.inner.lock().await;
            match msg.method.as_deref() {
                Some("mining.authorize") => {
                    // The proxy authorizes upstream itself (with the pool/buyer
                    // account) during the handshake/switch, and the main loop owns
                    // registration — the miner's authorize is never forwarded. Drop
                    // a stray one (e.g. a retransmit during the extranonce grace).
                    return;
                }
                Some("mining.submit") => {
                    let diff = i.current_difficulty;
                    let g = i.active.generation;
                    // Passthrough credits on the id-matched upstream response; the
                    // SV2 translator credits on SubmitSharesSuccess instead, so it
                    // must not also leak entries into `pending`.
                    if !i.translating {
                        i.pending.insert(id_key(&msg.id), (g, diff));
                    }
                    i.submitted_shares += 1;
                    if let Routing::Rented { order_id, .. } = &i.routing {
                        submit_order = Some(order_id.clone());
                    }
                    let up_worker = upstream_worker(&i.active.target.user, &i.label);
                    if let Some(arr) = msg.params.as_mut().and_then(|p| p.as_array_mut()) {
                        if let Some(first) = arr.first_mut() {
                            *first = json!(up_worker);
                        }
                    }
                }
                Some("mining.extranonce.subscribe") => {
                    i.extranonce_capable = true;
                }
                Some("mining.configure") => {
                    i.configure = Some(msg.clone());
                }
                _ => {}
            }
            let _ = i.active.to_up.send(msg.to_line());
        }
        if let Some(order_id) = submit_order {
            self.orders.add_submitted(&order_id, 1);
        }
    }

    pub async fn worker_label(&self) -> String {
        self.inner.lock().await.label.clone()
    }

    /// Snapshot for the control API.
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
            protocol: "sv1",
        }
    }
}

fn id_key(id: &Option<Value>) -> String {
    id.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "null".into())
}

// ── upstream establishment (passthrough SV1 or translated SV2) ───────

/// Default nominal hashrate (H/s) advertised when opening an Extended channel on
/// an SV2 buyer pool behind an SV1 miner; the pool's vardiff adjusts from here.
#[cfg(feature = "sv2")]
const SV2_UP_NOMINAL_HASHRATE: f32 = 1.0e12;
/// Extranonce-2 size requested from the SV2 pool — also the SV1 `extranonce2_size`.
#[cfg(feature = "sv2")]
const SV2_UP_MIN_EXTRANONCE: u16 = 4;

/// A freshly connected upstream, not yet spawned into reader/writer tasks. The
/// caller installs it under the session lock so the new generation is visible
/// before the reader runs (so the first job is never dropped as stale).
enum RawUpstream {
    /// Same protocol as the miner: SV1 lines are forwarded verbatim.
    Sv1(UpstreamConn),
    /// An SV2 buyer pool behind an SV1 miner: an open Extended channel whose jobs
    /// and shares are translated (see [`crate::proto::translate`]). Boxed — the
    /// Noise halves are far larger than the SV1 variant.
    #[cfg(feature = "sv2")]
    Sv2(Box<Sv2RawUpstream>),
}

/// An opened SV2 Extended channel ready to translate for an SV1 miner.
#[cfg(feature = "sv2")]
struct Sv2RawUpstream {
    read: crate::proto::sv2::relay::Read,
    write: crate::proto::sv2::relay::Write,
    channel_id: u32,
    extranonce1: String,
    extranonce2_size: u32,
    initial_diff: f64,
}

/// Connect to `target`, auto-detecting SV1 (passthrough) vs SV2 (translate).
/// `user_identity` is the worker the upstream is authorized + submitted under
/// (SV1 authorize, or the SV2 Extended channel's account) — they must match so
/// strict pools (e.g. ckpool) don't reject submits as "Worker mismatch".
async fn connect_raw(
    target: &UpstreamTarget,
    configure: Option<&RpcMessage>,
    user_identity: &str,
) -> anyhow::Result<RawUpstream> {
    #[cfg(not(feature = "sv2"))]
    {
        return Ok(RawUpstream::Sv1(connect_upstream(target, configure, user_identity).await?));
    }
    // Native first: try SV1 (reusing its socket on success); if the pool doesn't
    // answer as SV1, it's an SV2 buyer pool → open an Extended channel + translate.
    #[cfg(feature = "sv2")]
    match tokio::time::timeout(translate::UPSTREAM_PROBE_TIMEOUT, connect_upstream(target, configure, user_identity))
        .await
    {
        Ok(Ok(conn)) => Ok(RawUpstream::Sv1(conn)),
        res => {
            if let Ok(Err(e)) = &res {
                debug!(url = %target.url, error = %e, "upstream not SV1; trying SV2 translation");
            } else if res.is_err() {
                debug!(url = %target.url, "SV1 connect timed out; trying SV2 translation");
            }
            connect_sv2_translate(target, user_identity).await
        }
    }
}

/// Open an Extended channel on an SV2 pool to serve an SV1 miner through it.
#[cfg(feature = "sv2")]
async fn connect_sv2_translate(
    target: &UpstreamTarget,
    user_identity: &str,
) -> anyhow::Result<RawUpstream> {
    use crate::proto::sv2::relay::{connect_setup, open_on, OpenSpec};
    let (mut read, mut write, _flags) = connect_setup(target).await?;
    let spec = OpenSpec::Extended {
        request_id: 1,
        nominal_hash_rate: SV2_UP_NOMINAL_HASHRATE,
        // Most permissive max_target — let the pool's vardiff pick the working one.
        max_target: vec![0xff; 32],
        min_extranonce_size: SV2_UP_MIN_EXTRANONCE,
    };
    let info = open_on(&mut read, &mut write, &spec, user_identity).await?;
    let extranonce1 = info.extranonce_prefix.to_lower_hex_string();
    let initial_diff = translate::difficulty_from_target(&info.target);
    Ok(RawUpstream::Sv2(Box::new(Sv2RawUpstream {
        read,
        write,
        channel_id: info.up_channel_id,
        extranonce1,
        extranonce2_size: info.extranonce_size as u32,
        initial_diff,
    })))
}

impl Session {
    /// Install `raw` as the active upstream under the session lock, aborting the
    /// previous one. The reader/writer are spawned here (inside the lock) so the
    /// new generation is in place before the reader can forward — no first-job
    /// drop. Returns the extranonce to surface to the miner.
    async fn install_raw(
        self: &Arc<Self>,
        raw: RawUpstream,
        generation: u64,
        target: UpstreamTarget,
        routing: Routing,
    ) -> (String, u32) {
        let mut i = self.inner.lock().await;
        i.active.reader.abort();
        i.active.writer.abort();
        let (to_up, reader, writer, en1, en2, prelude, translating, translate_diff) = match raw {
            RawUpstream::Sv1(conn) => {
                let (to_up, rx) = mpsc::unbounded_channel::<String>();
                let writer = spawn_writer(conn.write, rx);
                let reader = spawn_upstream_reader(self.clone(), generation, conn.reader);
                (to_up, reader, writer, conn.extranonce1, conn.extranonce2_size, conn.prelude, false, None)
            }
            #[cfg(feature = "sv2")]
            RawUpstream::Sv2(b) => {
                let Sv2RawUpstream {
                    read,
                    write,
                    channel_id,
                    extranonce1,
                    extranonce2_size,
                    initial_diff,
                } = *b;
                let state = Arc::new(Mutex::new(Sv2UpState {
                    channel_id,
                    ..Default::default()
                }));
                let (to_up, rx) = mpsc::unbounded_channel::<String>();
                let writer = spawn_sv2_translate_writer(write, state.clone(), rx);
                let reader = spawn_sv2_translate_reader(self.clone(), generation, read, state);
                (
                    to_up,
                    reader,
                    writer,
                    extranonce1,
                    extranonce2_size,
                    vec![translate::set_difficulty_to_line(initial_diff)],
                    true,
                    Some(initial_diff),
                )
            }
        };
        i.active = ActiveUpstream {
            generation,
            target,
            to_up,
            reader,
            writer,
        };
        i.routing = routing;
        i.extranonce1 = en1.clone();
        i.extranonce2_size = en2;
        i.translating = translating;
        if let Some(d) = translate_diff {
            i.current_difficulty = d;
        }
        // In-flight submits were sent to the old upstream; their responses won't
        // arrive with the new generation, so drop the orphaned credit entries.
        i.pending.clear();
        i.pending_prelude = prelude;
        (en1, en2)
    }
}

// ── SV2 upstream translator (combo 3): SV1 miner ↔ SV2 buyer pool ────

/// Shared state between the two translate driver tasks: job versions (to rebuild
/// the SV2 submit version), the sequence counter, and the submit id mapping
/// (SV2 `sequence_number` → the miner's SV1 submit id, for the result reply).
#[cfg(feature = "sv2")]
#[derive(Default)]
struct Sv2UpState {
    channel_id: u32,
    next_seq: u32,
    latest_version: u32,
    job_versions: std::collections::HashMap<u32, u32>,
    pending_submits: VecDeque<(u32, Option<Value>)>,
}

/// Translate the miner's SV1 `mining.submit` lines into `SubmitSharesExtended`
/// frames for the SV2 pool.
#[cfg(feature = "sv2")]
fn spawn_sv2_translate_writer(
    mut write: crate::proto::sv2::relay::Write,
    state: Arc<Mutex<Sv2UpState>>,
    mut rx: mpsc::UnboundedReceiver<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let Ok(msg) = RpcMessage::parse(&line) else {
                continue;
            };
            if msg.method.as_deref() != Some("mining.submit") {
                continue; // only shares cross to the SV2 pool
            }
            let req = sv1_json::StandardRequest {
                id: msg.id.as_ref().and_then(|v| v.as_u64()).unwrap_or(0),
                method: "mining.submit".to_string(),
                params: msg.params.clone().unwrap_or(Value::Null),
            };
            let Ok(submit) = client_to_server::Submit::try_from(req) else {
                continue;
            };
            let (channel_id, seq, job_version) = {
                let mut s = state.lock().await;
                let seq = s.next_seq;
                s.next_seq = s.next_seq.wrapping_add(1);
                let job_version = submit
                    .job_id
                    .parse::<u32>()
                    .ok()
                    .and_then(|j| s.job_versions.get(&j).copied())
                    .unwrap_or(s.latest_version);
                s.pending_submits.push_back((seq, msg.id.clone()));
                (s.channel_id, seq, job_version)
            };
            let mask = submit
                .version_bits
                .as_ref()
                .map(|_| HexU32Be(translate::VERSION_ROLLING_MASK));
            let sv2_submit = match stratum_core::stratum_translation::sv1_to_sv2::build_sv2_submit_shares_extended_from_sv1_submit(
                &submit, channel_id, seq, job_version, mask,
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = ?e, "sv1→sv2 submit translation failed");
                    continue;
                }
            };
            let frame = wire::frame_from(AnyMessage::Mining(Mining::SubmitSharesExtended(sv2_submit)));
            if write.write_frame(frame).await.is_err() {
                break;
            }
        }
    })
}

/// Translate the SV2 pool's jobs / target / share results back into SV1 lines for
/// the miner, and credit accepted shares. Future jobs are buffered until their
/// `SetNewPrevHash` arrives (per SV2 §7), then emitted as a `mining.notify`.
#[cfg(feature = "sv2")]
fn spawn_sv2_translate_reader(
    session: Arc<Session>,
    generation: u64,
    mut read: crate::proto::sv2::relay::Read,
    state: Arc<Mutex<Sv2UpState>>,
) -> JoinHandle<()> {
    use crate::proto::sv2::relay::{
        parse_new_extended_job, parse_set_new_prev_hash, parse_set_target, parse_submit_error_seq,
        parse_submit_success,
    };
    tokio::spawn(async move {
        let mut prev: Option<mining::SetNewPrevHash<'static>> = None;
        let mut job: Option<mining::NewExtendedMiningJob<'static>> = None;
        while let Ok(frame) = read.read_frame().await {
            let Some(mut f) = wire::into_sv2(frame) else {
                continue;
            };
            let Some(mt) = wire::msg_type(&f) else {
                continue;
            };
            if mt == mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB {
                if let Some(j) = parse_new_extended_job(&mut f) {
                    {
                        let mut s = state.lock().await;
                        if s.job_versions.len() >= 64 {
                            s.job_versions.clear();
                        }
                        s.job_versions.insert(j.job_id, j.version);
                        s.latest_version = j.version;
                    }
                    if j.min_ntime.clone().into_inner().is_none() {
                        // Future job — wait for SetNewPrevHash to activate it.
                        job = Some(j);
                    } else {
                        if let Some(p) = prev.clone() {
                            emit_translate_notify(&session, generation, p, j.clone(), false).await;
                        }
                        job = Some(j);
                    }
                }
            } else if mt == mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH {
                if let Some(p) = parse_set_new_prev_hash(&mut f) {
                    prev = Some(p.clone());
                    if let Some(j) = job.clone() {
                        emit_translate_notify(&session, generation, p, j, true).await;
                    }
                }
            } else if mt == mining::MESSAGE_TYPE_SET_TARGET {
                if let Some(t) = parse_set_target(&mut f) {
                    let diff = translate::difficulty_from_target(&t);
                    if session.set_translate_difficulty(generation, diff).await {
                        session.send_or_stash(generation, translate::set_difficulty_to_line(diff)).await;
                    }
                }
            } else if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS {
                if let Some((last_seq, count)) = parse_submit_success(&mut f) {
                    session.credit_translate_accepted(generation, count).await;
                    let ids = {
                        let mut s = state.lock().await;
                        drain_acked(&mut s.pending_submits, last_seq)
                    };
                    for id in ids {
                        session.send_submit_result(id, true).await;
                    }
                }
            } else if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_ERROR {
                if let Some(seq) = parse_submit_error_seq(&mut f) {
                    let id = {
                        let mut s = state.lock().await;
                        remove_seq(&mut s.pending_submits, seq)
                    };
                    if let Some(id) = id {
                        session.send_submit_result(id, false).await;
                    }
                }
            }
        }
        // Pool closed/errored (an intentional swap aborts this task first).
        let _ = session.died_tx.send(generation);
    })
}

/// Build + emit a `mining.notify` for the miner from an SV2 job + prev-hash.
#[cfg(feature = "sv2")]
async fn emit_translate_notify(
    session: &Arc<Session>,
    generation: u64,
    prev: mining::SetNewPrevHash<'static>,
    job: mining::NewExtendedMiningJob<'static>,
    clean: bool,
) {
    match translate::sv2_job_to_sv1_notify(prev, job, clean) {
        Ok(notify) => session.send_or_stash(generation, translate::notify_to_line(notify)).await,
        Err(e) => warn!(error = %e, "sv2→sv1 notify translation failed"),
    }
}

/// Pop all `(seq, id)` with `seq <= last_seq` (the pool acked them), returning
/// the miner submit ids to answer `result: true`.
#[cfg(feature = "sv2")]
fn drain_acked(q: &mut VecDeque<(u32, Option<Value>)>, last_seq: u32) -> Vec<Option<Value>> {
    let mut out = Vec::new();
    while let Some(&(seq, _)) = q.front() {
        if seq <= last_seq {
            out.push(q.pop_front().unwrap().1);
        } else {
            break;
        }
    }
    out
}

/// Remove the entry for `seq` (a rejected share), returning the miner submit id.
#[cfg(feature = "sv2")]
fn remove_seq(q: &mut VecDeque<(u32, Option<Value>)>, seq: u32) -> Option<Option<Value>> {
    let pos = q.iter().position(|(s, _)| *s == seq)?;
    Some(q.remove(pos).unwrap().1)
}

#[cfg(feature = "sv2")]
impl Session {
    /// Send a line to the miner, or stash it as prelude if the miner hasn't
    /// subscribed yet (so a job never precedes the subscribe reply). No-op if the
    /// generation is stale (a swap happened).
    async fn send_or_stash(&self, generation: u64, line: String) {
        let send = {
            let mut i = self.inner.lock().await;
            if generation != i.active.generation {
                return;
            }
            if i.subscribed {
                true
            } else {
                i.pending_prelude.push(line.clone());
                false
            }
        };
        if send {
            let _ = self.to_miner.send(line);
        }
    }

    /// Set the share difficulty implied by the SV2 pool's current target. Returns
    /// false (and does nothing) if the generation is stale.
    async fn set_translate_difficulty(&self, generation: u64, diff: f64) -> bool {
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return false;
        }
        i.current_difficulty = diff;
        true
    }

    /// Credit `count` accepted shares (diff-weighted) to the hashrate window and,
    /// when rented, the order. Generation-guarded.
    async fn credit_translate_accepted(&self, generation: u64, count: u32) {
        let credit = {
            let mut i = self.inner.lock().await;
            if generation != i.active.generation {
                return;
            }
            let diff = i.current_difficulty;
            let work = diff * count as f64;
            let mut credit = None;
            if work > 0.0 {
                i.hashrate.record(work);
                i.delivered_work += work;
                i.accepted_shares += count as u64;
                if let Routing::Rented { order_id, .. } = &i.routing {
                    credit = Some((order_id.clone(), work, count as u64));
                }
                debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted shares (translated)");
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

    /// Answer a miner `mining.submit` with `result: true/false`.
    async fn send_submit_result(&self, id: Option<Value>, ok: bool) {
        let reply = RpcMessage {
            id,
            method: None,
            params: None,
            result: Some(json!(ok)),
            error: Some(if ok {
                Value::Null
            } else {
                json!([20, "rejected", Value::Null])
            }),
        };
        let _ = self.to_miner.send(reply.to_line());
    }
}

/// A connected + handshaken upstream, positioned for the streaming reader.
struct UpstreamConn {
    reader: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    extranonce1: String,
    extranonce2_size: u32,
    /// Notifications (`set_difficulty`/`notify`) the pool sent during the
    /// handshake, in order. Must be forwarded to the miner — otherwise it never
    /// gets its initial difficulty (mines at "diff 0" → all shares rejected).
    prelude: Vec<String>,
}

/// Connect to `target`, drive `configure`(replay)→`subscribe`→`authorize`, and
/// return the stream positioned after the handshake plus the extranonce.
async fn connect_upstream(
    target: &UpstreamTarget,
    configure: Option<&RpcMessage>,
    user_identity: &str,
) -> anyhow::Result<UpstreamConn> {
    let stream = TcpStream::connect(&target.url).await?;
    let _ = stream.set_nodelay(true);
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut prelude: Vec<String> = Vec::new();

    if let Some(cfg) = configure {
        w.write_all(cfg.to_line().as_bytes()).await?;
        let _ = read_response(&mut reader, &mut prelude).await?; // discard upstream configure reply
    }

    let sub = RpcMessage::request(json!(1), "mining.subscribe", json!(["stratum-rental-proxy/0.1"]));
    w.write_all(sub.to_line().as_bytes()).await?;
    let sub_resp = read_response(&mut reader, &mut prelude).await?;
    let (extranonce1, extranonce2_size) =
        parse_subscribe_result(&sub_resp).ok_or_else(|| anyhow::anyhow!("bad subscribe result"))?;

    // Authorize with the worker we submit under (matches the submit's worker so
    // strict pools don't reject every share as "Worker mismatch").
    let auth = RpcMessage::request(json!(2), "mining.authorize", json!([user_identity, target.password]));
    w.write_all(auth.to_line().as_bytes()).await?;
    let _ = read_response(&mut reader, &mut prelude).await?; // authorize reply (value ignored for now)

    Ok(UpstreamConn {
        reader,
        write: w,
        extranonce1,
        extranonce2_size,
        prelude,
    })
}

/// Read lines until a *response* (has `result`/`error`, no `method`). Any
/// notifications (`set_difficulty`/`notify`) that interleave the handshake are
/// pushed to `prelude` so the caller can forward them to the miner — the pool's
/// initial `set_difficulty`+`notify` arrive here, and dropping them leaves the
/// miner mining at "diff 0" (every share rejected as "Difficulty too low").
async fn read_response(
    reader: &mut BufReader<OwnedReadHalf>,
    prelude: &mut Vec<String>,
) -> anyhow::Result<RpcMessage> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("upstream closed during handshake");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(msg) = RpcMessage::parse(trimmed) {
            if msg.method.is_none() {
                return Ok(msg);
            }
            // Keep the newline — the writer sends lines verbatim, and stratum is
            // newline-delimited. Without it this notification glues onto the next
            // message (e.g. set_difficulty + authorize result run together) and
            // the miner only parses the first, missing the authorize result.
            prelude.push(format!("{trimmed}\n"));
        }
    }
}

/// `mining.subscribe` result shape: `[subscriptions, extranonce1, en2_size]`.
fn parse_subscribe_result(msg: &RpcMessage) -> Option<(String, u32)> {
    let arr = msg.result.as_ref()?.as_array()?;
    if arr.len() < 3 {
        return None;
    }
    let en1 = arr[1].as_str()?.to_string();
    let en2 = arr[2].as_u64()? as u32;
    Some((en1, en2))
}

fn spawn_writer(mut half: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<String>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if half.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    })
}

fn spawn_upstream_reader(
    session: Arc<Session>,
    generation: u64,
    reader: BufReader<OwnedReadHalf>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = RpcMessage::parse(&line) else {
                continue;
            };
            if let Some(out) = session.on_upstream_msg(generation, msg).await {
                if session.to_miner.send(out).is_err() {
                    break;
                }
            }
        }
        // The loop ended = the pool closed/errored (an intentional swap aborts
        // this task first). Tell the supervisor so it can reconnect / fail over.
        let _ = session.died_tx.send(generation);
    })
}

/// Per-session supervisor: when the active upstream drops, reconnect with capped
/// backoff — to the order's pool (primary→fallback) while rented, or the
/// seller's default while idle. Generation-guarded; stale signals (from an
/// already-swapped reader) are ignored.
async fn supervise_upstream(session: Arc<Session>, mut died_rx: mpsc::UnboundedReceiver<u64>) {
    while let Some(gen) = died_rx.recv().await {
        if session.inner.lock().await.active.generation != gen {
            continue; // stale (already swapped away)
        }
        warn!(gen, "sv1 upstream dropped — reconnecting/failing over");
        let mut backoff = Duration::from_millis(500);
        loop {
            let action = {
                let i = session.inner.lock().await;
                if i.active.generation != gen {
                    None
                } else {
                    match &i.routing {
                        Routing::Rented { order_id } => Some(Some(order_id.clone())),
                        Routing::Idle => Some(None),
                    }
                }
            };
            let res = match action {
                None => break,
                Some(Some(oid)) => session.switch_to_order(oid).await,
                Some(None) => session.revert().await,
            };
            match res {
                Ok(()) => {
                    info!(gen, "sv1 upstream re-established after drop");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "sv1 reconnect failed; backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
}

/// The Stratum V1 downstream adapter: a transparent full-proxy with a
/// swappable upstream. Plugs into the [`DownstreamAdapter`] seam.
#[derive(Clone, Copy, Default)]
pub struct Sv1Adapter;

impl DownstreamAdapter for Sv1Adapter {
    fn protocol(&self) -> &'static str {
        "sv1"
    }

    async fn serve(&self, miner: TcpStream, peer: String, ctx: ProxyContext) -> anyhow::Result<()> {
        handle_seller_miner(miner, peer, ctx).await
    }
}

/// Drive one seller miner end to end. Connects the default upstream, answers
/// the miner handshake (synthesizing configure + subscribe), registers the
/// session under the miner's worker, then relays until either side closes.
pub async fn handle_seller_miner(
    miner: TcpStream,
    peer: String,
    ctx: ProxyContext,
) -> anyhow::Result<()> {
    let ProxyContext {
        default_target,
        registry,
        sellers,
        orders,
    } = ctx;
    let ip = peer_ip(&peer);
    // A fresh reconnect-hint (the miner returning onto its own pool) wins over
    // the bootstrap pool: we run the handshake straight against the right pool,
    // so the miner gets the correct extranonce from its first job and needs no
    // mid-session switch. Otherwise SV1 must answer mining.subscribe (extranonce)
    // before the worker is known at mining.authorize, so it falls back to the
    // bootstrap pool. Register-only: unregistered workers are rejected at
    // authorize (below); the bootstrap never serves them.
    let resolved_target = {
        let mut hints = reconnect_hints().lock().await;
        match hints.remove(&ip) {
            Some((t, at)) if at.elapsed() < RECONNECT_HINT_TTL => Some(t),
            _ => None,
        }
    };
    let Some(handshake_target) = resolved_target.or(default_target) else {
        anyhow::bail!(
            "SV1 needs a handshake bootstrap pool (RENTAL_PROXY_POOL_URL); \
             register-only SV1 is unavailable without one — use SV2"
        );
    };
    let _ = miner.set_nodelay(true);
    let (miner_r, miner_w) = miner.into_split();

    // Connect + handshake the bootstrap upstream (protocol auto-detected). The
    // worker isn't known until authorize, so an SV2 channel opens under the bare
    // account here; a later switch (at authorize/rent) re-opens with the worker.
    let raw = connect_raw(&handshake_target, None, &handshake_target.user)
        .await
        .map_err(|e| anyhow::anyhow!("connect upstream {}: {e}", handshake_target.url))?;

    let (to_miner, to_miner_rx) = mpsc::unbounded_channel::<String>();
    let miner_writer = spawn_writer(miner_w, to_miner_rx);

    let (died_tx, died_rx) = mpsc::unbounded_channel::<u64>();
    let (placeholder_to_up, _placeholder_rx) = mpsc::unbounded_channel::<String>();
    let session = Arc::new(Session {
        to_miner: to_miner.clone(),
        switch: Mutex::new(()),
        died_tx,
        orders: orders.clone(),
        inner: Mutex::new(Inner {
            active: ActiveUpstream {
                generation: 0,
                target: handshake_target.clone(),
                to_up: placeholder_to_up,
                reader: tokio::spawn(async {}), // placeholders, installed below
                writer: tokio::spawn(async {}),
            },
            generation_counter: 0,
            current_difficulty: 1.0,
            pending: HashMap::new(),
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            accept_low_logged: false,
            routing: Routing::Idle,
            default_target: handshake_target.clone(),
            configure: None,
            extranonce_capable: false,
            label: peer.clone(),
            pending_prelude: Vec::new(),
            extranonce1: String::new(),
            extranonce2_size: 0,
            translating: false,
            subscribed: false,
        }),
    });

    // Install the bootstrap upstream as `active` (spawns its reader/writer inside
    // the session lock so the generation is visible first; sets extranonce1/2 for
    // the subscribe reply and stashes the initial set_difficulty/notify prelude).
    let generation = {
        let mut i = session.inner.lock().await;
        i.generation_counter += 1;
        i.generation_counter
    };
    session
        .install_raw(raw, generation, handshake_target.clone(), Routing::Idle)
        .await;
    // Supervisor: reconnect / fail over to the fallback if the upstream drops.
    let supervisor = tokio::spawn(supervise_upstream(session.clone(), died_rx));

    info!(%peer, upstream = %handshake_target.url, "relay established (idle)");

    // Miner reader loop (runs on this task): answer handshake locally, relay
    // the rest to the active upstream.
    let mut lines = BufReader::new(miner_r).lines();
    let result: anyhow::Result<()> = async {
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = RpcMessage::parse(&line) else {
                debug!(line, "unparseable from miner");
                continue;
            };
            match msg.method.as_deref() {
                Some("mining.configure") => {
                    // Synthesize an accept (standard BIP320 mask); remember it
                    // to replay to upstreams.
                    session.inner.lock().await.configure = Some(msg.clone());
                    let reply = RpcMessage {
                        id: msg.id.clone(),
                        method: None,
                        params: None,
                        result: Some(json!({
                            "version-rolling": true,
                            "version-rolling.mask": VERSION_ROLLING_MASK
                        })),
                        error: Some(Value::Null),
                    };
                    let _ = to_miner.send(reply.to_line());
                }
                Some("mining.subscribe") => {
                    // Answer with the active upstream's extranonce (set by the
                    // install: SV1 pool's extranonce, or an SV2 channel's prefix).
                    let (en1, en2) = {
                        let i = session.inner.lock().await;
                        (i.extranonce1.clone(), i.extranonce2_size)
                    };
                    let reply = RpcMessage {
                        id: msg.id.clone(),
                        method: None,
                        params: None,
                        result: Some(json!([
                            [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                            en1,
                            en2
                        ])),
                        error: Some(Value::Null),
                    };
                    let _ = to_miner.send(reply.to_line());
                    // Mark subscribed + flush any prelude (the upstream's initial
                    // set_difficulty/notify, or translated jobs stashed before the
                    // subscribe reply) atomically so a job never precedes it.
                    let prelude = {
                        let mut i = session.inner.lock().await;
                        i.subscribed = true;
                        std::mem::take(&mut i.pending_prelude)
                    };
                    for line in prelude {
                        let _ = to_miner.send(line);
                    }
                }
                Some("mining.extranonce.subscribe") => {
                    session.inner.lock().await.extranonce_capable = true;
                    let reply = RpcMessage {
                        id: msg.id.clone(),
                        method: None,
                        params: None,
                        result: Some(json!(true)),
                        error: Some(Value::Null),
                    };
                    let _ = to_miner.send(reply.to_line());
                }
                _ => {
                    // authorize / submit / suggest_difficulty / etc.
                    let auth_worker = if msg.method.as_deref() == Some("mining.authorize") {
                        msg.params
                            .as_ref()
                            .and_then(|p| p.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    } else {
                        None
                    };
                    // On authorize: register-only. Resume an active rental, else
                    // apply the seller's configured default pool. A worker with
                    // neither is unregistered → reject and close.
                    if let Some(w) = auth_worker {
                        let order = orders.active_for_worker(&w, crate::orders::now_ms()).await;
                        let rig = sellers.default_pool(&w).await;
                        if order.is_none() && rig.is_none() {
                            let reply = RpcMessage {
                                id: msg.id.clone(),
                                method: None,
                                params: None,
                                result: Some(json!(false)),
                                error: Some(json!([24, "unregistered worker — register the rig first", Value::Null])),
                            };
                            let _ = to_miner.send(reply.to_line());
                            warn!(worker = %w, "rejected unregistered worker (register-only)");
                            break;
                        }
                        // Register the worker and answer the authorize OURSELVES.
                        // The upstream is authorized in the handshake/switch (with
                        // the pool/buyer account), so we don't forward the miner's
                        // authorize — and crucially, answering it now is what makes
                        // the miner proceed to send suggest_difficulty +
                        // mining.extranonce.subscribe (it waits for the authorize
                        // result first). Without this the grace window below never
                        // sees the subscribe and we always fall back to reconnect.
                        session.inner.lock().await.label = w.clone();
                        registry
                            .insert(w.clone(), AnySession::Sv1(session.clone()))
                            .await;
                        let auth_reply = RpcMessage {
                            id: msg.id.clone(),
                            method: None,
                            params: None,
                            result: Some(json!(true)),
                            error: Some(Value::Null),
                        };
                        let _ = to_miner.send(auth_reply.to_line());
                        // Where this worker should mine: its active rental's target,
                        // else its seller default pool.
                        let want = order
                            .as_ref()
                            .map(|o| o.target.clone())
                            .or_else(|| rig.clone());
                        if let Some(want) = want {
                            if session.active_target().await == want {
                                // Already on the right pool (resolved reconnect, or
                                // the handshake pool happens to be it). No switch →
                                // the miner keeps the correct extranonce.
                                if let Some(o) = &order {
                                    session.attach_order(o.id.clone()).await;
                                    info!(worker = %w, order = %o.id, "resumed active rental (no switch)");
                                } else {
                                    info!(worker = %w, upstream = %want.url, "on seller default pool");
                                }
                            } else {
                                // A switch is needed. The miner sends
                                // mining.extranonce.subscribe only AFTER it receives
                                // the authorize result (which the upstream is
                                // delivering now), so wait briefly for it before
                                // choosing a live switch vs a reconnect.
                                if !session.inner.lock().await.extranonce_capable {
                                    let deadline = Instant::now() + EXTRANONCE_GRACE;
                                    loop {
                                        if session.inner.lock().await.extranonce_capable {
                                            break;
                                        }
                                        let remaining =
                                            deadline.saturating_duration_since(Instant::now());
                                        if remaining.is_zero() {
                                            break;
                                        }
                                        match tokio::time::timeout(remaining, lines.next_line()).await
                                        {
                                            Ok(Ok(Some(l))) => {
                                                let t = l.trim();
                                                if t.is_empty() {
                                                    continue;
                                                }
                                                let Ok(gm) = RpcMessage::parse(t) else {
                                                    continue;
                                                };
                                                if gm.method.as_deref()
                                                    == Some("mining.extranonce.subscribe")
                                                {
                                                    session.inner.lock().await.extranonce_capable =
                                                        true;
                                                    let reply = RpcMessage {
                                                        id: gm.id.clone(),
                                                        method: None,
                                                        params: None,
                                                        result: Some(json!(true)),
                                                        error: Some(Value::Null),
                                                    };
                                                    let _ = to_miner.send(reply.to_line());
                                                } else {
                                                    session.on_miner_msg(gm).await;
                                                }
                                            }
                                            _ => break, // timeout, EOF, or read error
                                        }
                                    }
                                }
                                if session.inner.lock().await.extranonce_capable {
                                    // Live switch: the miner takes a set_extranonce.
                                    let res = match &order {
                                        Some(o) => session.switch_to(o.id.clone(), o.target.clone()).await,
                                        None => session.set_default(want.clone()).await,
                                    };
                                    match res {
                                        Ok(()) => info!(worker = %w, upstream = %want.url, "switched upstream (extranonce-capable)"),
                                        Err(e) => warn!(worker = %w, error = %e, "upstream switch failed"),
                                    }
                                } else {
                                    // Can't take a live extranonce change → reconnect the
                                    // miner straight onto its pool (correct extranonce from
                                    // the first job, no mid-session switch).
                                    reconnect_hints()
                                        .lock()
                                        .await
                                        .insert(ip.clone(), (want, Instant::now()));
                                    let _ = to_miner.send(RpcMessage::client_reconnect("", 0, 1).to_line());
                                    info!(worker = %w, "non-extranonce miner → client.reconnect onto its pool");
                                    break;
                                }
                            }
                        }
                    } else {
                        session.on_miner_msg(msg).await;
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        debug!(%peer, error = %e, "miner read ended");
    }

    // Teardown: deregister + abort upstream + writer.
    let worker = session.worker_label().await;
    registry.remove_if(&worker, &AnySession::Sv1(session.clone())).await;
    supervisor.abort();
    {
        let i = session.inner.lock().await;
        i.active.reader.abort();
        i.active.writer.abort();
    }
    miner_writer.abort();
    info!(%peer, "relay closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The pool's initial `set_difficulty` + `notify` interleave the handshake
    /// (they arrive before/around the authorize reply). `read_response` must keep
    /// them in `prelude` (so the relay can forward them) and still return the
    /// response — dropping them leaves the miner at "diff 0" → every share
    /// rejected as "Difficulty too low".
    #[test]
    fn upstream_worker_keeps_rig_and_tags_proxy() {
        // Account stays a valid payout address; rig name kept + tagged.
        assert_eq!(
            upstream_worker("bc1qSELLER", "bc1qSELLER.bitaxe"),
            "bc1qSELLER.bitaxe-bp-proxy"
        );
        // Rental: buyer account, seller's rig name, still tagged → reaches the buyer.
        assert_eq!(
            upstream_worker("bc1qBUYER", "bc1qSELLER.bitaxe"),
            "bc1qBUYER.bitaxe-bp-proxy"
        );
        // No worker suffix → tag becomes the worker name (account stays valid).
        assert_eq!(upstream_worker("bc1qADDR", "bc1qADDR"), "bc1qADDR.bp-proxy");
    }

    #[test]
    fn peer_ip_strips_port() {
        assert_eq!(peer_ip("192.168.5.20:64178"), "192.168.5.20");
        assert_eq!(peer_ip("10.0.0.1:3333"), "10.0.0.1");
        // No port → returned as-is (defensive).
        assert_eq!(peer_ip("nohost"), "nohost");
    }

    /// Minimal SV1 pool: completes the `subscribe` (handing back `en1`) +
    /// `authorize` handshake so [`connect_upstream`] succeeds, then idles.
    pub(crate) async fn mock_sv1_pool(listener: TcpListener, en1: String) -> anyhow::Result<()> {
        // Loop-accept so protocol detection's probe connection and the real
        // connect are both served (real pools accept many connections).
        loop {
            let (sock, _) = listener.accept().await?;
            let en1 = en1.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(msg) = RpcMessage::parse(&line) else {
                        continue;
                    };
                    let result = match msg.method.as_deref() {
                        Some("mining.subscribe") => json!([
                            [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                            en1,
                            4
                        ]),
                        Some("mining.authorize") => json!(true),
                        _ => continue,
                    };
                    let reply = RpcMessage {
                        id: msg.id.clone(),
                        method: None,
                        params: None,
                        result: Some(result),
                        error: Some(Value::Null),
                    };
                    let _ = w.write_all(reply.to_line().as_bytes()).await;
                }
            });
        }
    }

    #[tokio::test]
    async fn switch_clears_orphaned_pending_submits() {
        // A switch must drop submit-credit entries left in flight on the old
        // upstream (their responses never arrive with the new generation), else
        // `pending` grows unbounded across switches.
        let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = pool_a.local_addr().unwrap();
        let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = pool_b.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(pool_a, "aaaa".into()));
        tokio::spawn(mock_sv1_pool(pool_b, "bbbb".into()));

        let target_a = UpstreamTarget {
            url: a_addr.to_string(),
            user: "acctA".into(),
            password: "x".into(),
            authority_pubkey: None,
        };
        let conn = connect_upstream(&target_a, None, &target_a.user).await.unwrap();
        let (to_miner, _to_miner_rx) = mpsc::unbounded_channel::<String>();
        let (to_up, up_rx) = mpsc::unbounded_channel::<String>();
        let up_writer = spawn_writer(conn.write, up_rx);
        let session = Arc::new(Session {
            to_miner,
            switch: Mutex::new(()),
            died_tx: mpsc::unbounded_channel().0,
            orders: crate::orders::OrderStore::new(crate::db::test_pool().await),
            inner: Mutex::new(Inner {
                active: ActiveUpstream {
                    generation: 0,
                    target: target_a.clone(),
                    to_up,
                    reader: tokio::spawn(async {}),
                    writer: up_writer,
                },
                generation_counter: 0,
                current_difficulty: 1.0,
                pending: HashMap::new(),
                hashrate: HashrateWindow::new(Duration::from_secs(600)),
                delivered_work: 0.0,
                accepted_shares: 0,
                submitted_shares: 0,
                accept_low_logged: false,
                routing: Routing::Idle,
                default_target: target_a.clone(),
                configure: None,
                extranonce_capable: true,
                label: "bc1qSELLER.rig1".into(),
                pending_prelude: Vec::new(),
                extranonce1: String::new(),
                extranonce2_size: 0,
                translating: false,
                subscribed: false,
            }),
        });
        {
            let reader = spawn_upstream_reader(session.clone(), 0, conn.reader);
            let mut i = session.inner.lock().await;
            let old = std::mem::replace(&mut i.active.reader, reader);
            old.abort();
            // Two submits awaiting upstream responses.
            i.pending.insert("1".into(), (0, 1000.0));
            i.pending.insert("2".into(), (0, 1000.0));
        }

        let target_b = UpstreamTarget {
            url: b_addr.to_string(),
            user: "acctB".into(),
            password: "x".into(),
            authority_pubkey: None,
        };
        session.switch_to("o1".to_string(), target_b).await.unwrap();

        assert!(
            session.inner.lock().await.pending.is_empty(),
            "switch cleared the orphaned pending submits"
        );
    }

    #[tokio::test]
    async fn read_response_keeps_handshake_notifications() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[512]}\n")
                .await
                .unwrap();
            s.write_all(b"{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job1\"]}\n")
                .await
                .unwrap();
            s.write_all(b"{\"id\":2,\"result\":true,\"error\":null}\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, _w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut prelude: Vec<String> = Vec::new();
        let resp = read_response(&mut reader, &mut prelude).await.unwrap();

        assert!(resp.method.is_none(), "returned message is the response");
        assert_eq!(resp.result, Some(json!(true)));
        assert_eq!(prelude.len(), 2, "both handshake notifications kept");
        assert!(prelude[0].contains("set_difficulty"));
        assert!(prelude[1].contains("notify"));
        // Each kept line must end with a newline so it isn't glued to the next
        // message when forwarded to the miner.
        assert!(prelude[0].ends_with('\n'));
        assert!(prelude[1].ends_with('\n'));
        server.await.unwrap();
    }
}

/// Combo 3: an SV1 miner rented onto an SV2 buyer pool. The proxy opens an
/// Extended channel on the SV2 pool and translates jobs/shares both ways.
#[cfg(all(test, feature = "sv2"))]
mod sv2_translate_tests {
    use super::tests::mock_sv1_pool;
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::{TcpListener, TcpStream};

    use crate::proto::sv2::keys::NoiseKeys;
    use crate::proto::sv2::relay::{Read as PoolRead, Write as PoolWrite};
    use stratum_apps::network_helpers::accept_noise_connection;
    use stratum_core::binary_sv2::{B032, B064K, U256};
    use stratum_core::common_messages_sv2 as common;
    use stratum_core::common_messages_sv2::SetupConnectionSuccess;
    use stratum_core::mining_sv2::{
        NewExtendedMiningJob, OpenExtendedMiningChannelSuccess, SetNewPrevHash, SubmitSharesSuccess,
    };
    use stratum_core::parsers_sv2::{AnyMessage, CommonMessages};

    fn diff1_target() -> Vec<u8> {
        let mut t = vec![0u8; 32];
        t[28] = 1;
        t
    }

    /// A minimal legacy (non-witness) coinbase split into prefix/suffix — enough
    /// for the notify builder's BIP141 check (which reads prefix bytes 4–5) to
    /// see "no segwit marker" and pass it through unchanged.
    fn legacy_cb() -> (Vec<u8>, Vec<u8>) {
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&1u32.to_le_bytes()); // version
        prefix.push(0x01); // input count (byte 4 ≠ 0 ⇒ not a segwit marker)
        prefix.extend_from_slice(&[0u8; 32]); // prevout hash
        prefix.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        prefix.push(0x07); // scriptSig length (3 prefix + 4 extranonce)
        prefix.extend_from_slice(&[0x03, 0x33, 0x33, 0x33]); // scriptSig up to extranonce
        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        suffix.push(0x00); // output count
        suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime
        (prefix, suffix)
    }

    async fn pool_read_one(read: &mut PoolRead) -> anyhow::Result<wire::Sv2Frame> {
        let frame = read.read_frame().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
        wire::into_sv2(frame).ok_or_else(|| anyhow::anyhow!("handshake frame"))
    }

    /// A mock SV2 pool: loop-accepts (so detection probes + the real connect are
    /// served), opens the Extended channel, sends a future job + prev-hash, and
    /// accepts shares. Reports each share's `(channel_id, sequence_number)`.
    async fn mock_sv2_pool(
        listener: TcpListener,
        keys: NoiseKeys,
        prefix: Vec<u8>,
        cid: u32,
        submits: mpsc::UnboundedSender<(u32, u32)>,
    ) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let _ = sock.set_nodelay(true);
            let keys = keys.clone();
            let prefix = prefix.clone();
            let submits = submits.clone();
            tokio::spawn(async move {
                let Ok(stream) =
                    accept_noise_connection::<wire::Msg>(sock, keys.public(), keys.secret(), 3600).await
                else {
                    return; // detection probe / plaintext → handshake fails
                };
                let (mut read, mut write) = stream.into_split();
                let _ = serve_sv2(&mut read, &mut write, prefix, cid, submits).await;
            });
        }
    }

    async fn serve_sv2(
        read: &mut PoolRead,
        write: &mut PoolWrite,
        prefix: Vec<u8>,
        cid: u32,
        submits: mpsc::UnboundedSender<(u32, u32)>,
    ) -> anyhow::Result<()> {
        // Wait for SetupConnection, then acknowledge.
        loop {
            let f = pool_read_one(read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
                break;
            }
        }
        let ack = AnyMessage::Common(CommonMessages::SetupConnectionSuccess(SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        }));
        write.write_frame(wire::frame_from(ack)).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;

        while let Ok(mut f) = pool_read_one(read).await {
            let Some(mt) = wire::msg_type(&f) else { continue };
            if mt == mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL {
                let payload = f.payload();
                let request_id = match Mining::try_from((mt, payload)) {
                    Ok(Mining::OpenExtendedMiningChannel(m)) => m.request_id,
                    _ => continue,
                };
                let success = OpenExtendedMiningChannelSuccess {
                    request_id,
                    channel_id: cid,
                    target: U256::try_from(diff1_target()).unwrap(),
                    extranonce_size: 4,
                    extranonce_prefix: B032::try_from(prefix.clone()).unwrap(),
                    group_channel_id: 0,
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::OpenExtendedMiningChannelSuccess(success),
                    )))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                // Future job, then its activating prev-hash (SV2 §7 ordering).
                let (cb_prefix, cb_suffix) = legacy_cb();
                let job = NewExtendedMiningJob {
                    channel_id: cid,
                    job_id: 1,
                    min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path: Vec::<U256>::new().into(),
                    coinbase_tx_prefix: B064K::try_from(cb_prefix).unwrap(),
                    coinbase_tx_suffix: B064K::try_from(cb_suffix).unwrap(),
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(Mining::NewExtendedMiningJob(job))))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let prev = SetNewPrevHash {
                    channel_id: cid,
                    job_id: 1,
                    prev_hash: U256::from([0x11u8; 32]),
                    min_ntime: 0x6500_0000,
                    nbits: 0x1707_2cf6,
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(Mining::SetNewPrevHash(prev))))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            } else if mt == mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED {
                let payload = f.payload();
                if let Ok(Mining::SubmitSharesExtended(m)) = Mining::try_from((mt, payload)) {
                    let _ = submits.send((m.channel_id, m.sequence_number));
                    let ok = SubmitSharesSuccess {
                        channel_id: m.channel_id,
                        last_sequence_number: m.sequence_number,
                        new_submits_accepted_count: 1,
                        new_shares_sum: 1,
                    };
                    write
                        .write_frame(wire::frame_from(AnyMessage::Mining(Mining::SubmitSharesSuccess(ok))))
                        .await
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                }
            }
        }
        Ok(())
    }

    /// A line-based SV1 miner driver.
    struct MockSv1Miner {
        lines: tokio::io::Lines<TokioBufReader<tokio::net::tcp::OwnedReadHalf>>,
        write: tokio::net::tcp::OwnedWriteHalf,
    }

    impl MockSv1Miner {
        async fn connect(addr: std::net::SocketAddr) -> Self {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let _ = tcp.set_nodelay(true);
            let (r, w) = tcp.into_split();
            Self {
                lines: TokioBufReader::new(r).lines(),
                write: w,
            }
        }
        async fn send(&mut self, line: &str) {
            self.write.write_all(line.as_bytes()).await.unwrap();
            self.write.write_all(b"\n").await.unwrap();
        }
        /// Read until a request/notification with `method`; return its params.
        async fn read_method(&mut self, method: &str) -> Value {
            loop {
                let line = self.lines.next_line().await.unwrap().expect("miner stream open");
                if line.trim().is_empty() {
                    continue;
                }
                let msg = RpcMessage::parse(&line).unwrap();
                if msg.method.as_deref() == Some(method) {
                    return msg.params.unwrap_or(Value::Null);
                }
            }
        }
        /// Read until a response with `id`; return its `result`.
        async fn read_response(&mut self, id: i64) -> Value {
            loop {
                let line = self.lines.next_line().await.unwrap().expect("miner stream open");
                if line.trim().is_empty() {
                    continue;
                }
                let msg = RpcMessage::parse(&line).unwrap();
                if msg.method.is_none() && msg.id == Some(json!(id)) {
                    return msg.result.unwrap_or(Value::Null);
                }
            }
        }
    }

    #[tokio::test]
    async fn sv1_miner_rented_onto_sv2_pool_translates_end_to_end() {
        // SV1 bootstrap pool (also the rig's idle pool) for the handshake.
        let boot = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let boot_addr = boot.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(boot, "deadbeef".into()));

        // SV2 buyer pool (the rental target) — channel id 50, prefix 0xCC..
        let sv2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sv2_addr = sv2.local_addr().unwrap();
        let (sub_tx, mut sub_rx) = mpsc::unbounded_channel::<(u32, u32)>();
        tokio::spawn(mock_sv2_pool(sv2, NoiseKeys::generate(), vec![0xCC; 4], 50, sub_tx));

        let registry = crate::registry::Registry::new();
        let db = crate::db::test_pool().await;
        let orders = crate::orders::OrderStore::new(db.clone());
        let boot_target = UpstreamTarget {
            url: boot_addr.to_string(),
            user: "acctBoot".into(),
            password: "x".into(),
            authority_pubkey: None,
        };
        let ctx = ProxyContext {
            default_target: Some(boot_target.clone()),
            registry: registry.clone(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
        // Rig idle = the bootstrap pool, so authorize stays put (no SV1 switch);
        // the rental then switches to the SV2 buyer pool (the combo-3 path).
        ctx.sellers
            .set(
                "bc1qSELLER.rig1".into(),
                crate::store::Rig {
                    default_pool: boot_target.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // Run the SV1 relay for one miner connection.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner(sock, peer.to_string(), ctx).await;
        });

        // SV1 miner handshake: configure, subscribe, extranonce.subscribe, authorize.
        let mut miner = MockSv1Miner::connect(proxy_addr).await;
        miner
            .send(r#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]}"#)
            .await;
        let _ = miner.read_response(1).await;
        miner.send(r#"{"id":2,"method":"mining.subscribe","params":["miner/1"]}"#).await;
        let _ = miner.read_response(2).await;
        miner.send(r#"{"id":3,"method":"mining.extranonce.subscribe","params":[]}"#).await;
        let _ = miner.read_response(3).await;
        miner.send(r#"{"id":4,"method":"mining.authorize","params":["bc1qSELLER.rig1","x"]}"#).await;
        assert_eq!(miner.read_response(4).await, json!(true), "authorize accepted");

        // Rent: switch the session onto the SV2 buyer pool (translation).
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        let sv2_target = UpstreamTarget {
            url: sv2_addr.to_string(),
            user: "acctBuyer".into(),
            password: String::new(),
            authority_pubkey: None,
        };
        let order = orders
            .create("bc1qSELLER.rig1".into(), sv2_target.clone(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        sess.switch_to(order.id.clone(), sv2_target).await.unwrap();

        // The miner is re-pointed: new extranonce (the SV2 channel prefix) + a
        // translated job built from the SV2 future job + prev-hash.
        let set_en = tokio::time::timeout(Duration::from_secs(5), miner.read_method("mining.set_extranonce"))
            .await
            .expect("miner gets set_extranonce after the rental switch");
        let en1 = set_en.as_array().unwrap()[0].as_str().unwrap().to_string();
        assert_eq!(en1, "cccccccc", "miner extranonce1 = the SV2 channel prefix");

        let notify = tokio::time::timeout(Duration::from_secs(5), miner.read_method("mining.notify"))
            .await
            .expect("miner receives a translated mining.notify");
        let job_id = notify.as_array().unwrap()[0].as_str().unwrap().to_string();

        // Submit a share: the proxy translates it to SubmitSharesExtended.
        miner
            .send(&format!(
                r#"{{"id":5,"method":"mining.submit","params":["bc1qSELLER.rig1","{job_id}","00000000","65000000","00000000","00000000"]}}"#
            ))
            .await;

        // The SV2 pool received the translated share on its channel id.
        let (ch, _seq) = tokio::time::timeout(Duration::from_secs(5), sub_rx.recv())
            .await
            .expect("share reached the SV2 pool")
            .unwrap();
        assert_eq!(ch, 50, "share submitted on the SV2 channel id");

        // The pool's accept is translated back to an SV1 result:true.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), miner.read_response(5))
                .await
                .expect("miner gets the share result"),
            json!(true),
            "translated share accepted end to end"
        );

        // Accounting credited the rental (diff-weighted delivered work).
        let st = sess.status().await;
        assert_eq!(st.routing, "rented");
        assert!(st.accepted_shares >= 1, "accepted share counted");
        assert!(st.delivered_work > 0.0, "delivered work credited");
    }
}
