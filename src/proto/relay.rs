// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection SV1 relay with a swappable upstream.
//!
//! Full-proxy model: the proxy drives the upstream handshake itself
//! (`configure`→`subscribe`→`authorize`) and synthesizes the miner-facing
//! handshake (`mining.configure` reply + `mining.subscribe` reply carrying the
//! upstream's extranonce).
//!
//! SV1 only learns the worker at `mining.authorize`, after `mining.subscribe`
//! has been answered, so the handshake runs against a bootstrap pool (or the
//! pool a reconnect hint names). Once the worker is known the session moves to
//! the worker's pool: live with `mining.set_extranonce` for an
//! extranonce-capable miner, otherwise by `client.reconnect` straight onto it.
//! Every later pool change the miner did not start (rent start or end,
//! idle-pool edit, recovery after a dropped upstream) drops the connection so
//! the miner re-handshakes.
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

use super::sv1::{self, PoolConn, RpcMessage};
use super::ProxyContext;
use crate::control::{AnySession, SessionStatus};
use crate::session::{Delivery, Routing, UpstreamTarget};
use crate::share_gate::{Sv1Gate, Verdict};

// Translation path (combo 3: SV1 miner ↔ SV2 buyer pool).
use crate::proto::sv2::wire;
use crate::proto::translate;
use std::collections::VecDeque;
use stratum_core::bitcoin::hashes::hex::{DisplayHex, FromHex};
use stratum_core::mining_sv2 as mining;
use stratum_core::parsers_sv2::{AnyMessageOwned, MiningOwned};
use stratum_core::sv1_api::{json_rpc as sv1_json, methods::client_to_server, utils::HexU32Be};

type Tx = mpsc::UnboundedSender<String>;

/// How long a reconnect-hint stays valid (the miner should reconnect at once).
const RECONNECT_HINT_TTL: Duration = Duration::from_secs(120);

/// After authorize, how long to wait for the miner's `mining.extranonce.subscribe`
/// before deciding live-switch vs reconnect. Miners (e.g. BitAxe) send it only
/// after they receive the authorize result, so the proxy must give it a moment.
/// The wait ends as soon as the subscribe arrives — this is only the ceiling for
/// miners that never send it (they then take the reconnect path). The miner can
/// only send it after the authorize result has made the round trip, so this must
/// exceed the link RTT: ~48ms was observed over a WAN link, so 250ms gives
/// ample margin (50ms is enough only for LAN-local miners).
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
    peer.rsplit_once(':')
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_else(|| peer.to_string())
}

/// Worker name to send upstream: the upstream account (pool user / buyer) plus
/// the miner's own worker name, tagged `-bp-proxy` so the pool clearly shows the
/// hashrate is coming through the rental proxy. The account part (before the
/// first `.`) stays a valid payout address; the tag rides on the worker suffix.
pub(crate) fn upstream_worker(account: &str, miner_label: &str) -> String {
    match miner_label
        .split_once('.')
        .map(|(_, s)| s)
        .filter(|s| !s.is_empty())
    {
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
    delivery: Delivery,
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
    /// The miner's share gate (its own difficulty, the shares it judges). Set
    /// by the first upstream install; every line to the miner and every submit
    /// from it passes through it.
    gate: Option<Sv1Gate>,
}

impl Inner {
    /// Pass a line bound for the miner through the gate: jobs are tracked, the
    /// pool's difficulty becomes the miner's. `None` drops the line (a
    /// difficulty the miner already has).
    fn line_to_miner(&mut self, line: String) -> Option<String> {
        match self.gate.as_mut() {
            Some(g) => g.line_to_miner(line),
            None => Some(line),
        }
    }

    /// Deliver a line to the miner, or stash it as prelude until the miner has
    /// subscribed (a job or difficulty must not precede the subscribe reply).
    /// Every path that writes to the miner after the handshake goes through
    /// here with the session lock held, so the miner sees lines in the order
    /// the gate produced them. Returns `false` when the miner is gone.
    fn emit(&mut self, to_miner: &Tx, line: String) -> bool {
        if self.subscribed {
            to_miner.send(line).is_ok()
        } else {
            self.pending_prelude.push(line);
            true
        }
    }

    /// Mark the miner subscribed and deliver what was stashed for it.
    fn flush_prelude(&mut self, to_miner: &Tx) {
        self.subscribed = true;
        for line in std::mem::take(&mut self.pending_prelude) {
            let _ = to_miner.send(line);
        }
    }

    /// Whether the miner's gate can judge its shares. When it cannot, the
    /// hashrate is measured from the pool's accepted work instead.
    fn gate_tracking(&self) -> bool {
        self.gate.as_ref().is_some_and(Sv1Gate::is_tracking)
    }
}

/// The typed `mining.submit` inside a miner message, if it is one.
fn parse_submit(msg: &RpcMessage) -> Option<client_to_server::Submit> {
    let req = sv1_json::StandardRequest {
        id: msg.id.as_ref().and_then(|v| v.as_u64()).unwrap_or(0),
        method: "mining.submit".to_string(),
        params: msg.params.clone().unwrap_or(Value::Null),
    };
    client_to_server::Submit::try_from(req).ok()
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
    /// Fired by [`Session::force_reconnect`] to drop the miner connection so it
    /// reconnects and re-resolves its upstream from current state. Used for
    /// every pool change the miner did not start: operator changes (idle-pool
    /// edit, rent start, rent end/cancel) and recovery after a dropped upstream
    /// ([`crate::control::supervise_upstream`]).
    reconnect: tokio::sync::Notify,
}

impl Session {
    /// Switch this session's hashrate to `target` (a rental starts).
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
            .ok_or_else(|| anyhow::anyhow!("order {order_id} not found"))?;
        order
            .connect_with_fallback(|target| self.switch_to(order_id.clone(), target))
            .await
            .map(drop)
    }

    /// The session's routing, if `generation` is still its active upstream.
    pub async fn routing_if_active(&self, generation: u64) -> Option<Routing> {
        let i = self.inner.lock().await;
        (i.active.generation == generation).then(|| i.routing.clone())
    }

    /// Switch back to the seller's default upstream (a rental ends).
    pub async fn revert(self: &Arc<Self>) -> anyhow::Result<()> {
        let default = self.inner.lock().await.default_target.clone();
        self.swap_upstream(default, Routing::Idle).await
    }

    /// Drop the miner connection so it reconnects and re-resolves its upstream
    /// from current state. The caller must persist the new state (store/order)
    /// BEFORE calling this. Preferred over a live swap for operator-initiated
    /// changes — a fresh handshake hands the miner the new pool's
    /// extranonce/difficulty cleanly instead of relying on a live re-point.
    pub fn force_reconnect(&self) {
        self.reconnect.notify_one();
    }

    /// Set the seller's configured default upstream and use it now (the miner
    /// is idle). Applied when an extranonce-capable miner authorizes and its
    /// rig's idle pool differs from the pool the handshake ran against.
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

    async fn swap_upstream(
        self: &Arc<Self>,
        target: UpstreamTarget,
        routing: Routing,
    ) -> anyhow::Result<()> {
        // Hold the switch lock for the whole swap so concurrent switches run
        // strictly one after another (the last to acquire wins). Released on return.
        let _switch = self.switch.lock().await;
        // Snapshot what the handshake needs without holding the lock across IO.
        let (configure, capable, generation, label) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            (
                i.configure.clone(),
                i.extranonce_capable,
                i.generation_counter,
                i.label.clone(),
            )
        };
        let user_identity = upstream_worker(&target.user, &label);

        // Connect + handshake the new upstream BEFORE tearing down the old, so a
        // failed switch leaves the miner mining on the current upstream. Detection
        // picks passthrough (SV1) vs translation (SV2 buyer pool) automatically.
        let raw = connect_raw(&target, configure.as_ref(), &user_identity)
            .await
            .map_err(|e| anyhow::anyhow!("switch: connect {}: {e}", target.url))?;

        // Swap atomically (the reader is spawned inside the lock so the new
        // generation is visible before it can forward — no first-job drop),
        // and re-point the miner in the same hold of the lock.
        self.install_raw(raw, generation, target.clone(), routing, capable)
            .await;
        if !capable {
            // Left connected, this miner would keep building on an extranonce1
            // the new upstream does not know, and the pool would reject every
            // share. It cannot be told mid-session, so drop it and let it come
            // back.
            warn!(upstream = %target.url, "miner not extranonce-capable; reconnecting it onto the new upstream");
            self.force_reconnect();
        }
        info!(upstream = %target.url, generation, capable, "upstream switched");
        Ok(())
    }

    /// Process a line from the upstream tagged `generation` and pass it on to
    /// the miner (a stale-upstream line is dropped). Returns `false` when the
    /// miner is gone.
    async fn on_upstream_msg(&self, generation: u64, msg: RpcMessage) -> bool {
        let mut order_credit: Option<(String, f64)> = None;
        let mut order_reject: Option<(String, String)> = None;
        let alive = {
            let mut guard = self.inner.lock().await;
            let i = &mut *guard;
            if generation != i.active.generation {
                return true; // stale upstream (already swapped away)
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
                    // A submit response: credit an accepted share (diff-weighted),
                    // keep a rejected one's reason for the rental's pool health.
                    let idk = id_key(&msg.id);
                    let ours = i.pending.remove(&idk).filter(|(g, _)| *g == generation);
                    if let Some((_, diff)) = ours {
                        if matches!(&msg.result, Some(Value::Bool(true))) {
                            if !i.gate_tracking() {
                                i.delivery.measured(diff);
                            }
                            if i.delivery.accepted(diff, 1, &i.label) {
                                order_credit = i.routing.order_id().map(|o| (o.to_string(), diff));
                            }
                        } else {
                            order_reject = i
                                .routing
                                .order_id()
                                .map(|o| (o.to_string(), msg.reject_reason()));
                        }
                    }
                }
                _ => {}
            }
            match i.line_to_miner(msg.to_line()) {
                Some(line) => i.emit(&self.to_miner, line),
                None => true,
            }
        };
        if let Some((order_id, diff)) = order_credit {
            self.orders.add_work(&order_id, diff, 1);
        }
        if let Some((order_id, reason)) = order_reject {
            self.orders.note_rejected(&order_id, reason);
        }
        alive
    }

    /// Process a line from the miner; sends the (possibly rewritten) line to the
    /// active upstream. Authorize is owned by the main handshake loop (which
    /// registers the session and answers it locally) and is never handled here.
    async fn on_miner_msg(self: &Arc<Self>, mut msg: RpcMessage) {
        let mut submit_order: Option<String> = None;
        {
            let mut guard = self.inner.lock().await;
            let i = &mut *guard;
            if msg.method.as_deref() == Some("mining.submit") {
                let verdict = match (i.gate.as_mut(), parse_submit(&msg)) {
                    (Some(g), Some(submit)) => g.check(&submit),
                    (Some(g), None) => g.unplaced(),
                    (None, _) => Verdict::Forward { measured: None },
                };
                if let Some(d) = verdict.measured() {
                    i.delivery.measured(d);
                }
                if let Verdict::Withhold { .. } = verdict {
                    // Met the miner's target, not the pool's: the pool would
                    // reject it, so the proxy answers it.
                    let _ = self
                        .to_miner
                        .send(RpcMessage::response(msg.id.clone(), json!(true)).to_line());
                    return;
                }
            }
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
                    i.delivery.submitted(&i.label);
                    submit_order = i.routing.order_id().map(str::to_string);
                    let up_worker = upstream_worker(&i.active.target.user, &i.label);
                    if let Some(arr) = msg.params.as_mut().and_then(|p| p.as_array_mut()) {
                        if let Some(first) = arr.first_mut() {
                            *first = json!(up_worker);
                        }
                    }
                }
                Some("mining.suggest_difficulty") => {
                    // The miner names the difficulty it wants: it sizes the
                    // miner target until vardiff knows better. The pool still
                    // receives it below.
                    let suggested = msg
                        .params
                        .as_ref()
                        .and_then(|p| p.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_f64());
                    let line = match (suggested, i.gate.as_mut()) {
                        (Some(d), Some(g)) => g.suggest_difficulty(d),
                        _ => None,
                    };
                    if let Some(line) = line {
                        i.emit(&self.to_miner, line);
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

    pub(crate) fn orders(&self) -> &crate::orders::OrderStore {
        &self.orders
    }

    /// Snapshot for the control API.
    pub async fn status(&self) -> SessionStatus {
        let i = self.inner.lock().await;
        i.delivery
            .status(&i.label, &i.routing, &i.active.target.url, "sv1")
    }
}

fn id_key(id: &Option<Value>) -> String {
    id.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".into())
}

// ── upstream establishment (passthrough SV1 or translated SV2) ───────

/// Default nominal hashrate (H/s) advertised when opening an Extended channel on
/// an SV2 buyer pool behind an SV1 miner; the pool's vardiff adjusts from here.
const SV2_UP_NOMINAL_HASHRATE: f32 = 1.0e12;
/// Extranonce-2 size requested from the SV2 pool — also the SV1 `extranonce2_size`.
const SV2_UP_MIN_EXTRANONCE: u16 = 4;

/// The Extended channel the proxy opens on an SV2 pool for an SV1 miner. The
/// pre-rental pool probe opens the same one.
pub(crate) fn translate_open_spec() -> crate::proto::sv2::relay::OpenSpec {
    crate::proto::sv2::relay::OpenSpec::Extended {
        request_id: 1,
        nominal_hash_rate: SV2_UP_NOMINAL_HASHRATE,
        // Most permissive max_target — let the pool's vardiff pick the working one.
        max_target: vec![0xff; 32],
        min_extranonce_size: SV2_UP_MIN_EXTRANONCE,
    }
}

/// A freshly connected upstream, not yet spawned into reader/writer tasks. The
/// caller installs it under the session lock so the new generation is visible
/// before the reader runs (so the first job is never dropped as stale).
enum RawUpstream {
    /// Same protocol as the miner: SV1 lines are forwarded verbatim.
    Sv1(PoolConn),
    /// An SV2 buyer pool behind an SV1 miner: an open Extended channel whose jobs
    /// and shares are translated (see [`crate::proto::translate`]). Boxed — the
    /// Noise halves are far larger than the SV1 variant.
    Sv2(Box<Sv2RawUpstream>),
}

/// An opened SV2 Extended channel ready to translate for an SV1 miner.
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
    // Native first: try SV1 (reusing its socket on success); if the pool doesn't
    // answer as SV1, it's an SV2 buyer pool → open an Extended channel + translate.
    match tokio::time::timeout(
        translate::UPSTREAM_PROBE_TIMEOUT,
        sv1::connect_pool(target, user_identity, configure),
    )
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
async fn connect_sv2_translate(
    target: &UpstreamTarget,
    user_identity: &str,
) -> anyhow::Result<RawUpstream> {
    use crate::proto::sv2::relay::{connect_setup, open_on};
    let (mut read, mut write) = connect_setup(target).await?;
    let spec = translate_open_spec();
    // This is the ONLY channel on a freshly-connected upstream, so no earlier
    // channel exists whose job/prev-hash could arrive before this success —
    // anything buffered here really is unexpected, unlike in the multi-channel
    // re-open loop. Say so instead of dropping it in silence.
    let mut unexpected = Vec::new();
    let info = open_on(&mut read, &mut write, &spec, user_identity, &mut unexpected).await?;
    if !unexpected.is_empty() {
        warn!(
            frames = unexpected.len(),
            upstream = %target.url,
            "sv2 translate open: unexpected frames before OpenSuccess; dropped"
        );
    }
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
        extranonce_capable: bool,
    ) -> (String, u32) {
        let mut i = self.inner.lock().await;
        i.active.reader.abort();
        i.active.writer.abort();
        let (to_up, reader, writer, en1, en2, prelude, translating, translate_diff) = match raw {
            RawUpstream::Sv1(conn) => {
                let (to_up, rx) = mpsc::unbounded_channel::<String>();
                let writer = spawn_writer(conn.write, rx);
                let reader = spawn_upstream_reader(self.clone(), generation, conn.read);
                (
                    to_up,
                    reader,
                    writer,
                    conn.extranonce1,
                    conn.extranonce2_size,
                    conn.prelude,
                    false,
                    None,
                )
            }
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
        // The miner's gate for this upstream, starting from the pool's
        // difficulty: the last one in its handshake prelude (a translated SV2
        // pool's is synthesized there too), or none yet when the pool sets it
        // after the handshake. A renewed gate
        // keeps the device's vardiff estimate across the switch. The prelude
        // then passes through it like every later line, so the miner's first
        // set_difficulty already carries the miner difficulty.
        let start_difficulty = prelude
            .iter()
            .rev()
            .find_map(|l| translate::set_difficulty_from_line(l));
        let en1_bytes = Vec::<u8>::from_hex(&en1).unwrap_or_default();
        let fresh = Sv1Gate::new(
            &en1_bytes,
            en2 as u16,
            start_difficulty.map(translate::target_from_difficulty),
        );
        let mut gate = match i.gate.take() {
            Some(old) => old.renewed(fresh),
            None => fresh,
        };
        let prelude: Vec<String> = prelude
            .into_iter()
            .filter_map(|l| gate.line_to_miner(l))
            .collect();
        i.gate = Some(gate);
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
        // A miner already past its subscribe is re-pointed here, in the same
        // hold of the lock that installed the reader: the new extranonce, then
        // the new upstream's initial set_difficulty/notify (else it keeps the
        // old target and every share is rejected as "Difficulty too low").
        // The reader waits on this lock, so none of its lines can overtake
        // them. Modern ASICs honor set_extranonce live; a miner that can't is
        // reconnected by the caller.
        if i.subscribed {
            if extranonce_capable {
                let _ = self
                    .to_miner
                    .send(RpcMessage::set_extranonce(&en1, en2).to_line());
            }
            i.flush_prelude(&self.to_miner);
        }
        (en1, en2)
    }
}

// ── SV2 upstream translator (combo 3): SV1 miner ↔ SV2 buyer pool ────

/// Shared state between the two translate driver tasks: job versions (to rebuild
/// the SV2 submit version), the sequence counter, and the submit id mapping
/// (SV2 `sequence_number` → the miner's SV1 submit id, for the result reply).
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
            let Some(submit) = parse_submit(&msg) else {
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
            let frame = wire::frame_from(AnyMessageOwned::Mining(
                MiningOwned::SubmitSharesExtended(sv2_submit),
            ));
            if write.write_frame(frame).await.is_err() {
                break;
            }
        }
    })
}

/// Translate the SV2 pool's jobs / target / share results back into SV1 lines for
/// the miner, and credit accepted shares. Future jobs are buffered until their
/// `SetNewPrevHash` arrives (per SV2 §7), then emitted as a `mining.notify`.
fn spawn_sv2_translate_reader(
    session: Arc<Session>,
    generation: u64,
    mut read: crate::proto::sv2::relay::Read,
    state: Arc<Mutex<Sv2UpState>>,
) -> JoinHandle<()> {
    use crate::proto::sv2::relay::codec::{
        parse_new_extended_job, parse_set_new_prev_hash, parse_set_target, parse_submit_error,
        parse_submit_success,
    };
    tokio::spawn(async move {
        let mut prev: Option<mining::SetNewPrevHashOwned> = None;
        let mut job: Option<mining::NewExtendedMiningJobOwned> = None;
        while let Ok(mut f) = read.read_frame().await {
            let mt = wire::msg_type(&f);
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
                    if j.ntime_start.clone().into_inner().is_none() {
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
                        session
                            .send_or_stash(generation, translate::set_difficulty_to_line(diff))
                            .await;
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
                if let Some((seq, code)) = parse_submit_error(&mut f) {
                    session.note_translate_rejected(generation, code).await;
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
async fn emit_translate_notify(
    session: &Arc<Session>,
    generation: u64,
    prev: mining::SetNewPrevHashOwned,
    job: mining::NewExtendedMiningJobOwned,
    clean: bool,
) {
    match translate::sv2_job_to_sv1_notify(prev, job, clean) {
        Ok(notify) => {
            session
                .send_or_stash(generation, translate::notify_to_line(notify))
                .await
        }
        Err(e) => warn!(error = %e, "sv2→sv1 notify translation failed"),
    }
}

/// Pop all `(seq, id)` with `seq <= last_seq` (the pool acked them), returning
/// the miner submit ids to answer `result: true`.
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
fn remove_seq(q: &mut VecDeque<(u32, Option<Value>)>, seq: u32) -> Option<Option<Value>> {
    let pos = q.iter().position(|(s, _)| *s == seq)?;
    Some(q.remove(pos).unwrap().1)
}

impl Session {
    /// Send a line to the miner, or stash it as prelude if the miner hasn't
    /// subscribed yet (so a job never precedes the subscribe reply). No-op if the
    /// generation is stale (a swap happened).
    async fn send_or_stash(&self, generation: u64, line: String) {
        let mut i = self.inner.lock().await;
        if generation != i.active.generation {
            return;
        }
        if let Some(line) = i.line_to_miner(line) {
            i.emit(&self.to_miner, line);
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
            let mut guard = self.inner.lock().await;
            let i = &mut *guard;
            if generation != i.active.generation {
                return;
            }
            let work = i.current_difficulty * count as f64;
            let shares = count as u64;
            if !i.gate_tracking() {
                i.delivery.measured(work);
            }
            if i.delivery.accepted(work, shares, &i.label) {
                i.routing.order_id().map(|o| (o.to_string(), work, shares))
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

    /// Answer a miner `mining.submit` with `result: true/false`.
    async fn send_submit_result(&self, id: Option<Value>, ok: bool) {
        let reply = if ok {
            RpcMessage::response(id, json!(true))
        } else {
            RpcMessage::refusal(id, 20, "rejected")
        };
        let _ = self.to_miner.send(reply.to_line());
    }
}

/// Retarget the miner when its gate's vardiff says so. Runs for the life of
/// the miner connection; a retarget waits for the subscribe reply, before
/// which the miner takes no difficulty.
async fn run_vardiff(session: Arc<Session>) {
    let mut every = tokio::time::interval(crate::share_gate::VARDIFF_TICK);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let mut i = session.inner.lock().await;
        if !i.subscribed {
            continue;
        }
        if let Some(line) = i.gate.as_mut().and_then(Sv1Gate::tick) {
            i.emit(&session.to_miner, line);
        }
    }
}

fn spawn_writer(
    mut half: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<String>,
) -> JoinHandle<()> {
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
            if !session.on_upstream_msg(generation, msg).await {
                break;
            }
        }
        // The loop ended = the pool closed/errored (an intentional swap aborts
        // this task first). Tell the supervisor so it can reconnect / fail over.
        let _ = session.died_tx.send(generation);
    })
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
        // SV2 rig bundling registry; not used by the SV1 relay.
        ..
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
        reconnect: tokio::sync::Notify::new(),
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
            delivery: Delivery::new(),
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
            gate: None,
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
        .install_raw(
            raw,
            generation,
            handshake_target.clone(),
            Routing::Idle,
            false,
        )
        .await;
    // Supervisor: reconnect / fail over to the fallback if the upstream drops.
    let supervisor = tokio::spawn(crate::control::supervise_upstream(
        AnySession::Sv1(session.clone()),
        died_rx,
    ));
    let vardiff = tokio::spawn(run_vardiff(session.clone()));

    info!(%peer, upstream = %handshake_target.url, "relay established (idle)");

    // Miner reader loop (runs on this task): answer handshake locally, relay
    // the rest to the active upstream.
    let mut lines = BufReader::new(miner_r).lines();
    let result: anyhow::Result<()> = async {
        loop {
            let line = tokio::select! {
                biased;
                // Operator-initiated pool change: close the connection so the
                // miner reconnects and re-handshakes against the updated upstream
                // (correct extranonce from job 1). A bare close reliably triggers
                // a reconnect to the same proxy; a client.reconnect notification
                // would race the writer teardown and be dropped before flushing.
                _ = session.reconnect.notified() => {
                    info!(%peer, "forcing miner reconnect for pool change");
                    break;
                }
                line = lines.next_line() => match line? {
                    Some(l) => l,
                    None => break,
                },
            };
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
                    let reply = RpcMessage::response(
                        msg.id.clone(),
                        json!({
                            "version-rolling": true,
                            "version-rolling.mask": sv1::version_rolling_mask_hex()
                        }),
                    );
                    let _ = to_miner.send(reply.to_line());
                }
                Some("mining.subscribe") => {
                    // Answer with the active upstream's extranonce (set by the
                    // install: SV1 pool's extranonce, or an SV2 channel's prefix).
                    let (en1, en2) = {
                        let i = session.inner.lock().await;
                        (i.extranonce1.clone(), i.extranonce2_size)
                    };
                    let reply = RpcMessage::response(
                        msg.id.clone(),
                        json!([
                            [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                            en1,
                            en2
                        ]),
                    );
                    let _ = to_miner.send(reply.to_line());
                    // Mark subscribed + flush any prelude (the upstream's initial
                    // set_difficulty/notify, or translated jobs stashed before the
                    // subscribe reply) under the lock, so neither a job precedes
                    // the reply nor a live line overtakes the stashed ones.
                    session.inner.lock().await.flush_prelude(&to_miner);
                }
                Some("mining.extranonce.subscribe") => {
                    session.inner.lock().await.extranonce_capable = true;
                    let reply = RpcMessage::response(msg.id.clone(), json!(true));
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
                            let reply = RpcMessage::refusal(
                                msg.id.clone(),
                                24,
                                "unregistered worker — register the rig first",
                            );
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
                        let auth_reply = RpcMessage::response(msg.id.clone(), json!(true));
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
                                                    let reply = RpcMessage::response(gm.id.clone(), json!(true));
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
    registry
        .remove_if(&worker, &AnySession::Sv1(session.clone()))
        .await;
    supervisor.abort();
    vardiff.abort();
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
    /// `authorize` handshake so [`sv1::connect_pool`] succeeds, then idles.
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
                    let reply = RpcMessage::response(msg.id.clone(), result);
                    let _ = w.write_all(reply.to_line().as_bytes()).await;
                }
            });
        }
    }

    /// An idle, extranonce-capable session connected to `target` (its idle
    /// pool) as generation 0, reporting dropped upstreams on `died_tx`.
    async fn idle_session_on(
        target: &UpstreamTarget,
        died_tx: mpsc::UnboundedSender<u64>,
    ) -> Arc<Session> {
        let conn = sv1::connect_pool(target, &target.user, None).await.unwrap();
        let (to_miner, _to_miner_rx) = mpsc::unbounded_channel::<String>();
        let (to_up, up_rx) = mpsc::unbounded_channel::<String>();
        let session = Arc::new(Session {
            to_miner,
            switch: Mutex::new(()),
            died_tx,
            orders: crate::orders::OrderStore::new(crate::db::test_pool().await),
            reconnect: tokio::sync::Notify::new(),
            inner: Mutex::new(Inner {
                active: ActiveUpstream {
                    generation: 0,
                    target: target.clone(),
                    to_up,
                    reader: tokio::spawn(async {}),
                    writer: spawn_writer(conn.write, up_rx),
                },
                generation_counter: 0,
                current_difficulty: 1.0,
                pending: HashMap::new(),
                delivery: Delivery::new(),
                routing: Routing::Idle,
                default_target: target.clone(),
                configure: None,
                extranonce_capable: true,
                label: "bc1qSELLER.rig1".into(),
                pending_prelude: Vec::new(),
                extranonce1: String::new(),
                extranonce2_size: 0,
                translating: false,
                subscribed: false,
                gate: None,
            }),
        });
        let reader = spawn_upstream_reader(session.clone(), 0, conn.read);
        std::mem::replace(&mut session.inner.lock().await.active.reader, reader).abort();
        session
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
        let session = idle_session_on(&target_a, mpsc::unbounded_channel().0).await;
        {
            let mut i = session.inner.lock().await;
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
    async fn a_share_the_rental_pool_rejects_leaves_its_reason_on_the_order() {
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(pool, "aaaa".into()));
        let target = UpstreamTarget {
            url: addr.to_string(),
            user: "acctA".into(),
            password: "x".into(),
            authority_pubkey: None,
        };
        let (died_tx, _died_rx) = mpsc::unbounded_channel();
        let session = idle_session_on(&target, died_tx).await;
        let order = session
            .orders
            .create("acctA.rig".into(), target.clone(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        session.attach_order(order.id.clone()).await;

        let submit = RpcMessage::request(
            json!(7),
            "mining.submit",
            json!(["acctA.rig", "1", "00000000", "65000000", "00000000"]),
        );
        session.on_miner_msg(submit).await;
        let refusal = RpcMessage::refusal(Some(json!(7)), 23, "Low difficulty share");
        session.on_upstream_msg(0, refusal).await;

        // Enough unanswered submits for the rule to end the rental; its detail
        // carries the pool's words from the refusal above.
        session
            .orders
            .add_submitted(&order.id, crate::orders::UNACCEPTED_SUBMITS_LIMIT);
        session.orders.flush().await;
        let ended = session.orders.take_finished(crate::orders::now_ms()).await;
        assert_eq!(ended.len(), 1);
        let detail = ended[0].end_detail.as_deref().unwrap();
        assert!(detail.contains("Low difficulty share (23)"), "{detail}");
    }

    #[tokio::test]
    async fn an_upstream_that_comes_back_reconnects_an_extranonce_capable_miner() {
        // After its pool connection drops, the supervisor re-establishes the
        // upstream and then drops the miner, even one that would accept a live
        // `mining.set_extranonce`: recovery gives every miner a fresh handshake.
        let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = pool.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(pool, "aaaa".into()));
        let target = UpstreamTarget {
            url: addr.to_string(),
            user: "acctA".into(),
            password: "x".into(),
            authority_pubkey: None,
        };
        let (died_tx, died_rx) = mpsc::unbounded_channel();
        let session = idle_session_on(&target, died_tx.clone()).await;
        tokio::spawn(crate::control::supervise_upstream(
            AnySession::Sv1(session.clone()),
            died_rx,
        ));

        // The generation-0 reader reports its pool connection gone.
        died_tx.send(0).unwrap();

        tokio::time::timeout(Duration::from_secs(5), session.reconnect.notified())
            .await
            .expect("miner reconnected after the upstream came back");
        assert!(
            session.inner.lock().await.active.generation > 0,
            "the upstream was re-established before the reconnect"
        );
    }
}

/// Combo 3: an SV1 miner rented onto an SV2 buyer pool. The proxy opens an
/// Extended channel on the SV2 pool and translates jobs/shares both ways.
#[cfg(test)]
pub(crate) mod sv2_translate_tests {
    use super::tests::mock_sv1_pool;
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::{TcpListener, TcpStream};

    use crate::proto::sv2::keys::NoiseKeys;
    use crate::proto::sv2::relay::{Read as PoolRead, Write as PoolWrite};
    use stratum_apps::network_helpers::accept_noise_connection;
    use stratum_core::binary_sv2::{
        B032Owned, B064KOwned, Seq0255Owned, Sv2OptionOwned, U256Owned,
    };
    use stratum_core::common_messages_sv2 as common;
    use stratum_core::common_messages_sv2::SetupConnectionSuccess;
    use stratum_core::mining_sv2::{
        NewExtendedMiningJobOwned, OpenExtendedMiningChannelSuccessOwned, SetNewPrevHashOwned,
        SubmitSharesSuccess,
    };
    use stratum_core::parsers_sv2::{CommonMessagesOwned, Mining};

    fn diff1_target() -> Vec<u8> {
        // The difficulty-1 target in the current (bdiff) convention.
        crate::proto::translate::target_from_difficulty(1.0).to_vec()
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
        read.read_frame()
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    /// A mock SV2 pool: loop-accepts (so detection probes + the real connect are
    /// served), opens the Extended channel, sends a future job + prev-hash, and
    /// accepts shares. Reports each share's `(channel_id, sequence_number)`.
    pub(crate) async fn mock_sv2_pool(
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
                    accept_noise_connection(sock, keys.public(), keys.secret(), 3600).await
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
            if wire::msg_type(&f) == common::MESSAGE_TYPE_SETUP_CONNECTION {
                break;
            }
        }
        let ack = AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(
            SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            },
        ));
        write
            .write_frame(wire::frame_from(ack))
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

        while let Ok(mut f) = pool_read_one(read).await {
            let mt = wire::msg_type(&f);
            if mt == mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL {
                let payload = f.payload();
                let request_id = match Mining::try_from((mt, payload)) {
                    Ok(Mining::OpenExtendedMiningChannel(m)) => m.request_id,
                    _ => continue,
                };
                let success = OpenExtendedMiningChannelSuccessOwned {
                    request_id,
                    channel_id: cid,
                    target: U256Owned::try_from(diff1_target()).unwrap(),
                    extranonce_size: 4,
                    extranonce_prefix: B032Owned::try_from(prefix.clone()).unwrap(),
                    group_channel_id: 0,
                };
                write
                    .write_frame(wire::frame_from(AnyMessageOwned::Mining(
                        MiningOwned::OpenExtendedMiningChannelSuccess(success),
                    )))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                // Future job, then its activating prev-hash (SV2 §7 ordering).
                let (cb_prefix, cb_suffix) = legacy_cb();
                let job = NewExtendedMiningJobOwned {
                    channel_id: cid,
                    job_id: 1,
                    ntime_start: Sv2OptionOwned::new(None),
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path: Seq0255Owned::new(Vec::new()).unwrap(),
                    coinbase_tx_prefix: B064KOwned::try_from(cb_prefix).unwrap(),
                    coinbase_tx_suffix: B064KOwned::try_from(cb_suffix).unwrap(),
                };
                write
                    .write_frame(wire::frame_from(AnyMessageOwned::Mining(
                        MiningOwned::NewExtendedMiningJob(job),
                    )))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let prev = SetNewPrevHashOwned {
                    channel_id: cid,
                    job_id: 1,
                    prev_hash: U256Owned::from([0x11u8; 32]),
                    ntime_start: 0x6500_0000,
                    nbits: 0x1707_2cf6,
                };
                write
                    .write_frame(wire::frame_from(AnyMessageOwned::Mining(
                        MiningOwned::SetNewPrevHash(prev),
                    )))
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
                        .write_frame(wire::frame_from(AnyMessageOwned::Mining(
                            MiningOwned::SubmitSharesSuccess(ok),
                        )))
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
                let line = self
                    .lines
                    .next_line()
                    .await
                    .unwrap()
                    .expect("miner stream open");
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
                let line = self
                    .lines
                    .next_line()
                    .await
                    .unwrap()
                    .expect("miner stream open");
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
    async fn force_reconnect_directs_sv1_miner_to_reconnect() {
        // An operator pool change calls force_reconnect on a connected SV1 miner;
        // the proxy must close the connection so the miner re-handshakes against
        // the new upstream rather than relying on a live re-point it may not honor.
        let boot = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let boot_addr = boot.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(boot, "deadbeef".into()));

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
            sv2_rigs: Default::default(),
            sellers: crate::store::SellerStore::new(db.clone()),
            orders: orders.clone(),
        };
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

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, peer) = proxy.accept().await.unwrap();
            let _ = handle_seller_miner(sock, peer.to_string(), ctx).await;
        });

        let mut miner = MockSv1Miner::connect(proxy_addr).await;
        miner
            .send(r#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]}"#)
            .await;
        let _ = miner.read_response(1).await;
        miner
            .send(r#"{"id":2,"method":"mining.subscribe","params":["miner/1"]}"#)
            .await;
        let _ = miner.read_response(2).await;
        miner
            .send(r#"{"id":4,"method":"mining.authorize","params":["bc1qSELLER.rig1","x"]}"#)
            .await;
        assert_eq!(
            miner.read_response(4).await,
            json!(true),
            "authorize accepted"
        );

        // Grab the live session and force a reconnect.
        let sess = loop {
            if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        sess.force_reconnect();

        // Drain the miner's stream: the proxy must close the connection
        // (Ok(None) = EOF, or a read error).
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match miner.lines.next_line().await {
                    Ok(Some(_)) => continue, // drain any queued lines
                    _ => return true,        // EOF or error → connection closed
                }
            }
        })
        .await
        .expect("force_reconnect should close the SV1 miner connection within 5s");
        assert!(closed);

        // The session deregisters after teardown.
        let gone = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if registry.get_all("bc1qSELLER.rig1").await.is_empty() {
                    return true;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session should deregister after a forced reconnect");
        assert!(gone);
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
        tokio::spawn(mock_sv2_pool(
            sv2,
            NoiseKeys::generate(),
            vec![0xCC; 4],
            50,
            sub_tx,
        ));

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
            sv2_rigs: Default::default(),
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
        miner
            .send(r#"{"id":2,"method":"mining.subscribe","params":["miner/1"]}"#)
            .await;
        let _ = miner.read_response(2).await;
        miner
            .send(r#"{"id":3,"method":"mining.extranonce.subscribe","params":[]}"#)
            .await;
        let _ = miner.read_response(3).await;
        miner
            .send(r#"{"id":4,"method":"mining.authorize","params":["bc1qSELLER.rig1","x"]}"#)
            .await;
        assert_eq!(
            miner.read_response(4).await,
            json!(true),
            "authorize accepted"
        );

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
            .create(
                "bc1qSELLER.rig1".into(),
                sv2_target.clone(),
                None,
                0,
                0.0,
                0.0,
            )
            .await
            .unwrap();
        sess.switch_to(order.id.clone(), sv2_target).await.unwrap();

        // The miner is re-pointed: new extranonce (the SV2 channel prefix) + a
        // translated job built from the SV2 future job + prev-hash.
        let set_en = tokio::time::timeout(
            Duration::from_secs(5),
            miner.read_method("mining.set_extranonce"),
        )
        .await
        .expect("miner gets set_extranonce after the rental switch");
        let en1 = set_en.as_array().unwrap()[0].as_str().unwrap().to_string();
        assert_eq!(
            en1, "cccccccc",
            "miner extranonce1 = the SV2 channel prefix"
        );

        let notify =
            tokio::time::timeout(Duration::from_secs(5), miner.read_method("mining.notify"))
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
