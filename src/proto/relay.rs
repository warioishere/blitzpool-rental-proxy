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
use crate::registry::Registry;
use crate::session::{HashrateWindow, Routing, UpstreamTarget};

/// Standard BIP320 version-rolling mask we advertise to the miner.
const VERSION_ROLLING_MASK: &str = "1fffe000";

type Tx = mpsc::UnboundedSender<String>;

/// How long a reconnect-hint stays valid (the miner should reconnect at once).
const RECONNECT_HINT_TTL: Duration = Duration::from_secs(120);

/// After authorize, how long to wait for the miner's `mining.extranonce.subscribe`
/// before deciding live-switch vs reconnect. Miners (e.g. BitAxe) send it only
/// after they receive the authorize result, so the proxy must give it a moment.
/// The wait ends as soon as the subscribe arrives — this is only the ceiling for
/// miners that never send it (they then take the reconnect path). 50ms is enough
/// in practice (confirmed from earlier TS-pool testing with a BitAxe).
const EXTRANONCE_GRACE: Duration = Duration::from_millis(50);

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
fn upstream_worker(account: &str, miner_label: &str) -> String {
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
}

/// A live seller-miner session. Held by the relay tasks and the registry.
pub struct Session {
    to_miner: Tx,
    inner: Mutex<Inner>,
    /// For crediting measured delivered work to the active rental order.
    orders: Arc<crate::orders::OrderStore>,
}

impl Session {
    /// Switch this session's hashrate to `target` (a rental starts).
    pub async fn switch_to(self: &Arc<Self>, order_id: String, target: UpstreamTarget) -> anyhow::Result<()> {
        self.swap_upstream(target.clone(), Routing::Rented {
            order_id,
            target,
            until_unix_ms: 0,
        })
        .await
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

    pub async fn default_target(&self) -> UpstreamTarget {
        self.inner.lock().await.default_target.clone()
    }

    /// Current upstream this session relays to (idle pool or rented target).
    pub async fn active_target(&self) -> UpstreamTarget {
        self.inner.lock().await.active.target.clone()
    }

    /// Mark this session as serving `order` WITHOUT reconnecting the upstream —
    /// used when the handshake already connected the rental's target (a resolved
    /// reconnect), so the miner keeps the extranonce it was given.
    pub async fn attach_order(&self, order_id: String, target: UpstreamTarget) {
        let mut i = self.inner.lock().await;
        i.routing = Routing::Rented {
            order_id,
            target,
            until_unix_ms: 0,
        };
    }

    async fn swap_upstream(self: &Arc<Self>, target: UpstreamTarget, routing: Routing) -> anyhow::Result<()> {
        // Snapshot what the handshake needs without holding the lock across IO.
        let (configure, capable, generation) = {
            let mut i = self.inner.lock().await;
            i.generation_counter += 1;
            (i.configure.clone(), i.extranonce_capable, i.generation_counter)
        };

        // Connect + handshake the new upstream BEFORE tearing down the old, so
        // a failed switch leaves the miner mining on the current upstream.
        let conn = connect_upstream(&target, configure.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("switch: connect {}: {e}", target.url))?;

        let (to_up, rx) = mpsc::unbounded_channel::<String>();
        let writer = spawn_writer(conn.write, rx);
        let reader = spawn_upstream_reader(self.clone(), generation, conn.reader);

        // Swap atomically: abort the old upstream, install the new one.
        {
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
            i.routing = routing;
        }

        // Tell the miner about the new extranonce. Modern ASICs honor this
        // live; the new upstream's set_difficulty + notify follow via its
        // reader. (Non-extranonce-capable miners are a deferred case.)
        if capable {
            let _ = self
                .to_miner
                .send(RpcMessage::set_extranonce(&conn.extranonce1, conn.extranonce2_size).to_line());
        } else {
            warn!(upstream = %target.url, "miner not extranonce-capable; live switch may need a reconnect");
        }
        // Forward the new upstream's initial set_difficulty + notify so the miner
        // re-targets to the new pool (else it keeps the old / "diff 0" and the new
        // pool rejects every share as "Difficulty too low").
        for line in conn.prelude {
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
            self.orders.add_work(&order_id, diff, 1).await;
        }
        Some(msg.to_line())
    }

    /// Process a line from the miner; sends the (possibly rewritten) line to
    /// the active upstream. `registry`/`self_arc` let an `authorize` register
    /// the session under the miner's worker name.
    async fn on_miner_msg(self: &Arc<Self>, mut msg: RpcMessage, registry: &Arc<Registry>) {
        let mut submit_order: Option<String> = None;
        {
            let mut i = self.inner.lock().await;
            match msg.method.as_deref() {
                Some("mining.authorize") => {
                    if let Some(w) = msg
                        .params
                        .as_ref()
                        .and_then(|p| p.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                    {
                        i.label = w.to_string();
                        registry.insert(w.to_string(), AnySession::Sv1(self.clone())).await;
                    }
                    let up_worker = upstream_worker(&i.active.target.user, &i.label);
                    msg.params = Some(json!([up_worker, i.active.target.password]));
                }
                Some("mining.submit") => {
                    let diff = i.current_difficulty;
                    let g = i.active.generation;
                    i.pending.insert(id_key(&msg.id), (g, diff));
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
            self.orders.add_submitted(&order_id, 1).await;
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

    let auth = RpcMessage::request(json!(2), "mining.authorize", json!([target.user, target.password]));
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
            prelude.push(trimmed.to_string());
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
    })
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

    let (to_miner, to_miner_rx) = mpsc::unbounded_channel::<String>();
    let miner_writer = spawn_writer(miner_w, to_miner_rx);

    // Connect the handshake upstream up front (idle routing).
    let conn = connect_upstream(&handshake_target, None)
        .await
        .map_err(|e| anyhow::anyhow!("connect upstream {}: {e}", handshake_target.url))?;
    let en1 = conn.extranonce1.clone();
    let en2 = conn.extranonce2_size;
    let initial_prelude = conn.prelude;

    let (to_up, up_rx) = mpsc::unbounded_channel::<String>();
    let up_writer = spawn_writer(conn.write, up_rx);

    let session = Arc::new(Session {
        to_miner: to_miner.clone(),
        orders: orders.clone(),
        inner: Mutex::new(Inner {
            active: ActiveUpstream {
                generation: 0,
                target: handshake_target.clone(),
                to_up,
                reader: tokio::spawn(async {}), // placeholder, replaced below
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
            default_target: handshake_target.clone(),
            configure: None,
            extranonce_capable: false,
            label: peer.clone(),
            pending_prelude: initial_prelude,
        }),
    });

    // Now that the Session exists, wire the upstream reader to it.
    {
        let reader = spawn_upstream_reader(session.clone(), 0, conn.reader);
        let mut i = session.inner.lock().await;
        let old = std::mem::replace(&mut i.active.reader, reader);
        old.abort();
    }

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
                    // Answer with the (current) upstream's extranonce.
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
                    // Now flush the upstream's initial set_difficulty + notify that
                    // arrived during the handshake (before the miner subscribed).
                    let prelude = std::mem::take(&mut session.inner.lock().await.pending_prelude);
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
                                    session.attach_order(o.id.clone(), o.target.clone()).await;
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
                                                    session.on_miner_msg(gm, &registry).await;
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
                        session.on_miner_msg(msg, &registry).await;
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
        server.await.unwrap();
    }
}
