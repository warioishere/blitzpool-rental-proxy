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
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::sv1::RpcMessage;
use crate::registry::Registry;
use crate::session::{HashrateWindow, Routing, UpstreamTarget};
use crate::store::SellerStore;

/// Standard BIP320 version-rolling mask we advertise to the miner.
const VERSION_ROLLING_MASK: &str = "1fffe000";

type Tx = mpsc::UnboundedSender<String>;

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
    routing: Routing,
    default_target: UpstreamTarget,
    /// Miner's `mining.configure` (remembered to replay to each upstream).
    configure: Option<RpcMessage>,
    extranonce_capable: bool,
    label: String,
}

/// A live seller-miner session. Held by the relay tasks and the registry.
pub struct Session {
    to_miner: Tx,
    inner: Mutex<Inner>,
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
        info!(upstream = %target.url, generation, capable, "upstream switched");
        Ok(())
    }

    /// Process a line from the upstream tagged `generation`; returns the line
    /// to forward to the miner (or `None` to drop a stale-upstream line).
    async fn on_upstream_msg(&self, generation: u64, msg: RpcMessage) -> Option<String> {
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
                // A response — credit accepted submits to the hashrate window.
                let idk = id_key(&msg.id);
                if let Some((g, diff)) = i.pending.remove(&idk) {
                    if g == generation && matches!(&msg.result, Some(Value::Bool(true))) {
                        i.hashrate.record(diff);
                        debug!(worker = %i.label, hashrate = i.hashrate.hashes_per_second(), "accepted share");
                    }
                }
            }
            _ => {}
        }
        Some(msg.to_line())
    }

    /// Process a line from the miner; sends the (possibly rewritten) line to
    /// the active upstream. `registry`/`self_arc` let an `authorize` register
    /// the session under the miner's worker name.
    async fn on_miner_msg(self: &Arc<Self>, mut msg: RpcMessage, registry: &Arc<Registry>) {
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
                    registry.insert(w.to_string(), self.clone()).await;
                }
                msg.params = Some(json!([i.active.target.user, i.active.target.password]));
            }
            Some("mining.submit") => {
                let diff = i.current_difficulty;
                let g = i.active.generation;
                i.pending.insert(id_key(&msg.id), (g, diff));
                if let Some(arr) = msg.params.as_mut().and_then(|p| p.as_array_mut()) {
                    if let Some(first) = arr.first_mut() {
                        *first = json!(i.active.target.user);
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
        }
    }
}

/// API-facing snapshot of a live session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionStatus {
    pub worker: String,
    pub routing: String,
    pub order_id: Option<String>,
    pub upstream_url: String,
    pub hashrate_hs: f64,
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

    if let Some(cfg) = configure {
        w.write_all(cfg.to_line().as_bytes()).await?;
        let _ = read_response(&mut reader).await?; // discard upstream configure reply
    }

    let sub = RpcMessage::request(json!(1), "mining.subscribe", json!(["stratum-rental-proxy/0.1"]));
    w.write_all(sub.to_line().as_bytes()).await?;
    let sub_resp = read_response(&mut reader).await?;
    let (extranonce1, extranonce2_size) =
        parse_subscribe_result(&sub_resp).ok_or_else(|| anyhow::anyhow!("bad subscribe result"))?;

    let auth = RpcMessage::request(json!(2), "mining.authorize", json!([target.user, target.password]));
    w.write_all(auth.to_line().as_bytes()).await?;
    let _ = read_response(&mut reader).await?; // authorize reply (value ignored for now)

    Ok(UpstreamConn {
        reader,
        write: w,
        extranonce1,
        extranonce2_size,
    })
}

/// Read lines until a *response* (has `result`/`error`, no `method`), skipping
/// notifications (`set_difficulty`/`notify`) that may interleave a handshake.
async fn read_response(reader: &mut BufReader<OwnedReadHalf>) -> anyhow::Result<RpcMessage> {
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

/// Drive one seller miner end to end. Connects the default upstream, answers
/// the miner handshake (synthesizing configure + subscribe), registers the
/// session under the miner's worker, then relays until either side closes.
pub async fn handle_seller_miner(
    miner: TcpStream,
    peer: String,
    default_target: UpstreamTarget,
    registry: Arc<Registry>,
    sellers: Arc<SellerStore>,
) -> anyhow::Result<()> {
    let _ = miner.set_nodelay(true);
    let (miner_r, miner_w) = miner.into_split();

    let (to_miner, to_miner_rx) = mpsc::unbounded_channel::<String>();
    let miner_writer = spawn_writer(miner_w, to_miner_rx);

    // Connect the default upstream up front (idle routing).
    let conn = connect_upstream(&default_target, None)
        .await
        .map_err(|e| anyhow::anyhow!("connect default upstream {}: {e}", default_target.url))?;
    let en1 = conn.extranonce1.clone();
    let en2 = conn.extranonce2_size;

    let (to_up, up_rx) = mpsc::unbounded_channel::<String>();
    let up_writer = spawn_writer(conn.write, up_rx);

    let session = Arc::new(Session {
        to_miner: to_miner.clone(),
        inner: Mutex::new(Inner {
            active: ActiveUpstream {
                generation: 0,
                target: default_target.clone(),
                to_up,
                reader: tokio::spawn(async {}), // placeholder, replaced below
                writer: up_writer,
            },
            generation_counter: 0,
            current_difficulty: 1.0,
            pending: HashMap::new(),
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
            routing: Routing::Idle,
            default_target: default_target.clone(),
            configure: None,
            extranonce_capable: false,
            label: peer.clone(),
        }),
    });

    // Now that the Session exists, wire the upstream reader to it.
    {
        let reader = spawn_upstream_reader(session.clone(), 0, conn.reader);
        let mut i = session.inner.lock().await;
        let old = std::mem::replace(&mut i.active.reader, reader);
        old.abort();
    }

    info!(%peer, upstream = %default_target.url, "relay established (idle)");

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
                    session.on_miner_msg(msg, &registry).await;
                    // On authorize, apply this seller's configured default pool
                    // (if any) when it differs from the process-wide default.
                    if let Some(w) = auth_worker {
                        if let Some(def) = sellers.get(&w).await {
                            if session.default_target().await != def {
                                match session.set_default(def.clone()).await {
                                    Ok(()) => info!(worker = %w, upstream = %def.url, "applied seller default pool"),
                                    Err(e) => warn!(worker = %w, error = %e, "apply seller default failed"),
                                }
                            }
                        }
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
    registry.remove_if(&worker, &session).await;
    {
        let i = session.inner.lock().await;
        i.active.reader.abort();
        i.active.writer.abort();
    }
    miner_writer.abort();
    info!(%peer, "relay closed");
    Ok(())
}
