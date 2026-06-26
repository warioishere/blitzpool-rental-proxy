//! Per-connection SV1 relay: a seller's miner (downstream) ⇄ upstream pool.
//!
//! Transparent pass-through: the miner's handshake (`configure`/`subscribe`/
//! `extranonce.subscribe`) is forwarded verbatim so the miner mines as if
//! wired straight to the upstream; only `authorize` credentials and the
//! `submit` worker name are rewritten to the upstream account. Accepted
//! submits feed the per-miner hashrate window.
//!
//! Upstream state (extranonce1/size, current difficulty) and the miner's
//! extranonce-subscribe capability are captured here for the runtime
//! pool-switch (milestone 2) — they aren't acted on yet.
//!
//! IDs are forwarded verbatim in both directions: the upstream echoes the
//! miner's request ids, so responses route back without remapping. Submit ids
//! are remembered (→ difficulty at submit time) so an accepted-share response
//! can be credited to the hashrate window.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

use super::sv1::RpcMessage;
use crate::session::{HashrateWindow, UpstreamTarget};

struct RelayState {
    upstream: UpstreamTarget,
    /// Latest difficulty announced by the upstream (`mining.set_difficulty`).
    current_difficulty: f64,
    /// Set when the miner sends `mining.extranonce.subscribe` (needed for a
    /// seamless switch in milestone 2).
    miner_extranonce_capable: bool,
    upstream_extranonce1: Option<String>,
    upstream_extranonce2_size: Option<u32>,
    /// submit id (serialized) → difficulty at submit time.
    pending_submits: HashMap<String, f64>,
    hashrate: HashrateWindow,
    /// Worker label the miner authorized with (for logs).
    miner_label: String,
}

fn id_key(id: &Option<Value>) -> String {
    id.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "null".into())
}

/// Drive one seller miner: connect its (default) upstream and relay until
/// either side closes.
pub async fn handle_seller_miner(
    miner: TcpStream,
    peer: String,
    upstream: UpstreamTarget,
) -> anyhow::Result<()> {
    let up = TcpStream::connect(&upstream.url)
        .await
        .map_err(|e| anyhow::anyhow!("connect upstream {}: {e}", upstream.url))?;
    let _ = miner.set_nodelay(true);
    let _ = up.set_nodelay(true);
    info!(%peer, upstream = %upstream.url, "relay established");

    let (miner_r, mut miner_w) = miner.into_split();
    let (up_r, mut up_w) = up.into_split();

    let (to_miner_tx, mut to_miner_rx) = mpsc::unbounded_channel::<String>();
    let (to_up_tx, mut to_up_rx) = mpsc::unbounded_channel::<String>();

    let state = Arc::new(Mutex::new(RelayState {
        upstream: upstream.clone(),
        current_difficulty: 1.0,
        miner_extranonce_capable: false,
        upstream_extranonce1: None,
        upstream_extranonce2_size: None,
        pending_submits: HashMap::new(),
        hashrate: HashrateWindow::new(Duration::from_secs(600)),
        miner_label: peer.clone(),
    }));

    // Single-writer task per socket; they end when their channel closes.
    let w_miner = tokio::spawn(async move {
        while let Some(line) = to_miner_rx.recv().await {
            if miner_w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let w_up = tokio::spawn(async move {
        while let Some(line) = to_up_rx.recv().await {
            if up_w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    // Miner → upstream.
    let st_m = state.clone();
    let to_up = to_up_tx.clone();
    let mut miner_reader = tokio::spawn(async move {
        let mut lines = BufReader::new(miner_r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = RpcMessage::parse(&line) else {
                debug!(line, "unparseable from miner");
                continue;
            };
            let out = handle_from_miner(&st_m, msg).await;
            if to_up.send(out).is_err() {
                break;
            }
        }
    });

    // Upstream → miner.
    let st_u = state.clone();
    let to_miner = to_miner_tx.clone();
    let mut up_reader = tokio::spawn(async move {
        let mut lines = BufReader::new(up_r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = RpcMessage::parse(&line) else {
                debug!(line, "unparseable from upstream");
                continue;
            };
            let out = handle_from_upstream(&st_u, msg).await;
            if to_miner.send(out).is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut miner_reader => { up_reader.abort(); }
        _ = &mut up_reader => { miner_reader.abort(); }
    }
    w_miner.abort();
    w_up.abort();
    info!(%peer, "relay closed");
    Ok(())
}

/// Process a line from the miner; returns the line to send upstream.
async fn handle_from_miner(state: &Arc<Mutex<RelayState>>, mut msg: RpcMessage) -> String {
    match msg.method.as_deref() {
        Some("mining.authorize") => {
            let mut st = state.lock().await;
            if let Some(w) = msg
                .params
                .as_ref()
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                st.miner_label = w.to_string();
            }
            // Authorize to the upstream with the routed account, not the
            // miner's own credentials.
            msg.params = Some(json!([st.upstream.user, st.upstream.password]));
        }
        Some("mining.submit") => {
            let mut st = state.lock().await;
            let diff = st.current_difficulty;
            st.pending_submits.insert(id_key(&msg.id), diff);
            // Rewrite the worker (param 0) to the upstream account.
            if let Some(arr) = msg.params.as_mut().and_then(|p| p.as_array_mut()) {
                if let Some(first) = arr.first_mut() {
                    *first = json!(st.upstream.user);
                }
            }
        }
        Some("mining.extranonce.subscribe") => {
            state.lock().await.miner_extranonce_capable = true;
            // Forwarded verbatim — the upstream may honor it too.
        }
        _ => {} // configure / subscribe / suggest_difficulty / etc. — verbatim
    }
    msg.to_line()
}

/// Process a line from the upstream; returns the line to send to the miner.
async fn handle_from_upstream(state: &Arc<Mutex<RelayState>>, msg: RpcMessage) -> String {
    match msg.method.as_deref() {
        Some("mining.set_difficulty") => {
            if let Some(d) = msg
                .params
                .as_ref()
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_f64())
            {
                state.lock().await.current_difficulty = d;
                debug!(difficulty = d, "upstream set_difficulty");
            }
        }
        Some("mining.set_extranonce") => {
            if let Some(arr) = msg.params.as_ref().and_then(|p| p.as_array()) {
                let mut st = state.lock().await;
                st.upstream_extranonce1 = arr.first().and_then(|v| v.as_str()).map(str::to_string);
                st.upstream_extranonce2_size = arr.get(1).and_then(|v| v.as_u64()).map(|n| n as u32);
            }
        }
        Some(_) => {} // mining.notify etc. — verbatim
        None => {
            // A response. Submit ack → credit hashrate; subscribe result →
            // capture extranonce.
            let idk = id_key(&msg.id);
            let mut st = state.lock().await;
            if let Some(diff) = st.pending_submits.remove(&idk) {
                if matches!(&msg.result, Some(Value::Bool(true))) {
                    st.hashrate.record(diff);
                    debug!(
                        worker = %st.miner_label,
                        hashrate = st.hashrate.hashes_per_second(),
                        "accepted share"
                    );
                } else {
                    debug!(error = ?msg.error, "rejected share");
                }
            } else if let Some(arr) = msg.result.as_ref().and_then(|r| r.as_array()) {
                // mining.subscribe result: [subscriptions, extranonce1, en2_size]
                if arr.len() == 3 {
                    if let (Some(en1), Some(en2)) = (arr[1].as_str(), arr[2].as_u64()) {
                        st.upstream_extranonce1 = Some(en1.to_string());
                        st.upstream_extranonce2_size = Some(en2 as u32);
                        debug!(extranonce1 = en1, en2_size = en2, "captured upstream extranonce");
                    }
                }
            }
        }
    }
    msg.to_line()
}
