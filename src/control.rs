//! Minimal control API for M2: line-delimited JSON over TCP to switch a
//! connected miner's upstream. A proper authenticated HTTP/web API arrives in
//! milestone 3 — this is enough to drive + test the runtime switch.
//!
//! Commands (one JSON object per line):
//!   {"cmd":"list"}
//!   {"cmd":"set_target","worker":"<w>","url":"host:port","user":"acct","pass":"x","order_id":"o1"}
//!   {"cmd":"clear_target","worker":"<w>"}
//! Reply: {"ok":true,...} or {"ok":false,"error":"..."}.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::registry::Registry;
use crate::session::UpstreamTarget;

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    List,
    SetTarget {
        worker: String,
        #[serde(default)]
        order_id: Option<String>,
        url: String,
        user: String,
        #[serde(default)]
        pass: String,
    },
    ClearTarget {
        worker: String,
    },
}

pub async fn run(addr: String, registry: Arc<Registry>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "control API listening");
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "control accept failed");
                continue;
            }
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let resp = handle(&registry, line.trim()).await;
                if w.write_all((resp.to_string() + "\n").as_bytes()).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn handle(registry: &Arc<Registry>, line: &str) -> Value {
    let cmd: Command = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => return json!({"ok": false, "error": format!("bad command: {e}")}),
    };
    match cmd {
        Command::List => json!({"ok": true, "workers": registry.list().await}),
        Command::SetTarget {
            worker,
            order_id,
            url,
            user,
            pass,
        } => match registry.get(&worker).await {
            Some(session) => {
                let target = UpstreamTarget {
                    url,
                    user,
                    password: pass,
                };
                match session.switch_to(order_id.unwrap_or_default(), target).await {
                    Ok(()) => json!({"ok": true}),
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                }
            }
            None => json!({"ok": false, "error": "worker not connected"}),
        },
        Command::ClearTarget { worker } => match registry.get(&worker).await {
            Some(session) => match session.revert().await {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            },
            None => json!({"ok": false, "error": "worker not connected"}),
        },
    }
}
