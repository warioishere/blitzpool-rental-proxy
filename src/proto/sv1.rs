// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 wire format and pool client. SV1 is JSON-RPC over
//! newline-delimited TCP.
//!
//! The proxy mostly *relays* lines, so the wire type is one struct that can
//! represent both a request (`method` set) and a response (`result`/`error`
//! set) — only the messages the proxy acts on are interpreted further.
//!
//! [`connect_pool`] is the one SV1 pool handshake, used by the SV1 relay
//! (passthrough) and by the SV2 relay (an SV1 pool behind an SV2 miner).

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::proto::translate::VERSION_ROLLING_MASK;
use crate::session::UpstreamTarget;

/// One JSON-RPC line on the wire (request or response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl RpcMessage {
    /// Parse a single wire line (without the trailing newline).
    pub fn parse(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim())
    }

    /// `Ok` only for a `mining.authorize` answered with `true`. A pool that
    /// refuses the login can keep the connection open and reject every share,
    /// which from the outside looks like a rig delivering nothing.
    pub fn check_authorized(&self) -> anyhow::Result<()> {
        if matches!(self.result, Some(Value::Bool(true))) {
            return Ok(());
        }
        Err(crate::proto::LoginRefused(format!(
            "mining.authorize refused (result={}, error={})",
            self.result.as_ref().unwrap_or(&Value::Null),
            self.error.as_ref().unwrap_or(&Value::Null)
        ))
        .into())
    }

    /// The pool's words for a refused request: the message of a
    /// `[code, message, data]` error, else the raw error or result.
    pub fn reject_reason(&self) -> String {
        match self.error.as_ref() {
            Some(Value::Array(a)) => match (a.first(), a.get(1).and_then(Value::as_str)) {
                (Some(code), Some(msg)) => format!("{msg} ({code})"),
                _ => Value::Array(a.clone()).to_string(),
            },
            Some(Value::Null) | None => {
                format!("result={}", self.result.as_ref().unwrap_or(&Value::Null))
            }
            Some(other) => other.to_string(),
        }
    }

    /// Serialize to a wire line *including* the trailing `\n`.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_else(|_| "{}".into());
        s.push('\n');
        s
    }

    /// A request/notification (`id` may be `Null` for notifications).
    pub fn request(id: Value, method: &str, params: Value) -> Self {
        Self {
            id: Some(id),
            method: Some(method.to_string()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    /// A response to request `id`: `result` with a null error.
    pub fn response(id: Option<Value>, result: Value) -> Self {
        Self {
            id,
            method: None,
            params: None,
            result: Some(result),
            error: Some(Value::Null),
        }
    }

    /// A refused request `id`: `result: false` and a `[code, message, null]`
    /// error.
    pub fn refusal(id: Option<Value>, code: i64, message: &str) -> Self {
        Self {
            id,
            method: None,
            params: None,
            result: Some(json!(false)),
            error: Some(json!([code, message, Value::Null])),
        }
    }

    /// The proxy's own `mining.configure` asking a pool for BIP320 version
    /// rolling with [`VERSION_ROLLING_MASK`].
    pub fn version_rolling_configure() -> Self {
        Self::request(
            json!(1),
            "mining.configure",
            json!([["version-rolling"], {"version-rolling.mask": version_rolling_mask_hex()}]),
        )
    }

    /// The version-rolling mask a pool granted in its `mining.configure` reply:
    /// `None` if it refused version rolling, the default mask if it granted it
    /// without naming one.
    fn granted_version_mask(&self) -> Option<u32> {
        let r = self.result.as_ref()?;
        if r.get("version-rolling")?.as_bool() != Some(true) {
            return None;
        }
        let mask = r
            .get("version-rolling.mask")
            .and_then(|v| v.as_str())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        Some(mask.unwrap_or(VERSION_ROLLING_MASK))
    }

    /// `mining.set_extranonce` notification (server → miner) — used on an
    /// upstream switch when the miner supports the extranonce-subscribe
    /// extension.
    pub fn set_extranonce(extranonce1: &str, extranonce2_size: u32) -> Self {
        Self::request(
            Value::Null,
            "mining.set_extranonce",
            json!([extranonce1, extranonce2_size]),
        )
    }

    /// `client.reconnect` (server → miner) — the universal fallback for an
    /// upstream switch when the miner can't take a live extranonce change.
    pub fn client_reconnect(host: &str, port: u16, wait_secs: u32) -> Self {
        Self::request(
            Value::Null,
            "client.reconnect",
            json!([host, port, wait_secs]),
        )
    }
}

/// [`VERSION_ROLLING_MASK`] as the 8-digit hex string SV1 carries it in.
pub fn version_rolling_mask_hex() -> String {
    format!("{VERSION_ROLLING_MASK:08x}")
}

/// A connected SV1 pool, positioned after the handshake.
pub struct PoolConn {
    pub read: BufReader<OwnedReadHalf>,
    pub write: OwnedWriteHalf,
    /// The pool's extranonce1, hex as it came in the subscribe result.
    pub extranonce1: String,
    pub extranonce2_size: u32,
    /// The version-rolling mask the pool granted in reply to `configure`;
    /// `None` when no `configure` was sent or the pool refused version rolling.
    pub version_mask: Option<u32>,
    /// Notifications (`set_difficulty`/`notify`) the pool sent during the
    /// handshake, in order and newline-terminated. They carry the initial
    /// difficulty and first job, so the caller must deliver them: without them
    /// a miner mines at "diff 0" and every share is rejected.
    pub prelude: Vec<String>,
}

/// Connect to an SV1 pool and run `configure` (when given) → `subscribe` →
/// `authorize`.
///
/// `user_identity` is the worker the connection authorizes as. The caller
/// submits shares under the same name: strict pools (e.g. ckpool) reject a
/// submit whose worker differs from the authorized one ("Worker mismatch").
pub async fn connect_pool(
    target: &UpstreamTarget,
    user_identity: &str,
    configure: Option<&RpcMessage>,
) -> anyhow::Result<PoolConn> {
    let tcp = TcpStream::connect(&target.url)
        .await
        .with_context(|| format!("connect sv1 upstream {}", target.url))?;
    let _ = tcp.set_nodelay(true);
    let (r, mut write) = tcp.into_split();
    let mut read = BufReader::new(r);
    let mut prelude: Vec<String> = Vec::new();

    let version_mask = match configure {
        Some(cfg) => {
            write.write_all(cfg.to_line().as_bytes()).await?;
            read_response(&mut read, &mut prelude)
                .await?
                .granted_version_mask()
        }
        None => None,
    };

    let sub = RpcMessage::request(json!(2), "mining.subscribe", json!(["bp-proxy"]));
    write.write_all(sub.to_line().as_bytes()).await?;
    let sub_resp = read_response(&mut read, &mut prelude).await?;
    let (extranonce1, extranonce2_size) =
        parse_subscribe_result(&sub_resp).ok_or_else(|| anyhow::anyhow!("bad subscribe result"))?;

    let auth = RpcMessage::request(
        json!(3),
        "mining.authorize",
        json!([user_identity, target.password]),
    );
    write.write_all(auth.to_line().as_bytes()).await?;
    read_response(&mut read, &mut prelude)
        .await?
        .check_authorized()?;

    Ok(PoolConn {
        read,
        write,
        extranonce1,
        extranonce2_size,
        version_mask,
        prelude,
    })
}

/// Read lines until a *response* (has `result`/`error`, no `method`). Any
/// notifications that interleave the handshake are pushed to `prelude`.
pub(crate) async fn read_response(
    reader: &mut BufReader<OwnedReadHalf>,
    prelude: &mut Vec<String>,
) -> anyhow::Result<RpcMessage> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            anyhow::bail!("sv1 upstream closed during handshake");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(msg) = RpcMessage::parse(trimmed) {
            if msg.method.is_none() {
                return Ok(msg);
            }
            // Keep the newline: these lines are written to the miner verbatim,
            // and stratum is newline-delimited. Without it a notification glues
            // onto the next message and the miner parses only the first.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn only_a_true_authorize_result_counts_as_authorized() {
        let ok = RpcMessage::parse(r#"{"id":3,"result":true,"error":null}"#).unwrap();
        assert!(ok.check_authorized().is_ok());

        let refused =
            RpcMessage::parse(r#"{"id":3,"result":false,"error":[24,"Unauthorized worker",null]}"#)
                .unwrap();
        let err = refused.check_authorized().unwrap_err().to_string();
        assert!(
            err.contains("Unauthorized worker"),
            "the pool's reason is kept: {err}"
        );

        let error_only =
            RpcMessage::parse(r#"{"id":3,"result":null,"error":[20,"Other",null]}"#).unwrap();
        assert!(error_only.check_authorized().is_err());
    }

    #[test]
    fn parses_subscribe_request() {
        let line = r#"{"id":1,"method":"mining.subscribe","params":["cgminer/4.10"]}"#;
        let m = RpcMessage::parse(line).unwrap();
        assert_eq!(m.method.as_deref(), Some("mining.subscribe"));
        assert_eq!(m.id, Some(json!(1)));
    }

    #[test]
    fn parses_response_without_method() {
        let line = r#"{"id":2,"result":true,"error":null}"#;
        let m = RpcMessage::parse(line).unwrap();
        assert!(m.method.is_none());
        assert_eq!(m.result, Some(json!(true)));
    }

    #[test]
    fn set_extranonce_roundtrip() {
        let e = RpcMessage::set_extranonce("deadbeef", 4);
        let parsed = RpcMessage::parse(e.to_line().trim()).unwrap();
        assert_eq!(parsed.method.as_deref(), Some("mining.set_extranonce"));
    }

    /// The pool's initial `set_difficulty` + `notify` interleave the handshake
    /// (they arrive before/around the authorize reply). `read_response` must keep
    /// them in `prelude` (so the relay can forward them) and still return the
    /// response — dropping them leaves the miner at "diff 0" → every share
    /// rejected as "Difficulty too low".
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
            s.write_all(b"{\"id\":2,\"result\":true,\"error\":null}\n")
                .await
                .unwrap();
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
