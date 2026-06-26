//! Stratum V1 protocol adapter: line codec + (later) downstream server and
//! swappable upstream client. SV1 is JSON-RPC over newline-delimited TCP.
//!
//! The proxy mostly *relays* lines, so the wire type is one struct that can
//! represent both a request (`method` set) and a response (`result`/`error`
//! set) — only the messages the proxy acts on are interpreted further.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

    /// Serialize to a wire line *including* the trailing `\n`.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_else(|_| "{}".into());
        s.push('\n');
        s
    }

    pub fn is_method(&self, m: &str) -> bool {
        self.method.as_deref() == Some(m)
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

    /// `mining.set_difficulty` notification (server → miner).
    pub fn set_difficulty(diff: f64) -> Self {
        Self::request(Value::Null, "mining.set_difficulty", json!([diff]))
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

/// Fields of a `mining.submit` (miner → upstream), positional params:
/// `[worker_name, job_id, extranonce2, ntime, nonce]`.
#[derive(Debug, Clone)]
pub struct Submit {
    pub worker: String,
    pub job_id: String,
    pub extranonce2: String,
    pub ntime: String,
    pub nonce: String,
}

impl Submit {
    pub fn from_message(msg: &RpcMessage) -> Option<Self> {
        if !msg.is_method("mining.submit") {
            return None;
        }
        let p = msg.params.as_ref()?.as_array()?;
        let s = |i: usize| p.get(i).and_then(|v| v.as_str()).map(str::to_string);
        Some(Self {
            worker: s(0)?,
            job_id: s(1)?,
            extranonce2: s(2)?,
            ntime: s(3)?,
            nonce: s(4)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subscribe_request() {
        let line = r#"{"id":1,"method":"mining.subscribe","params":["cgminer/4.10"]}"#;
        let m = RpcMessage::parse(line).unwrap();
        assert!(m.is_method("mining.subscribe"));
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
    fn reads_submit_fields() {
        let line = r#"{"id":4,"method":"mining.submit","params":["addr.worker","job1","00000000","65000000","12345678"]}"#;
        let m = RpcMessage::parse(line).unwrap();
        let s = Submit::from_message(&m).unwrap();
        assert_eq!(s.worker, "addr.worker");
        assert_eq!(s.job_id, "job1");
        assert_eq!(s.nonce, "12345678");
    }

    #[test]
    fn set_difficulty_and_extranonce_roundtrip() {
        let d = RpcMessage::set_difficulty(1024.0);
        assert!(d.to_line().contains("mining.set_difficulty"));
        let e = RpcMessage::set_extranonce("deadbeef", 4);
        let parsed = RpcMessage::parse(e.to_line().trim()).unwrap();
        assert!(parsed.is_method("mining.set_extranonce"));
    }
}
