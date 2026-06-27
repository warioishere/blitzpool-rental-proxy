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

#[cfg(test)]
mod tests {
    use super::*;

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
}
