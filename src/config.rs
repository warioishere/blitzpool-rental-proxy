// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-time configuration of the Stratum listener. Rigs and orders are
//! runtime state (SQLite, steered through the control API).
//!
//!   RENTAL_PROXY_LISTEN     (default 0.0.0.0:3333) — the one downstream port;
//!                           SV1 and SV2 are told apart per connection.
//!   RENTAL_PROXY_POOL_URL   host:port of the SV1 handshake-bootstrap pool
//!   RENTAL_PROXY_POOL_USER  account/worker at that pool
//!   RENTAL_PROXY_POOL_PASS  (default "x")

use crate::session::UpstreamTarget;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the downstream Stratum server listens on for sellers' miners.
    pub listen: String,
    /// SV1 handshake-bootstrap pool (see [`crate::proto::ProxyContext`]).
    /// `None` when unset: SV1 miners are then refused, SV2 works.
    pub default_upstream: Option<UpstreamTarget>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            listen: std::env::var("RENTAL_PROXY_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:3333".to_string()),
            default_upstream: std::env::var("RENTAL_PROXY_POOL_URL").ok().map(|url| {
                UpstreamTarget {
                    url,
                    user: std::env::var("RENTAL_PROXY_POOL_USER").unwrap_or_default(),
                    password: std::env::var("RENTAL_PROXY_POOL_PASS")
                        .unwrap_or_else(|_| "x".into()),
                    authority_pubkey: std::env::var("RENTAL_PROXY_POOL_AUTHORITY").ok(),
                }
            }),
        }
    }
}
