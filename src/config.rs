//! Static process configuration. Seller/buyer/order state is runtime (control
//! API, milestone 3) — this only holds boot-time settings.
//!
//! Milestone 1 has no seller registry yet, so a single default upstream is
//! taken from the environment to make the relay testable end-to-end:
//!   RENTAL_PROXY_LISTEN     (default 0.0.0.0:3333) — the one downstream port
//!   RENTAL_PROXY_PROTOCOL   sv1 | sv2 | both (default sv1). `both` auto-detects
//!                           SV1 vs SV2 per connection on the same port.
//!   RENTAL_PROXY_POOL_URL   host:port of the upstream to relay to
//!   RENTAL_PROXY_POOL_USER  account/worker at the upstream
//!   RENTAL_PROXY_POOL_PASS  (default "x")

use crate::session::UpstreamTarget;

/// Which Stratum protocol the downstream listener speaks. Selects the
/// [`crate::proto::adapter::DownstreamAdapter`] at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Sv1,
    Sv2,
    /// Serve SV1 and SV2 on the same port: the first byte of each connection
    /// is peeked to classify it (SV1 JSON vs SV2 Noise) and dispatched to the
    /// matching adapter. One listener, one shared registry/state/control API.
    Both,
}

impl Protocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sv1" | "v1" | "1" | "stratum1" => Some(Protocol::Sv1),
            "sv2" | "v2" | "2" | "stratum2" => Some(Protocol::Sv2),
            "both" | "sv1+sv2" | "all" => Some(Protocol::Both),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the downstream Stratum server listens on for sellers' miners.
    pub listen: String,
    /// Wire protocol spoken to sellers' miners (RENTAL_PROXY_PROTOCOL).
    pub protocol: Protocol,
    /// Default upstream every miner relays to until per-seller config (M3)
    /// and rentals (M2) exist. `None` until configured.
    pub default_upstream: Option<UpstreamTarget>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:3333".to_string(),
            protocol: Protocol::default(),
            default_upstream: None,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(listen) = std::env::var("RENTAL_PROXY_LISTEN") {
            c.listen = listen;
        }
        if let Ok(proto) = std::env::var("RENTAL_PROXY_PROTOCOL") {
            if let Some(p) = Protocol::parse(&proto) {
                c.protocol = p;
            }
        }
        if let Ok(url) = std::env::var("RENTAL_PROXY_POOL_URL") {
            c.default_upstream = Some(UpstreamTarget {
                url,
                user: std::env::var("RENTAL_PROXY_POOL_USER").unwrap_or_default(),
                password: std::env::var("RENTAL_PROXY_POOL_PASS").unwrap_or_else(|_| "x".into()),
                authority_pubkey: std::env::var("RENTAL_PROXY_POOL_AUTHORITY").ok(),
            });
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_parse_accepts_known_aliases() {
        assert_eq!(Protocol::parse("sv1"), Some(Protocol::Sv1));
        assert_eq!(Protocol::parse("V1"), Some(Protocol::Sv1));
        assert_eq!(Protocol::parse("sv2"), Some(Protocol::Sv2));
        assert_eq!(Protocol::parse("2"), Some(Protocol::Sv2));
        assert_eq!(Protocol::parse(" both "), Some(Protocol::Both));
        assert_eq!(Protocol::parse("SV1+SV2"), Some(Protocol::Both));
        assert_eq!(Protocol::parse("nonsense"), None);
    }

    #[test]
    fn protocol_defaults_to_sv1() {
        assert_eq!(Protocol::default(), Protocol::Sv1);
    }
}
