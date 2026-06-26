//! Static process configuration. Seller/buyer/order state is runtime (control
//! API, milestone 3) — this only holds boot-time settings.
//!
//! Milestone 1 has no seller registry yet, so a single default upstream is
//! taken from the environment to make the relay testable end-to-end:
//!   RENTAL_PROXY_LISTEN     (default 0.0.0.0:3333)
//!   RENTAL_PROXY_POOL_URL   host:port of the upstream to relay to
//!   RENTAL_PROXY_POOL_USER  account/worker at the upstream
//!   RENTAL_PROXY_POOL_PASS  (default "x")

use crate::session::UpstreamTarget;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the downstream Stratum server listens on for sellers' miners.
    pub listen: String,
    /// Default upstream every miner relays to until per-seller config (M3)
    /// and rentals (M2) exist. `None` until configured.
    pub default_upstream: Option<UpstreamTarget>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:3333".to_string(),
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
        if let Ok(url) = std::env::var("RENTAL_PROXY_POOL_URL") {
            c.default_upstream = Some(UpstreamTarget {
                url,
                user: std::env::var("RENTAL_PROXY_POOL_USER").unwrap_or_default(),
                password: std::env::var("RENTAL_PROXY_POOL_PASS").unwrap_or_else(|_| "x".into()),
            });
        }
        c
    }
}
