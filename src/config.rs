//! Static process configuration. Seller/buyer/order state is runtime (control
//! API, milestone 3) — this only holds boot-time settings.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address the downstream Stratum server listens on for sellers' miners.
    pub listen: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:3333".to_string(),
        }
    }
}

impl Config {
    /// Minimal env-based config for the scaffold; a file loader comes with the
    /// control/config layer in milestone 3.
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(listen) = std::env::var("RENTAL_PROXY_LISTEN") {
            c.listen = listen;
        }
        c
    }
}
