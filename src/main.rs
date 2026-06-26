//! stratum-rental-proxy — entry point.
//!
//! Milestone 1 scaffold: binds the downstream Stratum server and accepts
//! seller miners. The per-connection handler (SV1 handshake → connect default
//! upstream → relay + hashrate) and the runtime pool-switch are the next
//! increments; the foundations (`proto::sv1` codec, `session`) are in place.

// Foundations are scaffolded ahead of being wired; silence dead-code noise
// until the relay + control layers consume them.
#![allow(dead_code)]

mod api;
mod config;
mod proto;
mod registry;
mod session;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::from_env();
    info!(listen = %cfg.listen, "stratum-rental-proxy starting");

    // M1: one default upstream for everyone (per-seller config = M3,
    // rentals = M2). Without it there's nothing to relay to.
    let upstream = cfg.default_upstream.clone().context(
        "set RENTAL_PROXY_POOL_URL (+ _USER/_PASS) — milestone 1 relays every \
         miner to this default upstream",
    )?;
    info!(upstream = %upstream.url, "default upstream");

    let registry = registry::Registry::new();

    // HTTP control API — the proxy is fully steerable here; the web UI calls it.
    let api_addr = std::env::var("RENTAL_PROXY_API").unwrap_or_else(|_| "127.0.0.1:8080".into());
    {
        let state = api::AppState {
            registry: registry.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = api::serve(api_addr, state).await {
                warn!(error = %e, "HTTP API stopped");
            }
        });
    }

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!("listening for seller miners");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let upstream = upstream.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let peer = peer.to_string();
            if let Err(e) =
                proto::relay::handle_seller_miner(sock, peer.clone(), upstream, registry).await
            {
                warn!(%peer, error = %e, "relay ended with error");
            }
        });
    }
}
