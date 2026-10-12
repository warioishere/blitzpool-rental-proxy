// SPDX-License-Identifier: AGPL-3.0-or-later

//! stratum-rental-proxy — entry point.
//!
//! Binds the downstream Stratum server (SV1 and SV2 on one port),
//! accepts seller miners, and drives each through its protocol relay with a
//! swappable upstream: idle → the rig's default pool, rented → the buyer's pool.
//! Persistent rig/order state lives in SQLite; the HTTP control API steers
//! rentals and the expiry task auto-reverts finished ones.

mod api;
mod chain;
mod config;
mod control;
mod db;
mod hashrate;
mod orders;
mod probe;
mod proto;
mod registry;
mod session;
mod store;

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use proto::ProxyContext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::from_env();
    info!(listen = %cfg.listen, "stratum-rental-proxy starting");

    // Register-only: only workers with a registered rig (or an active rental)
    // are served. The optional default upstream is purely an SV1 handshake
    // bootstrap (SV2 needs none). Unset ⇒ SV1 unavailable, SV2 register-only.
    match &cfg.default_upstream {
        Some(u) => info!(bootstrap = %u.url, "SV1 handshake bootstrap configured (register-only routing)"),
        None => info!("no SV1 bootstrap (RENTAL_PROXY_POOL_URL unset) — SV2 register-only; SV1 miners rejected"),
    }

    // The Bitcoin tip the pool probe checks a buyer pool's first job against.
    let chain = chain::Electrum::from_env()
        .context("RENTAL_PROXY_ELECTRUM")?
        .map(Arc::new);
    match &chain {
        Some(e) => {
            info!(electrum = %e.describe(), "pool probe checks jobs against the Bitcoin tip")
        }
        None => warn!("RENTAL_PROXY_ELECTRUM unset — the pool probe does not check the chain"),
    }

    let registry = registry::Registry::new();

    // Persistent state (rigs + orders) in one embedded SQLite file.
    let db_url =
        std::env::var("RENTAL_PROXY_DB").unwrap_or_else(|_| "sqlite://rental-proxy.db".into());
    let pool = db::connect(&db_url)
        .await
        .with_context(|| format!("open state DB {db_url}"))?;
    info!(db = %db_url, "state database ready");

    let sellers = store::SellerStore::new(pool.clone());
    let orders = orders::OrderStore::new(pool.clone());
    let hashrate = hashrate::HashrateStore::new(pool.clone());

    // Auto-revert expired rentals.
    orders::spawn_expiry(orders.clone(), registry.clone());

    // Sample each rig's delivered hashrate into 10-min slots (marketplace chart).
    hashrate::spawn_sampler(registry.clone(), sellers.clone(), hashrate.clone());

    // HTTP control API — the proxy is fully steerable here; the web UI calls it.
    // Every endpoint except /api/health requires this bearer token; unset means
    // the API fails closed (rejects all) so it is never exposed unauthenticated.
    let api_token: Arc<str> = std::env::var("RENTAL_PROXY_API_TOKEN")
        .unwrap_or_default()
        .into();
    if api_token.is_empty() {
        warn!(
            "RENTAL_PROXY_API_TOKEN not set — control API will reject every request \
             until a token is configured"
        );
    }
    let api_addr = std::env::var("RENTAL_PROXY_API").unwrap_or_else(|_| "127.0.0.1:8080".into());
    {
        let state = api::AppState {
            registry: registry.clone(),
            sellers: sellers.clone(),
            orders: orders.clone(),
            hashrate: hashrate.clone(),
            api_token: api_token.clone(),
            chain,
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

    let ctx = ProxyContext {
        default_target: cfg.default_upstream.clone(),
        registry,
        sellers,
        orders,
        sv2_rigs: Default::default(),
    };

    accept_loop(listener, ctx).await
}

/// Accept seller miners on the one port and tell SV1 from SV2 per connection.
/// The first byte is peeked (not consumed) and routed to the matching relay,
/// which then reads the full stream from the start.
async fn accept_loop(listener: TcpListener, ctx: ProxyContext) -> anyhow::Result<()> {
    info!("listening for seller miners (SV1 and SV2 on one port)");
    let keys = proto::sv2::keys::NoiseKeys::from_env_or_generate();
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let keys = keys.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let peer = peer.to_string();
            // Peek one byte to classify; if the peer never sends, drop quietly.
            let mut first = [0u8; 1];
            match sock.peek(&mut first).await {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) => {
                    warn!(%peer, error = %e, "protocol peek failed");
                    return;
                }
            }
            let result = if proto::detect::is_sv1(first[0]) {
                proto::relay::handle_seller_miner(sock, peer.clone(), ctx).await
            } else {
                proto::sv2::relay::handle_seller_miner_sv2(sock, peer.clone(), ctx, keys).await
            };
            if let Err(e) = result {
                warn!(%peer, error = %e, "session ended with error");
            }
        });
    }
}
