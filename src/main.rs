// SPDX-License-Identifier: AGPL-3.0-or-later

//! stratum-rental-proxy — entry point.
//!
//! Binds the downstream Stratum server (SV1, SV2, or auto-detect on one port),
//! accepts seller miners, and drives each through its protocol relay with a
//! swappable upstream: idle → the rig's default pool, rented → the buyer's pool.
//! Persistent rig/order state lives in SQLite; the HTTP control API steers
//! rentals and the expiry task auto-reverts finished ones.

mod api;
mod config;
mod control;
mod db;
mod hashrate;
mod orders;
mod proto;
mod registry;
mod session;
mod store;

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use config::Protocol;
use proto::adapter::{DownstreamAdapter, ProxyContext};

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
        #[cfg(feature = "sv2")]
        sv2_rigs: Default::default(),
    };

    // Select the wire protocol's adapter at boot; the accept loop is
    // monomorphised over it (generics, no per-message dyn dispatch). `Both`
    // peeks the first byte of each connection and dispatches per-connection.
    match cfg.protocol {
        Protocol::Sv1 => accept_loop(listener, proto::relay::Sv1Adapter, ctx).await,
        Protocol::Sv2 => {
            // `default()` generates/loads the Noise key in the real adapter; in
            // a non-`sv2` build the adapter is a unit stub (hence the allow).
            #[allow(clippy::default_constructed_unit_structs)]
            let adapter = proto::sv2::Sv2Adapter::default();
            accept_loop(listener, adapter, ctx).await
        }
        Protocol::Both => accept_loop_auto(listener, ctx).await,
    }
}

/// Accept seller miners and hand each to `adapter` with the shared context.
async fn accept_loop<A: DownstreamAdapter>(
    listener: TcpListener,
    adapter: A,
    ctx: ProxyContext,
) -> anyhow::Result<()> {
    info!(protocol = adapter.protocol(), "listening for seller miners");
    let adapter = Arc::new(adapter);
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let adapter = adapter.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let peer = peer.to_string();
            if let Err(e) = adapter.serve(sock, peer.clone(), ctx).await {
                warn!(%peer, error = %e, "session ended with error");
            }
        });
    }
}

/// Accept seller miners and auto-detect SV1 vs SV2 per connection (one port).
/// The first byte is peeked (not consumed) and routed to the matching adapter,
/// which then reads the full stream from the start.
async fn accept_loop_auto(listener: TcpListener, ctx: ProxyContext) -> anyhow::Result<()> {
    info!("listening for seller miners (auto SV1/SV2 on one port)");
    let sv1 = proto::relay::Sv1Adapter;
    #[allow(clippy::default_constructed_unit_structs)]
    let sv2 = proto::sv2::Sv2Adapter::default();
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        // The real (`--features sv2`) adapter holds Noise keys and needs a clone
        // per task; the no-feature stub is a Copy unit (clone_on_copy is inert).
        #[allow(clippy::clone_on_copy)]
        let sv2 = sv2.clone();
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
            let result = match proto::detect::detect(first[0]) {
                Protocol::Sv2 => sv2.serve(sock, peer.clone(), ctx).await,
                _ => sv1.serve(sock, peer.clone(), ctx).await,
            };
            if let Err(e) = result {
                warn!(%peer, error = %e, "session ended with error");
            }
        });
    }
}
