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

    // M1: one default upstream for everyone (per-seller config = M3,
    // rentals = M2). Without it there's nothing to relay to.
    let upstream = cfg.default_upstream.clone().context(
        "set RENTAL_PROXY_POOL_URL (+ _USER/_PASS) — milestone 1 relays every \
         miner to this default upstream",
    )?;
    info!(upstream = %upstream.url, "default upstream");

    let registry = registry::Registry::new();

    let sellers_path = std::env::var("RENTAL_PROXY_SELLERS")
        .unwrap_or_else(|_| "sellers.json".into())
        .into();
    let sellers = store::SellerStore::load(sellers_path).await;

    let orders_path = std::env::var("RENTAL_PROXY_ORDERS")
        .unwrap_or_else(|_| "orders.json".into())
        .into();
    let orders = orders::OrderStore::load(orders_path).await;

    // Auto-revert expired rentals.
    orders::spawn_expiry(orders.clone(), registry.clone());

    // HTTP control API — the proxy is fully steerable here; the web UI calls it.
    let api_addr = std::env::var("RENTAL_PROXY_API").unwrap_or_else(|_| "127.0.0.1:8080".into());
    {
        let state = api::AppState {
            registry: registry.clone(),
            sellers: sellers.clone(),
            orders: orders.clone(),
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
        default_target: upstream,
        registry,
        sellers,
        orders,
    };

    // Select the wire protocol's adapter at boot; the accept loop is
    // monomorphised over it (generics, no per-message dyn dispatch).
    match cfg.protocol {
        Protocol::Sv1 => accept_loop(listener, proto::relay::Sv1Adapter, ctx).await,
        Protocol::Sv2 => {
            warn!(
                "RENTAL_PROXY_PROTOCOL=sv2: the SV2 downstream relay is not implemented \
                 yet — connections will be refused. Use sv1 until the SV2 milestone lands."
            );
            accept_loop(listener, proto::sv2::Sv2Adapter, ctx).await
        }
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
