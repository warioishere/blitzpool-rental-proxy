//! Protocol-agnostic adapter seam.
//!
//! The proxy core — session registry, routing, rental orders, seller config,
//! hashrate accounting, the control API — knows nothing about the wire
//! protocol. Each Stratum version plugs in here as a [`DownstreamAdapter`]:
//! given an accepted miner socket and the shared [`ProxyContext`], it drives
//! that one connection end-to-end (downstream handshake + swappable upstream).
//!
//! The adapter is chosen once at boot from config and the listener is
//! monomorphised over it (generics, not `dyn`), so there is no per-message
//! virtual dispatch. SV1 ([`super::sv1::relay`]) is live; SV2
//! ([`super::sv2`]) plugs into the same seam.

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::orders::OrderStore;
use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::SellerStore;

/// Shared, protocol-independent state handed to every connection handler.
#[derive(Clone)]
pub struct ProxyContext {
    /// Process-wide fallback pool used when a seller has no per-worker default.
    pub default_target: UpstreamTarget,
    /// Live sessions, keyed by worker name (for the control API + rentals).
    pub registry: Arc<Registry>,
    /// Per-worker default pools configured by sellers.
    pub sellers: Arc<SellerStore>,
    /// Rental orders (a buyer renting a worker until a deadline).
    pub orders: Arc<OrderStore>,
}

/// Drives a single downstream miner connection for one Stratum protocol.
///
/// Implementors own the protocol-specific handshake and the swappable-upstream
/// relay; everything they need that is protocol-agnostic arrives via
/// [`ProxyContext`]. `serve` returns when the connection ends (either side
/// closes) or errors.
pub trait DownstreamAdapter: Clone + Send + Sync + 'static {
    /// Short protocol name for logs/metrics, e.g. `"sv1"`.
    fn protocol(&self) -> &'static str;

    /// Handle one accepted miner connection to completion.
    fn serve(
        &self,
        miner: TcpStream,
        peer: String,
        ctx: ProxyContext,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}
