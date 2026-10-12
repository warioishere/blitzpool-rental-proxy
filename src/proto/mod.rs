// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum protocol handling. The proxy core (session, routing, control,
//! accounting) is protocol-agnostic; each relay drives one downstream miner
//! connection with a swappable upstream client.
//!
//! - [`sv1`] codec + [`relay`]: Stratum V1 miners.
//! - [`sv2`]: Stratum V2 miners (Noise transport, channel relay).
//! - [`translate`]: SV1<->SV2 job/share translation, used when the miner and
//!   its current pool speak different protocols.
//! - [`detect`]: first-byte SV1/SV2 classification of the shared listen port.

use std::sync::Arc;

use crate::orders::OrderStore;
use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::SellerStore;

pub mod detect;
pub mod relay;
pub mod sv1;
pub mod sv2;
pub mod translate;

/// A pool refused the proxy's login: an SV1 `mining.authorize` not answered
/// `true`, or an SV2 `OpenMiningChannel` answered with an error (SV2 carries
/// the user identity in the channel open). Holds the pool's reason; callers
/// that must tell a refusal from a broken connection downcast to it.
#[derive(Debug, thiserror::Error)]
#[error("pool refused the login: {0}")]
pub struct LoginRefused(pub String);

/// Shared, protocol-independent state handed to every connection handler.
#[derive(Clone)]
pub struct ProxyContext {
    /// Optional SV1 handshake-bootstrap pool. The proxy is **register-only**:
    /// only workers with a registered rig (or an active rental) are served;
    /// unregistered miners are rejected. SV2 needs nothing here (it learns the
    /// worker from `OpenMiningChannel` before connecting upstream). SV1 must
    /// answer `mining.subscribe` (extranonce) *before* the worker is known at
    /// `mining.authorize`, so it needs a bootstrap pool to source that
    /// extranonce; `None` ⇒ SV1 is unavailable, SV2 still works.
    pub default_target: Option<UpstreamTarget>,
    /// Live sessions, keyed by worker name (for the control API + rentals).
    pub registry: Arc<Registry>,
    /// Per-worker default pools configured by sellers.
    pub sellers: Arc<SellerStore>,
    /// Rental orders (a buyer renting a worker until a deadline).
    pub orders: Arc<OrderStore>,
    /// Bundle-target SV2 rig per worker, so several same-rig SV2 miners share one
    /// upstream (one group of N channels) instead of one upstream each.
    pub sv2_rigs: Arc<sv2::relay::Sv2RigRegistry>,
}
