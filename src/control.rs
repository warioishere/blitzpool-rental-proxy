//! Protocol-agnostic control surface over a live session.
//!
//! The registry and control API don't care whether a session speaks SV1 or
//! SV2; they hold an [`AnySession`] and call the same operations (switch,
//! revert, set-default, status). The proxy runs one protocol per process, so
//! this is a closed enum (no `dyn`), with the SV2 variant behind the `sv2`
//! feature.

use std::sync::Arc;

use crate::session::UpstreamTarget;

/// API-facing snapshot of a live session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionStatus {
    pub worker: String,
    /// `"idle"` or `"rented"`.
    pub routing: String,
    pub order_id: Option<String>,
    pub upstream_url: String,
    pub hashrate_hs: f64,
    /// `"sv1"` or `"sv2"`.
    pub protocol: &'static str,
}

/// A live session of either protocol, addressable by the registry/control API.
#[derive(Clone)]
pub enum AnySession {
    Sv1(Arc<crate::proto::relay::Session>),
    #[cfg(feature = "sv2")]
    Sv2(Arc<crate::proto::sv2::relay::Sv2Session>),
}

impl AnySession {
    /// Route this session's hashrate to `target` (a rental starts).
    pub async fn switch_to(&self, order_id: String, target: UpstreamTarget) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.switch_to(order_id, target).await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.switch_to(order_id, target).await,
        }
    }

    /// Route back to the seller's default upstream (a rental ends).
    pub async fn revert(&self) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.revert().await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.revert().await,
        }
    }

    /// Set + apply the seller's default upstream (while idle).
    pub async fn set_default(&self, target: UpstreamTarget) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.set_default(target).await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.set_default(target).await,
        }
    }

    pub async fn default_target(&self) -> UpstreamTarget {
        match self {
            AnySession::Sv1(s) => s.default_target().await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.default_target().await,
        }
    }

    pub async fn status(&self) -> SessionStatus {
        match self {
            AnySession::Sv1(s) => s.status().await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.status().await,
        }
    }

    /// Same underlying session instance? (registry eviction guard)
    pub fn ptr_eq(&self, other: &AnySession) -> bool {
        match (self, other) {
            (AnySession::Sv1(a), AnySession::Sv1(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "sv2")]
            (AnySession::Sv2(a), AnySession::Sv2(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "sv2")]
            _ => false,
        }
    }
}
