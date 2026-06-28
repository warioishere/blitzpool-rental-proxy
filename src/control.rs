// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol-agnostic control surface over a live session.
//!
//! The registry and control API don't care whether a session speaks SV1 or
//! SV2; they hold an [`AnySession`] and call the same operations (switch,
//! revert, set-default, status). The proxy runs one protocol per process, so
//! this is a closed enum (no `dyn`), with the SV2 variant behind the `sv2`
//! feature.

use std::sync::Arc;

#[cfg(all(test, feature = "sv2"))]
use crate::session::UpstreamTarget;

/// Minimum submitted-share sample before the accept-ratio is considered
/// meaningful (avoids flagging on early startup noise).
pub const ACCEPT_RATIO_MIN_SAMPLE: u64 = 50;
/// Accept-ratio (accepted/submitted) below which a session is flagged — a
/// possible sign the buyer's pool is under-reporting accepted shares (or the
/// miner is producing many stale/invalid shares). A signal to investigate, not
/// proof; the UI/operator can apply a stricter policy on the raw counts.
pub const ACCEPT_RATIO_THRESHOLD: f64 = 0.75;

/// Accept-ratio = accepted/submitted (1.0 when nothing submitted yet).
pub fn accept_ratio(accepted: u64, submitted: u64) -> f64 {
    if submitted == 0 {
        1.0
    } else {
        accepted as f64 / submitted as f64
    }
}

/// Whether the accept-ratio is low enough to flag (with a meaningful sample).
pub fn accept_ratio_low(accepted: u64, submitted: u64) -> bool {
    submitted >= ACCEPT_RATIO_MIN_SAMPLE
        && accept_ratio(accepted, submitted) < ACCEPT_RATIO_THRESHOLD
}

/// API-facing snapshot of a live session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionStatus {
    pub worker: String,
    /// `"idle"` or `"rented"`.
    pub routing: String,
    pub order_id: Option<String>,
    pub upstream_url: String,
    /// Live (windowed) delivered hashrate estimate, hashes/second.
    pub hashrate_hs: f64,
    /// Lifetime delivered work this session, in diff-1 share units (Σ accepted
    /// share difficulty). Per-rental delivered work is tracked on the order.
    pub delivered_work: f64,
    /// Lifetime accepted shares this session.
    pub accepted_shares: u64,
    /// Lifetime shares submitted by the miner this session.
    pub submitted_shares: u64,
    /// accepted/submitted (1.0 if nothing submitted yet).
    pub accept_ratio: f64,
    /// True when the accept-ratio is suspiciously low (possible pool
    /// under-reporting or a misbehaving miner).
    pub accept_ratio_low: bool,
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
    /// Route this session's hashrate to a single `target` (no fallback). The
    /// production path forces a reconnect; this lower-level live-swap form is
    /// used by the sv2 relay tests to drive a switch without a stored order.
    #[cfg(all(test, feature = "sv2"))]
    pub async fn switch_to(&self, order_id: String, target: UpstreamTarget) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.switch_to(order_id, target).await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.switch_to(order_id, target).await,
        }
    }

    /// Route this session onto a rental order's pool, with primary→fallback
    /// failover (the pools are resolved from the order). Production switches go
    /// through [`AnySession::force_reconnect`]; this live-swap path is exercised
    /// by the sv2 relay failover tests.
    #[cfg(all(test, feature = "sv2"))]
    pub async fn switch_to_order(&self, order_id: String) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.switch_to_order(order_id).await,
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.switch_to_order(order_id).await,
        }
    }

    /// Drop the miner connection so it reconnects and re-resolves its upstream
    /// from current state. Callers MUST persist the new pool/rental state before
    /// calling this. Used for operator-initiated pool changes (idle-pool edit,
    /// rent start, rent end/cancel) so the miner gets a clean handshake on the
    /// new pool instead of a live re-point it may not honor (wasted shares).
    pub fn force_reconnect(&self) {
        match self {
            AnySession::Sv1(s) => s.force_reconnect(),
            #[cfg(feature = "sv2")]
            AnySession::Sv2(s) => s.force_reconnect(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_ratio_basic() {
        assert_eq!(accept_ratio(0, 0), 1.0); // nothing submitted yet
        assert_eq!(accept_ratio(9, 10), 0.9);
        assert_eq!(accept_ratio(0, 10), 0.0);
    }

    #[test]
    fn accept_ratio_flag_needs_sample_and_low_ratio() {
        // Below threshold but too few samples → not flagged.
        assert!(!accept_ratio_low(0, 10));
        // Enough samples, healthy ratio → not flagged.
        assert!(!accept_ratio_low(95, 100));
        // Enough samples, low ratio → flagged.
        assert!(accept_ratio_low(40, 100));
        // Exactly at the minimum sample, zero accepted → flagged.
        assert!(accept_ratio_low(0, ACCEPT_RATIO_MIN_SAMPLE));
    }
}
