// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol-agnostic control surface over a live session.
//!
//! The registry and control API don't care whether a session speaks SV1 or
//! SV2; they hold an [`AnySession`] and call the same operations (switch,
//! revert, set-default, status). A closed enum, one variant per protocol.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::session::Routing;
#[cfg(test)]
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
    Sv2(Arc<crate::proto::sv2::relay::Sv2Session>),
}

impl AnySession {
    /// Route this session's hashrate to a single `target` (no fallback). The
    /// production path forces a reconnect; this lower-level live-swap form is
    /// used by the sv2 relay tests to drive a switch without a stored order.
    #[cfg(test)]
    pub async fn switch_to(&self, order_id: String, target: UpstreamTarget) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.switch_to(order_id, target).await,
            AnySession::Sv2(s) => s.switch_to(order_id, target).await,
        }
    }

    /// Connect a rental order's pool (primary, then fallback) and make it the
    /// active upstream.
    pub async fn switch_to_order(&self, order_id: String) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.switch_to_order(order_id).await,
            AnySession::Sv2(s) => s.switch_to_order(order_id).await,
        }
    }

    /// Make the seller's idle pool the active upstream again.
    async fn revert(&self) -> anyhow::Result<()> {
        match self {
            AnySession::Sv1(s) => s.revert().await,
            AnySession::Sv2(s) => s.revert().await,
        }
    }

    /// The session's routing, if `generation` is still its active upstream.
    async fn routing_if_active(&self, generation: u64) -> Option<Routing> {
        match self {
            AnySession::Sv1(s) => s.routing_if_active(generation).await,
            AnySession::Sv2(s) => s.routing_if_active(generation).await,
        }
    }

    fn protocol(&self) -> &'static str {
        match self {
            AnySession::Sv1(_) => "sv1",
            AnySession::Sv2(_) => "sv2",
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
            AnySession::Sv2(s) => s.force_reconnect(),
        }
    }

    pub async fn status(&self) -> SessionStatus {
        match self {
            AnySession::Sv1(s) => s.status().await,
            AnySession::Sv2(s) => s.status().await,
        }
    }

    /// Same underlying session instance? (registry eviction guard)
    pub fn ptr_eq(&self, other: &AnySession) -> bool {
        match (self, other) {
            (AnySession::Sv1(a), AnySession::Sv1(b)) => Arc::ptr_eq(a, b),
            (AnySession::Sv2(a), AnySession::Sv2(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// Per-session supervisor: when the active upstream drops, re-establish it
/// with capped backoff — the order's pool (primary, then fallback) while
/// rented, the seller's idle pool while idle — and then reconnect the miners.
///
/// The reconnect is the same rule every operator path follows: a miner gets a
/// new pool through a fresh handshake, never through a live re-point. A
/// re-point cannot carry everything the miner needs (SV2 has no message for
/// the extranonce *size* a channel was opened with, and a re-opened channel
/// gets whatever the pool assigns this time), and miners that ignore a
/// mid-session extranonce change keep hashing work the pool rejects.
///
/// Readers report their generation on `died_rx` when their pool connection
/// ends; a report for a generation that is no longer active (an intentional
/// swap happened since) is ignored, and a swap made elsewhere ends the retry.
pub async fn supervise_upstream(session: AnySession, mut died_rx: mpsc::UnboundedReceiver<u64>) {
    let protocol = session.protocol();
    while let Some(gen) = died_rx.recv().await {
        if session.routing_if_active(gen).await.is_none() {
            continue;
        }
        warn!(
            gen,
            protocol, "upstream dropped — reconnecting/failing over"
        );
        let mut backoff = Duration::from_millis(500);
        while let Some(routing) = session.routing_if_active(gen).await {
            let res = match routing.order_id() {
                Some(order_id) => session.switch_to_order(order_id.to_string()).await,
                None => session.revert().await,
            };
            match res {
                Ok(()) => {
                    session.force_reconnect();
                    info!(
                        gen,
                        protocol, "upstream re-established after drop — reconnecting miners"
                    );
                    break;
                }
                Err(e) => {
                    warn!(protocol, error = %e, "upstream reconnect failed; backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
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
