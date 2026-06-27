//! Live session registry: maps a seller's **rig** (worker name) to its active
//! session(s), so the control layer can find a connected rig and switch where
//! its hashrate goes. Sessions are held protocol-agnostically as [`AnySession`].
//!
//! ## One rig = many miners (the MiningRigRentals model)
//!
//! A worker name is a *rig*, not a single miner: a seller can point several
//! miners (e.g. 3× BitAxe) at the same worker name to sell their combined
//! hashrate as ONE listing. Each miner is still its own connection/session
//! (own channel + own upstream); the registry just groups them under the shared
//! worker name. Rent/release act on ALL sessions of a rig at once, and the
//! rig's status sums their hashrate/work. Distinct worker names stay
//! independently rentable. This is routing-level grouping only — NOT
//! channel-aggregation (no extranonce splitting); see the relays.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::control::{accept_ratio, accept_ratio_low, AnySession, SessionStatus};

#[derive(Default)]
pub struct Registry {
    /// worker (rig) → all sessions currently mining under that name.
    inner: Mutex<HashMap<String, Vec<AnySession>>>,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add a session under its worker name (does not evict siblings sharing the
    /// name — they sum into one rig).
    pub async fn insert(&self, worker: String, session: AnySession) {
        self.inner.lock().await.entry(worker).or_default().push(session);
    }

    /// Remove only this exact session instance (a late disconnect must not evict
    /// a freshly reconnected sibling). Drops the rig entry when its last session
    /// goes.
    pub async fn remove_if(&self, worker: &str, session: &AnySession) {
        let mut map = self.inner.lock().await;
        if let Some(sessions) = map.get_mut(worker) {
            sessions.retain(|s| !s.ptr_eq(session));
            if sessions.is_empty() {
                map.remove(worker);
            }
        }
    }

    /// Every session currently mining under `worker` (empty if none connected).
    pub async fn get_all(&self, worker: &str) -> Vec<AnySession> {
        self.inner
            .lock()
            .await
            .get(worker)
            .cloned()
            .unwrap_or_default()
    }

    /// Aggregated status of a rig: sums hashrate/work across its sessions, with
    /// routing/order taken from a rented session if any (the rig is "rented"
    /// when any session is). `None` if the rig has no connected sessions.
    pub async fn aggregated_status(&self, worker: &str) -> Option<SessionStatus> {
        let sessions = self.get_all(worker).await;
        if sessions.is_empty() {
            return None;
        }
        let mut parts = Vec::with_capacity(sessions.len());
        for s in &sessions {
            parts.push(s.status().await);
        }
        Some(aggregate(parts))
    }

    /// Status snapshot of every connected rig (one entry per worker name, summed
    /// across that rig's sessions).
    pub async fn snapshot(&self) -> Vec<SessionStatus> {
        let groups: Vec<Vec<AnySession>> =
            self.inner.lock().await.values().cloned().collect();
        let mut out = Vec::with_capacity(groups.len());
        for sessions in groups {
            let mut parts = Vec::with_capacity(sessions.len());
            for s in &sessions {
                parts.push(s.status().await);
            }
            if !parts.is_empty() {
                out.push(aggregate(parts));
            }
        }
        out
    }
}

/// Combine the per-session statuses of one rig into a single rig status. Sums
/// the delivered metrics; routing/order/upstream come from a rented session if
/// present (so a rented rig reads as rented even mid-switch), else the first.
fn aggregate(mut parts: Vec<SessionStatus>) -> SessionStatus {
    // Prefer a rented session for the routing-identifying fields.
    let lead_idx = parts
        .iter()
        .position(|p| p.routing == "rented")
        .unwrap_or(0);
    let hashrate_hs: f64 = parts.iter().map(|p| p.hashrate_hs).sum();
    let delivered_work: f64 = parts.iter().map(|p| p.delivered_work).sum();
    let accepted_shares: u64 = parts.iter().map(|p| p.accepted_shares).sum();
    let submitted_shares: u64 = parts.iter().map(|p| p.submitted_shares).sum();
    let lead = parts.swap_remove(lead_idx);
    SessionStatus {
        worker: lead.worker,
        routing: lead.routing,
        order_id: lead.order_id,
        upstream_url: lead.upstream_url,
        hashrate_hs,
        delivered_work,
        accepted_shares,
        submitted_shares,
        accept_ratio: accept_ratio(accepted_shares, submitted_shares),
        accept_ratio_low: accept_ratio_low(accepted_shares, submitted_shares),
        protocol: lead.protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(routing: &str, hs: f64, accepted: u64, submitted: u64) -> SessionStatus {
        SessionStatus {
            worker: "bc1qSELLER.farm".into(),
            routing: routing.into(),
            order_id: if routing == "rented" {
                Some("o1".into())
            } else {
                None
            },
            upstream_url: "pool:3333".into(),
            hashrate_hs: hs,
            delivered_work: hs, // arbitrary stand-in for the sum check
            accepted_shares: accepted,
            submitted_shares: submitted,
            accept_ratio: accept_ratio(accepted, submitted),
            accept_ratio_low: accept_ratio_low(accepted, submitted),
            protocol: "sv2",
        }
    }

    #[test]
    fn aggregate_sums_hashrate_and_work() {
        let agg = aggregate(vec![
            status("idle", 1.5e12, 10, 10),
            status("idle", 1.5e12, 20, 20),
            status("idle", 1.5e12, 30, 30),
        ]);
        assert!((agg.hashrate_hs - 4.5e12).abs() < 1.0, "3×1.5TH ⇒ 4.5TH");
        assert_eq!(agg.accepted_shares, 60);
        assert_eq!(agg.submitted_shares, 60);
        assert_eq!(agg.routing, "idle");
    }

    #[test]
    fn aggregate_reads_rented_when_any_session_rented() {
        let agg = aggregate(vec![
            status("idle", 1.0e12, 5, 5),
            status("rented", 1.0e12, 5, 5),
        ]);
        assert_eq!(agg.routing, "rented", "rig is rented when any session is");
        assert_eq!(agg.order_id.as_deref(), Some("o1"));
        assert!((agg.hashrate_hs - 2.0e12).abs() < 1.0);
    }
}
