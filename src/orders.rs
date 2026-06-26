//! Rental orders: a buyer rents a worker's hashrate until a deadline.
//!
//! Creating an order switches the session to the buyer's target; a background
//! expiry task reverts the session to its default when the deadline passes.
//! Orders are persisted, so a rental is resumed when the miner reconnects
//! (the relay checks for an active order on authorize) and expired orders are
//! cleaned up after a restart.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::info;

use crate::registry::Registry;
use crate::session::UpstreamTarget;

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Active,
    Ended,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub worker: String,
    pub target: UpstreamTarget,
    pub created_ms: i64,
    /// Auto-revert deadline (epoch ms). `0` = open-ended (no auto-revert).
    pub until_ms: i64,
    pub status: OrderStatus,
    /// Delivered work measured by the proxy over this rental, in diff-1 share
    /// units (Σ of accepted-share difficulty). Hashes = `delivered_work * 2^32`;
    /// average delivered hashrate = `delivered_work * 2^32 / elapsed_seconds`.
    /// This is the billing basis (pro-rata on actual delivery).
    #[serde(default)]
    pub delivered_work: f64,
    /// Count of accepted shares credited to this rental.
    #[serde(default)]
    pub accepted_shares: u64,
    /// Count of shares the miner submitted during this rental. Together with
    /// `accepted_shares` gives the accept-ratio (a fraud/health signal).
    #[serde(default)]
    pub submitted_shares: u64,
}

impl Order {
    fn is_live(&self, now: i64) -> bool {
        self.status == OrderStatus::Active && (self.until_ms == 0 || self.until_ms > now)
    }
}

pub struct OrderStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, Order>>,
}

impl OrderStore {
    pub async fn load(path: PathBuf) -> Arc<Self> {
        let map = match tokio::fs::read(&path).await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        Arc::new(Self {
            path,
            inner: Mutex::new(map),
        })
    }

    pub async fn create(&self, worker: String, target: UpstreamTarget, until_ms: i64) -> Order {
        let now = now_ms();
        let id = format!("o{}-{}", now, SEQ.fetch_add(1, Ordering::Relaxed));
        let order = Order {
            id: id.clone(),
            worker,
            target,
            created_ms: now,
            until_ms,
            status: OrderStatus::Active,
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
        };
        self.inner.lock().await.insert(id, order.clone());
        let _ = self.save().await;
        order
    }

    pub async fn get(&self, id: &str) -> Option<Order> {
        self.inner.lock().await.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<Order> {
        self.inner.lock().await.values().cloned().collect()
    }

    /// The live order for a worker (used to resume a rental on reconnect).
    pub async fn active_for_worker(&self, worker: &str, now: i64) -> Option<Order> {
        self.inner
            .lock()
            .await
            .values()
            .find(|o| o.worker == worker && o.is_live(now))
            .cloned()
    }

    /// Credit measured delivered work to an order (in-memory; persisted by the
    /// periodic [`flush`](Self::flush)). No-op if the order is unknown.
    pub async fn add_work(&self, id: &str, work: f64, accepted_shares: u64) {
        let mut map = self.inner.lock().await;
        if let Some(o) = map.get_mut(id) {
            o.delivered_work += work;
            o.accepted_shares += accepted_shares;
        }
    }

    /// Count submitted shares against an order (for the accept-ratio).
    pub async fn add_submitted(&self, id: &str, submitted: u64) {
        let mut map = self.inner.lock().await;
        if let Some(o) = map.get_mut(id) {
            o.submitted_shares += submitted;
        }
    }

    /// Persist the store (called periodically so accumulated work survives a
    /// restart; at most one tick's worth of work is lost on a crash).
    pub async fn flush(&self) -> std::io::Result<()> {
        self.save().await
    }

    /// Cancel an order; returns it so the caller can revert the session.
    pub async fn cancel(&self, id: &str) -> Option<Order> {
        let order = {
            let mut map = self.inner.lock().await;
            let o = map.get_mut(id)?;
            o.status = OrderStatus::Cancelled;
            o.clone()
        };
        let _ = self.save().await;
        Some(order)
    }

    /// Mark every past-deadline active order as ended; returns them so the
    /// caller can revert the corresponding sessions.
    pub async fn take_expired(&self, now: i64) -> Vec<Order> {
        let expired: Vec<Order> = {
            let mut map = self.inner.lock().await;
            let mut out = Vec::new();
            for o in map.values_mut() {
                if o.status == OrderStatus::Active && o.until_ms > 0 && o.until_ms <= now {
                    o.status = OrderStatus::Ended;
                    out.push(o.clone());
                }
            }
            out
        };
        if !expired.is_empty() {
            let _ = self.save().await;
        }
        expired
    }

    async fn save(&self) -> std::io::Result<()> {
        let data = {
            let map = self.inner.lock().await;
            serde_json::to_vec_pretty(&*map).unwrap_or_else(|_| b"{}".to_vec())
        };
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &data).await?;
        tokio::fs::rename(&tmp, &self.path).await
    }
}

/// Background task: every 5s, revert expired rentals and persist accumulated
/// delivered work (so billing survives a restart).
pub fn spawn_expiry(orders: Arc<OrderStore>, registry: Arc<Registry>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            for o in orders.take_expired(now_ms()).await {
                if let Some(session) = registry.get(&o.worker).await {
                    let _ = session.revert().await;
                    info!(order = %o.id, worker = %o.worker, "rental expired → reverted to default");
                }
            }
            let _ = orders.flush().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("srp_orders_{}_{}.json", std::process::id(), tag))
    }
    fn target() -> UpstreamTarget {
        UpstreamTarget {
            url: "buyer:3333".into(),
            user: "b".into(),
            password: "x".into(),
            authority_pubkey: None,
        }
    }

    #[tokio::test]
    async fn create_active_for_worker_and_cancel() {
        let p = tmp_path("crud");
        let _ = std::fs::remove_file(&p);
        let store = OrderStore::load(p.clone()).await;
        let o = store.create("w1".into(), target(), 0).await; // open-ended
        assert!(store.active_for_worker("w1", now_ms()).await.is_some());
        let cancelled = store.cancel(&o.id).await.unwrap();
        assert_eq!(cancelled.status, OrderStatus::Cancelled);
        assert!(store.active_for_worker("w1", now_ms()).await.is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn expiry_marks_ended_and_is_returned() {
        let p = tmp_path("expire");
        let _ = std::fs::remove_file(&p);
        let store = OrderStore::load(p.clone()).await;
        // already past deadline
        let _o = store.create("w2".into(), target(), now_ms() - 1000).await;
        let live_now = store.create("w3".into(), target(), now_ms() + 60_000).await;
        let expired = store.take_expired(now_ms()).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].worker, "w2");
        // not-yet-due order stays active + nothing returned a second time
        assert!(store.active_for_worker("w3", now_ms()).await.is_some());
        assert!(store.take_expired(now_ms()).await.is_empty());
        let _ = live_now;
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn persists_across_reload() {
        let p = tmp_path("persist");
        let _ = std::fs::remove_file(&p);
        let id = {
            let store = OrderStore::load(p.clone()).await;
            store.create("w4".into(), target(), 0).await.id
        };
        let reloaded = OrderStore::load(p.clone()).await;
        assert!(reloaded.get(&id).await.is_some());
        let _ = std::fs::remove_file(&p);
    }
}
