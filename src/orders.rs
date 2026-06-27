//! Rental orders (SQLite, `orders` table): a buyer rents a worker's hashrate
//! until a deadline and/or a prepaid budget.
//!
//! Creating an order switches the session to the buyer's target; a background
//! expiry task reverts the session to its default when the deadline passes or
//! the prepaid budget is consumed. Orders are persisted, so a rental is resumed
//! when the miner reconnects (the relay checks for an active order on authorize)
//! and finished orders are cleaned up after a restart. Measured delivered work
//! (the billing basis) is accumulated durably here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::task::JoinHandle;
use tracing::info;

use crate::registry::Registry;
use crate::session::UpstreamTarget;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Hashes in one TH·day: 1e12 H/s × 86400 s. Used to turn measured work into
/// the billable TH·day quantity.
const HASHES_PER_TH_DAY: f64 = 1e12 * 86_400.0;
/// Hashes per diff-1 share (2^32).
const DIFF1_HASHES: f64 = 4_294_967_296.0;

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

impl OrderStatus {
    fn as_db(&self) -> &'static str {
        match self {
            OrderStatus::Active => "active",
            OrderStatus::Ended => "ended",
            OrderStatus::Cancelled => "cancelled",
        }
    }
    fn from_db(s: &str) -> OrderStatus {
        match s {
            "ended" => OrderStatus::Ended,
            "cancelled" => OrderStatus::Cancelled,
            _ => OrderStatus::Active,
        }
    }
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
    /// Agreed price per TH/day (same currency unit as `budget`, e.g. sats).
    #[serde(default)]
    pub price_per_th_day: f64,
    /// Prepaid amount allocated to this rental (same unit as price). `0` = no
    /// limit (open-ended). When the measured cost reaches it, the proxy stops
    /// routing (pay-as-you-hash; no refunds — the credit is consumed).
    #[serde(default)]
    pub budget: f64,
}

impl Order {
    /// An order that's currently in effect: active, not past its deadline, and
    /// with prepaid budget remaining.
    pub fn is_live(&self, now: i64) -> bool {
        self.status == OrderStatus::Active
            && (self.until_ms == 0 || self.until_ms > now)
            && !self.funding_exhausted()
    }

    /// Billable cost so far = delivered TH·days × price.
    pub fn cost(&self) -> f64 {
        let th_days = self.delivered_work * DIFF1_HASHES / HASHES_PER_TH_DAY;
        th_days * self.price_per_th_day
    }

    /// Remaining prepaid budget (0 if no budget set or already spent).
    pub fn budget_remaining(&self) -> f64 {
        if self.budget <= 0.0 {
            0.0
        } else {
            (self.budget - self.cost()).max(0.0)
        }
    }

    /// True when a budgeted rental has consumed its prepaid credit.
    pub fn funding_exhausted(&self) -> bool {
        self.budget > 0.0 && self.cost() >= self.budget
    }
}

/// Flat DB row → [`Order`].
struct OrderRow {
    id: String,
    worker: String,
    target_url: String,
    target_user: String,
    target_password: String,
    target_authority: Option<String>,
    created_ms: i64,
    until_ms: i64,
    status: String,
    delivered_work: f64,
    accepted_shares: i64,
    submitted_shares: i64,
    price_per_th_day: f64,
    budget: f64,
}

impl OrderRow {
    fn into_order(self) -> Order {
        Order {
            id: self.id,
            worker: self.worker,
            target: UpstreamTarget {
                url: self.target_url,
                user: self.target_user,
                password: self.target_password,
                authority_pubkey: self.target_authority,
            },
            created_ms: self.created_ms,
            until_ms: self.until_ms,
            status: OrderStatus::from_db(&self.status),
            delivered_work: self.delivered_work,
            accepted_shares: self.accepted_shares as u64,
            submitted_shares: self.submitted_shares as u64,
            price_per_th_day: self.price_per_th_day,
            budget: self.budget,
        }
    }
}

/// Why [`OrderStore::create`] could not record an order.
#[derive(Debug)]
pub enum CreateOrderError {
    /// The worker already has an active order (one-active-per-worker guard).
    AlreadyActive,
    /// A database error.
    Db(sqlx::Error),
}

impl std::fmt::Display for CreateOrderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateOrderError::AlreadyActive => write!(f, "worker already has an active order"),
            CreateOrderError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CreateOrderError {}

pub struct OrderStore {
    pool: SqlitePool,
}

impl OrderStore {
    pub fn new(pool: SqlitePool) -> Arc<Self> {
        Arc::new(Self { pool })
    }

    /// Record a new active rental. Fails with [`CreateOrderError::AlreadyActive`]
    /// if the worker already has an active order — the DB's one-active-per-worker
    /// unique index is the authoritative guard against a double-rent race.
    pub async fn create(
        &self,
        worker: String,
        target: UpstreamTarget,
        until_ms: i64,
        price_per_th_day: f64,
        budget: f64,
    ) -> Result<Order, CreateOrderError> {
        let now = now_ms();
        let id = format!("o{}-{}", now, SEQ.fetch_add(1, Ordering::Relaxed));
        let status = OrderStatus::Active;
        sqlx::query!(
            "INSERT INTO orders (id, worker, target_url, target_user, target_password, \
             target_authority, created_ms, until_ms, status, delivered_work, accepted_shares, \
             submitted_shares, price_per_th_day, budget) \
             VALUES (?,?,?,?,?,?,?,?,?,0,0,0,?,?)",
            id,
            worker,
            target.url,
            target.user,
            target.password,
            target.authority_pubkey,
            now,
            until_ms,
            "active",
            price_per_th_day,
            budget,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
                CreateOrderError::AlreadyActive
            } else {
                CreateOrderError::Db(e)
            }
        })?;

        Ok(Order {
            id,
            worker,
            target,
            created_ms: now,
            until_ms,
            status,
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            price_per_th_day,
            budget,
        })
    }

    pub async fn get(&self, id: &str) -> Option<Order> {
        sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             created_ms, until_ms, status, delivered_work, accepted_shares, submitted_shares, \
             price_per_th_day, budget FROM orders WHERE id = ?",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .map(OrderRow::into_order)
    }

    pub async fn list(&self) -> Vec<Order> {
        sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             created_ms, until_ms, status, delivered_work, accepted_shares, submitted_shares, \
             price_per_th_day, budget FROM orders"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(OrderRow::into_order)
        .collect()
    }

    /// The live order for a worker (used to resume a rental on reconnect).
    pub async fn active_for_worker(&self, worker: &str, now: i64) -> Option<Order> {
        let rows = sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             created_ms, until_ms, status, delivered_work, accepted_shares, submitted_shares, \
             price_per_th_day, budget FROM orders \
             WHERE worker = ? AND status = 'active' AND (until_ms = 0 OR until_ms > ?)",
            worker,
            now
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(OrderRow::into_order)
            .find(|o| !o.funding_exhausted())
    }

    /// Credit measured delivered work to an order. No-op if the order is unknown.
    pub async fn add_work(&self, id: &str, work: f64, accepted_shares: u64) {
        let shares = accepted_shares as i64;
        let _ = sqlx::query!(
            "UPDATE orders SET delivered_work = delivered_work + ?, \
             accepted_shares = accepted_shares + ? WHERE id = ?",
            work,
            shares,
            id
        )
        .execute(&self.pool)
        .await;
    }

    /// Count submitted shares against an order (for the accept-ratio).
    pub async fn add_submitted(&self, id: &str, submitted: u64) {
        let n = submitted as i64;
        let _ = sqlx::query!(
            "UPDATE orders SET submitted_shares = submitted_shares + ? WHERE id = ?",
            n,
            id
        )
        .execute(&self.pool)
        .await;
    }

    /// Cancel an order; returns it (status updated) so the caller can revert.
    pub async fn cancel(&self, id: &str) -> Option<Order> {
        let existing = self.get(id).await?;
        let _ = sqlx::query!("UPDATE orders SET status = 'cancelled' WHERE id = ?", id)
            .execute(&self.pool)
            .await;
        Some(Order {
            status: OrderStatus::Cancelled,
            ..existing
        })
    }

    /// Mark every finished active order as ended (past its deadline OR with its
    /// prepaid budget consumed) and return them so the caller can revert the
    /// corresponding sessions.
    pub async fn take_expired(&self, now: i64) -> Vec<Order> {
        let active = sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             created_ms, until_ms, status, delivered_work, accepted_shares, submitted_shares, \
             price_per_th_day, budget FROM orders WHERE status = 'active'"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let mut finished = Vec::new();
        for o in active.into_iter().map(OrderRow::into_order) {
            let deadline_passed = o.until_ms > 0 && o.until_ms <= now;
            if deadline_passed || o.funding_exhausted() {
                let _ = sqlx::query!("UPDATE orders SET status = 'ended' WHERE id = ?", o.id)
                    .execute(&self.pool)
                    .await;
                finished.push(Order {
                    status: OrderStatus::Ended,
                    ..o
                });
            }
        }
        finished
    }
}

/// Background task: every 5s, revert sessions whose rental has finished
/// (deadline reached or prepaid budget consumed).
pub fn spawn_expiry(orders: Arc<OrderStore>, registry: Arc<Registry>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            for o in orders.take_expired(now_ms()).await {
                let sessions = registry.get_all(&o.worker).await;
                if !sessions.is_empty() {
                    for session in &sessions {
                        let _ = session.revert().await;
                    }
                    info!(order = %o.id, worker = %o.worker, sessions = sessions.len(), "rental finished → reverted to default");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store.create("w1".into(), target(), 0, 0.0, 0.0).await.unwrap(); // open-ended
        assert!(store.active_for_worker("w1", now_ms()).await.is_some());
        let cancelled = store.cancel(&o.id).await.unwrap();
        assert_eq!(cancelled.status, OrderStatus::Cancelled);
        assert!(store.active_for_worker("w1", now_ms()).await.is_none());
    }

    #[tokio::test]
    async fn one_active_order_per_worker() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let first = store.create("w7".into(), target(), 0, 0.0, 0.0).await.unwrap();
        // A second active order for the same worker is rejected by the DB guard.
        assert!(matches!(
            store.create("w7".into(), target(), 0, 0.0, 0.0).await,
            Err(CreateOrderError::AlreadyActive)
        ));
        // A different worker is unaffected.
        assert!(store.create("w8".into(), target(), 0, 0.0, 0.0).await.is_ok());
        // Once the first ends, the worker can be rented again.
        store.cancel(&first.id).await.unwrap();
        assert!(store.create("w7".into(), target(), 0, 0.0, 0.0).await.is_ok());
    }

    #[tokio::test]
    async fn expiry_marks_ended_and_is_returned() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let _past = store.create("w2".into(), target(), now_ms() - 1000, 0.0, 0.0).await.unwrap();
        let _live = store.create("w3".into(), target(), now_ms() + 60_000, 0.0, 0.0).await.unwrap();
        let expired = store.take_expired(now_ms()).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].worker, "w2");
        assert!(store.active_for_worker("w3", now_ms()).await.is_some());
        assert!(store.take_expired(now_ms()).await.is_empty());
    }

    #[tokio::test]
    async fn funding_exhausted_ends_the_order() {
        let store = OrderStore::new(crate::db::test_pool().await);
        // price 1.0 per TH·day, prepaid budget 100, open-ended deadline.
        let o = store.create("w5".into(), target(), 0, 1.0, 100.0).await.unwrap();
        assert!(store.take_expired(now_ms()).await.is_empty(), "fresh order is live");

        let work_for_100_th_days = 100.0 * HASHES_PER_TH_DAY / DIFF1_HASHES;
        store.add_work(&o.id, work_for_100_th_days, 1).await;

        let after = store.get(&o.id).await.unwrap();
        assert!((after.cost() - 100.0).abs() < 1e-6, "cost ≈ budget");
        assert_eq!(after.budget_remaining(), 0.0);

        let ended = store.take_expired(now_ms()).await;
        assert_eq!(ended.len(), 1, "exhausted budget ends the rental");
        assert_eq!(ended[0].id, o.id);
    }

    #[tokio::test]
    async fn work_and_submitted_accumulate() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store.create("w6".into(), target(), 0, 0.0, 0.0).await.unwrap();
        store.add_work(&o.id, 2.5, 2).await;
        store.add_work(&o.id, 1.5, 1).await;
        store.add_submitted(&o.id, 4).await;
        let got = store.get(&o.id).await.unwrap();
        assert!((got.delivered_work - 4.0).abs() < 1e-9);
        assert_eq!(got.accepted_shares, 3);
        assert_eq!(got.submitted_shares, 4);
    }

    #[tokio::test]
    async fn persists_across_reconnect() {
        let pool = crate::db::test_pool().await;
        let id = {
            let store = OrderStore::new(pool.clone());
            store.create("w4".into(), target(), 0, 0.0, 0.0).await.unwrap().id
        };
        let reloaded = OrderStore::new(pool);
        assert!(reloaded.get(&id).await.is_some());
    }
}
