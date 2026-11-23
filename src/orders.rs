// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rental orders (SQLite, `orders` table): a buyer rents a worker's hashrate
//! until a deadline and/or a prepaid budget.
//!
//! Creating an order reconnects the rig's miners onto the buyer's target; a
//! background expiry task reconnects them to the idle pool when the deadline
//! passes or the prepaid budget is consumed. Orders are persisted, so a rental
//! is resumed when the miner reconnects (the relays look up the active order
//! when the worker becomes known) and finished orders are ended after a
//! restart. Measured delivered work (the billing basis) is accumulated here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::registry::Registry;
use crate::session::{UpstreamTarget, DIFF1_HASHES};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Hashes in one TH·day: 1e12 H/s × 86400 s. Used to turn measured work into
/// the billable TH·day quantity.
const HASHES_PER_TH_DAY: f64 = 1e12 * 86_400.0;

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
    fn from_db(s: &str) -> OrderStatus {
        match s {
            "ended" => OrderStatus::Ended,
            "cancelled" => OrderStatus::Cancelled,
            _ => OrderStatus::Active,
        }
    }
}

/// Why an order left `active`. Serialized kebab-case, the same string the DB
/// stores, so the marketplace can map it to its own wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndReason {
    /// The rental reached its `until_ms`.
    Deadline,
    /// The measured cost reached the prepaid budget.
    Budget,
    /// Cancelled through the API.
    Cancelled,
    /// The buyer's pool accepted none of [`UNACCEPTED_SUBMITS_LIMIT`] shares,
    /// or, after it accepted some, rejected [`REJECTS_IN_A_ROW_LIMIT`] in a row.
    PoolRejectsShares,
    /// The buyer's pool connection dropped [`UNACCEPTED_DROPS_LIMIT`] times
    /// before it accepted a single share.
    PoolConnectionUnstable,
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Deadline => "deadline",
            EndReason::Budget => "budget",
            EndReason::Cancelled => "cancelled",
            EndReason::PoolRejectsShares => "pool-rejects-shares",
            EndReason::PoolConnectionUnstable => "pool-connection-unstable",
        }
    }

    fn from_db(s: &str) -> Option<EndReason> {
        [
            EndReason::Deadline,
            EndReason::Budget,
            EndReason::Cancelled,
            EndReason::PoolRejectsShares,
            EndReason::PoolConnectionUnstable,
        ]
        .into_iter()
        .find(|r| r.as_str() == s)
    }
}

/// Shares submitted on a rental, none of them accepted, after which the
/// buyer's pool is judged unable to take this rig's work and the rental ends.
pub const UNACCEPTED_SUBMITS_LIMIT: u64 = 30;
/// Shares the buyer's pool rejected in a row after it had accepted some, after
/// which the rental ends: a pool that takes shares and then stops (a blocked
/// worker, a changed login). Counted on rejects the pool sends, one per share,
/// so a pool that acknowledges accepted shares in batches, and silence during
/// an outage, never add to it.
pub const REJECTS_IN_A_ROW_LIMIT: u64 = 30;
/// Upstream drops on a rental, with no share accepted, after which the rental
/// ends.
pub const UNACCEPTED_DROPS_LIMIT: u32 = 10;

/// What the relays saw of a rental's pool beyond the share counters: how often
/// its connection dropped, the last reason it gave for rejecting a share, and
/// how many it rejected since it last accepted one. In memory only; a restart
/// starts the counts over.
#[derive(Default, Clone)]
struct PoolHealth {
    drops: u32,
    last_reject: Option<String>,
    /// Shares the pool rejected since it last accepted one.
    rejects_since_accept: u64,
    /// The order's accepted and submitted share counts when its pools were
    /// last replaced; zero for an order still on the pools it was created
    /// with. The pool rules judge the counts above these, so the current pools
    /// answer for their own shares only.
    accepted_before: u64,
    submitted_before: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub worker: String,
    pub target: UpstreamTarget,
    /// Optional fallback pool: if the proxy can't reach `target` (offline at the
    /// switch, or it drops mid-rental), it routes the rented hashrate here
    /// instead. Either protocol; the proxy translates when it differs from the
    /// rig's.
    #[serde(default)]
    pub fallback: Option<UpstreamTarget>,
    pub created_ms: i64,
    /// Auto-revert deadline (epoch ms). `0` = open-ended (no auto-revert).
    pub until_ms: i64,
    pub status: OrderStatus,
    /// When the order left `active` (ended or cancelled), epoch ms. `0` while
    /// still active, or unknown for rows that ended before the `ended_ms`
    /// migration.
    #[serde(default)]
    pub ended_ms: i64,
    /// Why the order ended; `None` while active, or for rows that ended before
    /// the `end_reason` migration.
    #[serde(default)]
    pub end_reason: Option<EndReason>,
    /// Detail for `end_reason`, e.g. the pool's reject reason.
    #[serde(default)]
    pub end_detail: Option<String>,
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
    /// When the proxy last measured a share this rental's miner found while
    /// routed to it with its pool connection up (epoch ms): validated against
    /// the miner's target, whether it met the pool's or not, or, for a channel
    /// the proxy cannot validate, accepted by the pool. `None` until the first
    /// one since the proxy started. A liveness signal for rentals whose pool
    /// accepts shares rarely; not billed, not stored.
    #[serde(default)]
    pub last_share_ms: Option<i64>,
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

    /// Run `connect` against the order's pool, then against its fallback pool
    /// when the primary fails. Returns the pool that took the connection and
    /// what `connect` returned for it.
    pub async fn connect_with_fallback<F, Fut, T>(
        &self,
        mut connect: F,
    ) -> anyhow::Result<(UpstreamTarget, T)>
    where
        F: FnMut(UpstreamTarget) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let primary_err = match connect(self.target.clone()).await {
            Ok(t) => return Ok((self.target.clone(), t)),
            Err(e) => e,
        };
        let Some(fallback) = &self.fallback else {
            return Err(primary_err);
        };
        warn!(order = %self.id, error = %primary_err, "primary buyer pool unreachable — using fallback");
        let t = connect(fallback.clone()).await?;
        Ok((fallback.clone(), t))
    }

    /// Is `pool` one of this order's pools (its primary or its fallback)?
    pub fn uses_pool(&self, pool: &UpstreamTarget) -> bool {
        self.target == *pool || self.fallback.as_ref() == Some(pool)
    }

    /// True when a budgeted rental has consumed its prepaid credit.
    pub fn funding_exhausted(&self) -> bool {
        self.budget > 0.0 && self.cost() >= self.budget
    }

    /// Why this active order must end now, if it must. Deadline and budget come
    /// first. Before the pool accepted a share, the pool rules judge submits
    /// and drops; after, only a run of rejects the pool itself sends, so a
    /// delivering rental is never ended by them. "The pool" is the order's
    /// current pools: shares counted before they were set are left out.
    fn end_cause(&self, health: &PoolHealth, now: i64) -> Option<(EndReason, Option<String>)> {
        if self.until_ms > 0 && self.until_ms <= now {
            return Some((EndReason::Deadline, None));
        }
        if self.funding_exhausted() {
            return Some((EndReason::Budget, None));
        }
        let accepted = self.accepted_shares.saturating_sub(health.accepted_before);
        let submitted = self
            .submitted_shares
            .saturating_sub(health.submitted_before);
        if accepted > 0 {
            if health.rejects_since_accept >= REJECTS_IN_A_ROW_LIMIT {
                let reason = health.last_reject.as_deref().unwrap_or("no reason given");
                let detail = format!(
                    "{} shares rejected in a row after the pool had accepted some; pool said: {reason}",
                    health.rejects_since_accept
                );
                return Some((EndReason::PoolRejectsShares, Some(detail)));
            }
            return None;
        }
        if submitted >= UNACCEPTED_SUBMITS_LIMIT {
            let detail = match &health.last_reject {
                Some(reason) => {
                    format!("{submitted} shares submitted, none accepted; pool said: {reason}")
                }
                None => {
                    format!("{submitted} shares submitted, none accepted; the pool did not answer")
                }
            };
            return Some((EndReason::PoolRejectsShares, Some(detail)));
        }
        if health.drops >= UNACCEPTED_DROPS_LIMIT {
            let detail = format!(
                "pool connection dropped {} times before a share was accepted",
                health.drops
            );
            return Some((EndReason::PoolConnectionUnstable, Some(detail)));
        }
        None
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
    fallback_url: Option<String>,
    fallback_user: Option<String>,
    fallback_password: Option<String>,
    fallback_authority: Option<String>,
    created_ms: i64,
    until_ms: i64,
    status: String,
    ended_ms: i64,
    end_reason: Option<String>,
    end_detail: Option<String>,
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
            fallback: self.fallback_url.map(|url| UpstreamTarget {
                url,
                user: self.fallback_user.unwrap_or_default(),
                password: self.fallback_password.unwrap_or_default(),
                authority_pubkey: self.fallback_authority,
            }),
            created_ms: self.created_ms,
            until_ms: self.until_ms,
            status: OrderStatus::from_db(&self.status),
            ended_ms: self.ended_ms,
            end_reason: self.end_reason.as_deref().and_then(EndReason::from_db),
            end_detail: self.end_detail,
            delivered_work: self.delivered_work,
            accepted_shares: self.accepted_shares as u64,
            submitted_shares: self.submitted_shares as u64,
            last_share_ms: None,
            price_per_th_day: self.price_per_th_day,
            budget: self.budget,
        }
    }
}

/// Why [`OrderStore::create`] could not record an order.
#[derive(Debug, thiserror::Error)]
pub enum CreateOrderError {
    /// The worker already has an active order (one-active-per-worker guard).
    #[error("worker already has an active order")]
    AlreadyActive,
    /// A database error.
    #[error(transparent)]
    Db(sqlx::Error),
}

/// Per-order accounting buffered in memory between DB flushes.
#[derive(Default, Clone, Copy)]
struct WorkDelta {
    work: f64,
    accepted: u64,
    submitted: u64,
}

pub struct OrderStore {
    pool: SqlitePool,
    /// Measured work / share counts buffered per order, flushed to the DB
    /// periodically by [`OrderStore::flush`] (one UPDATE per order) instead of
    /// one write per share. The expiry task flushes every tick before checking
    /// budgets, so funding enforcement stays current; a crash loses at most one
    /// flush interval of credit (the buyer is then slightly under-charged).
    pending: Mutex<HashMap<String, WorkDelta>>,
    /// Per-order pool health the share counters do not carry, read by
    /// [`OrderStore::take_finished`].
    health: Mutex<HashMap<String, PoolHealth>>,
    /// Per-order time of the last validated share, see
    /// [`Order::last_share_ms`]. In memory only.
    last_share: Mutex<HashMap<String, i64>>,
}

impl OrderStore {
    pub fn new(pool: SqlitePool) -> Arc<Self> {
        Arc::new(Self {
            pool,
            pending: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
            last_share: Mutex::new(HashMap::new()),
        })
    }

    /// `order` with its in-memory [`Order::last_share_ms`] filled in.
    fn with_last_share(&self, mut order: Order) -> Order {
        order.last_share_ms = self.last_share.lock().unwrap().get(&order.id).copied();
        order
    }

    /// Record a new active rental. Fails with [`CreateOrderError::AlreadyActive`]
    /// if the worker already has an active order — the DB's one-active-per-worker
    /// unique index is the authoritative guard against a double-rent race.
    pub async fn create(
        &self,
        worker: String,
        target: UpstreamTarget,
        fallback: Option<UpstreamTarget>,
        until_ms: i64,
        price_per_th_day: f64,
        budget: f64,
    ) -> Result<Order, CreateOrderError> {
        let now = now_ms();
        let id = format!("o{}-{}", now, SEQ.fetch_add(1, Ordering::Relaxed));
        let status = OrderStatus::Active;
        let fb_url = fallback.as_ref().map(|f| f.url.clone());
        let fb_user = fallback.as_ref().map(|f| f.user.clone());
        let fb_pass = fallback.as_ref().map(|f| f.password.clone());
        let fb_auth = fallback.as_ref().and_then(|f| f.authority_pubkey.clone());
        sqlx::query!(
            "INSERT INTO orders (id, worker, target_url, target_user, target_password, \
             target_authority, fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, delivered_work, accepted_shares, \
             submitted_shares, price_per_th_day, budget) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,0,?,?)",
            id,
            worker,
            target.url,
            target.user,
            target.password,
            target.authority_pubkey,
            fb_url,
            fb_user,
            fb_pass,
            fb_auth,
            now,
            until_ms,
            "active",
            price_per_th_day,
            budget,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                CreateOrderError::AlreadyActive
            } else {
                CreateOrderError::Db(e)
            }
        })?;

        Ok(Order {
            id,
            worker,
            target,
            fallback,
            created_ms: now,
            until_ms,
            status,
            ended_ms: 0,
            end_reason: None,
            end_detail: None,
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            last_share_ms: None,
            price_per_th_day,
            budget,
        })
    }

    pub async fn get(&self, id: &str) -> Option<Order> {
        sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, ended_ms, end_reason, end_detail, delivered_work, \
             accepted_shares, submitted_shares, price_per_th_day, budget FROM orders WHERE id = ?",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .map(|r| self.with_last_share(r.into_order()))
    }

    pub async fn list(&self) -> Vec<Order> {
        sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, ended_ms, end_reason, end_detail, delivered_work, \
             accepted_shares, submitted_shares, price_per_th_day, budget FROM orders"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| self.with_last_share(r.into_order()))
        .collect()
    }

    /// All orders for a worker, oldest first — the rental history the
    /// marketplace rig chart renders as bands.
    pub async fn list_for_worker(&self, worker: &str) -> Vec<Order> {
        sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, ended_ms, end_reason, end_detail, delivered_work, \
             accepted_shares, submitted_shares, price_per_th_day, budget FROM orders WHERE worker = ? ORDER BY created_ms ASC",
            worker
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| self.with_last_share(r.into_order()))
        .collect()
    }

    /// The live order for a worker (used to resume a rental on reconnect).
    pub async fn active_for_worker(&self, worker: &str, now: i64) -> Option<Order> {
        let rows = sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, ended_ms, end_reason, end_detail, delivered_work, \
             accepted_shares, submitted_shares, price_per_th_day, budget FROM orders \
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

    /// Replace an active order's pools; `None` when the order is not active.
    /// Everything else about the order stays. The pool rules start over for
    /// the new pools: the drops, rejects and share counts so far were the
    /// replaced pool's (see [`PoolHealth`]). Like the rest of the pool health
    /// this is held in memory, so after a restart the rules judge the order's
    /// whole counts again.
    pub async fn set_pools(
        &self,
        id: &str,
        target: &UpstreamTarget,
        fallback: Option<&UpstreamTarget>,
    ) -> Result<Option<Order>, sqlx::Error> {
        let fb_url = fallback.map(|f| f.url.as_str());
        let fb_user = fallback.map(|f| f.user.as_str());
        let fb_pass = fallback.map(|f| f.password.as_str());
        let fb_auth = fallback.and_then(|f| f.authority_pubkey.as_deref());
        let updated = sqlx::query!(
            "UPDATE orders SET target_url = ?, target_user = ?, target_password = ?, \
             target_authority = ?, fallback_url = ?, fallback_user = ?, fallback_password = ?, \
             fallback_authority = ? WHERE id = ? AND status = 'active'",
            target.url,
            target.user,
            target.password,
            target.authority_pubkey,
            fb_url,
            fb_user,
            fb_pass,
            fb_auth,
            id,
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated == 0 {
            return Ok(None);
        }
        Ok(self.restart_pool_rules(id).await)
    }

    /// Start the pool rules over for an active order from its share counts as
    /// they stand: the rules leave out what it has accepted and submitted so
    /// far. Returns the order. Buffered accounting is
    /// written first; shares a flush already under way is still writing are
    /// not in the counts read here.
    pub async fn restart_pool_rules(&self, id: &str) -> Option<Order> {
        self.flush().await;
        let order = self.get(id).await?;
        if order.status == OrderStatus::Active {
            self.health.lock().unwrap().insert(
                id.to_string(),
                PoolHealth {
                    accepted_before: order.accepted_shares,
                    submitted_before: order.submitted_shares,
                    ..PoolHealth::default()
                },
            );
        }
        Some(order)
    }

    /// Buffer measured delivered work + accepted shares for an order; written to
    /// the DB by [`OrderStore::flush`]. Hot-path: in-memory only, no DB write.
    pub fn add_work(&self, id: &str, work: f64, accepted_shares: u64) {
        {
            let mut p = self.pending.lock().unwrap();
            let d = p.entry(id.to_string()).or_default();
            d.work += work;
            d.accepted += accepted_shares;
        }
        if accepted_shares > 0 {
            if let Some(h) = self.health.lock().unwrap().get_mut(id) {
                h.rejects_since_accept = 0;
            }
        }
    }

    /// Buffer submitted shares for an order (for the accept-ratio); written by
    /// [`OrderStore::flush`]. Hot-path: in-memory only.
    pub fn add_submitted(&self, id: &str, submitted: u64) {
        let mut p = self.pending.lock().unwrap();
        p.entry(id.to_string()).or_default().submitted += submitted;
    }

    /// Count a share the rental's pool rejected and remember its reason; the
    /// latest one becomes the end detail when a pool rule ends the rental.
    pub fn note_rejected(&self, id: &str, reason: String) {
        let mut h = self.health.lock().unwrap();
        let e = h.entry(id.to_string()).or_default();
        e.last_reject = Some(reason);
        e.rejects_since_accept += 1;
    }

    /// Record that a share for this rental was validated at `at_ms`; see
    /// [`Order::last_share_ms`]. Hot-path: in-memory only.
    pub fn note_share(&self, id: &str, at_ms: i64) {
        let mut m = self.last_share.lock().unwrap();
        let t = m.entry(id.to_string()).or_insert(at_ms);
        *t = (*t).max(at_ms);
    }

    /// Count a dropped connection to the rental's pool.
    pub fn note_upstream_drop(&self, id: &str) {
        let mut h = self.health.lock().unwrap();
        h.entry(id.to_string()).or_default().drops += 1;
    }

    /// Flush buffered accounting to the DB — one UPDATE per order, coalescing all
    /// the per-share deltas accumulated since the last flush. A no-op if nothing
    /// is buffered. Never holds the buffer lock across the DB await.
    pub async fn flush(&self) {
        let drained: Vec<(String, WorkDelta)> = {
            let mut p = self.pending.lock().unwrap();
            if p.is_empty() {
                return;
            }
            std::mem::take(&mut *p).into_iter().collect()
        };
        for (id, d) in drained {
            let accepted = d.accepted as i64;
            let submitted = d.submitted as i64;
            let _ = sqlx::query!(
                "UPDATE orders SET delivered_work = delivered_work + ?, \
                 accepted_shares = accepted_shares + ?, \
                 submitted_shares = submitted_shares + ? WHERE id = ?",
                d.work,
                accepted,
                submitted,
                id
            )
            .execute(&self.pool)
            .await;
        }
    }

    /// Cancel an order; returns it (status updated) so the caller can revert.
    pub async fn cancel(&self, id: &str) -> Option<Order> {
        let existing = self.get(id).await?;
        let now = now_ms();
        let reason = EndReason::Cancelled.as_str();
        let _ = sqlx::query!(
            "UPDATE orders SET status = 'cancelled', ended_ms = ?, end_reason = ? WHERE id = ?",
            now,
            reason,
            id
        )
        .execute(&self.pool)
        .await;
        self.health.lock().unwrap().remove(id);
        Some(Order {
            status: OrderStatus::Cancelled,
            ended_ms: now,
            end_reason: Some(EndReason::Cancelled),
            end_detail: None,
            ..existing
        })
    }

    /// Mark every active order that must end as ended, with its
    /// [`EndReason`], and return them so the caller can revert the
    /// corresponding sessions. See [`Order::end_cause`] for the rules.
    pub async fn take_finished(&self, now: i64) -> Vec<Order> {
        let active = sqlx::query_as!(
            OrderRow,
            "SELECT id, worker, target_url, target_user, target_password, target_authority, \
             fallback_url, fallback_user, fallback_password, fallback_authority, \
             created_ms, until_ms, status, ended_ms, end_reason, end_detail, delivered_work, \
             accepted_shares, submitted_shares, price_per_th_day, budget FROM orders WHERE status = 'active'"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let mut finished = Vec::new();
        for o in active.into_iter().map(OrderRow::into_order) {
            let health = self
                .health
                .lock()
                .unwrap()
                .get(&o.id)
                .cloned()
                .unwrap_or_default();
            let Some((reason, detail)) = o.end_cause(&health, now) else {
                continue;
            };
            let reason_str = reason.as_str();
            let _ = sqlx::query!(
                "UPDATE orders SET status = 'ended', ended_ms = ?, end_reason = ?, end_detail = ? \
                 WHERE id = ?",
                now,
                reason_str,
                detail,
                o.id
            )
            .execute(&self.pool)
            .await;
            self.health.lock().unwrap().remove(&o.id);
            finished.push(Order {
                status: OrderStatus::Ended,
                ended_ms: now,
                end_reason: Some(reason),
                end_detail: detail,
                ..o
            });
        }
        finished
    }
}

/// Background task: every 5s, revert sessions whose rental has finished
/// (deadline reached, prepaid budget consumed, or a pool rule: a pool that
/// takes none of the rig's shares, or rejects them in a row after it took
/// some).
pub fn spawn_expiry(orders: Arc<OrderStore>, registry: Arc<Registry>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            // Persist buffered share accounting before checking budgets, so
            // funding_exhausted sees the just-delivered work.
            orders.flush().await;
            for o in orders.take_finished(now_ms()).await {
                // The order is already marked ended, so a reconnect resolves
                // back to the idle pool. Force it rather than a live re-point.
                let sessions = registry.force_reconnect_all(&o.worker).await;
                if sessions > 0 {
                    info!(order = %o.id, worker = %o.worker, sessions, reason = ?o.end_reason, detail = ?o.end_detail, "rental finished → miners reconnecting to default");
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
    async fn last_share_ms_keeps_the_latest_and_starts_empty() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("w".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        assert_eq!(o.last_share_ms, None);
        assert_eq!(store.get(&o.id).await.unwrap().last_share_ms, None);
        store.note_share(&o.id, 2_000);
        store.note_share(&o.id, 1_000);
        assert_eq!(store.get(&o.id).await.unwrap().last_share_ms, Some(2_000));
    }

    #[tokio::test]
    async fn new_pools_replace_an_active_orders_and_leave_the_rest() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("wp".into(), target(), Some(target()), 0, 2.0, 50.0)
            .await
            .unwrap();
        store.add_submitted(&o.id, 3);
        store.add_work(&o.id, 7.0, 2);
        store.flush().await;
        let pool = UpstreamTarget {
            url: "other:4444".into(),
            user: "buyer2".into(),
            password: "pw".into(),
            authority_pubkey: Some("key".into()),
        };

        let got = store.set_pools(&o.id, &pool, None).await.unwrap().unwrap();
        assert_eq!(got.target, pool);
        assert_eq!(got.fallback, None);
        let stored = store.get(&o.id).await.unwrap();
        assert_eq!((stored.target, stored.fallback), (pool.clone(), None));
        assert_eq!(stored.id, o.id);
        assert_eq!(stored.created_ms, o.created_ms);
        assert_eq!((stored.price_per_th_day, stored.budget), (2.0, 50.0));
        assert_eq!(stored.delivered_work, 7.0);
        assert_eq!((stored.accepted_shares, stored.submitted_shares), (2, 3));

        // An order that is over keeps the pools it ended on.
        store.cancel(&o.id).await.unwrap();
        assert!(store
            .set_pools(&o.id, &target(), None)
            .await
            .unwrap()
            .is_none());
        assert_eq!(store.get(&o.id).await.unwrap().target, pool);
    }

    #[tokio::test]
    async fn rejects_from_the_replaced_pool_do_not_count_against_the_new_one() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let run = |id: String, replace: bool| {
            let store = store.clone();
            async move {
                store.add_submitted(&id, 1);
                store.add_work(&id, 1.0, 1);
                for _ in 0..REJECTS_IN_A_ROW_LIMIT - 1 {
                    store.note_rejected(&id, "Stale (21)".into());
                }
                if replace {
                    store
                        .set_pools(&id, &target(), None)
                        .await
                        .unwrap()
                        .unwrap();
                }
                store.note_rejected(&id, "Stale (21)".into());
                store.flush().await;
            }
        };
        let kept = store
            .create("wk".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        let replaced = store
            .create("wr".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        run(kept.id.clone(), false).await;
        run(replaced.id.clone(), true).await;
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1, "only the order that kept its pool ends");
        assert_eq!(ended[0].id, kept.id);
    }

    #[tokio::test]
    async fn the_pool_rules_judge_new_pools_on_their_own_shares() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let other = UpstreamTarget {
            url: "other:4444".into(),
            ..target()
        };
        // The first pool accepted a share; the new one takes none of a full
        // limit of submits. Without new pools the accepted share spares the
        // order.
        let spared = store
            .create("w1".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        let silent = store
            .create("w2".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        // The first pool took none of a nearly full limit of submits; the new
        // one gets the whole limit again. Without new pools one more ends it.
        let used_up = store
            .create("w3".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        let fresh = store
            .create("w4".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();

        for id in [&spared.id, &silent.id] {
            store.add_submitted(id, 1);
            store.add_work(id, 1.0, 1);
        }
        for id in [&used_up.id, &fresh.id] {
            store.add_submitted(id, UNACCEPTED_SUBMITS_LIMIT - 1);
        }
        for id in [&silent.id, &fresh.id] {
            store.set_pools(id, &other, None).await.unwrap().unwrap();
        }
        for id in [&spared.id, &silent.id] {
            store.add_submitted(id, UNACCEPTED_SUBMITS_LIMIT);
        }
        for id in [&used_up.id, &fresh.id] {
            store.add_submitted(id, 1);
        }
        store.flush().await;

        let mut ended: Vec<String> = store
            .take_finished(now_ms())
            .await
            .into_iter()
            .map(|o| o.id)
            .collect();
        ended.sort();
        let mut want = vec![silent.id.clone(), used_up.id.clone()];
        want.sort();
        assert_eq!(ended, want);
        let detail = store.get(&silent.id).await.unwrap().end_detail.unwrap();
        assert!(
            detail.starts_with(&format!("{UNACCEPTED_SUBMITS_LIMIT} shares submitted")),
            "the detail counts the new pool's submits only: {detail}"
        );

        // The new pool's remaining submits still end the order.
        store.add_submitted(&fresh.id, UNACCEPTED_SUBMITS_LIMIT - 1);
        store.flush().await;
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].id, fresh.id);
    }

    #[tokio::test]
    async fn a_share_the_replaced_pool_accepts_late_is_not_the_new_pools_first() {
        // An accept from the replaced pool lands after the pools are set and
        // before the miners are off it. Restarting the rules once they are
        // leaves it out; otherwise it spares a new pool that accepts nothing.
        let store = OrderStore::new(crate::db::test_pool().await);
        let run = |worker: &'static str, restart: bool| {
            let store = store.clone();
            async move {
                let o = store
                    .create(worker.into(), target(), None, 0, 1.0, 0.0)
                    .await
                    .unwrap();
                store
                    .set_pools(&o.id, &target(), None)
                    .await
                    .unwrap()
                    .unwrap();
                store.add_submitted(&o.id, 1);
                store.add_work(&o.id, 1.0, 1);
                if restart {
                    store.restart_pool_rules(&o.id).await.unwrap();
                }
                store.add_submitted(&o.id, UNACCEPTED_SUBMITS_LIMIT);
                o.id
            }
        };
        let restarted = run("w1", true).await;
        let _spared = run("w2", false).await;
        store.flush().await;
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].id, restarted);

        // An order that is over gets no pool rules.
        store.restart_pool_rules(&restarted).await.unwrap();
        assert!(!store.health.lock().unwrap().contains_key(&restarted));
    }

    #[tokio::test]
    async fn create_active_for_worker_and_cancel() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("w1".into(), target(), None, 0, 0.0, 0.0)
            .await
            .unwrap(); // open-ended
        assert!(store.active_for_worker("w1", now_ms()).await.is_some());
        let cancelled = store.cancel(&o.id).await.unwrap();
        assert_eq!(cancelled.status, OrderStatus::Cancelled);
        assert!(store.active_for_worker("w1", now_ms()).await.is_none());
    }

    #[tokio::test]
    async fn cancel_and_expiry_stamp_ended_ms_and_list_for_worker() {
        let store = OrderStore::new(crate::db::test_pool().await);
        // Cancel stamps ended_ms.
        let o1 = store
            .create("wend".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        let c = store.cancel(&o1.id).await.unwrap();
        assert!(c.ended_ms > 0, "cancel sets ended_ms");
        assert_eq!(c.status, OrderStatus::Cancelled);
        assert_eq!(c.end_reason, Some(EndReason::Cancelled));

        // A second order (allowed now the first is cancelled) with a passed
        // deadline is ended by take_finished, which also stamps ended_ms.
        let o2 = store
            .create("wend".into(), target(), None, now_ms() - 1000, 1.0, 0.0)
            .await
            .unwrap();
        let expired = store.take_finished(now_ms()).await;
        assert!(
            expired.iter().any(|o| o.id == o2.id && o.ended_ms > 0),
            "take_finished sets ended_ms"
        );
        let stored = store.get(&o2.id).await.unwrap();
        assert_eq!(stored.end_reason, Some(EndReason::Deadline));
        assert_eq!(
            store.get(&o1.id).await.unwrap().end_reason,
            Some(EndReason::Cancelled)
        );

        // Both orders come back for the worker, oldest first, all ended.
        let all = store.list_for_worker("wend").await;
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|o| o.worker == "wend" && o.ended_ms > 0));
        assert_eq!(all[0].id, o1.id, "oldest first");
    }

    #[tokio::test]
    async fn one_active_order_per_worker() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let first = store
            .create("w7".into(), target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        // A second active order for the same worker is rejected by the DB guard.
        assert!(matches!(
            store.create("w7".into(), target(), None, 0, 0.0, 0.0).await,
            Err(CreateOrderError::AlreadyActive)
        ));
        // A different worker is unaffected.
        assert!(store
            .create("w8".into(), target(), None, 0, 0.0, 0.0)
            .await
            .is_ok());
        // Once the first ends, the worker can be rented again.
        store.cancel(&first.id).await.unwrap();
        assert!(store
            .create("w7".into(), target(), None, 0, 0.0, 0.0)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn expiry_marks_ended_and_is_returned() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let _past = store
            .create("w2".into(), target(), None, now_ms() - 1000, 0.0, 0.0)
            .await
            .unwrap();
        let _live = store
            .create("w3".into(), target(), None, now_ms() + 60_000, 0.0, 0.0)
            .await
            .unwrap();
        let expired = store.take_finished(now_ms()).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].worker, "w2");
        assert!(store.active_for_worker("w3", now_ms()).await.is_some());
        assert!(store.take_finished(now_ms()).await.is_empty());
    }

    #[tokio::test]
    async fn funding_exhausted_ends_the_order() {
        let store = OrderStore::new(crate::db::test_pool().await);
        // price 1.0 per TH·day, prepaid budget 100, open-ended deadline.
        let o = store
            .create("w5".into(), target(), None, 0, 1.0, 100.0)
            .await
            .unwrap();
        assert!(
            store.take_finished(now_ms()).await.is_empty(),
            "fresh order is live"
        );

        let work_for_100_th_days = 100.0 * HASHES_PER_TH_DAY / DIFF1_HASHES;
        store.add_work(&o.id, work_for_100_th_days, 1);
        store.flush().await;

        let after = store.get(&o.id).await.unwrap();
        assert!((after.cost() - 100.0).abs() < 1e-6, "cost ≈ budget");
        assert_eq!(after.budget_remaining(), 0.0);

        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1, "exhausted budget ends the rental");
        assert_eq!(ended[0].id, o.id);
        assert_eq!(ended[0].end_reason, Some(EndReason::Budget));
    }

    #[tokio::test]
    async fn a_pool_that_accepts_no_share_ends_the_rental_with_its_reason() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("wp".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        store.add_submitted(&o.id, UNACCEPTED_SUBMITS_LIMIT - 1);
        store.note_rejected(&o.id, "Stale (21)".into());
        store.flush().await;
        assert!(
            store.take_finished(now_ms()).await.is_empty(),
            "one share short of the limit"
        );

        store.add_submitted(&o.id, 1);
        store.flush().await;
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].end_reason, Some(EndReason::PoolRejectsShares));
        let stored = store.get(&o.id).await.unwrap();
        assert_eq!(stored.status, OrderStatus::Ended);
        assert_eq!(stored.end_reason, Some(EndReason::PoolRejectsShares));
        assert!(
            stored.end_detail.as_deref().unwrap().contains("Stale (21)"),
            "{:?}",
            stored.end_detail
        );
        assert!(store.active_for_worker("wp", now_ms()).await.is_none());
    }

    #[tokio::test]
    async fn the_submit_and_drop_rules_spare_a_rental_with_one_accepted_share() {
        let store = OrderStore::new(crate::db::test_pool().await);
        // Same counts on both: far past both limits. Only `delivering` has a
        // share accepted.
        let delivering = store
            .create("wa".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        let dead = store
            .create("wd".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        for id in [&delivering.id, &dead.id] {
            store.add_submitted(id, 10 * UNACCEPTED_SUBMITS_LIMIT);
            for _ in 0..10 * UNACCEPTED_DROPS_LIMIT {
                store.note_upstream_drop(id);
            }
        }
        store.add_work(&delivering.id, 1.0, 1);
        store.flush().await;
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].id, dead.id);
        assert!(store.active_for_worker("wa", now_ms()).await.is_some());
    }

    #[tokio::test]
    async fn a_pool_that_stops_accepting_ends_the_rental_after_a_run_of_rejects() {
        // The pool took shares, then rejects every one (a blocked worker): the
        // rental ends once the pool has rejected the limit in a row, and an
        // accepted share in between starts the count over.
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("ws".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        store.add_submitted(&o.id, 1);
        store.add_work(&o.id, 1.0, 1);
        for _ in 0..REJECTS_IN_A_ROW_LIMIT - 1 {
            store.note_rejected(&o.id, "Stale (21)".into());
        }
        store.add_work(&o.id, 1.0, 1);
        for _ in 0..REJECTS_IN_A_ROW_LIMIT - 1 {
            store.note_rejected(&o.id, "Worker banned".into());
        }
        store.flush().await;
        assert!(
            store.take_finished(now_ms()).await.is_empty(),
            "an accept in between starts the count over"
        );
        store.note_rejected(&o.id, "Worker banned".into());
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].end_reason, Some(EndReason::PoolRejectsShares));
        let detail = store.get(&o.id).await.unwrap().end_detail.unwrap();
        assert!(
            detail.contains("rejected in a row") && detail.contains("Worker banned"),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn submits_without_an_answer_never_end_a_delivering_rental() {
        // A pool that acknowledges accepted shares in batches, or an outage:
        // many submits, no ack yet, no reject. A rental that already had a
        // share accepted is not ended by that.
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("wb".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        store.add_submitted(&o.id, 1);
        store.add_work(&o.id, 1.0, 1);
        store.add_submitted(&o.id, 10 * REJECTS_IN_A_ROW_LIMIT);
        store.flush().await;
        assert!(store.take_finished(now_ms()).await.is_empty());
    }

    #[tokio::test]
    async fn a_pool_connection_that_keeps_dropping_ends_the_rental() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("wu".into(), target(), None, 0, 1.0, 0.0)
            .await
            .unwrap();
        for _ in 0..UNACCEPTED_DROPS_LIMIT - 1 {
            store.note_upstream_drop(&o.id);
        }
        assert!(store.take_finished(now_ms()).await.is_empty());
        store.note_upstream_drop(&o.id);
        let ended = store.take_finished(now_ms()).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].end_reason, Some(EndReason::PoolConnectionUnstable));
        assert_eq!(
            store.get(&o.id).await.unwrap().end_reason,
            Some(EndReason::PoolConnectionUnstable)
        );
    }

    #[test]
    fn end_reasons_round_trip_the_db_string() {
        for r in [
            EndReason::Deadline,
            EndReason::Budget,
            EndReason::Cancelled,
            EndReason::PoolRejectsShares,
            EndReason::PoolConnectionUnstable,
        ] {
            assert_eq!(EndReason::from_db(r.as_str()), Some(r));
            assert_eq!(serde_json::to_value(r).unwrap(), r.as_str());
        }
        assert_eq!(EndReason::from_db("unknown"), None);
    }

    #[tokio::test]
    async fn work_and_submitted_accumulate() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("w6".into(), target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        store.add_work(&o.id, 2.5, 2);
        store.add_work(&o.id, 1.5, 1);
        store.add_submitted(&o.id, 4);
        store.flush().await;
        let got = store.get(&o.id).await.unwrap();
        assert!((got.delivered_work - 4.0).abs() < 1e-9);
        assert_eq!(got.accepted_shares, 3);
        assert_eq!(got.submitted_shares, 4);
    }

    #[tokio::test]
    async fn fallback_pool_round_trips() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let fb = UpstreamTarget {
            url: "fallback:3333".into(),
            user: "fb".into(),
            password: "x".into(),
            authority_pubkey: Some("KEY".into()),
        };
        let o = store
            .create("wf".into(), target(), Some(fb.clone()), 0, 0.0, 0.0)
            .await
            .unwrap();
        assert_eq!(o.fallback, Some(fb.clone()));
        assert_eq!(store.get(&o.id).await.unwrap().fallback, Some(fb));
        // No fallback round-trips as None.
        let o2 = store
            .create("wf2".into(), target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        assert!(store.get(&o2.id).await.unwrap().fallback.is_none());
    }

    #[tokio::test]
    async fn add_work_is_buffered_until_flush() {
        let store = OrderStore::new(crate::db::test_pool().await);
        let o = store
            .create("wb".into(), target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        store.add_work(&o.id, 3.0, 2);
        store.add_submitted(&o.id, 5);
        // Buffered — not yet in the DB.
        let before = store.get(&o.id).await.unwrap();
        assert_eq!(before.delivered_work, 0.0);
        assert_eq!(before.accepted_shares, 0);
        assert_eq!(before.submitted_shares, 0);
        // Flush coalesces the buffered deltas into one write.
        store.flush().await;
        let after = store.get(&o.id).await.unwrap();
        assert!((after.delivered_work - 3.0).abs() < 1e-9);
        assert_eq!(after.accepted_shares, 2);
        assert_eq!(after.submitted_shares, 5);
    }

    #[tokio::test]
    async fn persists_across_reconnect() {
        let pool = crate::db::test_pool().await;
        let id = {
            let store = OrderStore::new(pool.clone());
            store
                .create("w4".into(), target(), None, 0, 0.0, 0.0)
                .await
                .unwrap()
                .id
        };
        let reloaded = OrderStore::new(pool);
        assert!(reloaded.get(&id).await.is_some());
    }
}
