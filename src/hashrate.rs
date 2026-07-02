//! Per-rig delivered-hashrate history for the marketplace rig chart.
//!
//! The proxy's live hashrate is a ~10-minute rolling estimate held in memory on
//! each session ([`crate::session::HashrateWindow`]) and is not persisted
//! anywhere. This module samples it once per 10-minute wall-clock slot and
//! stores one row per rig per slot — so a single read per slot IS that slot's
//! 10-min average. Rows older than 7 days are pruned each tick.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use crate::orders::now_ms;
use crate::registry::Registry;
use crate::store::SellerStore;

/// One sample row per 10-minute wall-clock slot.
const SLOT_MS: i64 = 600_000;
/// History retention — the chart shows at most 7 days.
const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Hashes/second in one TH/s (the live estimate is in H/s).
const HS_PER_THS: f64 = 1e12;

/// A single 10-minute delivered-hashrate slot.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub slot_ms: i64,
    pub hashrate_ths: f64,
    pub online: bool,
}

/// Persists + serves per-rig hashrate slots (10-min, 7-day retention).
pub struct HashrateStore {
    pool: SqlitePool,
}

impl HashrateStore {
    pub fn new(pool: SqlitePool) -> Arc<Self> {
        Arc::new(Self { pool })
    }

    /// Upsert one slot. Idempotent per `(worker, slot)`, so re-sampling the same
    /// slot (e.g. after a restart within the 10 min) overwrites rather than
    /// erroring on the primary key.
    pub async fn record(&self, worker: &str, slot_ms: i64, hashrate_ths: f64, online: bool) {
        let online_i = online as i64;
        let _ = sqlx::query!(
            "INSERT INTO rig_hashrate_samples (worker, slot_ms, hashrate_ths, online) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(worker, slot_ms) DO UPDATE SET \
                hashrate_ths = excluded.hashrate_ths, online = excluded.online",
            worker,
            slot_ms,
            hashrate_ths,
            online_i,
        )
        .execute(&self.pool)
        .await;
    }

    /// Slots for a worker at or after `since_ms`, oldest first.
    pub async fn since(&self, worker: &str, since_ms: i64) -> Vec<Sample> {
        sqlx::query!(
            "SELECT slot_ms, hashrate_ths, online FROM rig_hashrate_samples \
             WHERE worker = ? AND slot_ms >= ? ORDER BY slot_ms ASC",
            worker,
            since_ms,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| Sample {
            slot_ms: r.slot_ms,
            hashrate_ths: r.hashrate_ths,
            online: r.online != 0,
        })
        .collect()
    }

    /// Delete slots older than the retention window.
    pub async fn prune(&self, older_than_ms: i64) {
        let _ = sqlx::query!(
            "DELETE FROM rig_hashrate_samples WHERE slot_ms < ?",
            older_than_ms
        )
        .execute(&self.pool)
        .await;
    }
}

/// Background task: every 10 minutes record one delivered-hashrate slot per
/// registered rig (live estimate is already a ~10-min average → one read = the
/// slot average), then prune rows older than 7 days.
pub fn spawn_sampler(
    registry: Arc<Registry>,
    sellers: Arc<SellerStore>,
    hashrate: Arc<HashrateStore>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(SLOT_MS as u64));
        loop {
            tick.tick().await;
            let now = now_ms();
            let slot_ms = (now / SLOT_MS) * SLOT_MS;
            for worker in sellers.list().await.into_keys() {
                // A rig with no connected session, or 0 H/s, counts as offline.
                let (ths, online) = match registry.aggregated_status(&worker).await {
                    Some(st) if st.hashrate_hs > 0.0 => (st.hashrate_hs / HS_PER_THS, true),
                    _ => (0.0, false),
                };
                hashrate.record(&worker, slot_ms, ths, online).await;
            }
            hashrate.prune(now - RETENTION_MS).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_upsert_since_and_prune() {
        let hs = HashrateStore::new(crate::db::test_pool().await);
        hs.record("rigA", 1_000_000, 100.0, true).await;
        hs.record("rigA", 1_600_000, 0.0, false).await;
        hs.record("rigB", 1_600_000, 50.0, true).await;
        // Re-recording the same (worker, slot) overwrites, not errors on the PK.
        hs.record("rigA", 1_000_000, 120.0, true).await;

        let a = hs.since("rigA", 0).await;
        assert_eq!(a.len(), 2, "rigB is a different worker");
        assert_eq!(a[0].slot_ms, 1_000_000);
        assert!((a[0].hashrate_ths - 120.0).abs() < 1e-9, "upsert overwrote slot");
        assert!(a[0].online);
        assert_eq!(a[1].slot_ms, 1_600_000);
        assert!(!a[1].online, "0 h/s slot is offline");

        // `since` filters older slots out.
        let recent = hs.since("rigA", 1_500_000).await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].slot_ms, 1_600_000);

        // Pruning drops slots strictly older than the cutoff.
        hs.prune(1_500_000).await;
        let after = hs.since("rigA", 0).await;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].slot_ms, 1_600_000);
    }
}
