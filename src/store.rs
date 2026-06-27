//! Persistent rig/seller store (SQLite, `rigs` table): each seller miner's
//! worker name → its [`Rig`] (default pool + marketplace listing).
//!
//! Set via the API; the relay consults the default pool when a miner
//! authorizes. A worker with no entry falls back to the process-wide default
//! upstream. The marketplace fields (advertised hashrate, price) are what a
//! buyer sees and what billing uses together with measured delivered work.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::warn;

use crate::session::UpstreamTarget;

/// A seller's registered rig: where it mines while idle, plus the listing the
/// marketplace shows (capacity + price). Billing combines `price_per_th_day`
/// with the proxy's measured delivered work.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rig {
    /// Pool the rig mines on while idle (not rented).
    pub default_pool: UpstreamTarget,
    /// Advertised nominal hashrate in TH/s (what the seller claims, e.g. 220).
    #[serde(default)]
    pub advertised_ths: f64,
    /// Listed price per TH/s per day (the chosen price).
    #[serde(default)]
    pub price_per_th_day: f64,
    /// Acceptable price range per TH/s per day (for negotiation / auto-accept).
    #[serde(default)]
    pub price_min_per_th_day: f64,
    #[serde(default)]
    pub price_max_per_th_day: f64,
    /// Seller's payout address (e.g. BTC/LN) for rental earnings.
    #[serde(default)]
    pub payout_address: Option<String>,
}

pub struct SellerStore {
    pool: SqlitePool,
}

impl SellerStore {
    pub fn new(pool: SqlitePool) -> Arc<Self> {
        Arc::new(Self { pool })
    }

    pub async fn get(&self, worker: &str) -> Option<Rig> {
        let row = sqlx::query!(
            "SELECT pool_url, pool_user, pool_password, pool_authority, advertised_ths, \
             price_per_th_day, price_min_per_th_day, price_max_per_th_day, payout_address \
             FROM rigs WHERE worker = ?",
            worker
        )
        .fetch_optional(&self.pool)
        .await;
        match row {
            Ok(Some(r)) => Some(Rig {
                default_pool: UpstreamTarget {
                    url: r.pool_url,
                    user: r.pool_user,
                    password: r.pool_password,
                    authority_pubkey: r.pool_authority,
                },
                advertised_ths: r.advertised_ths,
                price_per_th_day: r.price_per_th_day,
                price_min_per_th_day: r.price_min_per_th_day,
                price_max_per_th_day: r.price_max_per_th_day,
                payout_address: r.payout_address,
            }),
            Ok(None) => None,
            Err(e) => {
                warn!(worker, error = %e, "rig lookup failed");
                None
            }
        }
    }

    /// The rig's idle/default pool (what the relay routes to when not rented).
    pub async fn default_pool(&self, worker: &str) -> Option<UpstreamTarget> {
        self.get(worker).await.map(|r| r.default_pool)
    }

    pub async fn set(&self, worker: String, rig: Rig) -> sqlx::Result<()> {
        sqlx::query!(
            "INSERT INTO rigs (worker, pool_url, pool_user, pool_password, pool_authority, \
             advertised_ths, price_per_th_day, price_min_per_th_day, price_max_per_th_day, payout_address) \
             VALUES (?,?,?,?,?,?,?,?,?,?) \
             ON CONFLICT(worker) DO UPDATE SET \
               pool_url=excluded.pool_url, pool_user=excluded.pool_user, \
               pool_password=excluded.pool_password, pool_authority=excluded.pool_authority, \
               advertised_ths=excluded.advertised_ths, price_per_th_day=excluded.price_per_th_day, \
               price_min_per_th_day=excluded.price_min_per_th_day, \
               price_max_per_th_day=excluded.price_max_per_th_day, payout_address=excluded.payout_address",
            worker,
            rig.default_pool.url,
            rig.default_pool.user,
            rig.default_pool.password,
            rig.default_pool.authority_pubkey,
            rig.advertised_ths,
            rig.price_per_th_day,
            rig.price_min_per_th_day,
            rig.price_max_per_th_day,
            rig.payout_address,
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    pub async fn remove(&self, worker: &str) -> sqlx::Result<bool> {
        let res = sqlx::query!("DELETE FROM rigs WHERE worker = ?", worker)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn list(&self) -> HashMap<String, Rig> {
        let rows = sqlx::query!(
            "SELECT worker, pool_url, pool_user, pool_password, pool_authority, advertised_ths, \
             price_per_th_day, price_min_per_th_day, price_max_per_th_day, payout_address FROM rigs"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|r| {
                (
                    r.worker,
                    Rig {
                        default_pool: UpstreamTarget {
                            url: r.pool_url,
                            user: r.pool_user,
                            password: r.pool_password,
                            authority_pubkey: r.pool_authority,
                        },
                        advertised_ths: r.advertised_ths,
                        price_per_th_day: r.price_per_th_day,
                        price_min_per_th_day: r.price_min_per_th_day,
                        price_max_per_th_day: r.price_max_per_th_day,
                        payout_address: r.payout_address,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rig(url: &str) -> Rig {
        Rig {
            default_pool: UpstreamTarget {
                url: url.into(),
                user: "acct".into(),
                password: "x".into(),
                authority_pubkey: None,
            },
            advertised_ths: 220.0,
            price_per_th_day: 0.05,
            price_min_per_th_day: 0.04,
            price_max_per_th_day: 0.06,
            payout_address: Some("bc1qPAYOUT".into()),
        }
    }

    #[tokio::test]
    async fn set_get_remove() {
        let store = SellerStore::new(crate::db::test_pool().await);
        assert!(store.get("w1").await.is_none());
        store.set("w1".into(), rig("poolA:3333")).await.unwrap();
        let got = store.get("w1").await.unwrap();
        assert_eq!(got.default_pool.url, "poolA:3333");
        assert_eq!(got.advertised_ths, 220.0);
        assert_eq!(store.default_pool("w1").await.unwrap().url, "poolA:3333");
        assert!(store.remove("w1").await.unwrap());
        assert!(!store.remove("w1").await.unwrap());
        assert!(store.get("w1").await.is_none());
    }

    #[tokio::test]
    async fn upsert_overwrites() {
        let store = SellerStore::new(crate::db::test_pool().await);
        store.set("w2".into(), rig("poolB:3333")).await.unwrap();
        let mut updated = rig("poolC:3333");
        updated.price_per_th_day = 0.09;
        store.set("w2".into(), updated).await.unwrap();
        let got = store.get("w2").await.unwrap();
        assert_eq!(got.default_pool.url, "poolC:3333");
        assert_eq!(got.price_per_th_day, 0.09);
        assert_eq!(store.list().await.len(), 1);
    }
}
