//! Persistent rig/seller store: each seller miner's worker name → its [`Rig`]
//! (default pool + marketplace listing). JSON-file backed, atomic save.
//!
//! Set via the API; the relay consults the default pool when a miner
//! authorizes. A worker with no entry falls back to the process-wide default
//! upstream. The marketplace fields (advertised hashrate, price) are what a
//! buyer sees and what billing uses together with measured delivered work.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

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
    /// Seller's payout address (e.g. BTC) for rental earnings.
    #[serde(default)]
    pub payout_address: Option<String>,
}

pub struct SellerStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, Rig>>,
}

impl SellerStore {
    /// Load from `path` (missing/corrupt file ⇒ empty store).
    pub async fn load(path: PathBuf) -> Arc<Self> {
        let map = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        Arc::new(Self {
            path,
            inner: Mutex::new(map),
        })
    }

    pub async fn get(&self, worker: &str) -> Option<Rig> {
        self.inner.lock().await.get(worker).cloned()
    }

    /// The rig's idle/default pool (what the relay routes to when not rented).
    pub async fn default_pool(&self, worker: &str) -> Option<UpstreamTarget> {
        self.inner.lock().await.get(worker).map(|r| r.default_pool.clone())
    }

    pub async fn set(&self, worker: String, rig: Rig) -> std::io::Result<()> {
        self.inner.lock().await.insert(worker, rig);
        self.save().await
    }

    pub async fn remove(&self, worker: &str) -> std::io::Result<bool> {
        let existed = self.inner.lock().await.remove(worker).is_some();
        if existed {
            self.save().await?;
        }
        Ok(existed)
    }

    pub async fn list(&self) -> HashMap<String, Rig> {
        self.inner.lock().await.clone()
    }

    async fn save(&self) -> std::io::Result<()> {
        let data = {
            let map = self.inner.lock().await;
            serde_json::to_vec_pretty(&*map).unwrap_or_else(|_| b"{}".to_vec())
        };
        // Atomic: write a sibling temp file then rename over the target.
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &data).await?;
        tokio::fs::rename(&tmp, &self.path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("srp_seller_{}_{}.json", std::process::id(), tag))
    }
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
        let p = tmp_path("crud");
        let _ = std::fs::remove_file(&p);
        let store = SellerStore::load(p.clone()).await;
        assert!(store.get("w1").await.is_none());
        store.set("w1".into(), rig("poolA:3333")).await.unwrap();
        let got = store.get("w1").await.unwrap();
        assert_eq!(got.default_pool.url, "poolA:3333");
        assert_eq!(got.advertised_ths, 220.0);
        assert_eq!(store.default_pool("w1").await.unwrap().url, "poolA:3333");
        assert!(store.remove("w1").await.unwrap());
        assert!(!store.remove("w1").await.unwrap());
        assert!(store.get("w1").await.is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn persists_across_reload() {
        let p = tmp_path("persist");
        let _ = std::fs::remove_file(&p);
        {
            let store = SellerStore::load(p.clone()).await;
            store.set("w2".into(), rig("poolB:3333")).await.unwrap();
        }
        let reloaded = SellerStore::load(p.clone()).await;
        let got = reloaded.get("w2").await.unwrap();
        assert_eq!(got.default_pool.url, "poolB:3333");
        assert_eq!(got.price_per_th_day, 0.05);
        let _ = std::fs::remove_file(&p);
    }
}
