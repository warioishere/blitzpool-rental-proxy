//! Persistent seller store: each seller miner's worker name → its default
//! pool (where it mines while idle). JSON-file backed, atomic save.
//!
//! Set via the API; consulted by the relay when a miner authorizes. A worker
//! with no entry falls back to the process-wide default upstream.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::session::UpstreamTarget;

pub struct SellerStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, UpstreamTarget>>,
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

    pub async fn get(&self, worker: &str) -> Option<UpstreamTarget> {
        self.inner.lock().await.get(worker).cloned()
    }

    pub async fn set(&self, worker: String, target: UpstreamTarget) -> std::io::Result<()> {
        self.inner.lock().await.insert(worker, target);
        self.save().await
    }

    pub async fn remove(&self, worker: &str) -> std::io::Result<bool> {
        let existed = self.inner.lock().await.remove(worker).is_some();
        if existed {
            self.save().await?;
        }
        Ok(existed)
    }

    pub async fn list(&self) -> HashMap<String, UpstreamTarget> {
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
    fn target(url: &str) -> UpstreamTarget {
        UpstreamTarget {
            url: url.into(),
            user: "acct".into(),
            password: "x".into(),
            authority_pubkey: None,
        }
    }

    #[tokio::test]
    async fn set_get_remove() {
        let p = tmp_path("crud");
        let _ = std::fs::remove_file(&p);
        let store = SellerStore::load(p.clone()).await;
        assert!(store.get("w1").await.is_none());
        store.set("w1".into(), target("poolA:3333")).await.unwrap();
        assert_eq!(store.get("w1").await.unwrap().url, "poolA:3333");
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
            store.set("w2".into(), target("poolB:3333")).await.unwrap();
        }
        let reloaded = SellerStore::load(p.clone()).await;
        assert_eq!(reloaded.get("w2").await.unwrap().url, "poolB:3333");
        let _ = std::fs::remove_file(&p);
    }
}
