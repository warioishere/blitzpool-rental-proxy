//! Live session registry: maps a seller miner's worker name to its active
//! session, so the control layer can find a connected miner and switch where
//! its hashrate goes. Sessions are held protocol-agnostically as
//! [`AnySession`].

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::control::{AnySession, SessionStatus};

#[derive(Default)]
pub struct Registry {
    inner: Mutex<HashMap<String, AnySession>>,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn insert(&self, worker: String, session: AnySession) {
        self.inner.lock().await.insert(worker, session);
    }

    /// Remove only if the stored session is the same instance (avoid a late
    /// disconnect evicting a freshly reconnected session under the same name).
    pub async fn remove_if(&self, worker: &str, session: &AnySession) {
        let mut map = self.inner.lock().await;
        if let Some(cur) = map.get(worker) {
            if cur.ptr_eq(session) {
                map.remove(worker);
            }
        }
    }

    pub async fn get(&self, worker: &str) -> Option<AnySession> {
        self.inner.lock().await.get(worker).cloned()
    }

    pub async fn list(&self) -> Vec<String> {
        self.inner.lock().await.keys().cloned().collect()
    }

    /// Status snapshot of every connected session.
    pub async fn snapshot(&self) -> Vec<SessionStatus> {
        let sessions: Vec<AnySession> = self.inner.lock().await.values().cloned().collect();
        let mut out = Vec::with_capacity(sessions.len());
        for s in sessions {
            out.push(s.status().await);
        }
        out
    }
}
