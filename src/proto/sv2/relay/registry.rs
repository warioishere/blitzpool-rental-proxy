// SPDX-License-Identifier: AGPL-3.0-or-later

//! Same-rig bundle registry: maps each worker name to its shared SV2 rig
//! (so several same-rig miners share one upstream) + the idle-grace reaper.

use super::*;

/// The bundle-target SV2 rig for each worker, so several same-rig miners share
/// one upstream (one group of N channels) instead of one upstream each. Holds
/// only non-translating (SV2) sessions; SV1-translated rigs and any parallel
/// standalone sessions are not bundle targets and stay 1:1.
pub struct Sv2RigRegistry {
    rigs: Mutex<HashMap<String, Arc<Sv2Session>>>,
    /// Per-worker create-or-attach gate so two same-rig miners connecting at once
    /// don't both build an upstream; the loser waits, then attaches. The idle
    /// reaper takes the same gate, so an attach and a reap can't interleave.
    /// Distinct workers don't contend. Kept for the proxy's lifetime (bounded by
    /// distinct worker names) so a waiting attach can't race a fresh gate Arc.
    gates: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// How long to keep an emptied rig's upstream warm before reaping it.
    pub(super) idle_grace: Duration,
}

impl Default for Sv2RigRegistry {
    fn default() -> Self {
        Self {
            rigs: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            idle_grace: DEFAULT_IDLE_GRACE,
        }
    }
}

impl Sv2RigRegistry {
    /// A registry with a custom idle-grace window (tests use a short one).
    #[cfg(test)]
    pub(super) fn with_grace(idle_grace: Duration) -> Self {
        Self {
            idle_grace,
            ..Default::default()
        }
    }

    /// The serialization gate for one worker's create-or-attach (and reap).
    pub(super) async fn gate(&self, worker: &str) -> Arc<Mutex<()>> {
        self.gates
            .lock()
            .await
            .entry(worker.to_string())
            .or_default()
            .clone()
    }

    /// The bundle-target rig for a worker, if one is registered.
    pub(super) async fn get(&self, worker: &str) -> Option<Arc<Sv2Session>> {
        self.rigs.lock().await.get(worker).cloned()
    }

    /// Is `rig` the currently-registered bundle target for `worker`?
    pub(super) async fn is_target(&self, worker: &str, rig: &Arc<Sv2Session>) -> bool {
        self.rigs
            .lock()
            .await
            .get(worker)
            .is_some_and(|r| Arc::ptr_eq(r, rig))
    }

    /// Register `rig` as the bundle target for `worker`, but only if the slot is
    /// free (a translated rig or a race may already hold it; then this session
    /// runs standalone). Returns whether it became the bundle target.
    pub(super) async fn insert_if_absent(&self, worker: &str, rig: Arc<Sv2Session>) -> bool {
        let mut m = self.rigs.lock().await;
        if m.contains_key(worker) {
            return false;
        }
        m.insert(worker.to_string(), rig);
        true
    }

    /// Remove `rig` as the bundle target for `worker` — but only if it is still
    /// the registered one (a late teardown must not evict a fresh replacement).
    /// The per-worker gate is intentionally kept.
    async fn remove(&self, worker: &str, rig: &Arc<Sv2Session>) {
        let mut m = self.rigs.lock().await;
        if m.get(worker).is_some_and(|existing| Arc::ptr_eq(existing, rig)) {
            m.remove(worker);
        }
    }
}

/// After the idle-grace window, reap a rig whose last member never came back:
/// drop it from both registries and abort its upstream tasks. No-ops if a member
/// has since (re)attached, or if the rig emptied again under a newer token (a
/// fresh reaper owns that round). Takes the per-worker gate so it can't interleave
/// with a concurrent attach.
pub(super) async fn reap_idle_rig(
    rigs: Arc<Sv2RigRegistry>,
    registry: Arc<crate::registry::Registry>,
    session: Arc<Sv2Session>,
    worker: String,
    token: u64,
    grace: Duration,
) {
    tokio::time::sleep(grace).await;
    let gate = rigs.gate(&worker).await;
    let _hold = gate.lock().await;
    {
        let i = session.inner.lock().await;
        if !i.members.is_empty() || i.idle_token != token {
            return; // a member rejoined, or a newer idle round owns the reap
        }
    }
    rigs.remove(&worker, &session).await;
    registry
        .remove_if(&worker, &AnySession::Sv2(session.clone()))
        .await;
    let i = session.inner.lock().await;
    i.active.reader.abort();
    i.active.writer.abort();
    if let Some(sup) = &i.supervisor {
        sup.abort();
    }
    info!(%worker, "sv2 rig reaped after idle grace");
}
