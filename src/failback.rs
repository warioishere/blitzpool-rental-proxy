// SPDX-License-Identifier: AGPL-3.0-or-later

//! Failback: a rental mining on its fallback pool goes back to its primary
//! once the primary passes the pool probe again.
//!
//! The relays connect a rental's primary first and its fallback only when the
//! primary fails, so the move back is a reconnect: the miners' fresh
//! handshakes try the primary first, as every operator pool change does.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::info;

use crate::chain::Electrum;
use crate::orders::{now_ms, Order, OrderStore};
use crate::proto::sv2::relay::Sv2RigRegistry;
use crate::registry::Registry;
use crate::session::UpstreamTarget;

/// How often the primaries of rentals on their fallback are looked at.
const FAILBACK_TICK: Duration = Duration::from_secs(60);
/// Probes in a row a primary must pass before its rental moves back, so a
/// primary that comes and goes does not move the rig with every pass.
const FAILBACK_PASSES: u32 = 3;
/// The longest wait between two probes of a failing primary, in rounds.
const MAX_WAIT_ROUNDS: u32 = 10;

/// Background task: every [`FAILBACK_TICK`], one [`Failback::round`].
pub fn spawn_failback(
    orders: Arc<OrderStore>,
    registry: Arc<Registry>,
    sv2_rigs: Arc<Sv2RigRegistry>,
    chain: Option<Arc<Electrum>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut failback = Failback::default();
        let mut tick = tokio::time::interval(FAILBACK_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            failback
                .round(&orders, &registry, &sv2_rigs, chain.as_deref())
                .await;
        }
    })
}

/// What one round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Round {
    /// The rentals whose primary was probed.
    pub probed: Vec<String>,
    /// The rentals moved back to their primary.
    pub moved: Vec<String>,
}

/// One rental on its fallback: how its primary has done lately.
struct Track {
    /// The primary the counts are about; a new one starts them over.
    primary: UpstreamTarget,
    /// Probes passed in a row.
    passes: u32,
    /// Probes failed in a row; a passed probe clears them.
    failures: u32,
    /// Moves that did not hold; only a move that holds clears them, by
    /// taking the rental off its fallback and so ending the track.
    failed_moves: u32,
    /// Rounds left before the next probe.
    wait: u32,
    /// The rental was moved back in the round before.
    moved: bool,
}

impl Track {
    fn new(primary: UpstreamTarget) -> Self {
        Self {
            primary,
            passes: 0,
            failures: 0,
            failed_moves: 0,
            wait: 0,
            moved: false,
        }
    }

    /// A passed probe.
    fn pass(&mut self) {
        self.passes += 1;
        self.failures = 0;
    }

    /// A failed probe.
    fn fail(&mut self) {
        self.failures += 1;
        self.back_off();
    }

    /// A move that did not hold: the primary passes the probe but does not
    /// take the rig.
    fn fail_move(&mut self) {
        self.failed_moves += 1;
        self.back_off();
    }

    /// Wait 1, 2, 4, 8 rounds, then [`MAX_WAIT_ROUNDS`], before the next
    /// probe, by the failures and failed moves so far.
    fn back_off(&mut self) {
        self.passes = 0;
        let n = self.failures + self.failed_moves;
        let rounds = 1u32
            .checked_shl(n - 1)
            .unwrap_or(u32::MAX)
            .min(MAX_WAIT_ROUNDS);
        self.wait = rounds - 1;
    }
}

/// The primaries' records, per rental on its fallback.
#[derive(Default)]
pub struct Failback {
    tracks: HashMap<String, Track>,
}

impl Failback {
    /// Probe the primary of every live rental with a session on its fallback,
    /// backing off while it fails, and move the rentals whose primary passed
    /// [`FAILBACK_PASSES`] probes in a row. A rental still on its fallback in
    /// the round after its move counts as a failure: its primary passes the
    /// probe but does not take the rig.
    pub async fn round(
        &mut self,
        orders: &OrderStore,
        registry: &Registry,
        sv2_rigs: &Sv2RigRegistry,
        chain: Option<&Electrum>,
    ) -> Round {
        let mut on_fallback = Vec::new();
        for order in orders.list().await {
            if order.is_live(now_ms()) && on_its_fallback(&order, registry).await {
                on_fallback.push(order);
            }
        }
        self.tracks
            .retain(|id, _| on_fallback.iter().any(|o| o.id == *id));

        let mut round = Round::default();
        for order in on_fallback {
            let track = self
                .tracks
                .entry(order.id.clone())
                .or_insert_with(|| Track::new(order.target.clone()));
            if track.primary != order.target {
                *track = Track::new(order.target.clone());
            }
            if std::mem::take(&mut track.moved) {
                track.fail_move();
                continue;
            }
            if track.wait > 0 {
                track.wait -= 1;
                continue;
            }
            round.probed.push(order.id.clone());
            let identity = crate::proto::relay::upstream_worker(&order.target.user, &order.worker);
            match crate::probe::probe_pool(&order.target, &identity, chain).await {
                Ok(_) => track.pass(),
                Err(_) => track.fail(),
            }
            if track.passes < FAILBACK_PASSES {
                continue;
            }
            // The probes took time: move the rental only if it still runs on
            // the pools they were about, and still on its fallback.
            let current = orders.get(&order.id).await.filter(|o| {
                o.is_live(now_ms()) && o.target == order.target && o.fallback == order.fallback
            });
            let still_on_fallback = match &current {
                Some(o) => on_its_fallback(o, registry).await,
                None => false,
            };
            if !still_on_fallback {
                self.tracks.remove(&order.id);
                continue;
            }
            track.passes = 0;
            track.moved = true;
            let reconnected =
                crate::control::reconnect_worker(registry, sv2_rigs, &order.worker).await;
            info!(order = %order.id, worker = %order.worker, primary = %order.target.url, reconnected, "primary pool back: moving the rental off its fallback");
            round.moved.push(order.id);
        }
        round
    }
}

/// Does a session of `order`'s rig mine the rental on its fallback pool?
async fn on_its_fallback(order: &Order, registry: &Registry) -> bool {
    let Some(fallback) = order.fallback.as_ref().filter(|f| **f != order.target) else {
        return false;
    };
    for session in registry.get_all(&order.worker).await {
        let (routing, pool) = session.upstream().await;
        if routing.order_id() == Some(order.id.as_str()) && pool == *fallback {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_primary_is_probed_ever_less_often_up_to_the_cap() {
        let mut track = Track::new(UpstreamTarget::default());
        let waits: Vec<u32> = (0..7)
            .map(|_| {
                track.fail();
                track.wait
            })
            .collect();
        assert_eq!(waits, vec![0, 1, 3, 7, 9, 9, 9]);
        for _ in 0..100 {
            track.fail();
        }
        assert_eq!(track.wait, MAX_WAIT_ROUNDS - 1);
    }

    #[test]
    fn moves_that_do_not_hold_wait_ever_longer_though_the_probe_passes() {
        let mut track = Track::new(UpstreamTarget::default());
        let waits: Vec<u32> = (0..5)
            .map(|_| {
                // The primary passes its probes, the move does not hold.
                for _ in 0..FAILBACK_PASSES {
                    track.pass();
                }
                track.fail_move();
                track.wait
            })
            .collect();
        assert_eq!(waits, vec![0, 1, 3, 7, 9]);
    }
}
