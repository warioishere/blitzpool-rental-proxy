//! Protocol-agnostic session model: where a seller's miner is currently
//! routed, plus a rolling window for measuring delivered hashrate.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Difficulty-1 share = 2^32 hashes.
const DIFF1_HASHES: f64 = 4_294_967_296.0;

/// An upstream the proxy connects to as a client (a pool).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamTarget {
    /// `host:port`.
    pub url: String,
    /// Worker / account name presented to the upstream.
    pub user: String,
    #[serde(default)]
    pub password: String,
}

/// Where a seller miner's hashrate currently goes.
#[derive(Debug, Clone)]
pub enum Routing {
    /// Not rented — mine on the seller's own default pool.
    Idle,
    /// Rented — forward to the buyer's target until `until_unix_ms`.
    Rented {
        order_id: String,
        target: UpstreamTarget,
        until_unix_ms: i64,
    },
}

impl Routing {
    /// The upstream this routing points at, given the seller's default.
    pub fn upstream<'a>(&'a self, default: &'a UpstreamTarget) -> &'a UpstreamTarget {
        match self {
            Routing::Idle => default,
            Routing::Rented { target, .. } => target,
        }
    }
}

/// A registered seller miner and its live routing + hashrate.
pub struct Session {
    pub seller_id: String,
    pub default_pool: UpstreamTarget,
    pub routing: Routing,
    pub hashrate: HashrateWindow,
}

impl Session {
    pub fn new(seller_id: impl Into<String>, default_pool: UpstreamTarget) -> Self {
        Self {
            seller_id: seller_id.into(),
            default_pool,
            routing: Routing::Idle,
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
        }
    }

    /// Current upstream target (default when idle, buyer target when rented).
    pub fn current_upstream(&self) -> &UpstreamTarget {
        self.routing.upstream(&self.default_pool)
    }

    pub fn is_rented(&self) -> bool {
        matches!(self.routing, Routing::Rented { .. })
    }
}

/// Rolling window of accepted-share difficulty → hashrate estimate.
/// `hashrate = Σ(share_diff) * 2^32 / window_seconds`.
pub struct HashrateWindow {
    window: Duration,
    samples: VecDeque<(Instant, f64)>,
}

impl HashrateWindow {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    /// Record an accepted share credited at `difficulty`.
    pub fn record(&mut self, difficulty: f64) {
        self.record_at(Instant::now(), difficulty);
    }

    fn record_at(&mut self, now: Instant, difficulty: f64) {
        self.samples.push_back((now, difficulty));
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&(t, _)) = self.samples.front() {
            if now.duration_since(t) > self.window {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Estimated hashes/second over the window.
    pub fn hashes_per_second(&self) -> f64 {
        let sum: f64 = self.samples.iter().map(|(_, d)| d).sum();
        let secs = self.window.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            sum * DIFF1_HASHES / secs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_uses_default_rented_uses_target() {
        let def = UpstreamTarget {
            url: "pool.a:3333".into(),
            user: "seller".into(),
            password: "x".into(),
        };
        let mut s = Session::new("seller1", def.clone());
        assert_eq!(s.current_upstream(), &def);

        let target = UpstreamTarget {
            url: "buyer-pool:3333".into(),
            user: "buyer".into(),
            password: "x".into(),
        };
        s.routing = Routing::Rented {
            order_id: "o1".into(),
            target: target.clone(),
            until_unix_ms: 0,
        };
        assert_eq!(s.current_upstream(), &target);
        assert!(s.is_rented());
    }

    #[test]
    fn hashrate_window_sums_difficulty() {
        let mut w = HashrateWindow::new(Duration::from_secs(600));
        for _ in 0..6 {
            w.record(1000.0);
        }
        // 6000 diff over 600s ⇒ 6000 * 2^32 / 600 hashes/s.
        let expected = 6000.0 * DIFF1_HASHES / 600.0;
        assert!((w.hashes_per_second() - expected).abs() < 1.0);
    }
}
