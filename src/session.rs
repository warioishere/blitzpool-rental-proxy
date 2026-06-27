//! Protocol-agnostic session model: where a seller's miner is currently
//! routed, plus a rolling window for measuring delivered hashrate.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Difficulty-1 share = 2^32 hashes.
const DIFF1_HASHES: f64 = 4_294_967_296.0;

/// An upstream the proxy connects to as a client (a pool).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamTarget {
    /// `host:port`.
    pub url: String,
    /// Worker / account name presented to the upstream.
    pub user: String,
    #[serde(default)]
    pub password: String,
    /// SV2 only: the pool's Noise authority public key (base58). When set, the
    /// proxy verifies it during the upstream handshake; when `None`, the link is
    /// encrypted but unauthenticated. Ignored by the SV1 adapter.
    #[serde(default)]
    pub authority_pubkey: Option<String>,
}

/// Where a seller miner's hashrate currently goes.
#[derive(Debug, Clone)]
pub enum Routing {
    /// Not rented — mine on the seller's own default pool.
    Idle,
    /// Rented to an order. The live buyer target is `ActiveUpstream::target`; the
    /// order id is kept here to credit delivered work to the rental. The rental's
    /// deadline + budget live on the [`crate::orders::Order`].
    Rented { order_id: String },
}

/// Rolling window of accepted-share difficulty → hashrate estimate.
/// `hashrate = Σ(share_diff) * 2^32 / elapsed_seconds`, where `elapsed` is the
/// real span covered by the samples (capped at the window), so the estimate is
/// right within about a minute of (re)connect instead of taking the whole window
/// to warm up.
pub struct HashrateWindow {
    window: Duration,
    samples: VecDeque<(Instant, f64)>,
}

/// Floor for the rate divisor: stops a single early share from spiking the
/// number right after (re)connect, while still converging within ~a minute.
const MIN_RATE_SECS: f64 = 60.0;

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

    /// Estimated hashes/second.
    pub fn hashes_per_second(&self) -> f64 {
        self.hashes_per_second_at(Instant::now())
    }

    /// Rate at `now`: Σ(diff)·2^32 divided by the real elapsed span (oldest
    /// sample → now), clamped to `[MIN_RATE_SECS, window]`. Dividing by the
    /// actual span (not the fixed window) means the estimate is correct shortly
    /// after (re)connect; once mining longer than the window, pruning keeps the
    /// oldest sample ~`window` back, so it settles to a rolling window average.
    fn hashes_per_second_at(&self, now: Instant) -> f64 {
        let Some(&(oldest, _)) = self.samples.front() else {
            return 0.0;
        };
        let sum: f64 = self.samples.iter().map(|(_, d)| d).sum();
        let span = now
            .duration_since(oldest)
            .as_secs_f64()
            .min(self.window.as_secs_f64())
            .max(MIN_RATE_SECS);
        sum * DIFF1_HASHES / span
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrate_divides_by_elapsed_span_not_full_window() {
        let mut w = HashrateWindow::new(Duration::from_secs(600));
        let start = Instant::now();
        // 6 shares of diff 1000 spread over 200s (every 40s).
        for i in 0..6 {
            w.record_at(start + Duration::from_secs(i * 40), 1000.0);
        }
        let now = start + Duration::from_secs(200);
        // Span 200s (above floor, below window) ⇒ divide by 200, not 600.
        let expected = 6000.0 * DIFF1_HASHES / 200.0;
        assert!((w.hashes_per_second_at(now) - expected).abs() < 1.0);
    }

    #[test]
    fn hashrate_floors_early_estimate() {
        let mut w = HashrateWindow::new(Duration::from_secs(600));
        let start = Instant::now();
        // Two shares within the first 2s — span below the floor ⇒ divide by 60s,
        // so a single early share can't spike the number.
        w.record_at(start, 1000.0);
        w.record_at(start + Duration::from_secs(2), 1000.0);
        let expected = 2000.0 * DIFF1_HASHES / MIN_RATE_SECS;
        assert!((w.hashes_per_second_at(start + Duration::from_secs(2)) - expected).abs() < 1.0);
    }

    #[test]
    fn hashrate_caps_at_window_when_mining_longer() {
        let mut w = HashrateWindow::new(Duration::from_secs(600));
        let start = Instant::now();
        // Steady shares every 10s for 700s; pruning keeps only the last ~600s.
        for i in 0..=70 {
            w.record_at(start + Duration::from_secs(i * 10), 1000.0);
        }
        let now = start + Duration::from_secs(700);
        let sum_in_window: f64 = w.samples.iter().map(|(_, d)| d).sum();
        // Span is capped at the 600s window, so divide the in-window sum by 600.
        let expected = sum_in_window * DIFF1_HASHES / 600.0;
        assert!((w.hashes_per_second_at(now) - expected).abs() < 1.0);
    }
}
