// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol-agnostic session model: where a seller's miner is currently
//! routed, plus a rolling window for measuring delivered hashrate.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::control::{accept_ratio, accept_ratio_low, SessionStatus};

/// Difficulty-1 share = 2^32 hashes.
pub const DIFF1_HASHES: f64 = 4_294_967_296.0;

/// Turn a pool address the way buyers and sellers type it into the `host:port`
/// the relays connect with. Miner menus teach `stratum+tcp://host:port`;
/// `TcpStream::connect` takes the whole string as the host name, so the scheme
/// must go before anything is stored, or every connect of the order fails.
///
/// Only the plain-TCP schemes are stripped; anything else (`stratum+ssl://`,
/// `ssl://`, `http://`) names a transport the proxy cannot speak and is refused
/// here, at the API, instead of failing quietly at the next connect.
pub fn normalize_pool_url(raw: &str) -> anyhow::Result<String> {
    let s = raw.trim();
    let s = ["stratum+tcp://", "tcp://"]
        .iter()
        .find_map(|p| {
            s.get(..p.len())
                .filter(|head| head.eq_ignore_ascii_case(p))
                .map(|_| &s[p.len()..])
        })
        .unwrap_or(s);
    if s.contains("://") {
        anyhow::bail!(
            "pool url {raw:?}: only plain tcp is routable (host:port or stratum+tcp://host:port)"
        );
    }
    let Some((host, port)) = s.rsplit_once(':') else {
        anyhow::bail!("pool url {raw:?} needs host:port");
    };
    if host.is_empty() || host.contains('/') || port.parse::<u16>().is_err() {
        anyhow::bail!("pool url {raw:?} is not host:port");
    }
    Ok(s.to_string())
}

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

impl Routing {
    /// The order this hashrate is credited to, when rented.
    pub fn order_id(&self) -> Option<&str> {
        match self {
            Routing::Idle => None,
            Routing::Rented { order_id } => Some(order_id),
        }
    }
}

/// What one session has delivered: the live hashrate window, lifetime
/// counters, and the accept-ratio health signal over them. Every relay path
/// (SV1, SV2, and both translations) books through this one type.
///
/// Two sources, kept apart: the hashrate window measures every share the
/// proxy validated against the miner's target ([`Delivery::measured`]), the
/// counters and the bill take only what the pool accepted
/// ([`Delivery::accepted`]).
pub struct Delivery {
    hashrate: HashrateWindow,
    /// Lifetime delivered work, diff-1 share units (Σ accepted share difficulty).
    delivered_work: f64,
    accepted_shares: u64,
    submitted_shares: u64,
    /// Edge-trigger so the low-accept-ratio warning is logged once.
    accept_low_logged: bool,
}

impl Delivery {
    pub fn new() -> Self {
        Self {
            hashrate: HashrateWindow::new(Duration::from_secs(600)),
            delivered_work: 0.0,
            accepted_shares: 0,
            submitted_shares: 0,
            accept_low_logged: false,
        }
    }

    /// Count a share the miner submitted. The accept ratio only falls on a
    /// submit, so this is where its warning fires (once per session) — also
    /// for a miner none of whose shares are ever accepted.
    pub fn submitted(&mut self, worker: &str) {
        self.submitted_shares += 1;
        if !self.accept_low_logged && accept_ratio_low(self.accepted_shares, self.submitted_shares)
        {
            self.accept_low_logged = true;
            warn!(
                %worker,
                accepted = self.accepted_shares,
                submitted = self.submitted_shares,
                ratio = accept_ratio(self.accepted_shares, self.submitted_shares),
                "low accept ratio — possible pool under-reporting or misbehaving miner"
            );
        }
    }

    /// Credit `shares` pool-accepted shares worth `work` diff-1 units in
    /// total. Returns `false`, crediting nothing, when `work` is not positive:
    /// the share difficulty is unknown, so there is no measured work to bill.
    pub fn accepted(&mut self, work: f64, shares: u64, worker: &str) -> bool {
        if work <= 0.0 {
            return false;
        }
        self.delivered_work += work;
        self.accepted_shares += shares;
        debug!(%worker, shares, work, "accepted shares");
        true
    }

    /// Feed the hashrate window one share the proxy validated against the
    /// miner's target, credited at that target's `difficulty`.
    pub fn measured(&mut self, difficulty: f64) {
        if difficulty > 0.0 {
            self.hashrate.record(difficulty);
        }
    }

    /// Snapshot for the control API.
    pub fn status(
        &self,
        worker: &str,
        routing: &Routing,
        upstream_url: &str,
        protocol: &'static str,
    ) -> SessionStatus {
        SessionStatus {
            worker: worker.to_string(),
            routing: match routing {
                Routing::Idle => "idle",
                Routing::Rented { .. } => "rented",
            }
            .to_string(),
            order_id: routing.order_id().map(str::to_string),
            upstream_url: upstream_url.to_string(),
            hashrate_hs: self.hashrate.hashes_per_second(),
            delivered_work: self.delivered_work,
            accepted_shares: self.accepted_shares,
            submitted_shares: self.submitted_shares,
            accept_ratio: accept_ratio(self.accepted_shares, self.submitted_shares),
            accept_ratio_low: accept_ratio_low(self.accepted_shares, self.submitted_shares),
            protocol,
        }
    }
}

/// Rolling window of measured-share difficulty → hashrate estimate.
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

    /// Record a measured share credited at `difficulty`.
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
    ///
    /// Samples older than the window are skipped here as well as pruned on
    /// record: a miner that stops submitting reads 0 once its last share has
    /// aged out, instead of holding its last value until the next share.
    fn hashes_per_second_at(&self, now: Instant) -> f64 {
        let mut live = self
            .samples
            .iter()
            .filter(|(t, _)| now.duration_since(*t) <= self.window);
        let Some(&(oldest, first)) = live.next() else {
            return 0.0;
        };
        let sum: f64 = first + live.map(|(_, d)| d).sum::<f64>();
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
    fn hashrate_reads_zero_once_the_last_share_ages_out() {
        // One share, then silence: past the window the estimate is 0, not the
        // last share spread over the window forever.
        let mut w = HashrateWindow::new(Duration::from_secs(600));
        let start = Instant::now();
        w.record_at(start, 1_000_000.0);
        let inside = start + Duration::from_secs(300);
        assert!(w.hashes_per_second_at(inside) > 0.0);
        let after = start + Duration::from_secs(601);
        assert_eq!(w.hashes_per_second_at(after), 0.0);
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

#[cfg(test)]
mod delivery_tests {
    use super::*;

    #[test]
    fn accepted_work_is_booked_and_reported() {
        let mut d = Delivery::new();
        d.submitted("w");
        d.submitted("w");
        d.measured(256.0);
        d.measured(256.0);
        assert!(d.accepted(512.0, 2, "w"));
        let rented = Routing::Rented {
            order_id: "o1".into(),
        };
        let st = d.status("w", &rented, "pool:3333", "sv2");
        assert_eq!(st.delivered_work, 512.0);
        assert_eq!(st.accepted_shares, 2);
        assert_eq!(st.submitted_shares, 2);
        assert_eq!(st.routing, "rented");
        assert_eq!(st.order_id.as_deref(), Some("o1"));
        assert!(st.hashrate_hs > 0.0);
    }

    #[test]
    fn the_hashrate_comes_from_measured_shares_not_from_the_bill() {
        // Pool-accepted work alone moves the bill, not the hashrate; a measured
        // share alone moves the hashrate, not the bill.
        let mut billed = Delivery::new();
        assert!(billed.accepted(1_000_000.0, 1, "w"));
        let st = billed.status("w", &Routing::Idle, "pool:3333", "sv2");
        assert_eq!(st.hashrate_hs, 0.0);
        assert_eq!(st.delivered_work, 1_000_000.0);

        let mut measured = Delivery::new();
        measured.measured(4096.0);
        let st = measured.status("w", &Routing::Idle, "pool:3333", "sv2");
        assert!(st.hashrate_hs > 0.0);
        assert_eq!(st.delivered_work, 0.0);
    }

    #[test]
    fn a_share_of_unknown_difficulty_books_nothing() {
        let mut d = Delivery::new();
        assert!(!d.accepted(0.0, 1, "w"));
        let st = d.status("w", &Routing::Idle, "pool:3333", "sv1");
        assert_eq!(st.accepted_shares, 0);
        assert_eq!(st.delivered_work, 0.0);
        assert_eq!(st.order_id, None);
        assert_eq!(st.routing, "idle");
    }
}

#[cfg(test)]
mod pool_url_tests {
    use super::normalize_pool_url;

    #[test]
    fn the_scheme_miner_menus_teach_is_stripped() {
        assert_eq!(
            normalize_pool_url("stratum+tcp://stratum.braiins.com:3333").unwrap(),
            "stratum.braiins.com:3333"
        );
        assert_eq!(normalize_pool_url("TCP://pool:3333").unwrap(), "pool:3333");
        assert_eq!(normalize_pool_url("  pool:3333 ").unwrap(), "pool:3333");
    }

    #[test]
    fn a_bare_host_port_passes_unchanged() {
        assert_eq!(
            normalize_pool_url("blitzpool.yourdevice.ch:3333").unwrap(),
            "blitzpool.yourdevice.ch:3333"
        );
        assert_eq!(normalize_pool_url("127.0.0.1:1").unwrap(), "127.0.0.1:1");
    }

    #[test]
    fn transports_the_proxy_cannot_speak_are_refused() {
        for bad in [
            "stratum+ssl://pool:3333",
            "ssl://pool:3333",
            "http://pool:3333",
            "pool",
            "pool:",
            ":3333",
            "pool:99999",
            "stratum+tcp://pool:3333/",
            "",
        ] {
            assert!(normalize_pool_url(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
