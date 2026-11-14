// SPDX-License-Identifier: AGPL-3.0-or-later

//! The proxy's own view of every share: which pool target it meets, which
//! miner target it meets, and the miner difficulty that keeps the hashrate
//! measurable.
//!
//! A pool may hand a channel a difficulty far above what the device behind it
//! finds in minutes. Counting only the shares the pool accepts then measures a
//! small rig from a handful of shares per hour, and no window short enough to
//! track a rental can turn that into a number. So the proxy gives the miner a
//! target of its own, sized by vardiff to a steady share rate, hashes every
//! share itself, and:
//!
//! - forwards a share that meets the pool's target, exactly as before;
//! - answers a share that meets only the miner target locally, crediting it to
//!   the hashrate measurement and nothing else;
//! - forwards everything it cannot place, so the pool keeps the last word.
//!
//! Only a share whose hash provably meets the miner target is ever held back.
//! A hash computed wrongly (a job the proxy tracked differently from the miner)
//! is a random number, which meets the miner target practically never, so such
//! a fault forwards every share instead of withholding work. Vardiff counts
//! every share the miner sends, placed or not, so the same fault pulls the
//! miner target toward the pool's rather than easing it toward zero; a gate
//! with no client channel at all leaves the measurement to the pool's accepted
//! work.
//!
//! Targets are per job, as the SV2 Mining Protocol has them (SetTarget applies
//! to jobs sent after it): a share is judged by the targets in force when its
//! job reached the miner, or by newer easier ones. A block-solving share always
//! goes to the pool.
//!
//! While the miner target rests only on the pool's (no device figure, nothing
//! measured yet), it is exactly the pool's, so nothing changes until vardiff
//! has a reason; and the miner target is never harder than the pool's, or the
//! shares between the two would go unsubmitted while the pool credits each
//! forwarded share at its own easier target.
//!
//! Job tracking, the header hash, stale and duplicate detection come from the
//! `channels_sv2` client channels; the miner difficulty from its classic
//! vardiff. The target comparisons are the proxy's: the client channel is held
//! at the maximum target so it reports the hash of every well-formed share.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use stratum_core::binary_sv2::U256Owned;
use stratum_core::bitcoin::hashes::hex::FromHex;
use stratum_core::bitcoin::hashes::Hash as _;
use stratum_core::bitcoin::Target;
use stratum_core::channels_sv2::client::extended::ExtendedChannel;
use stratum_core::channels_sv2::client::share_accounting::ShareValidationResult;
use stratum_core::channels_sv2::client::standard::StandardChannel;
use stratum_core::channels_sv2::extranonce_manager::ExtranoncePrefix;
use stratum_core::channels_sv2::target::{hash_rate_from_target, hash_rate_to_target};
use stratum_core::channels_sv2::{Vardiff, VardiffState};
use stratum_core::mining_sv2::{
    NewExtendedMiningJobOwned, NewMiningJobOwned, SetNewPrevHashOwned, SubmitSharesExtendedOwned,
    SubmitSharesStandard,
};
use stratum_core::sv1_api::{
    methods::client_to_server, methods::server_to_client, utils::HexU32Be,
};
use tracing::debug;

use crate::proto::translate;

/// Share rate the miner target is sized for. Ten a minute puts ~100 shares in
/// the 10-minute hashrate window, a statistical error of about ±10 %.
pub const SHARES_PER_MINUTE: f32 = 10.0;

/// How often the session ticker asks vardiff whether to retarget.
pub const VARDIFF_TICK: Duration = Duration::from_secs(15);

/// How many jobs' targets a gate remembers. The client channel keeps up to 16
/// past jobs per chain tip plus the future ones; a share on a job older than
/// this is judged on the current targets.
const JOB_TARGETS: usize = 64;

/// What to do with one share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// Send it to the pool. `measured` is the difficulty to credit to the
    /// hashrate measurement when the share provably met the miner target, and
    /// `None` when the proxy could not place it.
    Forward { measured: Option<f64> },
    /// It met the miner target but not the pool's: answer the miner locally
    /// and credit `measured` to the hashrate measurement only.
    Withhold { measured: f64 },
}

impl Verdict {
    /// The difficulty this share contributes to the hashrate measurement.
    pub fn measured(&self) -> Option<f64> {
        match *self {
            Verdict::Forward { measured } => measured,
            Verdict::Withhold { measured } => Some(measured),
        }
    }
}

/// The client channel that mirrors the jobs the miner hashes.
#[derive(Debug)]
enum Tracker {
    Extended(Box<ExtendedChannel>),
    Standard(Box<StandardChannel>),
    /// No client channel: `ExtendedChannel::new` refuses an extranonce prefix
    /// plus rollable size above 32 bytes, which an upstream can assign. Every
    /// share is forwarded unmeasured.
    Untracked,
}

/// Where the hashrate estimate that sizes the miner target comes from.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Seed {
    /// Only the pool's target: the miner target follows it exactly.
    Pool,
    /// The device's own figure (SV2 nominal hashrate, SV1 suggest_difficulty).
    Device,
    /// Vardiff measured the device; device figures do not override it.
    Measured,
}

/// What a gate knows about its device, carried to the gate built for the
/// same device behind a new upstream.
#[derive(Debug, Clone, Copy)]
pub struct DeviceEstimate {
    estimate: f32,
    seed: Seed,
    peak: f32,
    /// The easiest target the device accepts, as last updated by it.
    device_max: Target,
}

/// The targets in force when a job reached the miner. Per the SV2 spec
/// (Mining Protocol / SetTarget) a new target applies to jobs sent after it;
/// a job keeps the target it came with, and pools validate it that way.
#[derive(Debug, Clone, Copy)]
struct JobTargets {
    job_id: u32,
    downstream: Target,
    upstream: Target,
}

/// One downstream channel's share gate. See the module docs.
#[derive(Debug)]
pub struct ShareGate {
    tracker: Tracker,
    upstream: Target,
    downstream: Target,
    /// The easiest target the device accepts (SV2 `max_target`); the vardiff
    /// target never goes easier than this.
    device_max: Target,
    /// Targets per job, oldest first, at most [`JOB_TARGETS`].
    jobs: VecDeque<JobTargets>,
    vardiff: VardiffState,
    /// Hashrate estimate (H/s) that sizes the miner target.
    estimate: f32,
    seed: Seed,
    /// The highest estimate vardiff measured from placed shares. Vardiff
    /// never takes the estimate below a hundredth of it, so a miner that
    /// pauses and resumes does not come back on a near-zero difficulty.
    peak: f32,
    /// Shares since the last retarget whose hash met a miner target. Vardiff
    /// eases the miner target only while some arrive: shares that come in but
    /// cannot be placed say nothing about the device being too slow.
    placed_since_retarget: u32,
}

fn max_target() -> Target {
    Target::from_le_bytes([0xff; 32])
}

fn target_from_le(bytes: &[u8]) -> Target {
    let mut le = [0xffu8; 32];
    if bytes.len() == 32 {
        le.copy_from_slice(bytes);
    }
    Target::from_le_bytes(le)
}

/// Share difficulty of `target`, in the proxy's accounting units.
fn difficulty(target: Target) -> f64 {
    translate::difficulty_from_target(&target.to_le_bytes())
}

/// The hashrate that finds [`SHARES_PER_MINUTE`] shares at `target`.
fn hashrate_for(target: Target) -> f32 {
    let t: U256Owned = target.to_le_bytes().into();
    hash_rate_from_target(t, SHARES_PER_MINUTE as f64).unwrap_or(0.0) as f32
}

fn prefix(bytes: Vec<u8>) -> ExtranoncePrefix {
    ExtranoncePrefix::from_wire(bytes).unwrap_or_else(|_| {
        ExtranoncePrefix::from_wire(Vec::new()).expect("an empty prefix is always valid")
    })
}

impl ShareGate {
    /// Gate for an Extended channel: the miner rolls `rollable_extranonce_size`
    /// bytes after `extranonce_prefix`. `upstream_target` is the pool's, or
    /// `None` while an SV1 pool has not set a difficulty yet (difficulty 1 by
    /// the protocol's default until it does).
    pub fn extended(
        extranonce_prefix: Vec<u8>,
        rollable_extranonce_size: u16,
        upstream_target: Option<&[u8]>,
        device_max: &[u8],
        nominal_hashrate: f32,
    ) -> Self {
        let tracker = match ExtendedChannel::new(
            0,
            String::new(),
            prefix(extranonce_prefix),
            max_target(),
            nominal_hashrate,
            true,
            rollable_extranonce_size,
            None,
        ) {
            Ok(c) => Tracker::Extended(Box::new(c)),
            Err(e) => {
                debug!(error = ?e, "share gate: extended channel not tracked");
                Tracker::Untracked
            }
        };
        Self::with_tracker(tracker, upstream_target, device_max, nominal_hashrate)
    }

    /// Gate for a Standard (header-only) channel.
    pub fn standard(
        extranonce_prefix: Vec<u8>,
        upstream_target: Option<&[u8]>,
        device_max: &[u8],
        nominal_hashrate: f32,
    ) -> Self {
        let tracker = Tracker::Standard(Box::new(
            StandardChannel::new(
                0,
                String::new(),
                prefix(extranonce_prefix),
                max_target(),
                nominal_hashrate,
                None,
            )
            .expect("the maximum target is not zero"),
        ));
        Self::with_tracker(tracker, upstream_target, device_max, nominal_hashrate)
    }

    fn with_tracker(
        tracker: Tracker,
        upstream_target: Option<&[u8]>,
        device_max: &[u8],
        nominal_hashrate: f32,
    ) -> Self {
        let upstream = match upstream_target {
            Some(t) => target_from_le(t),
            None => Target::from_le_bytes(translate::target_from_difficulty(1.0)),
        };
        let mut gate = Self {
            tracker,
            upstream,
            downstream: upstream,
            device_max: target_from_le(device_max),
            jobs: VecDeque::new(),
            vardiff: VardiffState::new().expect("the system clock is past the epoch"),
            estimate: 0.0,
            seed: Seed::Pool,
            peak: 0.0,
            placed_since_retarget: 0,
        };
        if nominal_hashrate > 0.0 {
            gate.adopt(nominal_hashrate, Seed::Device);
            gate.downstream = gate.desired_downstream();
        } else {
            // Without a device figure the miner starts on the pool's target,
            // exactly what it would mine without the proxy; vardiff walks it
            // down from there.
            gate.estimate = gate.floor(hashrate_for(upstream));
        }
        gate
    }

    fn floor(&self, estimate: f32) -> f32 {
        estimate
            .max(self.vardiff.min_allowed_hashrate())
            .max(self.peak / 100.0)
    }

    fn adopt(&mut self, estimate: f32, seed: Seed) {
        self.estimate = self.floor(estimate);
        self.seed = seed;
    }

    /// Whether the gate can judge shares at all. When it cannot, every share
    /// goes to the pool unmeasured, and the session measures the pool's
    /// accepted work instead.
    pub fn is_tracking(&self) -> bool {
        !matches!(self.tracker, Tracker::Untracked)
    }

    /// What the gate knows about its device.
    pub fn device(&self) -> DeviceEstimate {
        DeviceEstimate {
            estimate: self.estimate,
            seed: self.seed,
            peak: self.peak,
            device_max: self.device_max,
        }
    }

    /// This gate for a device already known from another gate: the same device
    /// behind a new upstream keeps its miner target instead of restarting from
    /// the pool's. A device known only from its old pool's target starts from
    /// the new pool's.
    pub fn with_device(mut self, device: DeviceEstimate) -> Self {
        self.device_max = device.device_max;
        if device.seed != Seed::Pool {
            self.peak = device.peak;
            self.adopt(device.estimate, device.seed);
            self.downstream = self.desired_downstream();
        }
        self
    }

    /// The device names the target it wants (SV1 `mining.suggest_difficulty`):
    /// size the miner target from it until vardiff has measured the device.
    /// Returns the new miner target when it moved.
    pub fn suggest_target(&mut self, target: &[u8]) -> Option<[u8; 32]> {
        if self.seed == Seed::Measured {
            return None;
        }
        self.adopt(hashrate_for(target_from_le(target)), Seed::Device);
        let desired = self.desired_downstream();
        self.replace_downstream(desired)
    }

    /// The device updated its channel (SV2 `UpdateChannel`): the easiest
    /// target it accepts, and a nominal hashrate that sizes the miner target
    /// until vardiff has measured the device. Returns the new miner target
    /// when it moved.
    pub fn update_device(&mut self, nominal_hashrate: f32, device_max: &[u8]) -> Option<[u8; 32]> {
        self.device_max = target_from_le(device_max);
        if nominal_hashrate > 0.0 && self.seed != Seed::Measured {
            self.adopt(nominal_hashrate, Seed::Device);
        }
        let desired = self.desired_downstream();
        self.replace_downstream(desired)
    }

    /// The target the miner should hash against: the vardiff target, kept no
    /// easier than the device accepts, and never harder than the pool's.
    ///
    /// The pool bound is applied last and wins over the device bound. A miner
    /// target harder than the pool's means the miner never submits the shares
    /// between the two, while the pool credits every forwarded share at its own
    /// easier target: the work is under-counted. A pool that never saw the
    /// device's `max_target` (an SV1 pool behind a translated channel) can set
    /// a target easier than it; the miner then gets the pool's target, as it
    /// would without the proxy.
    fn desired_downstream(&self) -> Target {
        // A gate that cannot judge shares cannot measure an easier target
        // either: the miner hashes what the pool wants.
        if self.seed == Seed::Pool || !self.is_tracking() {
            return self.upstream;
        }
        let wanted = hash_rate_to_target(self.estimate as f64, SHARES_PER_MINUTE as f64)
            .unwrap_or(self.upstream);
        wanted.min(self.device_max).max(self.upstream)
    }

    fn replace_downstream(&mut self, new: Target) -> Option<[u8; 32]> {
        if new == self.downstream {
            return None;
        }
        self.downstream = new;
        Some(new.to_le_bytes())
    }

    /// The miner target (32 bytes, little-endian).
    pub fn downstream_target(&self) -> [u8; 32] {
        self.downstream.to_le_bytes()
    }

    /// Tell the miner its target as a difficulty (SV1): the miner turns that
    /// difficulty back into a target itself, so the gate judges against the
    /// target that difficulty stands for, not its own unrounded one. Returns
    /// the difficulty to send.
    fn downstream_as_difficulty(&mut self) -> f64 {
        let d = difficulty(self.downstream);
        let told = Target::from_le_bytes(translate::target_from_difficulty(d));
        // `target_from_difficulty` rounds toward the easier target; `max` keeps
        // the gate's own when float error in the difficulty puts `told` a hair
        // harder, so the miner target stays no harder than the pool's.
        self.downstream = told.max(self.downstream);
        d
    }

    /// The pool set a new target. Returns the new miner target when it moved.
    pub fn set_upstream_target(&mut self, target: &[u8]) -> Option<[u8; 32]> {
        self.upstream = target_from_le(target);
        if self.seed == Seed::Pool {
            self.estimate = self.floor(hashrate_for(self.upstream));
        }
        let desired = self.desired_downstream();
        self.replace_downstream(desired)
    }

    /// The pool moved the channel to a new extranonce prefix.
    pub fn set_extranonce_prefix(&mut self, bytes: Vec<u8>) {
        let p = prefix(bytes);
        let res = match &mut self.tracker {
            Tracker::Extended(c) => c.set_extranonce_prefix(p).map_err(|e| format!("{e:?}")),
            Tracker::Standard(c) => c.set_extranonce_prefix(p).map_err(|e| format!("{e:?}")),
            Tracker::Untracked => Ok(()),
        };
        if let Err(e) = res {
            debug!(error = %e, "share gate: extranonce prefix not taken");
        }
    }

    /// Remember the targets in force for a job reaching the miner now.
    fn note_job(&mut self, job_id: u32) {
        self.jobs.retain(|j| j.job_id != job_id);
        if self.jobs.len() >= JOB_TARGETS {
            self.jobs.pop_front();
        }
        self.jobs.push_back(JobTargets {
            job_id,
            downstream: self.downstream,
            upstream: self.upstream,
        });
    }

    fn job(&self, job_id: u32) -> Option<JobTargets> {
        self.jobs.iter().rev().find(|j| j.job_id == job_id).copied()
    }

    pub fn on_extended_job(&mut self, job: NewExtendedMiningJobOwned) {
        self.note_job(job.job_id);
        if let Tracker::Extended(c) = &mut self.tracker {
            if let Err(e) = c.on_new_extended_mining_job(job) {
                debug!(error = ?e, "share gate: extended job not tracked");
            }
        }
    }

    pub fn on_standard_job(&mut self, job: NewMiningJobOwned) {
        self.note_job(job.job_id);
        if let Tracker::Standard(c) = &mut self.tracker {
            if let Err(e) = c.on_new_mining_job(job) {
                debug!(error = ?e, "share gate: standard job not tracked");
            }
        }
    }

    pub fn on_prev_hash(&mut self, prev: SetNewPrevHashOwned) {
        let res = match &mut self.tracker {
            Tracker::Extended(c) => c.on_set_new_prev_hash(prev).map_err(|e| format!("{e:?}")),
            Tracker::Standard(c) => c.on_set_new_prev_hash(prev).map_err(|e| format!("{e:?}")),
            Tracker::Untracked => Ok(()),
        };
        if let Err(e) = res {
            debug!(error = %e, "share gate: prev-hash not tracked");
        }
    }

    pub fn check_extended(&mut self, share: &SubmitSharesExtendedOwned) -> Verdict {
        let hash = match &mut self.tracker {
            Tracker::Extended(c) => c.validate_share(share.clone()).ok(),
            Tracker::Standard(_) | Tracker::Untracked => None,
        };
        self.judge(share.job_id, hash)
    }

    pub fn check_standard(&mut self, share: &SubmitSharesStandard) -> Verdict {
        let hash = match &mut self.tracker {
            Tracker::Standard(c) => c.validate_share(share.clone()).ok(),
            Tracker::Extended(_) | Tracker::Untracked => None,
        };
        self.judge(share.job_id, hash)
    }

    /// The difficulty a share with hash `h` on `job` is credited at: the miner
    /// target its job came with, else the current one, if it met it.
    fn measured_for(&self, h: Target, job: Option<JobTargets>) -> Option<f64> {
        match job {
            Some(j) if h <= j.downstream => Some(difficulty(j.downstream)),
            _ if h <= self.downstream => Some(difficulty(self.downstream)),
            _ => None,
        }
    }

    /// A share the gate cannot place (no job, no client channel, not
    /// translatable): forwarded unmeasured, but counted toward the share rate.
    pub fn unplaced(&mut self) -> Verdict {
        self.vardiff.increment_shares_since_last_update();
        Verdict::Forward { measured: None }
    }

    fn judge(&mut self, job_id: u32, validated: Option<ShareValidationResult>) -> Verdict {
        // Every share the miner sends counts toward its share rate, placed or
        // not, so shares the gate cannot place never read as a slow device.
        let (raw, block) = match validated {
            Some(ShareValidationResult::Valid(h)) => (h.to_byte_array(), false),
            Some(ShareValidationResult::BlockFound(h)) => (h.to_byte_array(), true),
            None => return self.unplaced(),
        };
        self.vardiff.increment_shares_since_last_update();
        let h = Target::from_le_bytes(raw);
        let job = self.job(job_id);
        let measured = self.measured_for(h, job);
        if measured.is_some() {
            self.placed_since_retarget += 1;
        }
        // The pool judges a share by the target its job came with, or a newer
        // easier one: the easier of the two decides. A block always goes up.
        let pool_bound = job.map_or(self.upstream, |j| j.upstream.max(self.upstream));
        if block || h <= pool_bound {
            return Verdict::Forward { measured };
        }
        match measured {
            Some(d) => Verdict::Withhold { measured: d },
            None => Verdict::Forward { measured: None },
        }
    }

    #[cfg(test)]
    fn force_downstream(&mut self, target: Target) {
        self.seed = Seed::Device;
        self.downstream = target;
    }

    /// Ask vardiff whether the share rate warrants a new miner target. Returns
    /// it when it moved.
    pub fn tick(&mut self) -> Option<[u8; 32]> {
        if !self.is_tracking() {
            return None;
        }
        let shares = self.vardiff.shares_since_last_update;
        let placed = std::mem::take(&mut self.placed_since_retarget);
        match self
            .vardiff
            .try_vardiff(self.estimate, &self.downstream, SHARES_PER_MINUTE)
        {
            Ok(Some(new_estimate)) if new_estimate < self.estimate && shares > 0 && placed == 0 => {
                // Shares arrive but none could be placed: no evidence the
                // device is slower than its target. Keep the target.
                None
            }
            Ok(Some(new_estimate)) => {
                self.adopt(new_estimate, Seed::Measured);
                // Only an estimate measured from placed shares is evidence of
                // what the device does; one walked down from the pool's or the
                // device's own figure is not, and must not hold the floor up.
                if placed > 0 {
                    self.peak = self.peak.max(self.estimate);
                }
                let desired = self.desired_downstream();
                self.replace_downstream(desired)
            }
            Ok(None) => {
                // No retarget yet: the placed shares still count toward it.
                self.placed_since_retarget += placed;
                None
            }
            Err(e) => {
                self.placed_since_retarget += placed;
                debug!(error = ?e, "share gate: vardiff check failed");
                None
            }
        }
    }
}

/// The extranonce of a `mining.set_extranonce` line (`[extranonce1_hex,
/// extranonce2_size]`).
fn set_extranonce_from_line(line: &str) -> Option<(Vec<u8>, u16)> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("method")?.as_str()? != "mining.set_extranonce" {
        return None;
    }
    let params = v.get("params")?.as_array()?;
    let hex = params.first()?.as_str()?;
    let size = u16::try_from(params.get(1)?.as_u64()?).ok()?;
    Some((Vec::<u8>::from_hex(hex).ok()?, size))
}

/// How many SV1 jobs the gate remembers, oldest dropped first.
const SV1_JOBS: usize = 64;

/// [`ShareGate`] for an SV1 miner, whichever protocol the pool speaks: the
/// `mining.notify` lines the miner receives become the tracked jobs, its
/// `mining.submit` becomes the share checked against them, and the pool's
/// `mining.set_difficulty` becomes the upstream target. The miner sees
/// `set_difficulty` lines carrying the miner target instead.
#[derive(Debug)]
pub struct Sv1Gate {
    gate: ShareGate,
    /// The pool's string job id → the tracked job's id.
    job_ids: HashMap<String, u32>,
    /// `(pool job id, tracked id)` oldest first, for eviction. A pool may send
    /// a job id again; the entry it replaced must not evict the new mapping.
    job_order: VecDeque<(String, u32)>,
    /// Tracked job id → that job's block version, to rebuild a rolled version.
    job_versions: HashMap<u32, u32>,
    next_job_id: u32,
    has_prev_hash: bool,
    /// The miner difficulty last sent, so an unchanged one is not repeated.
    sent_difficulty: Option<f64>,
}

impl Sv1Gate {
    /// Gate for an SV1 miner mining `extranonce1` + `extranonce2_size` rolled
    /// bytes, behind a pool target `upstream_target` (`None` until the pool
    /// sets a difficulty).
    pub fn new(
        extranonce1: &[u8],
        extranonce2_size: u16,
        upstream_target: Option<[u8; 32]>,
    ) -> Self {
        Self {
            gate: ShareGate::extended(
                extranonce1.to_vec(),
                extranonce2_size,
                upstream_target.as_ref().map(|t| t.as_slice()),
                &[0xff; 32],
                0.0,
            ),
            job_ids: HashMap::new(),
            job_order: VecDeque::new(),
            job_versions: HashMap::new(),
            next_job_id: 1,
            has_prev_hash: false,
            sent_difficulty: None,
        }
    }

    /// Whether the gate can judge the miner's shares; see
    /// [`ShareGate::is_tracking`].
    pub fn is_tracking(&self) -> bool {
        self.gate.is_tracking()
    }

    /// This gate for a new upstream: fresh job state, same device estimate.
    pub fn renewed(&self, fresh: Sv1Gate) -> Sv1Gate {
        Sv1Gate {
            gate: fresh.gate.with_device(self.gate.device()),
            ..fresh
        }
    }

    /// Process one line on its way to the miner. A `mining.notify` is tracked
    /// and passed on; a `mining.set_difficulty` is the pool's and becomes a
    /// line carrying the miner difficulty, or nothing when that did not move;
    /// a `mining.set_extranonce` restarts the job state on the new extranonce.
    pub fn line_to_miner(&mut self, line: String) -> Option<String> {
        if let Some(notify) = translate::notify_from_line(&line) {
            self.on_notify(&notify);
            return Some(line);
        }
        if let Some((extranonce1, extranonce2_size)) = set_extranonce_from_line(&line) {
            let fresh = Sv1Gate::new(
                &extranonce1,
                extranonce2_size,
                Some(self.gate.upstream.to_le_bytes()),
            );
            let sent = self.sent_difficulty;
            *self = self.renewed(fresh);
            self.sent_difficulty = sent;
            return Some(line);
        }
        if let Some(d) = translate::set_difficulty_from_line(&line) {
            self.gate
                .set_upstream_target(&translate::target_from_difficulty(d));
            return self.difficulty_line();
        }
        Some(line)
    }

    /// A `set_difficulty` line for the current miner difficulty, unless that is
    /// the one the miner already has.
    pub fn difficulty_line(&mut self) -> Option<String> {
        let d = self.gate.downstream_as_difficulty();
        if self.sent_difficulty == Some(d) {
            return None;
        }
        self.sent_difficulty = Some(d);
        Some(translate::set_difficulty_to_line(d))
    }

    fn on_notify(&mut self, notify: &server_to_client::Notify) {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        if self.job_order.len() >= SV1_JOBS {
            if let Some((old, old_id)) = self.job_order.pop_front() {
                self.job_versions.remove(&old_id);
                if self.job_ids.get(&old) == Some(&old_id) {
                    self.job_ids.remove(&old);
                }
            }
        }
        self.job_ids.insert(notify.job_id.clone(), id);
        self.job_order.push_back((notify.job_id.clone(), id));
        self.job_versions.insert(id, notify.version.0);
        let as_future = notify.clean_jobs || !self.has_prev_hash;
        match translate::sv1_notify_to_sv2_job(notify, 0, id, as_future, true) {
            Ok((job, prev)) => {
                self.gate.on_extended_job(job);
                if let Some(p) = prev {
                    self.gate.on_prev_hash(p);
                    self.has_prev_hash = true;
                }
            }
            Err(e) => debug!(error = %e, "share gate: notify not tracked"),
        }
    }

    /// A `mining.submit` the relay could not parse: forwarded unmeasured,
    /// counted toward the share rate.
    pub fn unplaced(&mut self) -> Verdict {
        self.gate.unplaced()
    }

    /// Judge the miner's `mining.submit`.
    pub fn check(&mut self, submit: &client_to_server::Submit) -> Verdict {
        let Some(&id) = self.job_ids.get(&submit.job_id) else {
            return self.gate.unplaced();
        };
        let Some(&version) = self.job_versions.get(&id) else {
            return self.gate.unplaced();
        };
        let mut keyed = submit.clone();
        keyed.job_id = id.to_string();
        // The proxy answers the miner's mining.configure with this mask, so it
        // is the one the miner rolls within.
        let mask = submit
            .version_bits
            .as_ref()
            .map(|_| HexU32Be(translate::VERSION_ROLLING_MASK));
        match stratum_core::stratum_translation::sv1_to_sv2::build_sv2_submit_shares_extended_from_sv1_submit(
            &keyed, 0, 0, version, mask,
        ) {
            Ok(share) => self.gate.check_extended(&share),
            Err(e) => {
                debug!(error = ?e, "share gate: submit not translatable");
                self.gate.unplaced()
            }
        }
    }

    /// The miner's `mining.suggest_difficulty`: returns the `set_difficulty`
    /// line for the miner when its difficulty moved.
    pub fn suggest_difficulty(&mut self, difficulty: f64) -> Option<String> {
        self.gate
            .suggest_target(&translate::target_from_difficulty(difficulty))?;
        self.difficulty_line()
    }

    /// Ask vardiff whether to retarget; returns the `set_difficulty` line for
    /// the miner when the difficulty moved.
    pub fn tick(&mut self) -> Option<String> {
        self.gate.tick()?;
        self.difficulty_line()
    }
}

#[cfg(test)]
mod tests;
