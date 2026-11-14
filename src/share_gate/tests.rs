//! The gate judged against an independent oracle: each test builds a real
//! coinbase + header, hashes it itself, and checks the verdict the gate gives
//! for nonces whose hash it already knows to sit above, between or below the
//! two targets.

use super::*;
use stratum_core::binary_sv2::{Seq0255Owned, Sv2OptionOwned};
use stratum_core::bitcoin::hashes::{sha256d, Hash};
use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;

const PREFIX: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
const ROLLED: [u8; 4] = [0, 0, 0, 1];
const VERSION: u32 = 0x2000_0000;
const NTIME: u32 = 0x6500_0000;
/// Network difficulty 1: a random hash meets it with p = 2^-32, so no test
/// share is a block.
const NBITS: u32 = 0x1d00_ffff;
const PREV: [u8; 32] = [0x11; 32];

/// A target (little-endian) passing roughly one hash in `16^zero_nibbles`.
fn easy_target(top: u8, next: u8) -> [u8; 32] {
    let mut t = [0xffu8; 32];
    t[31] = top;
    t[30] = next;
    t
}

/// Pool target: about one hash in 4096 meets it.
fn up() -> [u8; 32] {
    easy_target(0x00, 0x0f)
}

/// Miner target: about one hash in 16 meets it.
fn down() -> [u8; 32] {
    easy_target(0x0f, 0xff)
}

fn le_leq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    true
}

/// A legacy coinbase reserving room for `en_len` extranonce bytes.
fn coinbase(en_len: usize) -> (Vec<u8>, Vec<u8>) {
    let script_prefix = [0x03u8, 0x33, 0x33, 0x33];
    let mut c1 = Vec::new();
    c1.extend_from_slice(&1u32.to_le_bytes());
    c1.push(0x01);
    c1.extend_from_slice(&[0u8; 32]);
    c1.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    c1.push((script_prefix.len() + en_len) as u8);
    c1.extend_from_slice(&script_prefix);
    let mut c2 = Vec::new();
    c2.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    c2.push(0x01);
    c2.extend_from_slice(&5_000_000_000u64.to_le_bytes());
    c2.push(0x00);
    c2.extend_from_slice(&0u32.to_le_bytes());
    (c1, c2)
}

fn job(job_id: u32) -> NewExtendedMiningJobOwned {
    let (c1, c2) = coinbase(PREFIX.len() + ROLLED.len());
    NewExtendedMiningJobOwned {
        channel_id: 0,
        job_id,
        ntime_start: Sv2OptionOwned::new(None),
        version: VERSION,
        version_rolling_allowed: true,
        merkle_path: Seq0255Owned::new(Vec::new()).unwrap(),
        coinbase_tx_prefix: c1.try_into().unwrap(),
        coinbase_tx_suffix: c2.try_into().unwrap(),
    }
}

fn prev_hash(job_id: u32) -> SetNewPrevHashOwned {
    prev_hash_bits(job_id, NBITS)
}

fn prev_hash_bits(job_id: u32, nbits: u32) -> SetNewPrevHashOwned {
    SetNewPrevHashOwned {
        channel_id: 0,
        job_id,
        prev_hash: PREV.into(),
        ntime_start: NTIME,
        nbits,
    }
}

/// The header hash of `nonce` on [`job`], computed here, not by the gate.
fn oracle_hash(nonce: u32) -> [u8; 32] {
    oracle_hash_bits(nonce, NBITS)
}

fn oracle_hash_bits(nonce: u32, nbits: u32) -> [u8; 32] {
    let (c1, c2) = coinbase(PREFIX.len() + ROLLED.len());
    let mut en = PREFIX.to_vec();
    en.extend_from_slice(&ROLLED);
    let root = merkle_root_from_path(&c1, &c2, &en, &Vec::<Vec<u8>>::new()).unwrap();
    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&PREV);
    header.extend_from_slice(&root);
    header.extend_from_slice(&NTIME.to_le_bytes());
    header.extend_from_slice(&nbits.to_le_bytes());
    header.extend_from_slice(&nonce.to_le_bytes());
    sha256d::Hash::hash(&header).to_byte_array()
}

/// The first nonce whose oracle hash satisfies `pred`.
fn nonce_where(pred: impl Fn(&[u8; 32]) -> bool) -> u32 {
    (0u32..2_000_000)
        .find(|n| pred(&oracle_hash(*n)))
        .expect("a nonce in range")
}

fn share(job_id: u32, nonce: u32) -> SubmitSharesExtendedOwned {
    SubmitSharesExtendedOwned {
        channel_id: 0,
        sequence_number: 0,
        job_id,
        nonce,
        ntime: NTIME,
        version: VERSION,
        extranonce: ROLLED.to_vec().try_into().unwrap(),
    }
}

/// A gate with job 1 active, pool target [`up`], miner target [`down`].
fn gate() -> ShareGate {
    let mut g = ShareGate::extended(
        PREFIX.to_vec(),
        ROLLED.len() as u16,
        Some(&up()),
        &[0xff; 32],
        0.0,
    );
    g.force_downstream(Target::from_le_bytes(down()));
    g.on_extended_job(job(1));
    g.on_prev_hash(prev_hash(1));
    g
}

fn diff(t: [u8; 32]) -> f64 {
    translate::difficulty_from_target(&t)
}

#[test]
fn a_share_meeting_the_pool_target_is_forwarded_and_measured() {
    let n = nonce_where(|h| le_leq(h, &up()));
    assert_eq!(
        gate().check_extended(&share(1, n)),
        Verdict::Forward {
            measured: Some(diff(down()))
        }
    );
}

#[test]
fn a_share_meeting_only_the_miner_target_is_withheld_and_measured() {
    let n = nonce_where(|h| le_leq(h, &down()) && !le_leq(h, &up()));
    assert_eq!(
        gate().check_extended(&share(1, n)),
        Verdict::Withhold {
            measured: diff(down())
        }
    );
}

#[test]
fn a_share_below_the_miner_target_is_forwarded_unmeasured() {
    let n = nonce_where(|h| !le_leq(h, &down()));
    assert_eq!(
        gate().check_extended(&share(1, n)),
        Verdict::Forward { measured: None }
    );
}

#[test]
fn a_share_for_an_unknown_job_is_forwarded_unmeasured() {
    let n = nonce_where(|h| le_leq(h, &down()) && !le_leq(h, &up()));
    assert_eq!(
        gate().check_extended(&share(99, n)),
        Verdict::Forward { measured: None }
    );
}

#[test]
fn a_gate_tracking_the_wrong_job_withholds_nothing() {
    // The fail-safe the module rests on. The same miner-target-only share,
    // judged by a gate whose prefix differs from the miner's: its hash is
    // random, misses the miner target, and the share goes to the pool. The
    // control in the second half proves the share is one the right gate holds.
    let n = nonce_where(|h| le_leq(h, &down()) && !le_leq(h, &up()));
    let mut wrong = ShareGate::extended(
        vec![0x01, 0x02, 0x03, 0x04],
        4,
        Some(&up()),
        &[0xff; 32],
        0.0,
    );
    wrong.force_downstream(Target::from_le_bytes(down()));
    wrong.on_extended_job(job(1));
    wrong.on_prev_hash(prev_hash(1));
    assert_eq!(
        wrong.check_extended(&share(1, n)),
        Verdict::Forward { measured: None }
    );
    assert!(matches!(
        gate().check_extended(&share(1, n)),
        Verdict::Withhold { .. }
    ));
}

/// A pool target harder than [`up`]: about one hash in 65536 meets it.
fn harder_up() -> [u8; 32] {
    easy_target(0x00, 0x00)
}

#[test]
fn a_share_on_a_job_from_before_a_harder_pool_target_is_still_forwarded() {
    // The pool judges a job by the target it came with (SV2 Mining Protocol /
    // SetTarget), however long ago that was: the gate must not withhold it.
    let n = nonce_where(|h| le_leq(h, &up()) && !le_leq(h, &harder_up()));
    let mut g = gate();
    g.set_upstream_target(&harder_up());
    assert!(matches!(
        g.check_extended(&share(1, n)),
        Verdict::Forward { measured: Some(_) }
    ));
}

#[test]
fn a_share_on_a_job_from_after_a_harder_pool_target_is_judged_on_it() {
    // The negative control: the same share on a job issued after the raise
    // misses that job's pool target and only meets the miner's.
    let n = nonce_where(|h| le_leq(h, &up()) && !le_leq(h, &harder_up()) && le_leq(h, &down()));
    let mut g = gate();
    g.set_upstream_target(&harder_up());
    g.on_extended_job(job(2));
    g.on_prev_hash(prev_hash(2));
    assert!(matches!(
        g.check_extended(&share(2, n)),
        Verdict::Withhold { .. }
    ));
}

#[test]
fn a_block_is_forwarded_even_below_the_pool_target() {
    // A network target easier than the pool's (regtest): a share that misses
    // the pool target but solves a block still goes up.
    const REGTEST_BITS: u32 = 0x207f_ffff;
    let n = (0u32..2_000_000)
        .find(|n| {
            let h = oracle_hash_bits(*n, REGTEST_BITS);
            le_leq(&h, &down()) && !le_leq(&h, &up())
        })
        .unwrap();
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    g.force_downstream(Target::from_le_bytes(down()));
    g.on_extended_job(job(1));
    g.on_prev_hash(prev_hash_bits(1, REGTEST_BITS));
    assert!(matches!(
        g.check_extended(&share(1, n)),
        Verdict::Forward { measured: Some(_) }
    ));
}

#[test]
fn a_gate_that_cannot_track_counts_every_share_toward_its_rate() {
    // Prefix plus rollable size above 32 bytes: no client channel. The shares
    // still count, so vardiff pulls the miner toward the pool's target.
    let mut g = ShareGate::extended(vec![0; 30], 4, Some(&up()), &[0xff; 32], 0.0);
    assert!(!g.is_tracking());
    assert_eq!(
        g.check_extended(&share(1, 0)),
        Verdict::Forward { measured: None }
    );
    assert_eq!(g.vardiff.shares_since_last_update, 1);
}

#[test]
fn vardiff_never_eases_below_a_hundredth_of_the_measured_peak() {
    // A device measured at 1 TH/s that goes quiet: however long it stays
    // silent, the miner target stops at a hundredth of that.
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&[0xff; 32]), &[0xff; 32], 1.0e12);
    g.peak = 1.0e12;
    for _ in 0..40 {
        g.vardiff.timestamp_of_last_update -= 600;
        g.tick();
    }
    assert!(g.estimate >= 1.0e10, "estimate {}", g.estimate);
}

#[test]
fn a_figure_no_share_backed_never_holds_the_floor_up() {
    // A pool difficulty far above the device seeds the estimate high; the
    // walk down on silence is no measurement, so it must not set the floor
    // and stall the miner above what it can find. Same for a device figure.
    let pool = translate::target_from_difficulty(1024.0);
    for nominal in [0.0, 1.0e12] {
        let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&pool), &[0xff; 32], nominal);
        let start = g.estimate;
        for _ in 0..40 {
            g.vardiff.timestamp_of_last_update -= 600;
            g.tick();
        }
        assert!(
            g.estimate < start / 1000.0,
            "nominal {nominal}: {} vs {start}",
            g.estimate
        );
        assert_eq!(g.peak, 0.0);
    }
}

#[test]
fn a_device_figure_no_longer_overrides_a_measured_estimate() {
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&[0xff; 32]), &[0xff; 32], 1.0e12);
    g.seed = Seed::Measured;
    assert!(g.suggest_target(&[0xff; 32]).is_none());
    g.update_device(1.0, &[0xff; 32]);
    assert_eq!(g.estimate, 1.0e12);
}

#[test]
fn a_pool_target_easier_than_vardiff_is_handed_to_the_miner_unchanged() {
    // A nominal hashrate that wants a far harder target than the pool's: the
    // miner gets the pool's, so every share it finds is one the pool wants.
    let g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&down()), &[0xff; 32], 1.0e15);
    assert_eq!(g.downstream_target(), down());
}

#[test]
fn the_vardiff_target_never_goes_easier_than_the_device_accepts() {
    // A vardiff estimate small enough to want a near-maximal target, a pool
    // target harder than the device's max_target: the miner gets the device's.
    let device_max = easy_target(0x0f, 0xff);
    let g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &device_max, 1.0);
    assert_eq!(g.downstream_target(), device_max);
}

#[test]
fn a_pool_target_easier_than_the_device_max_still_bounds_the_miner_target() {
    // A pool that never saw the device's max_target sets an easier target. The
    // miner target must not end up harder than the pool's: the miner would
    // skip the shares in between while the pool credits each forwarded share
    // at its own easier target.
    let device_max = easy_target(0x00, 0x0f);
    let pool = down();
    let g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&pool), &device_max, 1.0);
    assert_eq!(g.downstream_target(), pool);
}

#[test]
fn vardiff_eases_the_miner_target_when_no_shares_arrive() {
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    let before = g.downstream_target();
    g.vardiff.timestamp_of_last_update -= 60;
    let after = g.tick().expect("a silent minute retargets");
    assert!(
        Target::from_le_bytes(after) > Target::from_le_bytes(before),
        "the new miner target is easier"
    );
    // ...and it never goes harder than the pool's own.
    assert!(Target::from_le_bytes(after) >= Target::from_le_bytes(up()));
}

#[test]
fn a_renewed_gate_keeps_the_estimate_and_drops_the_jobs() {
    let n = nonce_where(|h| le_leq(h, &down()) && !le_leq(h, &up()));
    let mut old = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    old.estimate = 123.0;
    old.seed = Seed::Measured;
    let mut renewed = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0)
        .with_device(old.device());
    assert_eq!(renewed.estimate, 123.0);
    assert_eq!(
        renewed.check_extended(&share(1, n)),
        Verdict::Forward { measured: None },
        "the old upstream's jobs are not the new one's"
    );
}

// ── SV1 ─────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The `mining.notify` line for [`job`]/[`prev_hash`] (SV1 swaps the
/// prev-hash words; `translate::notify_from_line` undoes that).
fn notify_line() -> String {
    let notify = translate::sv2_job_to_sv1_notify(
        prev_hash(1),
        {
            let mut j = job(1);
            j.ntime_start = Sv2OptionOwned::new(Some(NTIME));
            j
        },
        true,
    )
    .unwrap();
    translate::notify_to_line(notify)
}

fn submit_line(job_id: &str, nonce: u32) -> client_to_server::Submit {
    let req = stratum_core::sv1_api::json_rpc::StandardRequest {
        id: 7,
        method: "mining.submit".to_string(),
        params: serde_json::json!([
            "w",
            job_id,
            hex(&ROLLED),
            format!("{NTIME:08x}"),
            format!("{nonce:08x}")
        ]),
    };
    client_to_server::Submit::try_from(req).unwrap()
}

fn sv1_gate() -> (Sv1Gate, String) {
    // The test targets are easier than difficulty 1, below what an SV1
    // difficulty resolves, so the pool target is set as a target.
    let mut g = Sv1Gate::new(&PREFIX, ROLLED.len() as u16, Some(up()));
    g.gate.force_downstream(Target::from_le_bytes(down()));
    let line = notify_line();
    let job_id = translate::notify_from_line(&line).unwrap().job_id;
    assert!(g.line_to_miner(line).is_some(), "a notify passes through");
    (g, job_id)
}

#[test]
fn sv1_submit_is_judged_on_the_notify_the_miner_received() {
    let (mut g, job_id) = sv1_gate();
    let withheld = nonce_where(|h| le_leq(h, &down()) && !le_leq(h, &up()));
    let forwarded = nonce_where(|h| le_leq(h, &up()));
    let low = nonce_where(|h| !le_leq(h, &down()));
    assert!(matches!(
        g.check(&submit_line(&job_id, withheld)),
        Verdict::Withhold { .. }
    ));
    assert!(matches!(
        g.check(&submit_line(&job_id, forwarded)),
        Verdict::Forward { measured: Some(_) }
    ));
    assert_eq!(
        g.check(&submit_line(&job_id, low)),
        Verdict::Forward { measured: None }
    );
    assert_eq!(
        g.check(&submit_line("not-a-job", withheld)),
        Verdict::Forward { measured: None }
    );
}

#[test]
fn a_pool_difficulty_set_after_the_handshake_is_the_one_the_miner_hears() {
    // No difficulty in the handshake (the pool sets it after the authorize),
    // no device figure: the miner follows the pool's difficulty when it comes,
    // instead of staying near the protocol's default of 1. Heard once.
    let mut g = Sv1Gate::new(&PREFIX, 4, None);
    let pool_line = translate::set_difficulty_to_line(1_000_000.0);
    let first = g.line_to_miner(pool_line.clone()).expect("first is sent");
    let told = translate::set_difficulty_from_line(&first).unwrap();
    assert!((told - 1_000_000.0).abs() < 1.0, "told {told}");
    assert!(
        g.line_to_miner(pool_line).is_none(),
        "unchanged → not repeated"
    );
}

#[test]
fn sv1_lines_are_read_as_pools_send_them() {
    // A notification with a numeric id, a set_difficulty with an extra param:
    // the gate must see both, or the miner would hear the pool's difficulty.
    let sd = r#"{"id":4,"method":"mining.set_difficulty","params":[512,"x"]}"#;
    assert_eq!(translate::set_difficulty_from_line(sd), Some(512.0));
    let mut v: serde_json::Value = serde_json::from_str(&notify_line()).unwrap();
    v["id"] = serde_json::json!(9);
    assert!(translate::notify_from_line(&v.to_string()).is_some());
}

#[test]
fn a_reused_sv1_job_id_survives_its_older_entry_being_evicted() {
    let mut g = Sv1Gate::new(&PREFIX, 4, Some(up()));
    let base: serde_json::Value = serde_json::from_str(&notify_line()).unwrap();
    let with_id = |id: &str, clean: bool| {
        let mut v = base.clone();
        v["params"][0] = serde_json::json!(id);
        v["params"][8] = serde_json::json!(clean);
        format!("{v}\n")
    };
    g.line_to_miner(with_id("x", true));
    for i in 0..(SV1_JOBS - 2) {
        g.line_to_miner(with_id(&format!("j{i}"), false));
    }
    g.line_to_miner(with_id("x", false));
    // One more evicts the first "x" entry; the second must stay mapped.
    g.line_to_miner(with_id("last", false));
    assert!(g.job_ids.contains_key("x"));
}

#[test]
fn a_suggested_difficulty_sizes_the_miner_target_below_the_pool() {
    // A pool at difficulty 1, an SV1 miner that suggests 0.0001: the miner
    // target follows the suggestion, never harder than the pool's.
    let pool = translate::target_from_difficulty(1.0);
    let mut g = Sv1Gate::new(&PREFIX, 4, Some(pool));
    assert_eq!(g.gate.downstream_target(), pool, "starts on the pool's");
    let line = g.suggest_difficulty(0.0001).expect("the difficulty moves");
    let told = translate::set_difficulty_from_line(&line).unwrap();
    assert!(told < 1.0, "told {told}");
    assert!(Target::from_le_bytes(g.gate.downstream_target()) >= Target::from_le_bytes(pool));
}

#[test]
fn an_update_channel_resizes_and_reclamps_the_miner_target() {
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    assert_eq!(g.downstream_target(), up(), "starts on the pool's");
    let device_max = easy_target(0x0f, 0xff);
    let moved = g.update_device(1.0, &device_max).expect("the target moves");
    assert_eq!(
        moved, device_max,
        "a tiny device, clamped to its max_target"
    );
}

#[test]
fn the_estimate_never_drops_below_the_vardiff_floor() {
    // A pool target with no threshold implies a zero hashrate; vardiff's
    // ratio arithmetic would never leave zero again.
    let g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&[0xff; 32]), &[0xff; 32], 0.0);
    assert!(g.estimate >= g.vardiff.min_allowed_hashrate());
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    g.suggest_target(&[0xff; 32]);
    assert!(g.estimate > 0.0);
}

#[test]
fn shares_that_cannot_be_placed_do_not_ease_the_miner_target() {
    // Shares arrive, none on a job the gate knows: no evidence the device is
    // slower than its target, so a silent-looking minute must not ease it.
    let mut g = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0);
    let before = g.downstream_target();
    for _ in 0..5 {
        assert_eq!(
            g.check_extended(&share(99, 0)),
            Verdict::Forward { measured: None }
        );
    }
    g.vardiff.timestamp_of_last_update -= 60;
    assert!(g.tick().is_none());
    assert_eq!(g.downstream_target(), before);
    // The control: the same gate with no shares at all does ease it.
    g.vardiff.set_shares_since_last_update(0);
    g.vardiff.timestamp_of_last_update -= 60;
    assert!(g.tick().is_some());
}

#[test]
fn a_gate_without_a_client_channel_hands_the_miner_the_pool_target() {
    // Prefix plus rollable size above 32 bytes: nothing can be judged, so a
    // device figure must not ease the miner below the pool's target.
    let mut g = ShareGate::extended(vec![0; 30], 4, Some(&up()), &[0xff; 32], 1.0);
    assert_eq!(g.downstream_target(), up());
    g.vardiff.timestamp_of_last_update -= 60;
    assert!(g.tick().is_none());
}

#[test]
fn an_updated_device_max_survives_an_upstream_swap() {
    let mut old = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 1.0);
    let device_max = easy_target(0x0f, 0xff);
    old.update_device(1.0, &device_max);
    let renewed = ShareGate::extended(PREFIX.to_vec(), 4, Some(&up()), &[0xff; 32], 0.0)
        .with_device(old.device());
    assert_eq!(renewed.downstream_target(), device_max);
}

#[test]
fn sv1_difficulty_as_a_string_and_notify_with_extra_params_are_read() {
    let sd = r#"{"id":null,"method":"mining.set_difficulty","params":["2048"]}"#;
    assert_eq!(translate::set_difficulty_from_line(sd), Some(2048.0));
    let mut v: serde_json::Value = serde_json::from_str(&notify_line()).unwrap();
    v["params"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("extra"));
    assert!(translate::notify_from_line(&v.to_string()).is_some());
}

#[test]
fn an_unparsable_sv1_submit_counts_toward_the_share_rate() {
    let mut g = Sv1Gate::new(&PREFIX, 4, Some(up()));
    assert_eq!(g.unplaced(), Verdict::Forward { measured: None });
    assert_eq!(
        g.check(&submit_line("unknown-job", 0)),
        Verdict::Forward { measured: None }
    );
    assert_eq!(g.gate.vardiff.shares_since_last_update, 2);
}
