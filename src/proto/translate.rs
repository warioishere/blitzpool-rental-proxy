//! Stratum V1 ↔ Stratum V2 job/share translation for the bidirectional upstream.
//!
//! The proxy is a fixed-protocol server to the seller's miner, but the buyer's
//! pool may speak either protocol. When they differ the upstream path translates
//! between them so shares still flow end to end:
//!
//! - **SV1 miner ↔ SV2 pool**: SV2 `NewExtendedMiningJob`+`SetNewPrevHash` become
//!   a `mining.notify`, `SetTarget` becomes `mining.set_difficulty`, and a
//!   `mining.submit` becomes `SubmitSharesExtended`. These conversions are
//!   provided by `stratum_translation`.
//! - **SV2 miner ↔ SV1 pool**: the inverse, built here — `mining.notify` becomes
//!   `NewExtendedMiningJob`(+`SetNewPrevHash`), `mining.set_difficulty` becomes
//!   `SetTarget`, and `SubmitSharesExtended` becomes a `mining.submit`.
//!
//! Byte order follows the SV2 spec: targets are 32-byte little-endian; the SV1
//! `mining.notify` prev-hash per-word swap is handled by the SV1 `PrevHash`
//! newtype (so the SV2 `prev_hash` is its natural internal order). A difficulty-1
//! share is 2^32 hashes, and the share difficulty implied by a target is computed
//! with the same authoritative target math the relay uses for accounting, so the
//! threshold the miner sees and the work the proxy credits agree.

use anyhow::{anyhow, Result};

use stratum_core::binary_sv2::{Seq0255, Sv2Option, U256};
use stratum_core::channels_sv2::target::{hash_rate_from_target, hash_rate_to_target};
use stratum_core::mining_sv2::{NewExtendedMiningJob, SetNewPrevHash, SubmitSharesExtended};
use stratum_core::stratum_translation::sv2_to_sv1;
use stratum_core::sv1_api::{
    json_rpc,
    methods::{client_to_server, server_to_client},
    utils::{Extranonce, HexU32Be, MerkleNode, PrevHash},
};

/// Difficulty-1 share = 2^32 hashes.
const DIFF1_HASHES: f64 = 4_294_967_296.0;

/// How long to wait for a native-protocol upstream connect before concluding the
/// pool speaks the *other* protocol and switching to translation. Detection is
/// folded into the connect: the native attempt is tried first (and its socket
/// reused on success); only on its failure/timeout is the other protocol tried.
pub const UPSTREAM_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Default BIP320 version-rolling mask advertised to miners and used to extract
/// the version-rolling bits from a submitted SV2 version field.
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;

// ── difficulty / target ─────────────────────────────────────────────

/// Share difficulty (diff-1 units) implied by a 32-byte little-endian `target`.
/// Uses the upstream stack's authoritative target math so the byte order +
/// diff-1 convention match the pools. Returns 0.0 for a zero/invalid target.
pub fn difficulty_from_target(target: &[u8]) -> f64 {
    let Ok(u) = U256::try_from(target.to_vec()) else {
        return 0.0;
    };
    // hash_rate_from_target(t, 1 share/min) = hashes_per_share / 60;
    // difficulty = hashes_per_share / 2^32.
    match hash_rate_from_target(u, 1.0) {
        Ok(h1) => h1 * 60.0 / DIFF1_HASHES,
        Err(_) => 0.0,
    }
}

/// The 32-byte little-endian target for a share `difficulty` (diff-1 units).
/// Exact inverse of [`difficulty_from_target`]: a difficulty-`d` share needs
/// `d * 2^32` hashes on average, so the target is the one the authoritative math
/// assigns to that work at one share per the 60-second basis. A non-positive or
/// non-finite difficulty yields the maximum target (no threshold).
pub fn target_from_difficulty(difficulty: f64) -> [u8; 32] {
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return [0xff; 32];
    }
    match hash_rate_to_target(difficulty * DIFF1_HASHES, 60.0) {
        Ok(t) => t.to_le_bytes(),
        Err(_) => [0xff; 32],
    }
}

// ── SV2 → SV1 (SV1 miner ↔ SV2 pool) ────────────────────────────────

/// Convert an SV2 job + prev-hash into an SV1 `mining.notify` (handles the SV2
/// coinbase's BIP141 stripping internally).
pub fn sv2_job_to_sv1_notify(
    prev_hash: SetNewPrevHash<'static>,
    job: NewExtendedMiningJob<'static>,
    clean_jobs: bool,
) -> Result<server_to_client::Notify<'static>> {
    sv2_to_sv1::build_sv1_notify_from_sv2(prev_hash, job, clean_jobs)
        .map_err(|e| anyhow!("sv2 job → sv1 notify: {e:?}"))
}

/// Serialize an SV1 `mining.notify` to a wire line (newline-terminated).
pub fn notify_to_line(notify: server_to_client::Notify<'static>) -> String {
    let msg: json_rpc::Message = notify.into();
    let mut s = serde_json::to_string(&msg).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

// ── SV1 → SV2 (SV2 miner ↔ SV1 pool) ────────────────────────────────

/// Parse an SV1 `mining.notify` line into a typed notify (the prev-hash word
/// swap is undone by the `PrevHash` newtype). Returns `None` if the line is not
/// a well-formed `mining.notify`.
pub fn notify_from_line(line: &str) -> Option<server_to_client::Notify<'static>> {
    let msg: json_rpc::Message = serde_json::from_str(line.trim()).ok()?;
    let json_rpc::Message::Notification(n) = msg else {
        return None;
    };
    if n.method != "mining.notify" {
        return None;
    }
    let parsed = server_to_client::Notify::try_from(n).ok()?;
    // Re-own every borrowed field so the notify is 'static (storable + sendable).
    Some(server_to_client::Notify {
        job_id: parsed.job_id,
        prev_hash: PrevHash(parsed.prev_hash.0.into_static()),
        coin_base1: parsed.coin_base1,
        coin_base2: parsed.coin_base2,
        merkle_branch: parsed
            .merkle_branch
            .into_iter()
            .map(|m| MerkleNode(m.0.into_static()))
            .collect(),
        version: parsed.version,
        bits: parsed.bits,
        time: parsed.time,
        clean_jobs: parsed.clean_jobs,
    })
}

/// Parse an SV1 `mining.set_difficulty` line into its difficulty value.
pub fn set_difficulty_from_line(line: &str) -> Option<f64> {
    let msg: json_rpc::Message = serde_json::from_str(line.trim()).ok()?;
    let json_rpc::Message::Notification(n) = msg else {
        return None;
    };
    if n.method != "mining.set_difficulty" {
        return None;
    }
    server_to_client::SetDifficulty::try_from(n).ok().map(|d| d.value)
}

/// Build an SV2 `NewExtendedMiningJob` (and, for a block change, the activating
/// `SetNewPrevHash`) from an SV1 `mining.notify`.
///
/// Per SV2 §7 a block-change job is a **future** job: it is sent first with an
/// empty `min_ntime` and then activated by `SetNewPrevHash`. A same-block job is
/// immediate (`min_ntime` set, no prev-hash). The caller decides `as_future`
/// (true on a clean job or the first job of a channel, which has no prev-hash
/// yet). `job_id` is the proxy-assigned SV2 id; the caller maps it back to the
/// pool's string job id for the eventual `mining.submit`.
pub fn sv1_notify_to_sv2_job(
    notify: &server_to_client::Notify<'_>,
    channel_id: u32,
    job_id: u32,
    as_future: bool,
    version_rolling_allowed: bool,
) -> Result<(NewExtendedMiningJob<'static>, Option<SetNewPrevHash<'static>>)> {
    let merkle_path: Vec<U256<'static>> = notify
        .merkle_branch
        .iter()
        .map(|m| m.0.clone().into_static())
        .collect();
    let coinbase_tx_prefix = Vec::<u8>::from(notify.coin_base1.clone());
    let coinbase_tx_suffix = Vec::<u8>::from(notify.coin_base2.clone());

    let job = NewExtendedMiningJob {
        channel_id,
        job_id,
        min_ntime: Sv2Option::new(if as_future { None } else { Some(notify.time.0) }),
        version: notify.version.0,
        version_rolling_allowed,
        merkle_path: Seq0255::new(merkle_path).map_err(|e| anyhow!("merkle_path: {e:?}"))?,
        coinbase_tx_prefix: coinbase_tx_prefix
            .try_into()
            .map_err(|_| anyhow!("coinbase prefix too long"))?,
        coinbase_tx_suffix: coinbase_tx_suffix
            .try_into()
            .map_err(|_| anyhow!("coinbase suffix too long"))?,
    };

    let prev_hash = if as_future {
        Some(SetNewPrevHash {
            channel_id,
            job_id,
            prev_hash: notify.prev_hash.0.clone().into_static(),
            min_ntime: notify.time.0,
            nbits: notify.bits.0,
        })
    } else {
        None
    };
    Ok((job, prev_hash))
}

/// Convert an SV2 `SubmitSharesExtended` into an SV1 `mining.submit`.
///
/// The SV2 `extranonce` is the miner-rolled part only (the prefix is fixed at
/// channel open), which is exactly the SV1 `extranonce2`. When the upstream pool
/// negotiated version rolling, `version_rolling_mask` is set and the SV1
/// `version_bits` carry the rolled bits (`version & mask`); otherwise no version
/// rolling is in play and `version_bits` is omitted.
pub fn sv2_submit_to_sv1(
    submit: &SubmitSharesExtended<'_>,
    user_name: String,
    job_id: String,
    id: u64,
    version_rolling_mask: Option<u32>,
) -> Result<client_to_server::Submit<'static>> {
    let extra_nonce2 = Extranonce::try_from(submit.extranonce.inner_as_ref().to_vec())
        .map_err(|e| anyhow!("extranonce: {e:?}"))?;
    Ok(client_to_server::Submit {
        user_name,
        job_id,
        extra_nonce2,
        time: HexU32Be(submit.ntime),
        nonce: HexU32Be(submit.nonce),
        version_bits: version_rolling_mask.map(|mask| HexU32Be(submit.version & mask)),
        id,
    })
}

/// Serialize an SV1 `mining.submit` to a wire line (newline-terminated).
pub fn submit_to_line(submit: client_to_server::Submit<'static>) -> String {
    let msg: json_rpc::Message = submit.into();
    let mut s = serde_json::to_string(&msg).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::bitcoin::hashes::{sha256d, Hash};
    use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;
    use stratum_core::sv1_api::utils::HexBytes;

    /// Assemble a minimal valid legacy (non-witness) coinbase transaction whose
    /// scriptSig contains an `en_len`-byte extranonce region, and return its
    /// `(coinb1, coinb2)` split at that region — i.e. the SV1 `mining.notify`
    /// coinbase parts. `coinb1 + extranonce + coinb2` is a byte-valid tx.
    fn legacy_coinbase(en_len: usize) -> (Vec<u8>, Vec<u8>) {
        // scriptSig = OP_PUSH3 + 3 height bytes + extranonce region.
        let script_prefix = [0x03u8, 0x33, 0x33, 0x33];
        let script_sig_len = script_prefix.len() + en_len;
        assert!(script_sig_len <= 100, "coinbase scriptSig must be ≤ 100 bytes");

        let mut coinb1 = Vec::new();
        coinb1.extend_from_slice(&1u32.to_le_bytes()); // version
        coinb1.push(0x01); // input count
        coinb1.extend_from_slice(&[0u8; 32]); // prevout hash
        coinb1.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
        coinb1.push(script_sig_len as u8); // scriptSig length (varint < 0xfd)
        coinb1.extend_from_slice(&script_prefix); // scriptSig up to the extranonce
        // ── extranonce goes here ──
        let mut coinb2 = Vec::new();
        coinb2.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        coinb2.push(0x01); // output count
        coinb2.extend_from_slice(&5_000_000_000u64.to_le_bytes()); // value (50 BTC)
        coinb2.push(0x00); // empty scriptPubKey (length 0)
        coinb2.extend_from_slice(&0u32.to_le_bytes()); // locktime
        (coinb1, coinb2)
    }

    fn sample_notify(clean: bool, merkle_branch: Vec<MerkleNode<'static>>) -> server_to_client::Notify<'static> {
        let (coinb1, coinb2) = legacy_coinbase(8);
        server_to_client::Notify {
            job_id: "abc123".to_string(),
            prev_hash: PrevHash(U256::from([0x11u8; 32])),
            coin_base1: HexBytes::from(coinb1),
            coin_base2: HexBytes::from(coinb2),
            merkle_branch,
            version: HexU32Be(0x2000_0000),
            bits: HexU32Be(0x1707_2cf6),
            time: HexU32Be(0x6500_0000),
            clean_jobs: clean,
        }
    }

    #[test]
    fn target_and_difficulty_round_trip() {
        for d in [0.5_f64, 1.0, 100.0, 8192.0, 1_000_000.0] {
            let t = target_from_difficulty(d);
            let back = difficulty_from_target(&t);
            let rel = (back - d).abs() / d;
            assert!(rel < 1e-3, "difficulty {d} round-tripped to {back} (rel {rel})");
        }
        // Non-positive difficulty → max target (no threshold).
        assert_eq!(target_from_difficulty(0.0), [0xff; 32]);
    }

    #[test]
    fn sv1_notify_round_trips_through_sv2() {
        // A clean (future) job with one merkle node. Convert SV1 notify → SV2
        // job+prev-hash, then back via the authoritative SV2→SV1 builder, and
        // assert every field survives — this proves the inverse is byte-exact
        // (esp. the prev-hash word swap, version/bits/ntime, coinbase, merkle).
        let original = sample_notify(true, vec![MerkleNode(U256::from([0x03u8; 32]))]);
        let (job, prev) = sv1_notify_to_sv2_job(&original, 1, 7, true, true).unwrap();
        let prev = prev.expect("clean job emits a SetNewPrevHash");

        let back = sv2_job_to_sv1_notify(prev, job, true).unwrap();

        assert_eq!(String::from(back.prev_hash.clone()), String::from(original.prev_hash.clone()));
        assert_eq!(back.coin_base1, original.coin_base1);
        assert_eq!(back.coin_base2, original.coin_base2);
        assert_eq!(back.version, original.version);
        assert_eq!(back.bits, original.bits);
        assert_eq!(back.time, original.time);
        assert_eq!(back.merkle_branch.len(), 1);
        assert_eq!(back.merkle_branch[0].0.inner_as_ref(), original.merkle_branch[0].0.inner_as_ref());
        assert!(back.clean_jobs);
    }

    #[test]
    fn same_block_job_is_immediate_not_future() {
        let notify = sample_notify(false, vec![]);
        let (job, prev) = sv1_notify_to_sv2_job(&notify, 3, 9, false, true).unwrap();
        assert!(prev.is_none(), "same-block job emits no prev-hash");
        assert_eq!(
            job.min_ntime.clone().into_inner(),
            Some(notify.time.0),
            "immediate job carries the job ntime"
        );
    }

    #[test]
    fn sv2_submit_translates_to_sv1_submit() {
        let submit = SubmitSharesExtended {
            channel_id: 5,
            sequence_number: 42,
            job_id: 9,
            nonce: 0xdead_beef,
            ntime: 0x6500_0001,
            version: 0x2123_4000,
            extranonce: U256::from([0u8; 32]).inner_as_ref()[..4].to_vec().try_into().unwrap(),
        };
        let s = sv2_submit_to_sv1(&submit, "bc1qX.rig".into(), "job7".into(), 11, Some(VERSION_ROLLING_MASK)).unwrap();
        assert_eq!(s.user_name, "bc1qX.rig");
        assert_eq!(s.job_id, "job7");
        assert_eq!(s.nonce.0, 0xdead_beef);
        assert_eq!(s.time.0, 0x6500_0001);
        assert_eq!(s.id, 11);
        // version_bits = version & mask (the rolled bits only).
        assert_eq!(s.version_bits.unwrap().0, 0x2123_4000 & VERSION_ROLLING_MASK);
        assert_eq!(s.extra_nonce2.0.inner_as_ref().len(), 4);

        // No mask negotiated → no version_bits.
        let s2 = sv2_submit_to_sv1(&submit, "w".into(), "j".into(), 1, None).unwrap();
        assert!(s2.version_bits.is_none());
    }

    #[test]
    fn translated_job_rebuilds_a_valid_header_that_can_meet_a_target() {
        // The whole combo-4 job pipeline at the byte level: SV1 notify → SV2 job,
        // then reassemble coinbase (prefix+extranonce+suffix) → merkle root →
        // 80-byte header → SHA256d, and confirm a nonce can meet an easy target.
        let notify = sample_notify(true, vec![]);
        let (job, prev) = sv1_notify_to_sv2_job(&notify, 1, 1, true, true).unwrap();
        let prev = prev.unwrap();

        // Pool prefix (extranonce1) + miner part (extranonce2) = 8-byte region.
        let extranonce: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00];
        let empty_path: Vec<Vec<u8>> = vec![];
        let merkle_root = merkle_root_from_path(
            job.coinbase_tx_prefix.inner_as_ref(),
            job.coinbase_tx_suffix.inner_as_ref(),
            &extranonce,
            &empty_path,
        )
        .expect("reassembled coinbase must deserialize as a valid transaction");
        assert_eq!(merkle_root.len(), 32);

        // Build the 80-byte header from the translated job/prev-hash fields.
        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&job.version.to_le_bytes());
        header.extend_from_slice(prev.prev_hash.inner_as_ref()); // internal order
        header.extend_from_slice(&merkle_root);
        header.extend_from_slice(&prev.min_ntime.to_le_bytes());
        header.extend_from_slice(&prev.nbits.to_le_bytes());
        let nonce_off = header.len();
        header.extend_from_slice(&0u32.to_le_bytes()); // nonce placeholder
        assert_eq!(header.len(), 80);

        // Easy target (~2^254): grinding a few nonces must find a hash ≤ target.
        let mut target = [0xffu8; 32];
        target[31] = 0x3f; // most-significant byte (little-endian) capped
        let mut found = false;
        for nonce in 0u32..100_000 {
            header[nonce_off..nonce_off + 4].copy_from_slice(&nonce.to_le_bytes());
            let hash = sha256d::Hash::hash(&header).to_byte_array();
            if le_leq(&hash, &target) {
                found = true;
                break;
            }
        }
        assert!(found, "no nonce met the easy target — header reconstruction is wrong");
    }

    /// `a ≤ b` for two 32-byte little-endian numbers.
    fn le_leq(a: &[u8], b: &[u8]) -> bool {
        for i in (0..32).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    #[test]
    fn notify_line_serializes_and_parses_back() {
        let original = sample_notify(true, vec![MerkleNode(U256::from([0x07u8; 32]))]);
        let line = notify_to_line(original.clone());
        assert!(line.ends_with('\n'), "wire line must be newline-terminated");
        let parsed = notify_from_line(&line).expect("round-trips back to a notify");
        assert_eq!(parsed.job_id, original.job_id);
        assert_eq!(String::from(parsed.prev_hash), String::from(original.prev_hash.clone()));
        assert_eq!(parsed.coin_base1, original.coin_base1);
        assert_eq!(parsed.coin_base2, original.coin_base2);
        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.bits, original.bits);
        assert_eq!(parsed.time, original.time);
        assert_eq!(parsed.merkle_branch.len(), 1);
        assert!(parsed.clean_jobs);
        // A non-notify line is rejected.
        assert!(notify_from_line("{\"id\":1,\"result\":true}").is_none());
    }

    #[test]
    fn set_difficulty_line_parses() {
        let line = "{\"method\":\"mining.set_difficulty\",\"params\":[1024.0]}";
        assert_eq!(set_difficulty_from_line(line), Some(1024.0));
        assert_eq!(set_difficulty_from_line("{\"method\":\"mining.notify\",\"params\":[]}"), None);
    }

    #[test]
    fn submit_line_is_a_valid_mining_submit() {
        let submit = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 0,
            job_id: 3,
            nonce: 0x1234_5678,
            ntime: 0x6500_0000,
            version: 0x2000_0000,
            extranonce: vec![1u8, 2, 3, 4].try_into().unwrap(),
        };
        let s = sv2_submit_to_sv1(&submit, "acct.rig".into(), "9".into(), 5, Some(VERSION_ROLLING_MASK)).unwrap();
        let line = submit_to_line(s);
        assert!(line.ends_with('\n'));
        let msg: json_rpc::Message = serde_json::from_str(line.trim()).unwrap();
        let json_rpc::Message::StandardRequest(req) = msg else {
            panic!("mining.submit must be a request");
        };
        assert_eq!(req.method, "mining.submit");
        assert_eq!(req.id, 5);
        let params = req.params.as_array().unwrap();
        assert_eq!(params[0], "acct.rig");
        assert_eq!(params[1], "9");
        assert_eq!(params[2], "01020304"); // extranonce2 hex
    }
}
