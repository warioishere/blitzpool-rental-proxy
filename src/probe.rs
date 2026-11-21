// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pre-rental check of a buyer's pool: connect it the way a rental would, log
//! in with the worker the rental would use, wait for the first job and check
//! that the job builds on the Bitcoin tip. A pool that fails is refused before
//! the order exists, so no rig is pointed at a pool that cannot take its work.

use std::time::Duration;

use serde::Serialize;
use stratum_core::bitcoin::hashes::Hash;
use stratum_core::bitcoin::BlockHash;
use stratum_core::mining_sv2 as mining;
use stratum_core::sv1_api::server_to_client::Notify;
use tokio::io::AsyncBufReadExt;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::chain::Electrum;
use crate::proto::sv1;
use crate::proto::sv2::relay::codec::{parse_new_extended_job, parse_set_new_prev_hash};
use crate::proto::sv2::relay::{open_on, probe_sv2, ProbeFailure, Read, Write};
use crate::proto::{translate, LoginRefused};
use crate::session::UpstreamTarget;

/// Upper bound for reaching a pool, logging in and receiving its first job.
const POOL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a pool that accepted the login gets to send its first job.
const JOB_WAIT: Duration = Duration::from_secs(5);
/// Blocks a job's height may lie from the Electrum tip + 1: the pool or the
/// Electrum server may each be a block behind at a block change.
const HEIGHT_TOLERANCE: u64 = 2;

/// Why a pool failed the probe. Serialized as the API's `error` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RefusalCode {
    /// No TCP connection.
    #[serde(rename = "pool-unreachable")]
    Unreachable,
    /// Connected, but neither a Stratum V1 nor a Stratum V2 handshake.
    #[serde(rename = "pool-not-stratum")]
    NotStratum,
    /// The pool refused the login (SV1 authorize, SV2 channel open).
    #[serde(rename = "pool-auth-refused")]
    AuthRefused,
    /// Logged in, but no job arrived.
    #[serde(rename = "pool-no-job")]
    NoJob,
    /// The first job does not build on the Bitcoin tip.
    #[serde(rename = "pool-wrong-chain")]
    WrongChain,
}

/// A pool that failed the probe, with the reason in words.
#[derive(Debug, Clone)]
pub struct PoolRefusal {
    pub code: RefusalCode,
    pub detail: String,
}

fn refuse(code: RefusalCode, detail: impl Into<String>) -> PoolRefusal {
    PoolRefusal {
        code,
        detail: detail.into(),
    }
}

/// What a pool's first job says about the chain it mines.
#[derive(Debug, Clone)]
pub struct PoolJob {
    /// `"sv1"` or `"sv2"`.
    pub protocol: &'static str,
    /// The height of the block the job builds (BIP34).
    pub height: u64,
    /// The block the job builds on.
    pub prev_hash: BlockHash,
}

/// Probe a rental's pools at once: the primary and, when given, the fallback,
/// each with the worker identity the rental would log in as there. Every pool
/// named must pass; a failure names the pool (`"primary"` or `"fallback"`).
pub async fn probe_pools(
    primary: &UpstreamTarget,
    primary_identity: &str,
    fallback: Option<(&UpstreamTarget, &str)>,
    chain: Option<&Electrum>,
) -> Result<(), (&'static str, PoolRefusal)> {
    let (p, f) = tokio::join!(probe_pool(primary, primary_identity, chain), async {
        match fallback {
            Some((t, identity)) => Some(probe_pool(t, identity, chain).await),
            None => None,
        }
    });
    p.map_err(|e| ("primary", e))?;
    if let Some(f) = f {
        f.map_err(|e| ("fallback", e))?;
    }
    Ok(())
}

/// Probe one pool. `identity` is the worker it is logged in as, the one the
/// rental would use.
pub async fn probe_pool(
    target: &UpstreamTarget,
    identity: &str,
    chain: Option<&Electrum>,
) -> Result<PoolJob, PoolRefusal> {
    let result: Result<PoolJob, PoolRefusal> = async {
        let job = first_job(target, identity, Instant::now() + POOL_TIMEOUT).await?;
        if let Some(chain) = chain {
            check_chain(&job, chain).await?;
        }
        Ok(job)
    }
    .await;
    match &result {
        Ok(job) => info!(
            url = %target.url,
            protocol = job.protocol,
            height = job.height,
            "pool probe passed"
        ),
        Err(r) => warn!(url = %target.url, code = ?r.code, detail = %r.detail, "pool probe failed"),
    }
    result
}

/// Connect like a rental does (SV2 first, an SV1 pool is reached when the
/// SV2 setup fails on an open connection), log in, return the first job.
async fn first_job(
    target: &UpstreamTarget,
    identity: &str,
    deadline: Instant,
) -> Result<PoolJob, PoolRefusal> {
    match probe_sv2(target).await {
        Ok((read, write)) => sv2_first_job(read, write, identity, deadline).await,
        Err(ProbeFailure::Unreachable(e)) => {
            Err(refuse(RefusalCode::Unreachable, format!("{e:#}")))
        }
        Err(ProbeFailure::NotSv2(_)) => sv1_first_job(target, identity, deadline).await,
    }
}

/// Time left until `deadline`, capped at `cap`.
fn left(deadline: Instant, cap: Duration) -> Duration {
    deadline.saturating_duration_since(Instant::now()).min(cap)
}

async fn sv1_first_job(
    target: &UpstreamTarget,
    identity: &str,
    deadline: Instant,
) -> Result<PoolJob, PoolRefusal> {
    let handshake = tokio::time::timeout(
        left(deadline, translate::UPSTREAM_PROBE_TIMEOUT),
        sv1::connect_pool(target, identity, None),
    )
    .await;
    let mut conn = match handshake {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            return Err(match e.downcast_ref::<LoginRefused>() {
                Some(r) => refuse(RefusalCode::AuthRefused, r.0.clone()),
                None => refuse(
                    RefusalCode::NotStratum,
                    format!("no Stratum V2 setup and no Stratum V1 handshake: {e:#}"),
                ),
            })
        }
        Err(_) => {
            return Err(refuse(
                RefusalCode::NotStratum,
                "no Stratum V2 setup and no Stratum V1 answer in time",
            ))
        }
    };
    if let Some(n) = conn
        .prelude
        .iter()
        .find_map(|l| translate::notify_from_line(l))
    {
        return job_from_notify(&n, "sv1");
    }
    let wait = async {
        let mut line = String::new();
        loop {
            line.clear();
            match conn.read.read_line(&mut line).await {
                Ok(0) => return Err("the pool closed the connection".to_string()),
                Err(e) => return Err(e.to_string()),
                Ok(_) => {}
            }
            if let Some(n) = translate::notify_from_line(&line) {
                return Ok(n);
            }
        }
    };
    match tokio::time::timeout(left(deadline, JOB_WAIT), wait).await {
        Ok(Ok(n)) => job_from_notify(&n, "sv1"),
        Ok(Err(e)) => Err(refuse(
            RefusalCode::NoJob,
            format!("login accepted, no job: {e}"),
        )),
        Err(_) => Err(refuse(RefusalCode::NoJob, "login accepted, no job in time")),
    }
}

async fn sv2_first_job(
    mut read: Read,
    mut write: Write,
    identity: &str,
    deadline: Instant,
) -> Result<PoolJob, PoolRefusal> {
    let mut frames = Vec::new();
    let spec = crate::proto::relay::translate_open_spec();
    let open = tokio::time::timeout(
        left(deadline, translate::UPSTREAM_PROBE_TIMEOUT),
        open_on(&mut read, &mut write, &spec, identity, &mut frames),
    )
    .await;
    match open {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(match e.downcast_ref::<LoginRefused>() {
                Some(r) => refuse(RefusalCode::AuthRefused, r.0.clone()),
                None => refuse(RefusalCode::NoJob, format!("channel open failed: {e:#}")),
            })
        }
        Err(_) => {
            return Err(refuse(
                RefusalCode::NoJob,
                "no answer to the channel open in time",
            ))
        }
    }
    let wait = async {
        let mut job: Option<mining::NewExtendedMiningJobOwned> = None;
        let mut prev: Option<mining::SetNewPrevHashOwned> = None;
        let mut pending = frames.into_iter();
        loop {
            let mut f = match pending.next() {
                Some(f) => f,
                None => match read.read_frame().await {
                    Ok(frame) => frame,
                    Err(e) => return Err(format!("{e:?}")),
                },
            };
            if let Some(j) = parse_new_extended_job(&mut f) {
                job = Some(j);
            } else if let Some(p) = parse_set_new_prev_hash(&mut f) {
                prev = Some(p);
            }
            if let (Some(j), Some(p)) = (&job, &prev) {
                return translate::sv2_job_to_sv1_notify(p.clone(), j.clone(), true)
                    .map_err(|e| e.to_string());
            }
        }
    };
    match tokio::time::timeout(left(deadline, JOB_WAIT), wait).await {
        Ok(Ok(n)) => job_from_notify(&n, "sv2"),
        Ok(Err(e)) => Err(refuse(
            RefusalCode::NoJob,
            format!("channel open accepted, no job: {e}"),
        )),
        Err(_) => Err(refuse(
            RefusalCode::NoJob,
            "channel open accepted, no job in time",
        )),
    }
}

fn job_from_notify(n: &Notify, protocol: &'static str) -> Result<PoolJob, PoolRefusal> {
    let height = bip34_height(n.coin_base1.as_ref()).ok_or_else(|| {
        refuse(
            RefusalCode::WrongChain,
            "the first job's coinbase carries no BIP34 block height",
        )
    })?;
    let prev: [u8; 32] = n.prev_hash.0.as_bytes().try_into().map_err(|_| {
        refuse(
            RefusalCode::WrongChain,
            "the first job's previous block hash is not 32 bytes",
        )
    })?;
    Ok(PoolJob {
        protocol,
        height,
        prev_hash: BlockHash::from_byte_array(prev),
    })
}

/// The block height a coinbase's scriptSig opens with (BIP34), from the part
/// of a non-witness coinbase serialization before the extranonce: version (4),
/// input count (1), the null prevout (36), scriptSig length (1, a coinbase
/// scriptSig is at most 100 bytes), then the height push.
fn bip34_height(coinbase1: &[u8]) -> Option<u64> {
    const SCRIPT_AT: usize = 4 + 1 + 36 + 1;
    if *coinbase1.get(4)? != 1 {
        return None;
    }
    let push = *coinbase1.get(SCRIPT_AT)?;
    match push {
        // OP_1..OP_16: heights 1 to 16.
        0x51..=0x60 => Some(u64::from(push - 0x50)),
        1..=8 => {
            let bytes = coinbase1.get(SCRIPT_AT + 1..SCRIPT_AT + 1 + push as usize)?;
            Some(
                bytes
                    .iter()
                    .rev()
                    .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
            )
        }
        _ => None,
    }
}

/// The job must build the block after the Electrum tip (within
/// [`HEIGHT_TOLERANCE`]) and, where the server has that block, on its hash.
/// An Electrum server that cannot be reached skips the check rather than
/// refusing every order.
async fn check_chain(job: &PoolJob, chain: &Electrum) -> Result<(), PoolRefusal> {
    let Some(prev_height) = job.height.checked_sub(1) else {
        return Err(refuse(
            RefusalCode::WrongChain,
            "the first job builds the genesis block",
        ));
    };
    let (tip, hash) = match chain.lookup(prev_height).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "chain check skipped: electrum unavailable");
            return Ok(());
        }
    };
    if job.height.abs_diff(tip + 1) > HEIGHT_TOLERANCE {
        return Err(refuse(
            RefusalCode::WrongChain,
            format!(
                "the pool's job builds block {}, the Bitcoin tip is {tip}",
                job.height
            ),
        ));
    }
    match hash {
        Some(hash) if hash != job.prev_hash => Err(refuse(
            RefusalCode::WrongChain,
            format!(
                "the pool's job builds on {}, Bitcoin block {prev_height} is {hash}",
                job.prev_hash
            ),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::tests::{mock_electrum, BLOCK1_HEADER};
    use crate::proto::sv2::keys::NoiseKeys;
    use serde_json::{json, Value};
    use stratum_core::bitcoin::block::Header;
    use stratum_core::bitcoin::consensus::encode::deserialize_hex;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// How the mock SV1 pool behaves after `mining.authorize`.
    #[derive(Clone)]
    pub(crate) enum Sv1Pool {
        /// Accept the login and send a job building block `height` on `prev`.
        Job { height: u32, prev: [u8; 32] },
        /// Refuse the login.
        Refuse,
        /// Accept the login and never send a job.
        Silent,
    }

    /// The SV1 `prevhash` field: the internal byte order with every 4-byte
    /// word reversed.
    fn sv1_prevhash(internal: [u8; 32]) -> String {
        internal
            .chunks(4)
            .flat_map(|w| w.iter().rev())
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A mock SV1 pool that answers every connection; the SV2 probe's Noise
    /// bytes are not JSON and get the connection closed, as a real SV1 pool
    /// would.
    async fn mock_sv1_pool(listener: TcpListener, mode: Sv1Pool) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let mode = mode.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(req) = serde_json::from_str::<Value>(&line) else {
                        return;
                    };
                    let id = req["id"].clone();
                    let out = match req["method"].as_str() {
                        Some("mining.subscribe") => {
                            json!({"id": id, "result": [[], "deadbeef", 4], "error": null})
                                .to_string()
                        }
                        Some("mining.authorize") => match &mode {
                            Sv1Pool::Refuse => json!({"id": id, "result": false, "error": [24, "Unauthorized worker", null]}).to_string(),
                            Sv1Pool::Silent => json!({"id": id, "result": true, "error": null}).to_string(),
                            Sv1Pool::Job { height, prev } => {
                                let h = height.to_le_bytes();
                                let coinb1 = format!(
                                    "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2003{:02x}{:02x}{:02x}",
                                    h[0], h[1], h[2]
                                );
                                let notify = json!({"id": null, "method": "mining.notify", "params": [
                                    "1", sv1_prevhash(*prev), coinb1, "ffffffff0100000000", [],
                                    "20000000", "1702f4d5", "65000000", true
                                ]});
                                format!(
                                    "{}\n{}",
                                    json!({"id": id, "result": true, "error": null}),
                                    notify
                                )
                            }
                        },
                        _ => continue,
                    };
                    if w.write_all(format!("{out}\n").as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    fn target(addr: std::net::SocketAddr) -> UpstreamTarget {
        UpstreamTarget {
            url: addr.to_string(),
            user: "bc1qBUYER".into(),
            password: "x".into(),
            authority_pubkey: None,
        }
    }

    pub(crate) async fn sv1_pool(mode: Sv1Pool) -> UpstreamTarget {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(mock_sv1_pool(listener, mode));
        target(addr)
    }

    /// An Electrum mock whose tip is block 1 (its header is the only one it
    /// serves), so a Bitcoin job builds block 2 on block 1's hash.
    async fn electrum_at_block1() -> Electrum {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(mock_electrum(listener, 1));
        Electrum::new(&format!("tcp://{addr}"), None).unwrap()
    }

    fn block1_hash() -> [u8; 32] {
        let header: Header = deserialize_hex(BLOCK1_HEADER).unwrap();
        header.block_hash().to_byte_array()
    }

    #[tokio::test]
    async fn an_sv1_pool_on_the_bitcoin_tip_passes() {
        let pool = sv1_pool(Sv1Pool::Job {
            height: 2,
            prev: block1_hash(),
        })
        .await;
        let chain = electrum_at_block1().await;
        let job = probe_pool(&pool, "bc1qBUYER.rig-bp-proxy", Some(&chain))
            .await
            .unwrap();
        assert_eq!(job.protocol, "sv1");
        assert_eq!(job.height, 2);
        assert_eq!(job.prev_hash.to_byte_array(), block1_hash());
    }

    #[tokio::test]
    async fn a_pool_far_from_the_tip_is_on_the_wrong_chain() {
        let pool = sv1_pool(Sv1Pool::Job {
            height: 2_430_000,
            prev: block1_hash(),
        })
        .await;
        let chain = electrum_at_block1().await;
        let r = probe_pool(&pool, "w", Some(&chain)).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::WrongChain);
        assert!(r.detail.contains("2430000"), "{}", r.detail);
    }

    #[tokio::test]
    async fn a_pool_at_the_tip_height_on_another_block_is_on_the_wrong_chain() {
        let pool = sv1_pool(Sv1Pool::Job {
            height: 2,
            prev: [0x11; 32],
        })
        .await;
        let chain = electrum_at_block1().await;
        let r = probe_pool(&pool, "w", Some(&chain)).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::WrongChain);
        assert!(r.detail.contains("Bitcoin block 1 is"), "{}", r.detail);
    }

    #[tokio::test]
    async fn a_refused_login_carries_the_pools_reason() {
        let pool = sv1_pool(Sv1Pool::Refuse).await;
        let r = probe_pool(&pool, "w", None).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::AuthRefused);
        assert!(r.detail.contains("Unauthorized worker"), "{}", r.detail);
    }

    #[tokio::test]
    async fn a_pool_that_sends_no_job_is_refused() {
        let pool = sv1_pool(Sv1Pool::Silent).await;
        let r = probe_pool(&pool, "w", None).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::NoJob);
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let r = probe_pool(&target(addr), "w", None).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::Unreachable);
    }

    #[tokio::test]
    async fn a_listener_that_speaks_no_stratum_is_refused_as_such() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });
        let r = probe_pool(&target(addr), "w", None).await.unwrap_err();
        assert_eq!(r.code, RefusalCode::NotStratum);
    }

    #[tokio::test]
    async fn an_sv2_pools_first_job_is_read() {
        // The relay tests' SV2 pool: scriptSig opens with 03 33 33 33 and the
        // job builds on 0x11…11.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        tokio::spawn(crate::proto::relay::sv2_translate_tests::mock_sv2_pool(
            listener,
            NoiseKeys::generate(),
            vec![0xCC; 4],
            50,
            tx,
        ));
        let job = probe_pool(&target(addr), "w", None).await.unwrap();
        assert_eq!(job.protocol, "sv2");
        assert_eq!(job.height, 0x33_3333);
        assert_eq!(job.prev_hash.to_byte_array(), [0x11; 32]);
    }

    #[test]
    fn refusal_codes_serialize_as_the_api_strings() {
        for (code, s) in [
            (RefusalCode::Unreachable, "pool-unreachable"),
            (RefusalCode::NotStratum, "pool-not-stratum"),
            (RefusalCode::AuthRefused, "pool-auth-refused"),
            (RefusalCode::NoJob, "pool-no-job"),
            (RefusalCode::WrongChain, "pool-wrong-chain"),
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), s);
        }
    }

    #[tokio::test]
    async fn a_failing_fallback_refuses_the_rental_and_is_named() {
        let primary = sv1_pool(Sv1Pool::Job {
            height: 2,
            prev: block1_hash(),
        })
        .await;
        let fallback = sv1_pool(Sv1Pool::Refuse).await;
        let (pool, r) = probe_pools(&primary, "w", Some((&fallback, "w")), None)
            .await
            .unwrap_err();
        assert_eq!(pool, "fallback");
        assert_eq!(r.code, RefusalCode::AuthRefused);
    }

    /// coinbase1 of a non-witness coinbase whose scriptSig opens with `script`.
    fn coinbase1(script: &[u8]) -> Vec<u8> {
        let mut v = vec![2, 0, 0, 0, 1];
        v.extend([0u8; 32]);
        v.extend([0xff; 4]);
        v.push(40);
        v.extend(script);
        v
    }

    #[test]
    fn bip34_height_reads_the_height_push() {
        // 962_000 = 0x0eadd0, pushed as 3 little-endian bytes.
        assert_eq!(
            bip34_height(&coinbase1(&[3, 0xd0, 0xad, 0x0e, 0xaa])),
            Some(962_000)
        );
        // potpool's ~24.3 M fits 4 bytes: 24_300_000 = 0x0172c9e0.
        assert_eq!(
            bip34_height(&coinbase1(&[4, 0xe0, 0xc9, 0x72, 0x01])),
            Some(24_300_000)
        );
        assert_eq!(bip34_height(&coinbase1(&[0x55])), Some(5));
        assert_eq!(bip34_height(&coinbase1(&[3, 0xd0])), None, "cut short");
        assert_eq!(bip34_height(&coinbase1(&[0x6a])), None, "no height push");
        let mut two_inputs = coinbase1(&[3, 1, 2, 3]);
        two_inputs[4] = 2;
        assert_eq!(bip34_height(&two_inputs), None);
    }
}
