//! First-byte protocol detection for the shared (`both`) listen port.
//!
//! When the proxy serves SV1 and SV2 on one port, each accepted connection is
//! classified by its first byte before any adapter touches it: SV1 speaks
//! JSON (`{` or leading whitespace), SV2 opens with a binary Noise handshake.
//! The byte is *peeked* (not consumed), so the chosen adapter reads the full
//! stream normally.

use crate::config::Protocol;

/// Classify a downstream connection from its first byte.
///
/// SV1 JSON-RPC starts with `{`; some lenient miners lead with whitespace, so
/// those count as SV1 too. Everything else (the Noise handshake's ephemeral
/// key bytes, or anything unexpected like a TLS `0x16` ClientHello) is treated
/// as SV2 — the SV2 adapter's handshake rejects genuine garbage and closes.
pub fn detect(first_byte: u8) -> Protocol {
    match first_byte {
        b'{' | b' ' | b'\n' | b'\r' => Protocol::Sv1,
        _ => Protocol::Sv2,
    }
}

/// Upstream (buyer pool) protocol detection.
///
/// The proxy is a fixed-protocol server to the seller's miner, but a buyer pool
/// may speak either Stratum version. Detection happens on the upstream-connect
/// path: probe the `prefer`red protocol first (the seller-miner's own protocol,
/// so the common same-protocol case wins on the first try), then the other.
///
/// - **SV2** is confirmed by completing the Noise handshake — only an SV2 pool
///   speaks it (probe with no authority pin; the real connect verifies the key).
/// - **SV1** is confirmed by a `mining.subscribe` drawing a JSON-RPC reply.
///
/// Each probe is bounded by a timeout so a wrong-protocol pool (which stays
/// silent) fails fast instead of hanging. Results are cached per URL — a pool's
/// protocol is stable, so a long-lived proxy detects each pool once.
#[cfg(feature = "sv2")]
mod upstream {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    use stratum_apps::network_helpers::connect_with_noise;

    use crate::config::Protocol;
    use crate::proto::sv2::wire::Msg;
    use crate::session::UpstreamTarget;

    /// Per-probe ceiling. A pool of the other protocol stays silent, so the probe
    /// must time out rather than block; 4s clears any plausible WAN handshake RTT.
    const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
    /// How long a detected protocol is trusted before re-probing.
    const CACHE_TTL: Duration = Duration::from_secs(600);

    fn cache() -> &'static Mutex<HashMap<String, (Protocol, Instant)>> {
        static C: OnceLock<Mutex<HashMap<String, (Protocol, Instant)>>> = OnceLock::new();
        C.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Forget a cached protocol (call when a connect with the cached protocol
    /// fails, so the next attempt re-detects).
    pub fn forget(url: &str) {
        cache().lock().unwrap().remove(url);
    }

    /// Detect `target`'s protocol, using the per-URL cache. `prefer` is tried
    /// first on a cache miss.
    pub async fn protocol(target: &UpstreamTarget, prefer: Protocol) -> anyhow::Result<Protocol> {
        if let Some((p, at)) = cache().lock().unwrap().get(&target.url).copied() {
            if at.elapsed() < CACHE_TTL {
                return Ok(p);
            }
        }
        let detected = detect(target, prefer, PROBE_TIMEOUT).await?;
        cache().lock().unwrap().insert(target.url.clone(), (detected, Instant::now()));
        Ok(detected)
    }

    /// Probe `target` (uncached). Tries `prefer` first, then the other protocol.
    pub async fn detect(
        target: &UpstreamTarget,
        prefer: Protocol,
        timeout: Duration,
    ) -> anyhow::Result<Protocol> {
        let order = match prefer {
            Protocol::Sv2 => [Protocol::Sv2, Protocol::Sv1],
            _ => [Protocol::Sv1, Protocol::Sv2],
        };
        for p in order {
            match p {
                Protocol::Sv2 if probe_sv2(target, timeout).await => return Ok(Protocol::Sv2),
                Protocol::Sv1 if probe_sv1(target, timeout).await => return Ok(Protocol::Sv1),
                _ => {}
            }
        }
        anyhow::bail!(
            "could not detect upstream protocol for {} (tried SV1 and SV2)",
            target.url
        )
    }

    /// True if the pool completes an SV2 Noise handshake.
    async fn probe_sv2(target: &UpstreamTarget, timeout: Duration) -> bool {
        let fut = async {
            let tcp = TcpStream::connect(&target.url).await.ok()?;
            let _ = tcp.set_nodelay(true);
            // Encrypted-only handshake (no authority pin); success ⟹ SV2.
            connect_with_noise::<Msg>(tcp, None).await.ok()?;
            Some(())
        };
        matches!(tokio::time::timeout(timeout, fut).await, Ok(Some(())))
    }

    /// True if a `mining.subscribe` draws a JSON-RPC reply (⟹ SV1).
    async fn probe_sv1(target: &UpstreamTarget, timeout: Duration) -> bool {
        let fut = async {
            let tcp = TcpStream::connect(&target.url).await.ok()?;
            let _ = tcp.set_nodelay(true);
            let (r, mut w) = tcp.into_split();
            w.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"rental-proxy-detect\"]}\n")
                .await
                .ok()?;
            let mut reader = BufReader::new(r);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await.ok()? == 0 {
                    return None; // closed without a reply
                }
                let t = line.trim();
                if t.is_empty() {
                    continue;
                }
                // Any parseable JSON object reply means we're talking to SV1.
                return serde_json::from_str::<serde_json::Value>(t).ok().map(|_| ());
            }
        };
        matches!(tokio::time::timeout(timeout, fut).await, Ok(Some(())))
    }
}

#[cfg(feature = "sv2")]
pub use upstream::{detect as detect_upstream, forget as forget_upstream_protocol, protocol as upstream_protocol};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_opener_and_whitespace_are_sv1() {
        for b in [b'{', b' ', b'\n', b'\r'] {
            assert_eq!(detect(b), Protocol::Sv1, "byte 0x{b:02x}");
        }
    }

    #[test]
    fn noise_handshake_bytes_are_sv2() {
        // The Noise first message starts with a curve point — sample some
        // plausible leading bytes that JSON/whitespace don't claim.
        for b in [0x00, 0x01, 0x16, 0x42, 0x80, 0xab, 0xff] {
            assert_eq!(detect(b), Protocol::Sv2, "byte 0x{b:02x}");
        }
    }
}

#[cfg(all(test, feature = "sv2"))]
mod upstream_tests {
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use stratum_apps::network_helpers::accept_noise_connection;

    use super::detect_upstream;
    use crate::config::Protocol;
    use crate::proto::sv2::keys::NoiseKeys;
    use crate::proto::sv2::wire::Msg;
    use crate::session::UpstreamTarget;

    /// A minimal SV1 pool: replies to `mining.subscribe` with a JSON result.
    async fn mock_sv1(listener: TcpListener) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                if let Ok(Some(_)) = lines.next_line().await {
                    let _ = w
                        .write_all(b"{\"id\":1,\"result\":[[[\"mining.notify\",\"1\"]],\"abcd\",4],\"error\":null}\n")
                        .await;
                }
            });
        }
    }

    /// A minimal SV2 pool: completes the Noise handshake, then idles briefly.
    async fn mock_sv2(listener: TcpListener, keys: NoiseKeys) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                if accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), 3600)
                    .await
                    .is_ok()
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
        }
    }

    fn target(url: String) -> UpstreamTarget {
        UpstreamTarget { url, ..Default::default() }
    }

    const T: Duration = Duration::from_millis(800);

    #[tokio::test]
    async fn detects_sv1_pool() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(mock_sv1(l));
        let t = target(addr.to_string());
        // Native-first (prefer SV1) and other-first (prefer SV2) both land on SV1.
        assert_eq!(detect_upstream(&t, Protocol::Sv1, T).await.unwrap(), Protocol::Sv1);
        assert_eq!(detect_upstream(&t, Protocol::Sv2, T).await.unwrap(), Protocol::Sv1);
    }

    #[tokio::test]
    async fn detects_sv2_pool() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(mock_sv2(l, NoiseKeys::generate()));
        let t = target(addr.to_string());
        assert_eq!(detect_upstream(&t, Protocol::Sv2, T).await.unwrap(), Protocol::Sv2);
        assert_eq!(detect_upstream(&t, Protocol::Sv1, T).await.unwrap(), Protocol::Sv2);
    }

    #[tokio::test]
    async fn unreachable_pool_errors() {
        // Bind then drop to free the port → nothing listening.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let t = target(addr.to_string());
        assert!(detect_upstream(&t, Protocol::Sv1, Duration::from_millis(300)).await.is_err());
    }
}
