// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Bitcoin chain as an Electrum server reports it: the tip height and the
//! header at a height. The pool probe ([`crate::probe`]) checks a buyer pool's
//! first job against it, so a rental never starts on a pool that mines some
//! other chain.
//!
//!   RENTAL_PROXY_ELECTRUM              tcp://host:port or ssl://host:port
//!   RENTAL_PROXY_ELECTRUM_CERT_SHA256  ssl only, optional: SHA-256 of the
//!                                      server certificate (hex, colons
//!                                      allowed). Set, it is the only
//!                                      certificate accepted, which is how a
//!                                      self-signed server is used; unset, the
//!                                      certificate must chain to a public CA.
//!
//! Electrum speaks newline-delimited JSON-RPC, like Stratum V1.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use stratum_core::bitcoin::block::Header;
use stratum_core::bitcoin::consensus::encode::deserialize_hex;
use stratum_core::bitcoin::hashes::{sha256, Hash};
use stratum_core::bitcoin::BlockHash;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

/// Upper bound for one chain lookup (connect, handshake and both calls).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// How the proxy reaches the Electrum server.
enum Transport {
    Tcp,
    Tls(TlsConnector),
}

/// A configured Electrum server.
pub struct Electrum {
    host: String,
    port: u16,
    transport: Transport,
}

impl Electrum {
    /// The server from the environment; `Ok(None)` when none is configured.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(url) = std::env::var("RENTAL_PROXY_ELECTRUM") else {
            return Ok(None);
        };
        let pin = std::env::var("RENTAL_PROXY_ELECTRUM_CERT_SHA256").ok();
        Self::new(&url, pin.as_deref()).map(Some)
    }

    /// `url` is `tcp://host:port` or `ssl://host:port`; `cert_sha256` pins the
    /// certificate of an ssl server.
    pub fn new(url: &str, cert_sha256: Option<&str>) -> anyhow::Result<Self> {
        let (scheme, addr) = url
            .split_once("://")
            .ok_or_else(|| anyhow!("electrum url {url:?} needs tcp:// or ssl://"))?;
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("electrum url {url:?} needs host:port"))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("electrum url {url:?}: bad port"))?;
        let transport = match (scheme, cert_sha256) {
            ("tcp", None) => Transport::Tcp,
            ("tcp", Some(_)) => bail!("a certificate pin needs an ssl:// electrum url"),
            ("ssl", pin) => Transport::Tls(tls_connector(pin)?),
            _ => bail!("electrum url {url:?} needs tcp:// or ssl://"),
        };
        Ok(Self {
            host: host.to_string(),
            port,
            transport,
        })
    }

    /// `host:port` and the transport, for the startup log.
    pub fn describe(&self) -> String {
        let scheme = match self.transport {
            Transport::Tcp => "tcp",
            Transport::Tls(_) => "ssl",
        };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    /// The tip height, and the hash of the block at `height` when the server
    /// has it (`height` ≤ tip).
    pub async fn lookup(&self, height: u64) -> anyhow::Result<(u64, Option<BlockHash>)> {
        tokio::time::timeout(LOOKUP_TIMEOUT, self.lookup_inner(height))
            .await
            .map_err(|_| anyhow!("electrum {} did not answer in time", self.describe()))?
    }

    async fn lookup_inner(&self, height: u64) -> anyhow::Result<(u64, Option<BlockHash>)> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("connect electrum {}", self.describe()))?;
        let _ = tcp.set_nodelay(true);
        match &self.transport {
            Transport::Tcp => query(tcp, height).await,
            Transport::Tls(connector) => {
                let name = ServerName::try_from(self.host.clone())
                    .with_context(|| format!("electrum host {:?}", self.host))?;
                let tls = connector
                    .connect(name, tcp)
                    .await
                    .with_context(|| format!("tls to electrum {}", self.describe()))?;
                query(tls, height).await
            }
        }
    }
}

/// `server.version` (some servers drop a client that does not open with it),
/// then the tip and, when it exists, the header at `height`.
async fn query<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    height: u64,
) -> anyhow::Result<(u64, Option<BlockHash>)> {
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    let mut results = Vec::new();
    for (id, method, params) in [
        (0, "server.version", json!(["stratum-rental-proxy", "1.4"])),
        (1, "blockchain.headers.subscribe", json!([])),
    ] {
        w.write_all(request_line(id, method, params).as_bytes())
            .await?;
        results.push(read_result(&mut lines, id).await?);
    }
    let tip = results[1]
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("electrum headers.subscribe without a height"))?;
    if height > tip {
        return Ok((tip, None));
    }
    w.write_all(request_line(2, "blockchain.block.header", json!([height])).as_bytes())
        .await?;
    let hex = read_result(&mut lines, 2).await?;
    let hex = hex
        .as_str()
        .ok_or_else(|| anyhow!("electrum block.header is not a hex string"))?;
    let header: Header = deserialize_hex(hex).context("electrum block.header")?;
    Ok((tip, Some(header.block_hash())))
}

fn request_line(id: u64, method: &str, params: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    )
}

/// Read lines until the response to `id`; notifications in between are
/// skipped.
async fn read_result<R: AsyncBufReadExt + Unpin>(
    lines: &mut tokio::io::Lines<R>,
    id: u64,
) -> anyhow::Result<Value> {
    loop {
        let line = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("electrum closed the connection"))?;
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if msg.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(err) = msg.get("error").filter(|e| !e.is_null()) {
            bail!("electrum error: {err}");
        }
        return msg
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("electrum response without a result"));
    }
}

fn tls_connector(cert_sha256: Option<&str>) -> anyhow::Result<TlsConnector> {
    let provider = Arc::new(ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("tls protocol versions")?;
    let config = match cert_sha256 {
        None => {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert {
                sha256: parse_pin(pin)?,
                provider,
            }))
            .with_no_client_auth(),
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// `AB:CD:…` or `abcd…` → 32 bytes.
fn parse_pin(pin: &str) -> anyhow::Result<[u8; 32]> {
    let hex: String = pin.chars().filter(|c| *c != ':').collect();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow!("RENTAL_PROXY_ELECTRUM_CERT_SHA256 is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("RENTAL_PROXY_ELECTRUM_CERT_SHA256 is not 32 bytes"))
}

/// Accepts exactly one server certificate, by its SHA-256; the handshake
/// signatures are still verified against it.
#[derive(Debug)]
struct PinnedCert {
    sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256::Hash::hash(end_entity.as_ref()).to_byte_array() == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "electrum certificate does not match RENTAL_PROXY_ELECTRUM_CERT_SHA256".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn urls_and_pins_are_parsed_or_refused() {
        assert!(matches!(
            Electrum::new("tcp://127.0.0.1:50001", None)
                .unwrap()
                .transport,
            Transport::Tcp
        ));
        assert!(matches!(
            Electrum::new("ssl://electrum.example:50002", None)
                .unwrap()
                .transport,
            Transport::Tls(_)
        ));
        let pin = "AB:".repeat(31) + "AB";
        assert!(Electrum::new("ssl://electrum.example:50002", Some(&pin)).is_ok());
        assert!(Electrum::new("tcp://h:50001", Some(&pin)).is_err());
        assert!(Electrum::new("ssl://h:50002", Some("abcd")).is_err());
        assert!(Electrum::new("h:50001", None).is_err());
        assert!(Electrum::new("http://h:50001", None).is_err());
    }

    /// Block 1's header; its hash is the well-known
    /// 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048.
    pub(crate) const BLOCK1_HEADER: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";

    /// A mock Electrum server: answers `server.version`, a tip of `tip`, and
    /// block 1's header for any height. Serves one connection.
    pub(crate) async fn mock_electrum(listener: TcpListener, tip: u64) {
        let (sock, _) = listener.accept().await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let req: Value = serde_json::from_str(&line).unwrap();
            let result = match req["method"].as_str().unwrap() {
                "server.version" => json!(["mock", "1.4"]),
                "blockchain.headers.subscribe" => json!({"height": tip, "hex": ""}),
                "blockchain.block.header" => json!(BLOCK1_HEADER),
                m => panic!("unexpected {m}"),
            };
            // A notification first, as a subscribed server may interleave one.
            let note = json!({"jsonrpc": "2.0", "method": "blockchain.headers.subscribe", "params": [{"height": tip}]});
            let resp = json!({"jsonrpc": "2.0", "id": req["id"], "result": result});
            w.write_all(format!("{note}\n{resp}\n").as_bytes())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn lookup_reads_the_tip_and_hashes_the_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(mock_electrum(listener, 900_000));
        let e = Electrum::new(&format!("tcp://{addr}"), None).unwrap();
        let (tip, hash) = e.lookup(1).await.unwrap();
        assert_eq!(tip, 900_000);
        assert_eq!(
            hash.unwrap().to_string(),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
    }

    #[tokio::test]
    async fn a_height_above_the_tip_returns_no_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(mock_electrum(listener, 10));
        let e = Electrum::new(&format!("tcp://{addr}"), None).unwrap();
        assert_eq!(e.lookup(11).await.unwrap(), (10, None));
    }
}
