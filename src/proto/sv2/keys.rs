//! The proxy's SV2 Noise authority keypair.
//!
//! The proxy is the Noise responder to the miner, so it needs a static
//! authority keypair. It is read from `RENTAL_PROXY_SV2_SECRET` (the base58
//! secret-key encoding used across the SV2 ecosystem) or generated at boot. The
//! public key is what a miner would pin to authenticate the proxy; miners that
//! connect without pinning (`None` authority) work regardless.

use secp256k1::{Secp256k1, SecretKey};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

/// The proxy's Noise authority keypair (responder side).
#[derive(Clone)]
pub struct NoiseKeys {
    secret: SecretKey,
}

impl NoiseKeys {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret, _public) = secp.generate_keypair(&mut rand::thread_rng());
        Self { secret }
    }

    /// Parse from the base58 secret-key string used by the SV2 tooling.
    pub fn from_secret_str(s: &str) -> anyhow::Result<Self> {
        let parsed: Secp256k1SecretKey = s
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid SV2 secret key (expected base58)"))?;
        Ok(Self {
            secret: parsed.into_inner(),
        })
    }

    /// Resolve the proxy's Noise authority key, in order of preference:
    /// 1. `RENTAL_PROXY_SV2_SECRET` — an explicit base58 secret.
    /// 2. `RENTAL_PROXY_SV2_SECRET_FILE` — a file holding the secret; created
    ///    (0600) with a fresh key on first boot, then reused. This gives the
    ///    proxy a **stable identity across restarts** so SV2 miners can pin it.
    /// 3. Otherwise a fresh ephemeral key (changes every restart).
    pub fn from_env_or_generate() -> Self {
        if let Ok(s) = std::env::var("RENTAL_PROXY_SV2_SECRET") {
            match Self::from_secret_str(&s) {
                Ok(k) => return k,
                Err(e) => tracing::warn!(error = %e, "RENTAL_PROXY_SV2_SECRET invalid; trying file/ephemeral"),
            }
        }
        if let Ok(path) = std::env::var("RENTAL_PROXY_SV2_SECRET_FILE") {
            if !path.trim().is_empty() {
                return Self::from_file_or_create(path.trim());
            }
        }
        let k = Self::generate();
        tracing::warn!(
            public_key = %k.public_b58(),
            "generated EPHEMERAL SV2 Noise authority key — it changes on restart; \
             set RENTAL_PROXY_SV2_SECRET_FILE to persist it"
        );
        k
    }

    /// Load the secret from `path`, or generate one and persist it (0600).
    fn from_file_or_create(path: &str) -> Self {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let s = contents.trim();
            if !s.is_empty() {
                match Self::from_secret_str(s) {
                    Ok(k) => {
                        tracing::info!(public_key = %k.public_b58(), path, "loaded persisted SV2 Noise authority key");
                        return k;
                    }
                    Err(e) => tracing::warn!(error = %e, path, "persisted SV2 secret invalid; regenerating"),
                }
            }
        }
        let k = Self::generate();
        let secret: String = k.secret().into();
        match std::fs::write(path, format!("{secret}\n")) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
                tracing::info!(public_key = %k.public_b58(), path, "generated + persisted SV2 Noise authority key");
            }
            Err(e) => tracing::warn!(error = %e, path, "could not persist SV2 secret; key is ephemeral this run"),
        }
        k
    }

    /// The key_utils secret wrapper (consumed by `accept_noise_connection`).
    pub fn secret(&self) -> Secp256k1SecretKey {
        Secp256k1SecretKey(self.secret)
    }

    /// The key_utils public wrapper (consumed by `accept_noise_connection`).
    pub fn public(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::from(Secp256k1SecretKey(self.secret))
    }

    /// Base58 encoding of the public key (for logging / pinning).
    pub fn public_b58(&self) -> String {
        self.public().into()
    }
}

/// Parse a pool's Noise authority public key (base58) for upstream
/// authentication. `None`/empty → unauthenticated (encrypted only).
pub fn parse_authority(pubkey: &Option<String>) -> anyhow::Result<Option<Secp256k1PublicKey>> {
    match pubkey.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            let key: Secp256k1PublicKey = s
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid pool authority public key (base58)"))?;
            Ok(Some(key))
        }
        None => Ok(None),
    }
}

trait IntoInnerSecret {
    fn into_inner(self) -> SecretKey;
}
impl IntoInnerSecret for Secp256k1SecretKey {
    fn into_inner(self) -> SecretKey {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_public_is_stable() {
        let k = NoiseKeys::generate();
        // public derivation is deterministic from the secret
        assert_eq!(k.public_b58(), k.public_b58());
        assert!(!k.public_b58().is_empty());
    }

    #[test]
    fn secret_str_roundtrips() {
        let k = NoiseKeys::generate();
        let s: String = k.secret().into();
        let reparsed = NoiseKeys::from_secret_str(&s).expect("reparse");
        assert_eq!(k.public_b58(), reparsed.public_b58());
    }

    #[test]
    fn file_persist_is_stable_across_calls() {
        let path = std::env::temp_dir().join(format!("srp_sv2_key_{}.b58", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);
        // First call generates + writes; second call must reload the same key.
        let first = NoiseKeys::from_file_or_create(p).public_b58();
        let second = NoiseKeys::from_file_or_create(p).public_b58();
        assert_eq!(first, second, "persisted key must be stable across restarts");
        let _ = std::fs::remove_file(&path);
    }
}
