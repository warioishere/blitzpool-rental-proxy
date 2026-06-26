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

    /// Read `RENTAL_PROXY_SV2_SECRET` or generate one (logging the public key).
    pub fn from_env_or_generate() -> Self {
        match std::env::var("RENTAL_PROXY_SV2_SECRET") {
            Ok(s) => match Self::from_secret_str(&s) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(error = %e, "RENTAL_PROXY_SV2_SECRET invalid; generating an ephemeral key");
                    Self::generate()
                }
            },
            Err(_) => {
                let k = Self::generate();
                tracing::info!(public_key = %k.public_b58(), "generated ephemeral SV2 Noise authority key");
                k
            }
        }
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
}
