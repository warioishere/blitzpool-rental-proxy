//! Stratum V2 downstream adapter.
//!
//! # Status
//!
//! Implemented and tested behind the `sv2` feature. [`Sv2Adapter`] plugs into
//! the [`DownstreamAdapter`] seam; the full relay ([`relay`]) is a Noise full
//! proxy with a swappable upstream — handshake on both sides, channel open
//! (Standard or Extended, mirrored upstream), bidirectional forwarding with
//! `channel_id` remapping, and a live rental switch via `SetExtranoncePrefix` +
//! `SetTarget` (the miner never reconnects). Supports **multiple mining
//! channels per connection** (each mapped independently; the switch re-opens
//! and re-points them all). Upstream pools can be **authenticated** via their
//! Noise authority public key (`UpstreamTarget::authority_pubkey`); when unset
//! the link is encrypted but unauthenticated. Proven end-to-end over loopback
//! Noise sockets against mock pools (see `relay::tests`), plus the lower-level
//! [`foundation`] (handshake + frame round-trips) and [`wire`] plumbing.
//! Without the feature the adapter is a stub that refuses loudly (never
//! silently accepts then drops a miner).
//!
//! # Dependencies
//!
//! The SV2 stack comes from the upstream stratum-mining git repo via
//! `stratum-core` (NOT crates.io). The crates.io releases at current majors do
//! not compile together in a fresh tree (`mining_sv2` 4.0's derives reference
//! `super::binary_sv2`, which the resolved `derive_codec_sv2`/`binary_sv2` pair
//! doesn't provide — `E0432/E0433: could not find binary_sv2 in super`). The
//! git workspace is internally consistent, which is why it builds; it is
//! pinned to an exact rev in `Cargo.toml` and gated behind `--features sv2` so
//! the default SV1 build stays lean.
//!
//! # Relay design
//!
//! The SV1 relay switches upstreams live with one `mining.set_extranonce`
//! because the proxy owns the miner-facing handshake + extranonce. SV2 is
//! heavier; the four pieces the relay handles:
//!
//! 1. **Encryption.** Every SV2 link is a Noise `NX` handshake (`codec_sv2` +
//!    `noise_sv2`): initiator `step_0` → responder `step_1` → initiator
//!    `step_2`, yielding a `NoiseCodec` per direction. The proxy is the
//!    responder to the miner and the initiator to each upstream — a fresh
//!    handshake per upstream on every switch.
//! 2. **Binary framing.** Messages are length-prefixed SV2 frames
//!    (`Sv2Frame::from_message(msg, msg_type, ext_type, channel_bit)` →
//!    `Encoder`; `StandardDecoder::next_frame` to read), carrying typed
//!    payloads (`mining_sv2`, `common_messages_sv2`), not JSON lines.
//! 3. **Channel model.** A miner opens a Standard or Extended channel
//!    (`OpenStandardMiningChannel` / `OpenExtendedMiningChannel`) bound to an
//!    `extranonce_prefix` + `channel_id` assigned by the *upstream*. Jobs
//!    arrive as `NewMiningJob`/`NewExtendedMiningJob` + `SetNewPrevHash`;
//!    shares go up as `SubmitSharesStandard`/`SubmitSharesExtended`.
//! 4. **Live switch.** Re-routing opens a new channel on the buyer's upstream
//!    and re-points the miner with `SetExtranoncePrefix` + `SetTarget` — the
//!    downstream `channel_id` is stable, so the miner does not re-open. The
//!    proxy mirrors whatever channel type the miner opened (Standard or
//!    Extended) onto each upstream, so jobs/shares map 1:1 with only the
//!    `channel_id` rewritten; no Standard↔Extended translation is needed.

/// Frame plumbing: build/parse/forward SV2 frames with channel-id rewriting.
#[cfg(feature = "sv2")]
pub mod wire;

/// The proxy's SV2 Noise authority keypair.
#[cfg(feature = "sv2")]
pub mod keys;

/// The SV2 downstream relay (full proxy with a swappable upstream).
#[cfg(feature = "sv2")]
pub mod relay;

/// With the `sv2` feature, the real relay adapter.
#[cfg(feature = "sv2")]
pub use relay::Sv2Adapter;

/// Without the `sv2` feature, a stub adapter that refuses loudly (never silently
/// accepts then drops a miner) — the SV2 stack is opt-in to keep the default
/// build lean.
#[cfg(not(feature = "sv2"))]
mod stub {
    use super::super::adapter::{DownstreamAdapter, ProxyContext};
    use tokio::net::TcpStream;

    #[derive(Clone, Copy, Default)]
    pub struct Sv2Adapter;

    impl DownstreamAdapter for Sv2Adapter {
        fn protocol(&self) -> &'static str {
            "sv2"
        }

        async fn serve(
            &self,
            _miner: TcpStream,
            peer: String,
            _ctx: ProxyContext,
        ) -> anyhow::Result<()> {
            anyhow::bail!(
                "SV2 selected but this binary was built without the `sv2` feature \
                 (peer {peer}); rebuild with `--features sv2`, or run with \
                 RENTAL_PROXY_PROTOCOL=sv1."
            )
        }
    }
}

#[cfg(not(feature = "sv2"))]
pub use stub::Sv2Adapter;
