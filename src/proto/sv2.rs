//! Stratum V2 downstream adapter.
//!
//! # Status
//!
//! [`Sv2Adapter`] plugs into the [`DownstreamAdapter`] seam, so the rest of the
//! proxy (registry, orders, sellers, control API, accounting) is already
//! protocol-agnostic. The wire-layer [`foundation`] (Noise handshake + frame
//! round-trips) is built and tested behind the `sv2` feature. The full relay —
//! downstream Noise server + swappable upstream client + channel re-open on
//! switch — is the remaining milestone, so `serve` **refuses loudly** for now
//! (it never silently accepts then drops a miner); `RENTAL_PROXY_PROTOCOL=sv2`
//! logs a clear boot warning.
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
//! # Relay design (the remaining milestone)
//!
//! The SV1 relay switches upstreams live with one `mining.set_extranonce`
//! because the proxy owns the miner-facing handshake + extranonce. SV2 is
//! heavier and the switch is structurally harder:
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
//!    and remaps the downstream channel's job stream + extranonce to it without
//!    the miner re-opening — the SV2 analogue of the SV1 `set_extranonce`, but
//!    it must translate channel ids, extranonce prefixes, and job ids across
//!    the boundary. Extended channels (one extranonce space the proxy
//!    sub-allocates) are the tractable target; pure Standard-channel miners may
//!    need an `OpenMiningChannel.Error` → reconnect on switch.

use tokio::net::TcpStream;

use super::adapter::{DownstreamAdapter, ProxyContext};

/// Verified SV2 wire-layer building blocks (Noise handshake + frame
/// round-trips), behind the `sv2` feature. The relay will be assembled on top.
#[cfg(feature = "sv2")]
pub mod foundation;

/// SV2 downstream adapter. Present so the protocol seam is complete; the full
/// relay is the next milestone (see module docs).
#[derive(Clone, Copy, Default)]
pub struct Sv2Adapter;

impl DownstreamAdapter for Sv2Adapter {
    fn protocol(&self) -> &'static str {
        "sv2"
    }

    async fn serve(&self, _miner: TcpStream, peer: String, _ctx: ProxyContext) -> anyhow::Result<()> {
        // Loud refusal — never silently accept then drop a miner.
        anyhow::bail!(
            "SV2 downstream relay is not implemented yet (peer {peer}); the protocol \
             seam + Noise/framing foundation are in place (see proto::sv2), but the \
             downstream server + swappable upstream relay is the remaining milestone. \
             Run with RENTAL_PROXY_PROTOCOL=sv1 for now."
        )
    }
}
