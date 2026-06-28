// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol adapters. The proxy core (session, routing, control, accounting)
//! is protocol-agnostic; each adapter implements the downstream server +
//! swappable upstream client for one Stratum protocol version, plugging into
//! the [`adapter::DownstreamAdapter`] seam.
//!
//! - [`sv1`] codec + [`relay`] — Stratum V1 (live).
//! - [`sv2`] — Stratum V2 (seam + Noise/framing foundation; relay is the next
//!   milestone).

pub mod adapter;
pub mod detect;
pub mod relay;
pub mod sv1;
pub mod sv2;
/// SV1<->SV2 job/share translation used by the bidirectional upstream paths.
#[cfg(feature = "sv2")]
pub mod translate;
