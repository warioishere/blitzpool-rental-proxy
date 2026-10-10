// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V2 downstream relay.
//!
//! The proxy is the Noise responder to the miner and the Noise initiator to
//! each upstream pool. It mirrors the miner's channel type (Standard or
//! Extended) onto the upstream and forwards jobs and shares with only the
//! `channel_id` rewritten; several same-rig miners can share one upstream.
//! An SV1 upstream is reached through [`crate::proto::translate`].
//!
//! The SV2 stack comes from the upstream stratum-mining git repositories
//! (`stratum-core`, `stratum-apps`), not crates.io: the crates.io releases at
//! the current majors do not compile together.

/// Frame plumbing: build/parse/forward SV2 frames with channel-id rewriting.
pub mod wire;

/// The proxy's SV2 Noise authority keypair.
pub mod keys;

/// The SV2 downstream relay (full proxy with a swappable upstream).
pub mod relay;
