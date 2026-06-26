//! Protocol adapters. The proxy core (session, routing, control, accounting)
//! is protocol-agnostic; each adapter here implements the downstream server +
//! swappable upstream client for one Stratum protocol version.
//!
//! - [`sv1`] — Stratum V1 (phase 1).
//! - `sv2` — Stratum V2 (planned; same core underneath).
//!
//! A future `ProtocolAdapter` trait will unify them once SV2 lands; until then
//! SV1 is wired directly.

pub mod relay;
pub mod sv1;
