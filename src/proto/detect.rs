// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-byte protocol detection for the shared (`both`) listen port.
//!
//! When the proxy serves SV1 and SV2 on one port, each accepted connection is
//! classified by its first byte before any adapter touches it: SV1 speaks
//! JSON (`{` or leading whitespace), SV2 opens with a binary Noise handshake.
//! The byte is *peeked* (not consumed), so the chosen adapter reads the full
//! stream normally.
//!
//! Upstream (buyer pool) protocol detection is separate: it is folded into the
//! upstream-connect path (the native protocol is attempted first and its socket
//! reused; only on failure is the other protocol tried + translated), so there
//! is no standalone upstream prober here.

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
