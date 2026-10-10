// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-byte protocol detection for the shared listen port.
//!
//! SV1 and SV2 miners connect to the same port. Each accepted connection is
//! classified by its first byte before any relay touches it: SV1 speaks JSON
//! (`{` or leading whitespace), SV2 opens with a binary Noise handshake. The
//! byte is *peeked* (not consumed), so the chosen relay reads the full stream.
//!
//! Upstream (buyer pool) protocol detection is separate: it is folded into the
//! upstream-connect path (the native protocol is attempted first and its socket
//! reused; only on failure is the other protocol tried + translated).

/// Whether a downstream connection whose first byte is `first_byte` speaks SV1.
///
/// SV1 JSON-RPC starts with `{`; some lenient miners lead with whitespace, so
/// those count as SV1 too. Everything else (the Noise handshake's ephemeral
/// key bytes, or anything unexpected like a TLS `0x16` ClientHello) goes to
/// SV2, whose handshake rejects genuine garbage and closes.
pub fn is_sv1(first_byte: u8) -> bool {
    matches!(first_byte, b'{' | b' ' | b'\n' | b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_opener_and_whitespace_are_sv1() {
        for b in [b'{', b' ', b'\n', b'\r'] {
            assert!(is_sv1(b), "byte 0x{b:02x}");
        }
    }

    #[test]
    fn noise_handshake_bytes_are_sv2() {
        // The Noise first message starts with a curve point — sample some
        // plausible leading bytes that JSON/whitespace don't claim.
        for b in [0x00, 0x01, 0x16, 0x42, 0x80, 0xab, 0xff] {
            assert!(!is_sv1(b), "byte 0x{b:02x}");
        }
    }
}
