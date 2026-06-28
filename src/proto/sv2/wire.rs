//! SV2 frame plumbing for the relay: build typed messages into frames, pull the
//! message type out of received frames, and rewrite the `channel_id` of a
//! channel-scoped message in place.
//!
//! The relay forwards most traffic (jobs, prev-hash, shares, set-target,
//! set-extranonce) by rewriting only the `channel_id` — which is always the
//! first 4 little-endian bytes of a channel-scoped payload — and re-emitting the
//! already-serialized frame. Only the handshake and channel-open messages are
//! parsed/built as typed structs.

use stratum_core::codec_sv2::{StandardEitherFrame, StandardSv2Frame};
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::mining_sv2 as mining;
use stratum_core::parsers_sv2::{AnyMessage, IsSv2Message};

/// The message type carried by frames on the wire.
pub type Msg = AnyMessage<'static>;
/// A frame as produced/consumed by the Noise transport.
pub type EitherFrame = StandardEitherFrame<Msg>;
/// A decoded (or to-be-encoded) SV2 frame.
pub type Sv2Frame = StandardSv2Frame<Msg>;

/// Wrap a typed message into a transport frame.
pub fn frame_from(msg: Msg) -> EitherFrame {
    let msg_type = msg.message_type();
    let channel_bit = msg.channel_bit();
    let ext = msg.extension_type();
    let frame = StandardSv2Frame::from_message(msg, msg_type, ext, channel_bit)
        .expect("message fits in one SV2 frame");
    frame.into()
}

/// Extract the SV2 frame from a transport frame (post-handshake frames are SV2,
/// not handshake frames).
pub fn into_sv2(frame: EitherFrame) -> Option<Sv2Frame> {
    match frame {
        Frame::Sv2(f) => Some(f),
        Frame::HandShake(_) => None,
    }
}

/// The message type byte of a decoded frame.
pub fn msg_type(frame: &Sv2Frame) -> Option<u8> {
    frame.get_header().map(|h| h.msg_type())
}

/// Overwrite the `channel_id` (first 4 LE bytes of the payload) of a decoded,
/// channel-scoped frame. No-op if the payload is shorter than 4 bytes (a
/// malformed frame) so a bad upstream/downstream frame can't panic the relay.
/// Callers read the id first and drop short frames, so this guard is a safety net.
pub fn rewrite_channel_id(frame: &mut Sv2Frame, channel_id: u32) {
    let payload = frame.payload();
    if payload.len() < 4 {
        return;
    }
    payload[..4].copy_from_slice(&channel_id.to_le_bytes());
}

/// Read the `channel_id` (first 4 LE bytes of the payload) of a decoded,
/// channel-scoped frame. Returns `None` if the payload is shorter than 4 bytes
/// (a malformed frame) so the relay drops it instead of panicking — the upstream
/// pool is only semi-trusted (a buyer supplies its target).
pub fn read_channel_id(frame: &mut Sv2Frame) -> Option<u32> {
    let payload = frame.payload();
    if payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// Channel-scoped mining messages carry `channel_id` as their first field, so
/// they can be forwarded with an in-place `channel_id` rewrite. Open-channel
/// (success/error) messages are excluded — their first field is `request_id`,
/// so the relay parses those as typed structs.
pub fn is_channel_scoped(msg_type: u8) -> bool {
    matches!(
        msg_type,
        mining::MESSAGE_TYPE_NEW_MINING_JOB
            | mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB
            | mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            | mining::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX
            | mining::MESSAGE_TYPE_SET_TARGET
            | mining::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD
            | mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED
            | mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS
            | mining::MESSAGE_TYPE_SUBMIT_SHARES_ERROR
            | mining::MESSAGE_TYPE_UPDATE_CHANNEL
            | mining::MESSAGE_TYPE_UPDATE_CHANNEL_ERROR
            | mining::MESSAGE_TYPE_CLOSE_CHANNEL
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::B032;
    use stratum_core::mining_sv2::SubmitSharesExtended;
    use stratum_core::parsers_sv2::Mining;

    #[test]
    fn channel_id_rewrite_roundtrips_through_serialization() {
        // Build a real channel-scoped message (channel_id = 1), serialize it,
        // decode it, rewrite channel_id → 42, and confirm via re-read.
        let submit = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 5,
            job_id: 9,
            nonce: 0xdead_beef,
            ntime: 0x6500_0000,
            version: 0x2000_0000,
            extranonce: B032::try_from(vec![1u8, 2, 3, 4]).unwrap(),
        };
        let msg = AnyMessage::Mining(Mining::SubmitSharesExtended(submit));
        assert!(is_channel_scoped(msg.message_type()));

        let bytes = encode_to_vec(into_sv2(frame_from(msg)).expect("sv2 frame"));
        let mut decoded = decode_from_bytes(&bytes);

        assert_eq!(read_channel_id(&mut decoded), Some(1));
        rewrite_channel_id(&mut decoded, 42);
        assert_eq!(read_channel_id(&mut decoded), Some(42));
    }

    #[test]
    fn short_payload_is_rejected_not_panicked() {
        // A channel-scoped frame whose payload is shorter than the 4-byte
        // channel_id (a malformed frame) must not panic: read returns None and
        // rewrite is a no-op. Hand-built header (ext=0, msg_type=0, len=2) + 2
        // payload bytes.
        let bytes = [0u8, 0, 0, 2, 0, 0, 0xAA, 0xBB];
        let mut frame = decode_from_bytes(&bytes);
        assert_eq!(read_channel_id(&mut frame), None);
        rewrite_channel_id(&mut frame, 7); // must not panic
        assert_eq!(read_channel_id(&mut frame), None);
    }

    fn encode_to_vec(frame: Sv2Frame) -> Vec<u8> {
        use stratum_core::codec_sv2::Encoder;
        let mut enc = Encoder::<Msg>::new();
        let s = enc.encode(frame).expect("encode");
        AsRef::<[u8]>::as_ref(&s).to_vec()
    }

    fn decode_from_bytes(bytes: &[u8]) -> Sv2Frame {
        use stratum_core::codec_sv2::StandardDecoder;
        let mut dec = StandardDecoder::<Msg>::new();
        let mut off = 0;
        loop {
            let w = dec.writable();
            let n = w.len().min(bytes.len() - off);
            w[..n].copy_from_slice(&bytes[off..off + n]);
            off += n;
            if let Ok(f) = dec.next_frame() {
                return f;
            }
        }
    }
}
