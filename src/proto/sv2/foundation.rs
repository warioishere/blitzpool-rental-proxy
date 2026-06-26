//! Verified SV2 wire-layer foundation (feature `sv2`).
//!
//! The groundwork the SV2 relay sits on, proven in isolation with round-trip
//! tests before the relay is assembled. Built on the upstream stratum-mining
//! stack via [`stratum_core`] (re-exports `codec_sv2`, `noise_sv2`,
//! `parsers_sv2`, `mining_sv2`, …):
//!
//! - [`encode_frame`] / [`decode_frame`] — build a typed SV2 message into a
//!   length-prefixed frame, serialize it, and read it back through the
//!   streaming decoder (the exact path the relay uses on the wire).
//! - [`noise_handshake_pair`] — run the Noise `NX` handshake between an
//!   initiator and a responder and hand back the two `NoiseCodec`s. The proxy
//!   is the responder to the miner and the initiator to each upstream; this
//!   proves the encrypted channel end to end.
//!
//! Not yet wired into [`super::Sv2Adapter::serve`] — the downstream server loop
//! + swappable upstream client + channel re-open on switch is the remaining SV2
//! milestone (see the parent module docs).

use stratum_core::codec_sv2::{Encoder, StandardDecoder, StandardSv2Frame};
use stratum_core::noise_sv2::{Initiator, NoiseCodec, Responder};
use stratum_core::parsers_sv2::{AnyMessage, IsSv2Message};

/// Serialize a typed SV2 message into an on-the-wire frame (header + payload).
pub fn encode_frame(msg: AnyMessage<'static>) -> Vec<u8> {
    let msg_type = msg.message_type();
    let channel_bit = msg.channel_bit();
    let frame = StandardSv2Frame::<AnyMessage>::from_message(msg, msg_type, 0, channel_bit)
        .expect("message fits in a single SV2 frame");
    let mut encoder = Encoder::<AnyMessage>::new();
    let serialized = encoder.encode(frame).expect("serialize frame");
    AsRef::<[u8]>::as_ref(&serialized).to_vec()
}

/// Feed `bytes` through the streaming decoder a chunk at a time (as a socket
/// would deliver them) and return `(message_type, payload)`. Panics if the
/// bytes do not contain exactly one complete frame — it is a test/groundwork
/// helper, not the production read loop.
pub fn decode_frame(bytes: &[u8]) -> (u8, Vec<u8>) {
    let mut decoder = StandardDecoder::<AnyMessage>::new();
    let mut offset = 0;
    let mut frame = loop {
        let writable = decoder.writable();
        let n = writable.len().min(bytes.len() - offset);
        assert!(n > 0, "decoder wants more bytes than the frame provides");
        writable[..n].copy_from_slice(&bytes[offset..offset + n]);
        offset += n;
        match decoder.next_frame() {
            Ok(frame) => break frame,
            Err(_) => continue, // MissingBytes: header read, payload still pending
        }
    };
    let msg_type = frame.get_header().expect("frame header").msg_type();
    let payload = frame.payload().to_vec();
    (msg_type, payload)
}

/// Run the Noise `NX` handshake and return `(initiator_codec, responder_codec)`
/// — a ready encrypted channel. The responder authenticates with a freshly
/// generated authority keypair; the initiator connects without pinning it
/// (`without_pk`), which is what an upstream-agnostic proxy does before it has
/// the pool's static key.
pub fn noise_handshake_pair() -> (NoiseCodec, NoiseCodec) {
    use secp256k1::{Keypair, Secp256k1};

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let authority = Keypair::new(&secp, &mut rng);

    // Certificate validity (seconds) the responder signs its static key for.
    let mut responder = Responder::new(authority, 3600);
    let mut initiator = Initiator::without_pk().expect("initiator");

    let first = initiator.step_0().expect("initiator step_0");
    let (second, responder_codec) = responder.step_1(first).expect("responder step_1");
    let initiator_codec = initiator.step_2(second).expect("initiator step_2");
    (initiator_codec, responder_codec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::{Str0255, U256};
    use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
    use stratum_core::mining_sv2::OpenExtendedMiningChannel;
    use stratum_core::parsers_sv2::{CommonMessages, Mining};

    fn setup_connection() -> AnyMessage<'static> {
        let sc = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: Str0255::try_from("proxy.example".to_string()).unwrap(),
            endpoint_port: 3333,
            vendor: Str0255::try_from("blitzpool".to_string()).unwrap(),
            hardware_version: Str0255::try_from(String::new()).unwrap(),
            firmware: Str0255::try_from(String::new()).unwrap(),
            device_id: Str0255::try_from(String::new()).unwrap(),
        };
        AnyMessage::Common(CommonMessages::SetupConnection(sc))
    }

    fn open_extended_channel() -> AnyMessage<'static> {
        let m = OpenExtendedMiningChannel {
            request_id: 7,
            user_identity: Str0255::try_from("seller.rig1".to_string()).unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        AnyMessage::Mining(Mining::OpenExtendedMiningChannel(m))
    }

    #[test]
    fn common_message_frame_roundtrips() {
        let msg = setup_connection();
        let want = msg.message_type();
        let bytes = encode_frame(msg);
        assert!(!bytes.is_empty());

        let (got, mut payload) = decode_frame(&bytes);
        assert_eq!(got, want);
        // Payload re-parses into the typed message, not just a surviving header.
        let parsed = CommonMessages::try_from((got, payload.as_mut_slice())).expect("re-parse");
        assert!(matches!(parsed, CommonMessages::SetupConnection(_)));
    }

    #[test]
    fn mining_message_frame_roundtrips() {
        let msg = open_extended_channel();
        let want = msg.message_type();
        // A channel-open request carries no channel id yet, so no channel bit.
        assert!(!msg.channel_bit());
        let bytes = encode_frame(msg);

        let (got, mut payload) = decode_frame(&bytes);
        assert_eq!(got, want);
        let parsed = Mining::try_from((got, payload.as_mut_slice())).expect("re-parse");
        assert!(matches!(parsed, Mining::OpenExtendedMiningChannel(_)));
    }

    #[test]
    fn noise_channel_roundtrips_a_payload() {
        let (mut initiator, mut responder) = noise_handshake_pair();
        let plaintext = b"stratum-rental-proxy sv2 noise check".to_vec();

        let mut buf = plaintext.clone();
        initiator.encrypt(&mut buf).expect("encrypt");
        assert_ne!(buf, plaintext, "payload should be ciphertext on the wire");

        responder.decrypt(&mut buf).expect("decrypt");
        assert_eq!(buf, plaintext, "responder recovers the initiator's plaintext");
    }
}
