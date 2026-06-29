// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 frame builders + parsers for the relay: SetupConnection(Success),
//! Open(Standard|Extended)MiningChannel(.Success), SetExtranoncePrefix,
//! SetTarget, CloseChannel — owned-byte build/parse; channel-id rewriting
//! is the caller's job.

use super::*;

// ── message builders ────────────────────────────────────────────────

pub(super) fn empty_str() -> Str0255<'static> {
    Str0255::try_from(String::new()).expect("empty str")
}

pub(super) fn setup_connection() -> EitherFrame {
    let sc = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: SV2_VERSION,
        max_version: SV2_VERSION,
        flags: 0,
        endpoint_host: empty_str(),
        endpoint_port: 0,
        // Identify the rental proxy to the upstream pool (the pool surfaces this
        // as the userAgent, e.g. `bp-proxy/sv2`, instead of the `jd-client/sv2`
        // placeholder it uses when the vendor is empty).
        vendor: Str0255::try_from("bp-proxy".to_string()).unwrap_or_else(|_| empty_str()),
        hardware_version: empty_str(),
        firmware: empty_str(),
        device_id: empty_str(),
    };
    wire::frame_from(AnyMessage::Common(CommonMessages::SetupConnection(sc)))
}

pub(super) fn setup_success(flags: u32) -> EitherFrame {
    let s = SetupConnectionSuccess {
        used_version: SV2_VERSION,
        flags,
    };
    wire::frame_from(AnyMessage::Common(CommonMessages::SetupConnectionSuccess(
        s,
    )))
}

/// Build an upstream `OpenMiningChannel` for `spec` under a caller-supplied
/// `request_id`. Several members of one rig may pick the SAME downstream
/// request_id, so the proxy assigns a unique one per open on the shared upstream
/// (see `Inner::next_up_req`) and maps the reply back to the member; the stored
/// spec keeps the miner's original request_id for the downstream OpenSuccess.
pub(super) fn open_channel_upstream(
    spec: &OpenSpec,
    account: &str,
    request_id: u32,
) -> anyhow::Result<EitherFrame> {
    let user = Str0255::try_from(account.to_string()).map_err(|_| anyhow!("account too long"))?;
    let msg = match spec {
        OpenSpec::Extended {
            nominal_hash_rate,
            max_target,
            min_extranonce_size,
            ..
        } => Mining::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
            request_id,
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
            min_extranonce_size: *min_extranonce_size,
        }),
        OpenSpec::Standard {
            nominal_hash_rate,
            max_target,
            ..
        } => Mining::OpenStandardMiningChannel(OpenStandardMiningChannel {
            request_id: U32AsRef::from(request_id),
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
        }),
    };
    Ok(wire::frame_from(AnyMessage::Mining(msg)))
}

pub(super) fn open_success_downstream(
    spec: &OpenSpec,
    down_channel_id: u32,
    down_group_id: u32,
    info: &ChannelInfo,
) -> anyhow::Result<EitherFrame> {
    let target = U256::try_from(info.target.clone()).map_err(|_| anyhow!("bad target"))?;
    let prefix =
        B032::try_from(info.extranonce_prefix.clone()).map_err(|_| anyhow!("bad extranonce"))?;
    let msg = if spec.is_extended() {
        Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
            request_id: spec.request_id(),
            channel_id: down_channel_id,
            target,
            extranonce_size: info.extranonce_size,
            extranonce_prefix: prefix,
            // Remapped into the downstream id namespace so the group-broadcast
            // jobs the pool addresses to this id reach the miner (see
            // `Inner::map_group`). Extended channels are the only grouped ones.
            group_channel_id: down_group_id,
        })
    } else {
        Mining::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
            request_id: U32AsRef::from(spec.request_id()),
            channel_id: down_channel_id,
            target,
            extranonce_prefix: prefix,
            group_channel_id: info.group_channel_id,
        })
    };
    Ok(wire::frame_from(AnyMessage::Mining(msg)))
}

pub(super) fn set_extranonce_prefix(channel_id: u32, prefix: Vec<u8>) -> anyhow::Result<EitherFrame> {
    let m = SetExtranoncePrefix {
        channel_id,
        extranonce_prefix: B032::try_from(prefix).map_err(|_| anyhow!("bad extranonce"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(
        Mining::SetExtranoncePrefix(m),
    )))
}

pub(super) fn set_target(channel_id: u32, target: Vec<u8>) -> anyhow::Result<EitherFrame> {
    let m = SetTarget {
        channel_id,
        maximum_target: U256::try_from(target).map_err(|_| anyhow!("bad target"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(Mining::SetTarget(m))))
}

pub(super) fn open_channel_error(request_id: u32, reason: &str) -> anyhow::Result<EitherFrame> {
    let m = OpenMiningChannelError {
        request_id,
        error_code: Str0255::try_from(reason.to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(
        Mining::OpenMiningChannelError(m),
    )))
}

/// Tell the upstream to close one of our channels — sent when a bundled member
/// disconnects so the pool drops just that member from the rig's group (the
/// other members keep mining on the shared upstream).
pub(super) fn close_channel_upstream(channel_id: u32) -> anyhow::Result<EitherFrame> {
    let m = mining::CloseChannel {
        channel_id,
        reason_code: Str0255::try_from("member disconnected".to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessage::Mining(Mining::CloseChannel(m))))
}

// ── message parsers (copy fields out as owned) ──────────────────────

pub(super) fn parse_miner_open(frame: &mut Sv2Frame) -> Option<MinerOpen> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenStandardMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.inner_as_ref()).into_owned(),
            spec: OpenSpec::Standard {
                request_id: m.request_id.as_u32(),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.inner_as_ref().to_vec(),
            },
        }),
        Mining::OpenExtendedMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.inner_as_ref()).into_owned(),
            spec: OpenSpec::Extended {
                request_id: m.request_id,
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.inner_as_ref().to_vec(),
                min_extranonce_size: m.min_extranonce_size,
            },
        }),
        _ => None,
    }
}

pub(crate) fn parse_open_success(frame: &mut Sv2Frame) -> Option<ChannelInfo> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenExtendedMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id,
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.inner_as_ref().to_vec(),
            target: m.target.inner_as_ref().to_vec(),
            extranonce_size: m.extranonce_size,
            group_channel_id: m.group_channel_id,
        }),
        Mining::OpenStandardMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id.as_u32(),
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.inner_as_ref().to_vec(),
            target: m.target.inner_as_ref().to_vec(),
            extranonce_size: 0,
            group_channel_id: m.group_channel_id,
        }),
        _ => None,
    }
}

/// The `request_id` of an `OpenMiningChannelError`, to route the failure back to
/// the member whose pending open it answers.
pub(super) fn parse_open_error_request_id(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenMiningChannelError(m) => Some(m.request_id),
        _ => None,
    }
}

pub(super) fn parse_setup_success_flags(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match CommonMessages::try_from((mt, payload)).ok()? {
        CommonMessages::SetupConnectionSuccess(s) => Some(s.flags),
        _ => None,
    }
}

pub(crate) fn parse_accepted_count(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => Some(s.new_submits_accepted_count),
        _ => None,
    }
}

/// `(last_sequence_number, new_submits_accepted_count)` of a `SubmitSharesSuccess`.
pub(crate) fn parse_submit_success(frame: &mut Sv2Frame) -> Option<(u32, u32)> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => {
            Some((s.last_sequence_number, s.new_submits_accepted_count))
        }
        _ => None,
    }
}

pub(crate) fn parse_set_target(frame: &mut Sv2Frame) -> Option<Vec<u8>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetTarget(m) => Some(m.maximum_target.inner_as_ref().to_vec()),
        _ => None,
    }
}

/// Parse a `NewExtendedMiningJob` out of a frame (owned/`'static`).
pub(crate) fn parse_new_extended_job(
    frame: &mut Sv2Frame,
) -> Option<mining::NewExtendedMiningJob<'static>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::NewExtendedMiningJob(m) => Some(m.into_static()),
        _ => None,
    }
}

/// Parse a `SetNewPrevHash` out of a frame (owned/`'static`).
pub(crate) fn parse_set_new_prev_hash(
    frame: &mut Sv2Frame,
) -> Option<mining::SetNewPrevHash<'static>> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetNewPrevHash(m) => Some(m.into_static()),
        _ => None,
    }
}

/// The `sequence_number` of a `SubmitSharesError` (the rejected share's id).
pub(crate) fn parse_submit_error_seq(frame: &mut Sv2Frame) -> Option<u32> {
    let mt = wire::msg_type(frame)?;
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesError(m) => Some(m.sequence_number),
        _ => None,
    }
}

/// Difficulty implied by a channel `target` (Bitcoin bdiff convention). The
/// single source of truth is [`crate::proto::translate::difficulty_from_target`].
pub(super) fn difficulty_from_target(target: &[u8]) -> f64 {
    crate::proto::translate::difficulty_from_target(target)
}
