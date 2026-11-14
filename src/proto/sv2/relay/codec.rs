// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 frame builders + parsers for the relay: SetupConnection(Success),
//! Open(Standard|Extended)MiningChannel(.Success), SetExtranoncePrefix,
//! SetTarget, CloseChannel — owned-byte build/parse; channel-id rewriting
//! is the caller's job.

use super::*;

// ── message builders ────────────────────────────────────────────────

pub(super) fn empty_str() -> Str0255Owned {
    Str0255Owned::try_from(String::new()).expect("empty str")
}

pub(super) fn setup_connection() -> Sv2Frame {
    let sc = SetupConnectionOwned {
        protocol: Protocol::MiningProtocol,
        min_version: SV2_VERSION,
        max_version: SV2_VERSION,
        flags: 0,
        endpoint_host: empty_str(),
        endpoint_port: 0,
        // Identify the rental proxy to the upstream pool (the pool surfaces this
        // as the userAgent, e.g. `bp-proxy/sv2`, instead of the `jd-client/sv2`
        // placeholder it uses when the vendor is empty).
        vendor: Str0255Owned::try_from("bp-proxy".to_string()).unwrap_or_else(|_| empty_str()),
        hardware_version: empty_str(),
        firmware: empty_str(),
        device_id: empty_str(),
    };
    wire::frame_from(AnyMessageOwned::Common(
        CommonMessagesOwned::SetupConnection(sc),
    ))
}

pub(super) fn setup_success(flags: u32) -> Sv2Frame {
    let s = SetupConnectionSuccessOwned {
        used_version: SV2_VERSION,
        flags,
    };
    wire::frame_from(AnyMessageOwned::Common(
        CommonMessagesOwned::SetupConnectionSuccess(s),
    ))
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
) -> anyhow::Result<Sv2Frame> {
    let user =
        Str0255Owned::try_from(account.to_string()).map_err(|_| anyhow!("account too long"))?;
    let msg = match spec {
        OpenSpec::Extended {
            nominal_hash_rate,
            max_target,
            min_extranonce_size,
            ..
        } => MiningOwned::OpenExtendedMiningChannel(OpenExtendedMiningChannelOwned {
            request_id,
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256Owned::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
            min_extranonce_size: *min_extranonce_size,
        }),
        OpenSpec::Standard {
            nominal_hash_rate,
            max_target,
            ..
        } => MiningOwned::OpenStandardMiningChannel(OpenStandardMiningChannelOwned {
            request_id,
            user_identity: user,
            nominal_hash_rate: *nominal_hash_rate,
            max_target: U256Owned::try_from(max_target.clone())
                .map_err(|_| anyhow!("bad max_target"))?,
        }),
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(msg)))
}

pub(super) fn open_success_downstream(
    spec: &OpenSpec,
    down_channel_id: u32,
    down_group_id: u32,
    info: &ChannelInfo,
) -> anyhow::Result<Sv2Frame> {
    let target = U256Owned::try_from(info.target.clone()).map_err(|_| anyhow!("bad target"))?;
    let prefix = B032Owned::try_from(info.extranonce_prefix.clone())
        .map_err(|_| anyhow!("bad extranonce"))?;
    let msg = if spec.is_extended() {
        MiningOwned::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccessOwned {
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
        MiningOwned::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccessOwned {
            request_id: spec.request_id(),
            channel_id: down_channel_id,
            target,
            extranonce_prefix: prefix,
            group_channel_id: info.group_channel_id,
        })
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(msg)))
}

pub(super) fn set_extranonce_prefix(channel_id: u32, prefix: Vec<u8>) -> anyhow::Result<Sv2Frame> {
    let m = SetExtranoncePrefixOwned {
        channel_id,
        extranonce_prefix: B032Owned::try_from(prefix).map_err(|_| anyhow!("bad extranonce"))?,
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(
        MiningOwned::SetExtranoncePrefix(m),
    )))
}

pub(super) fn set_target(channel_id: u32, target: Vec<u8>) -> anyhow::Result<Sv2Frame> {
    let m = SetTargetOwned {
        channel_id,
        target: U256Owned::try_from(target).map_err(|_| anyhow!("bad target"))?,
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(
        MiningOwned::SetTarget(m),
    )))
}

pub(super) fn open_channel_error(request_id: u32, reason: &str) -> anyhow::Result<Sv2Frame> {
    let m = OpenMiningChannelErrorOwned {
        request_id,
        error_code: Str0255Owned::try_from(reason.to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(
        MiningOwned::OpenMiningChannelError(m),
    )))
}

/// Tell the upstream to close one of our channels — sent when a bundled member
/// disconnects so the pool drops just that member from the rig's group (the
/// other members keep mining on the shared upstream).
pub(super) fn close_channel_upstream(channel_id: u32) -> anyhow::Result<Sv2Frame> {
    let m = mining::CloseChannelOwned {
        channel_id,
        reason_code: Str0255Owned::try_from("member disconnected".to_string())
            .map_err(|_| anyhow!("reason too long"))?,
    };
    Ok(wire::frame_from(AnyMessageOwned::Mining(
        MiningOwned::CloseChannel(m),
    )))
}

// ── message parsers (copy fields out as owned) ──────────────────────

pub(super) fn parse_miner_open(frame: &mut Sv2Frame) -> Option<MinerOpen> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenStandardMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.as_bytes()).into_owned(),
            spec: OpenSpec::Standard {
                request_id: m.request_id,
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.as_bytes().to_vec(),
            },
        }),
        Mining::OpenExtendedMiningChannel(m) => Some(MinerOpen {
            worker: String::from_utf8_lossy(m.user_identity.as_bytes()).into_owned(),
            spec: OpenSpec::Extended {
                request_id: m.request_id,
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: m.max_target.as_bytes().to_vec(),
                min_extranonce_size: m.min_extranonce_size,
            },
        }),
        _ => None,
    }
}

pub(crate) fn parse_open_success(frame: &mut Sv2Frame) -> Option<ChannelInfo> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenExtendedMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id,
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.as_bytes().to_vec(),
            target: m.target.as_bytes().to_vec(),
            extranonce_size: m.extranonce_size,
            group_channel_id: m.group_channel_id,
        }),
        Mining::OpenStandardMiningChannelSuccess(m) => Some(ChannelInfo {
            request_id: m.request_id,
            up_channel_id: m.channel_id,
            extranonce_prefix: m.extranonce_prefix.as_bytes().to_vec(),
            target: m.target.as_bytes().to_vec(),
            extranonce_size: 0,
            group_channel_id: m.group_channel_id,
        }),
        _ => None,
    }
}

/// The `request_id` of an `OpenMiningChannelError`, to route the failure back to
/// the member whose pending open it answers, and the pool's `error_code`.
pub(super) fn parse_open_error(frame: &mut Sv2Frame) -> Option<(u32, String)> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::OpenMiningChannelError(m) => Some((
            m.request_id,
            String::from_utf8_lossy(m.error_code.as_bytes()).into_owned(),
        )),
        _ => None,
    }
}

/// `(last_sequence_number, new_submits_accepted_count)` of a `SubmitSharesSuccess`.
pub(crate) fn parse_submit_success(frame: &mut Sv2Frame) -> Option<(u32, u32)> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesSuccess(s) => {
            Some((s.last_sequence_number, s.new_submits_accepted_count))
        }
        _ => None,
    }
}

pub(crate) fn parse_set_target(frame: &mut Sv2Frame) -> Option<Vec<u8>> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetTarget(m) => Some(m.target.as_bytes().to_vec()),
        _ => None,
    }
}

/// Parse a `NewExtendedMiningJob` out of a frame (owned).
pub(crate) fn parse_new_extended_job(
    frame: &mut Sv2Frame,
) -> Option<mining::NewExtendedMiningJobOwned> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::NewExtendedMiningJob(m) => Some(m.into_owned()),
        _ => None,
    }
}

/// Parse a `NewMiningJob` (Standard channel) out of a frame (owned).
pub(crate) fn parse_new_mining_job(frame: &mut Sv2Frame) -> Option<mining::NewMiningJobOwned> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::NewMiningJob(m) => Some(m.into_owned()),
        _ => None,
    }
}

/// The new prefix of a `SetExtranoncePrefix`.
pub(crate) fn parse_set_extranonce_prefix(frame: &mut Sv2Frame) -> Option<Vec<u8>> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetExtranoncePrefix(m) => Some(m.extranonce_prefix.as_bytes().to_vec()),
        _ => None,
    }
}

/// Parse a `SetNewPrevHash` out of a frame (owned).
pub(crate) fn parse_set_new_prev_hash(frame: &mut Sv2Frame) -> Option<mining::SetNewPrevHashOwned> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SetNewPrevHash(m) => Some(m.into_owned()),
        _ => None,
    }
}

/// The `sequence_number` (the rejected share's id) and `error_code` of a
/// `SubmitSharesError`.
pub(crate) fn parse_submit_error(frame: &mut Sv2Frame) -> Option<(u32, String)> {
    let mt = wire::msg_type(frame);
    let payload = frame.payload();
    match Mining::try_from((mt, payload)).ok()? {
        Mining::SubmitSharesError(m) => Some((
            m.sequence_number,
            String::from_utf8_lossy(m.error_code.as_bytes()).into_owned(),
        )),
        _ => None,
    }
}
