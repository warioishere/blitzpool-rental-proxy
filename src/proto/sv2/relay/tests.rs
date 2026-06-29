//! End-to-end relay test over real loopback Noise sockets: a mock miner
//! talks to the proxy, which relays to mock pool A; then a rental switch
//! re-points it to mock pool B without the miner reconnecting.

use super::*;
use stratum_core::binary_sv2::B032;
use stratum_core::mining_sv2::{SubmitSharesExtended, SubmitSharesSuccess, UpdateChannel};
use tokio::net::TcpListener;

fn ext_target(url: &str, user: &str) -> UpstreamTarget {
    UpstreamTarget {
        url: url.to_string(),
        user: user.to_string(),
        password: String::new(),
        authority_pubkey: None,
    }
}

/// Register a worker's rig (its idle pool) so the register-only relay serves
/// it — every test miner authorizes as `bc1qSELLER.rig1`.
async fn register_rig(sellers: &crate::store::SellerStore, worker: &str, idle: UpstreamTarget) {
    sellers
        .set(
            worker.to_string(),
            crate::store::Rig {
                default_pool: idle,
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// A channel target (little-endian) of 2^224 ⇒ difficulty ≈ 1, so accepted
/// shares carry real (non-zero) work. (`[0xff; 32]` is the max target =
/// difficulty 0, which the accounting correctly ignores.)
fn diff1_target() -> Vec<u8> {
    // The difficulty-1 target in the current (bdiff) convention.
    translate::target_from_difficulty(1.0).to_vec()
}

/// A mock SV2 pool: one connection, tagging its `extranonce_prefix`. Assigns
/// each opened channel a distinct id starting at `base_cid`. Reports the
/// `channel_id` of each received submit on `submits` and replies
/// `SubmitSharesSuccess` with that channel id (exercising the proxy's
/// downstream rewrite). Handles multiple channels on the one connection.
async fn mock_pool(
    listener: TcpListener,
    prefix: Vec<u8>,
    base_cid: u32,
    keys: NoiseKeys,
    submits: mpsc::UnboundedSender<u32>,
) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("pool noise: {e:?}"))?;
    let (read, write) = stream.into_split();
    serve_pool_conn(read, write, prefix, base_cid, submits).await
}

/// A pool that accepts MANY connections (several miners sharing one rig name,
/// each its own proxy→pool connection), serving each on its own task with a
/// distinct base channel id.
async fn mock_pool_multi(
    listener: TcpListener,
    prefix: Vec<u8>,
    base_cid: u32,
    keys: NoiseKeys,
    submits: mpsc::UnboundedSender<u32>,
) -> anyhow::Result<()> {
    let mut n = 0u32;
    loop {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let stream =
            accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
                .await
                .map_err(|e| anyhow!("pool noise: {e:?}"))?;
        let (read, write) = stream.into_split();
        let cid = base_cid + n * 10;
        n += 1;
        tokio::spawn(serve_pool_conn(
            read,
            write,
            prefix.clone(),
            cid,
            submits.clone(),
        ));
    }
}

/// Serve one pool connection: setup handshake, then opens → success (distinct
/// cid), submits → report + success, UpdateChannel → SetTarget.
async fn serve_pool_conn(
    mut read: Read,
    mut write: Write,
    prefix: Vec<u8>,
    base_cid: u32,
    submits: mpsc::UnboundedSender<u32>,
) -> anyhow::Result<()> {
    // SetupConnection → success.
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    // Steady loop: opens → success (distinct cid), submits → report + success.
    let mut next_cid = base_cid;
    while let Ok(mut f) = read_one(&mut read).await {
        match wire::msg_type(&f) {
            Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL)
            | Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL) => {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                let cid = next_cid;
                next_cid += 1;
                let info = ChannelInfo {
                    request_id: open.spec.request_id(),
                    up_channel_id: cid,
                    extranonce_prefix: prefix.clone(),
                    target: diff1_target(),
                    extranonce_size: 8,
                    group_channel_id: 0,
                };
                write
                    .write_frame(open_success_downstream(
                        &open.spec,
                        cid,
                        info.group_channel_id,
                        &info,
                    )?)
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) => {
                let Some(cid) = wire::read_channel_id(&mut f) else {
                    continue;
                };
                let _ = submits.send(cid);
                let ok = SubmitSharesSuccess {
                    channel_id: cid,
                    last_sequence_number: 0,
                    new_submits_accepted_count: 1,
                    new_shares_sum: 1,
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::SubmitSharesSuccess(ok),
                    )))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            Some(mining::MESSAGE_TYPE_UPDATE_CHANNEL) => {
                // Vardiff: answer the miner's hashrate update with a target.
                let Some(cid) = wire::read_channel_id(&mut f) else {
                    continue;
                };
                let st = SetTarget {
                    channel_id: cid,
                    maximum_target: U256::from([0x33u8; 32]),
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(Mining::SetTarget(st))))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

struct MockMiner {
    read: Read,
    write: Write,
}

impl MockMiner {
    async fn connect(addr: std::net::SocketAddr) -> anyhow::Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let stream = connect_with_noise::<Msg>(tcp, None)
            .await
            .map_err(|e| anyhow!("miner noise: {e:?}"))?;
        let (read, write) = stream.into_split();
        Ok(Self { read, write })
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        self.write
            .write_frame(setup_connection())
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        loop {
            let f = read_one(&mut self.read).await?;
            if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) {
                return Ok(());
            }
        }
    }

    /// Send an OpenExtendedMiningChannel without waiting for the success.
    async fn send_open(&mut self, worker: &str, request_id: u32) -> anyhow::Result<()> {
        let spec = OpenSpec::Extended {
            request_id,
            nominal_hash_rate: 1.0e12,
            max_target: vec![0xffu8; 32],
            min_extranonce_size: 8,
        };
        self.write
            .write_frame(open_channel_upstream(&spec, worker, request_id)?)
            .await
            .map_err(|e| anyhow!("{e:?}"))
    }

    /// Open an Extended channel; returns `(downstream_channel_id, prefix)`.
    async fn open(&mut self, worker: &str, request_id: u32) -> anyhow::Result<(u32, Vec<u8>)> {
        self.send_open(worker, request_id).await?;
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f)
                == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
            {
                let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                return Ok((info.up_channel_id, info.extranonce_prefix));
            }
        }
    }

    /// Open a Standard channel; returns `(downstream_channel_id, prefix)`.
    async fn open_standard(
        &mut self,
        worker: &str,
        request_id: u32,
    ) -> anyhow::Result<(u32, Vec<u8>)> {
        let spec = OpenSpec::Standard {
            request_id,
            nominal_hash_rate: 1.0e12,
            max_target: vec![0xffu8; 32],
        };
        self.write
            .write_frame(open_channel_upstream(&spec, worker, request_id)?)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f)
                == Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS)
            {
                let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                return Ok((info.up_channel_id, info.extranonce_prefix));
            }
        }
    }

    async fn update_channel(&mut self, channel_id: u32) -> anyhow::Result<()> {
        let m = UpdateChannel {
            channel_id,
            nominal_hash_rate: 2.0e12,
            maximum_target: U256::from([0xffu8; 32]),
        };
        self.write
            .write_frame(wire::frame_from(AnyMessage::Mining(Mining::UpdateChannel(
                m,
            ))))
            .await
            .map_err(|e| anyhow!("{e:?}"))
    }

    /// Read until SetTarget; returns `(channel_id, target_bytes)`.
    async fn read_until_set_target(&mut self) -> anyhow::Result<(u32, Vec<u8>)> {
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SET_TARGET) {
                let mt = wire::msg_type(&f).unwrap();
                let payload = f.payload();
                if let Ok(Mining::SetTarget(m)) = Mining::try_from((mt, payload)) {
                    return Ok((m.channel_id, m.maximum_target.inner_as_ref().to_vec()));
                }
            }
        }
    }

    async fn submit(&mut self, channel_id: u32, seq: u32) -> anyhow::Result<()> {
        let m = SubmitSharesExtended {
            channel_id,
            sequence_number: seq,
            job_id: 1,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: B032::try_from(vec![0u8; 8]).unwrap(),
        };
        self.write
            .write_frame(wire::frame_from(AnyMessage::Mining(
                Mining::SubmitSharesExtended(m),
            )))
            .await
            .map_err(|e| anyhow!("{e:?}"))
    }

    async fn submit_standard(&mut self, channel_id: u32, seq: u32) -> anyhow::Result<()> {
        let m = mining::SubmitSharesStandard {
            channel_id,
            sequence_number: seq,
            job_id: 1,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
        };
        self.write
            .write_frame(wire::frame_from(AnyMessage::Mining(
                Mining::SubmitSharesStandard(m),
            )))
            .await
            .map_err(|e| anyhow!("{e:?}"))
    }

    /// Read until a frame of `want` type; returns its channel_id.
    async fn read_until_cid(&mut self, want: u8) -> anyhow::Result<u32> {
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f) == Some(want) {
                if let Some(cid) = wire::read_channel_id(&mut f) {
                    return Ok(cid);
                }
            }
        }
    }

    /// Open an Extended channel; returns the OpenSuccess `(channel_id,
    /// group_channel_id, prefix)` the miner sees (all already remapped into
    /// the proxy's downstream id namespace).
    async fn open_full(
        &mut self,
        worker: &str,
        request_id: u32,
    ) -> anyhow::Result<(u32, u32, Vec<u8>)> {
        self.send_open(worker, request_id).await?;
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f)
                == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
            {
                let info = parse_open_success(&mut f).ok_or_else(|| anyhow!("bad success"))?;
                return Ok((
                    info.up_channel_id,
                    info.group_channel_id,
                    info.extranonce_prefix,
                ));
            }
        }
    }

    /// Read until SetExtranoncePrefix; returns `(channel_id, prefix)`.
    async fn read_until_set_extranonce(&mut self) -> anyhow::Result<(u32, Vec<u8>)> {
        loop {
            let mut f = read_one(&mut self.read).await?;
            if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX) {
                let mt = wire::msg_type(&f).unwrap();
                let payload = f.payload();
                if let Ok(Mining::SetExtranoncePrefix(m)) = Mining::try_from((mt, payload)) {
                    return Ok((m.channel_id, m.extranonce_prefix.inner_as_ref().to_vec()));
                }
            }
        }
    }
}

#[tokio::test]
async fn relay_forwards_open_share_and_switches_upstream() {
    // Mock pools A (cid 7, prefix AA) and B (cid 99, prefix BB).
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    // Proxy: default upstream = pool A.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: crate::orders::OrderStore::new(pool.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    // Miner connects + opens → lands on pool A.
    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, prefix1) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
    assert_eq!(prefix1, vec![0xAA; 8], "idle → seller default pool A");

    // Submit → reaches pool A; success comes back on the stable downstream cid.
    miner.submit(down_cid, 0).await.unwrap();
    assert_eq!(a_rx.recv().await.unwrap(), 7, "submit reached pool A");
    let ok_cid = miner
        .read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS)
        .await
        .unwrap();
    assert_eq!(
        ok_cid, down_cid,
        "success remapped to downstream channel id"
    );

    // Rent: switch the session to pool B.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();

    // Miner is re-pointed to pool B (new extranonce prefix), same channel id.
    let (re_cid, prefix2) = miner.read_until_set_extranonce().await.unwrap();
    assert_eq!(prefix2, vec![0xBB; 8], "rented → buyer pool B");
    assert_eq!(re_cid, down_cid, "re-point keeps the downstream channel id");

    // Submit again → now reaches pool B; the proxy rewrote down cid → pool B's 99.
    miner.submit(down_cid, 1).await.unwrap();
    assert_eq!(
        b_rx.recv().await.unwrap(),
        99,
        "submit reached pool B (cid remapped)"
    );
    let ok_cid2 = miner
        .read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS)
        .await
        .unwrap();
    assert_eq!(
        ok_cid2, down_cid,
        "success still on stable downstream channel id"
    );
}

#[tokio::test]
async fn relay_supports_multiple_channels_on_one_connection() {
    // Pool A assigns cids 7, 8; pool B assigns 99, 100.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: crate::orders::OrderStore::new(pool.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    // First channel (bootstrap, request_id 1) + a second channel (request_id 2).
    let (cid1, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
    let (cid2, _) = miner.open("bc1qSELLER.rig1", 2).await.unwrap();
    assert_ne!(cid1, cid2, "each channel gets a distinct downstream id");

    // Submit on each channel → both reach pool A on distinct upstream cids.
    miner.submit(cid1, 0).await.unwrap();
    miner.submit(cid2, 0).await.unwrap();
    let mut seen = vec![a_rx.recv().await.unwrap(), a_rx.recv().await.unwrap()];
    seen.sort_unstable();
    assert_eq!(seen, vec![7, 8], "both channels' submits reached pool A");

    // Switch both channels to pool B.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();

    // Both channels are re-pointed (two SetExtranoncePrefix, same down cids).
    let (rc1, _) = miner.read_until_set_extranonce().await.unwrap();
    let (rc2, _) = miner.read_until_set_extranonce().await.unwrap();
    let mut repointed = vec![rc1, rc2];
    repointed.sort_unstable();
    let mut expected = vec![cid1, cid2];
    expected.sort_unstable();
    assert_eq!(repointed, expected, "both channels re-pointed, ids stable");

    // Submit on both → reach pool B on its distinct cids.
    miner.submit(cid1, 1).await.unwrap();
    miner.submit(cid2, 1).await.unwrap();
    let mut seen_b = vec![b_rx.recv().await.unwrap(), b_rx.recv().await.unwrap()];
    seen_b.sort_unstable();
    assert_eq!(
        seen_b,
        vec![99, 100],
        "both channels' submits reached pool B"
    );
}

#[tokio::test]
async fn vardiff_set_target_forwards_to_miner() {
    // Pool answers the miner's UpdateChannel with a SetTarget; the proxy
    // forwards it back, remapped to the downstream channel id.
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pool.local_addr().unwrap();
    let (tx, _rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, NoiseKeys::generate(), tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: crate::orders::OrderStore::new(pool.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&addr.to_string(), "acct"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    miner.update_channel(down_cid).await.unwrap();
    let (cid, target) = miner.read_until_set_target().await.unwrap();
    assert_eq!(cid, down_cid, "SetTarget remapped to downstream channel id");
    assert_eq!(
        target,
        vec![0x33u8; 32],
        "pool's new target reached the miner"
    );
}

/// A pool that completes the first channel open, then signals + ignores any
/// further opens (leaving them pending at the proxy).
async fn mock_pool_stall(
    listener: TcpListener,
    keys: NoiseKeys,
    ignored: mpsc::UnboundedSender<u32>,
) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let mut opened = 0;
    while let Ok(mut f) = read_one(&mut read).await {
        let is_open = matches!(
            wire::msg_type(&f),
            Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL)
                | Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL)
        );
        if !is_open {
            continue;
        }
        let Some(open) = parse_miner_open(&mut f) else {
            continue;
        };
        if opened == 0 {
            opened += 1;
            let info = ChannelInfo {
                request_id: open.spec.request_id(),
                up_channel_id: 7,
                extranonce_prefix: vec![0xAA; 8],
                target: vec![0xffu8; 32],
                extranonce_size: 8,
                group_channel_id: 0,
            };
            write
                .write_frame(open_success_downstream(
                    &open.spec,
                    7,
                    info.group_channel_id,
                    &info,
                )?)
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
        } else {
            let _ = ignored.send(open.spec.request_id()); // stall this open
        }
    }
    Ok(())
}

#[tokio::test]
async fn switch_abandons_pending_open_with_error() {
    // Pool A completes the first open then stalls the second; pool B normal.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (ign_tx, mut ign_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_stall(pool_a, NoiseKeys::generate(), ign_tx));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: crate::orders::OrderStore::new(pool.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let _ = miner.open("bc1qSELLER.rig1", 1).await.unwrap(); // first channel ok
    miner.send_open("bc1qSELLER.rig1", 2).await.unwrap(); // second → stalls upstream
    assert_eq!(
        ign_rx.recv().await.unwrap(),
        2,
        "pool A received + stalled open #2"
    );

    // Switch to pool B: the in-flight open #2 must be abandoned with an error.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();

    let err_request_id = miner
        .read_until_cid(mining::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR)
        .await
        .unwrap();
    assert_eq!(err_request_id, 2, "pending open #2 abandoned with an error");
}

#[tokio::test]
async fn delivered_work_is_credited_to_the_rental_order() {
    // Default pool A (idle) + buyer pool B (rented).
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(pool.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    // Rent: create an order and switch the session onto buyer pool B.
    let order = orders
        .create(
            "bc1qSELLER.rig1".into(),
            ext_target(&b_addr.to_string(), "acctB"),
            None,
            0,
            0.0,
            0.0,
        )
        .await
        .unwrap();
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to(order.id.clone(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();
    let _ = miner.read_until_set_extranonce().await.unwrap();

    // Submit K accepted shares.
    let k = 3u64;
    for seq in 0..k {
        miner.submit(down_cid, seq as u32).await.unwrap();
        b_rx.recv().await.unwrap(); // pool B received the submit
    }

    // Work is buffered as the successes are forwarded; flush each poll to
    // drain it to the DB (bounded, so a regression fails instead of hanging).
    let mut credited = orders.get(&order.id).await.unwrap();
    for _ in 0..100_000 {
        if credited.accepted_shares >= k {
            break;
        }
        tokio::task::yield_now().await;
        orders.flush().await;
        credited = orders.get(&order.id).await.unwrap();
    }
    assert_eq!(
        credited.accepted_shares, k,
        "accepted shares credited to order"
    );
    assert_eq!(
        credited.submitted_shares, k,
        "submitted shares tracked on order"
    );
    let expected = difficulty_from_target(&diff1_target()) * k as f64;
    assert!(credited.delivered_work > 0.0, "delivered work measured");
    assert!(
        (credited.delivered_work - expected).abs() <= expected * 1e-6 + f64::MIN_POSITIVE,
        "delivered_work {} ~= {} (diff-weighted)",
        credited.delivered_work,
        expected
    );
}

#[tokio::test]
async fn upstream_authenticates_pool_authority() {
    // Pool with a known authority keypair.
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pool.local_addr().unwrap();
    let pool_keys = NoiseKeys::generate();
    let pool_pubkey = pool_keys.public_b58();
    let (tx, _rx) = mpsc::unbounded_channel();
    tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, pool_keys, tx));

    // Pinning the correct authority key: the upstream handshake succeeds.
    let mut target = ext_target(&addr.to_string(), "acct");
    target.authority_pubkey = Some(pool_pubkey);
    assert!(
        connect_setup(&target).await.is_ok(),
        "correct authority key should authenticate"
    );
}

#[tokio::test]
async fn upstream_rejects_wrong_pool_authority() {
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pool.local_addr().unwrap();
    let pool_keys = NoiseKeys::generate();
    let (tx, _rx) = mpsc::unbounded_channel();
    tokio::spawn(mock_pool(pool, vec![0xAA; 8], 7, pool_keys, tx));

    // Pinning a different authority key: the handshake must fail.
    let mut target = ext_target(&addr.to_string(), "acct");
    target.authority_pubkey = Some(NoiseKeys::generate().public_b58());
    assert!(
        connect_setup(&target).await.is_err(),
        "wrong authority key must be rejected"
    );
}

#[tokio::test]
async fn unregistered_worker_is_rejected() {
    // Register-only: a worker with no rig is refused at channel-open, before
    // any upstream is contacted (no mock pool needed).
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let pool = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(pool.clone()),
        orders: crate::orders::OrderStore::new(pool.clone()),
    };
    // No rig registered for the worker.
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    assert!(
        miner.open("bc1qUNREGISTERED", 1).await.is_err(),
        "unregistered worker open must fail (connection closed)"
    );
    assert!(registry.get_all("bc1qUNREGISTERED").await.is_empty());
}

/// A mock pool that groups the Extended channel the way the real pool does:
/// its OpenSuccess carries a distinct `group_channel_id`, and it then
/// broadcasts ONE `NewExtendedMiningJob` addressed to that GROUP id (not the
/// channel id). Exercises the proxy's group-id remapping.
async fn mock_pool_group(listener: TcpListener, keys: NoiseKeys) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("pool noise: {e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    while let Ok(mut f) = read_one(&mut read).await {
        if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
            let Some(open) = parse_miner_open(&mut f) else {
                continue;
            };
            // Channel id 10, a DISTINCT group id 77 (mimics the pool's group).
            let success =
                Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
                    request_id: open.spec.request_id(),
                    channel_id: 10,
                    target: U256::try_from(diff1_target()).unwrap(),
                    extranonce_size: 8,
                    extranonce_prefix: B032::try_from(vec![0xCC; 8]).unwrap(),
                    group_channel_id: 77,
                });
            write
                .write_frame(wire::frame_from(AnyMessage::Mining(success)))
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
            // The job is broadcast to the GROUP id (77), not the channel (10).
            let empty_path: Vec<U256> = vec![];
            let job = mining::NewExtendedMiningJob {
                channel_id: 77,
                job_id: 1,
                min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                version: 0x2000_0000,
                version_rolling_allowed: true,
                merkle_path: empty_path.into(),
                coinbase_tx_prefix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                coinbase_tx_suffix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
            };
            write
                .write_frame(wire::frame_from(AnyMessage::Mining(
                    Mining::NewExtendedMiningJob(job),
                )))
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn group_broadcast_job_reaches_miner() {
    // Regression: Extended channels are grouped, so the pool broadcasts
    // NewExtendedMiningJob to the group_channel_id — not the channel id. The
    // proxy must remap the group id into its downstream namespace, else the
    // job is dropped (down_cid=None) and the miner never starts real work.
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pool.local_addr().unwrap();
    tokio::spawn(mock_pool_group(pool, NoiseKeys::generate()));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&addr.to_string(), "acct"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, down_group, prefix) = miner.open_full("bc1qSELLER.rig1", 1).await.unwrap();
    assert_eq!(
        prefix,
        vec![0xCC; 8],
        "miner sees the pool's extranonce prefix"
    );
    assert_ne!(
        down_group, 0,
        "Extended OpenSuccess carries a remapped group id"
    );
    assert_ne!(
        down_group, down_cid,
        "group id is distinct from the channel id"
    );

    // The group-broadcast job must reach the miner, remapped to the
    // downstream group id (before the fix it was dropped as unmapped).
    let job_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await
    .expect("group-broadcast job was dropped (not remapped) — timed out")
    .unwrap();
    assert_eq!(
        job_cid, down_group,
        "group-broadcast job remapped to the downstream group id"
    );
}

/// A pool that completes the channel open (cid 99) and then *immediately*
/// broadcasts a `NewExtendedMiningJob` addressed to that channel — like a real
/// pool bootstrapping a freshly opened channel right after its OpenSuccess.
async fn mock_pool_job_after_open(
    listener: TcpListener,
    keys: NoiseKeys,
) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("pool noise: {e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    while let Ok(mut f) = read_one(&mut read).await {
        if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
            let Some(open) = parse_miner_open(&mut f) else {
                continue;
            };
            let info = ChannelInfo {
                request_id: open.spec.request_id(),
                up_channel_id: 99,
                extranonce_prefix: vec![0xBB; 8],
                target: diff1_target(),
                extranonce_size: 8,
                group_channel_id: 0,
            };
            write
                .write_frame(open_success_downstream(&open.spec, 99, 0, &info)?)
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
            // Bootstrap job, sent right after OpenSuccess to the channel id.
            let empty_path: Vec<U256> = vec![];
            let job = mining::NewExtendedMiningJob {
                channel_id: 99,
                job_id: 7,
                min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                version: 0x2000_0000,
                version_rolling_allowed: true,
                merkle_path: empty_path.into(),
                coinbase_tx_prefix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
                coinbase_tx_suffix: stratum_core::binary_sv2::B064K::try_from(vec![]).unwrap(),
            };
            write
                .write_frame(wire::frame_from(AnyMessage::Mining(
                    Mining::NewExtendedMiningJob(job),
                )))
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn switch_delivers_new_upstream_initial_job() {
    // Regression: on a rental switch the proxy opens a fresh channel on the
    // new upstream, then the steady reader takes over the same socket. The
    // job the new pool broadcasts right after OpenSuccess must reach the miner
    // (remapped to its stable downstream channel id) — i.e. the reader must
    // already be on the new generation when it processes that first frame, and
    // the post-OpenSuccess frames buffered on the socket must not be lost.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool_job_after_open(pool_b, NoiseKeys::generate()));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    // Rent: switch onto pool B, which sends a job right after the reopen.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();

    // The new upstream's bootstrap job must reach the miner, remapped to the
    // stable downstream channel id (read_until_cid skips the switch's
    // SetExtranoncePrefix/SetTarget re-point frames).
    let job_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await
    .expect("new upstream's post-switch job was dropped — timed out")
    .unwrap();
    assert_eq!(
        job_cid, down_cid,
        "post-switch job remapped to the stable downstream channel id"
    );
}

/// A pool that completes one channel open then drops the connection AND its
/// listener — simulating a pool that goes away mid-rental (reconnects refused).
async fn mock_pool_drop_once(listener: TcpListener, keys: NoiseKeys) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("pool noise: {e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    while let Ok(mut f) = read_one(&mut read).await {
        if wire::msg_type(&f) == Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) {
            let Some(open) = parse_miner_open(&mut f) else {
                continue;
            };
            let info = ChannelInfo {
                request_id: open.spec.request_id(),
                up_channel_id: 99,
                extranonce_prefix: vec![0xBB; 8],
                target: diff1_target(),
                extranonce_size: 8,
                group_channel_id: 0,
            };
            write
                .write_frame(open_success_downstream(&open.spec, 99, 0, &info)?)
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
            break;
        }
    }
    // Return → drops the connection (EOF to the proxy) + the listener (port
    // freed), so the proxy's reconnect to the primary is refused → fail over.
    Ok(())
}

#[tokio::test]
async fn mid_rental_failover_to_fallback_on_primary_drop() {
    // Rental primary serves the open then drops; the supervisor must reconnect,
    // find the primary gone, and fail over to the fallback pool.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary_addr = primary.local_addr().unwrap();
    let pool_fb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fb_addr = pool_fb.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (fb_tx, _fb_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool_drop_once(primary, NoiseKeys::generate()));
    tokio::spawn(mock_pool(
        pool_fb,
        vec![0xCC; 8],
        55,
        NoiseKeys::generate(),
        fb_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(db.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (_down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    let order = orders
        .create(
            "bc1qSELLER.rig1".into(),
            ext_target(&primary_addr.to_string(), "acctP"),
            Some(ext_target(&fb_addr.to_string(), "acctFB")),
            0,
            0.0,
            0.0,
        )
        .await
        .unwrap();
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    // Lands on the primary; the primary then drops → supervisor fails over.
    sess.switch_to_order(order.id.clone()).await.unwrap();

    // The miner is eventually re-pointed to the fallback (0xCC) by the supervisor.
    let mut got_fb = false;
    for _ in 0..50 {
        let res =
            tokio::time::timeout(Duration::from_secs(5), miner.read_until_set_extranonce())
                .await;
        let Ok(Ok((_, prefix))) = res else { break };
        if prefix == vec![0xCC; 8] {
            got_fb = true;
            break;
        }
    }
    assert!(
        got_fb,
        "supervisor failed the dropped primary over to the fallback pool"
    );
}

#[tokio::test]
async fn switch_falls_back_when_primary_pool_is_down() {
    // Rental primary points at a dead port; fallback = a live pool. switch_to_order
    // must try the primary, fail fast, and land on the fallback.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead); // free the port → connect refused
    let pool_fb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fb_addr = pool_fb.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (fb_tx, _fb_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_fb,
        vec![0xCC; 8],
        55,
        NoiseKeys::generate(),
        fb_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(db.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    let order = orders
        .create(
            "bc1qSELLER.rig1".into(),
            ext_target(&dead_addr.to_string(), "acctDead"),
            Some(ext_target(&fb_addr.to_string(), "acctFB")),
            0,
            0.0,
            0.0,
        )
        .await
        .unwrap();

    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.switch_to_order(order.id.clone()).await.unwrap();

    // Landed on the fallback: the miner is re-pointed to FB's extranonce prefix.
    let (re_cid, prefix) = miner.read_until_set_extranonce().await.unwrap();
    assert_eq!(
        prefix,
        vec![0xCC; 8],
        "primary down → switched to fallback pool"
    );
    assert_eq!(re_cid, down_cid);
    assert_eq!(sess.status().await.routing, "rented");
}

#[tokio::test]
async fn force_reconnect_drops_the_miner_connection() {
    // An operator pool change (idle-pool edit / rent / revert) calls
    // force_reconnect; the proxy must close the miner connection so it
    // reconnects and re-handshakes against the new upstream — instead of a
    // live re-point the miner might ignore and keep wasting shares on.
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pool_addr = pool.local_addr().unwrap();
    let (tx, _rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(pool, vec![0xAB; 8], 9, NoiseKeys::generate(), tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(db.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        // Short idle-grace so the post-drop deregistration is observable in the
        // test window (the miner here does not reconnect).
        sv2_rigs: Arc::new(Sv2RigRegistry::with_grace(Duration::from_millis(50))),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&pool_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    // Grab the live session and force a reconnect.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    sess.force_reconnect();

    // The miner's connection must close (drain any queued frames first).
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if read_one(&mut miner.read).await.is_err() {
                return true;
            }
        }
    })
    .await
    .expect("force_reconnect should close the miner connection within 5s");
    assert!(closed);
    // And the session is deregistered after the connection tears down.
    let gone = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if registry.get_all("bc1qSELLER.rig1").await.is_empty() {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session should deregister after a forced reconnect");
    assert!(gone);
}

#[tokio::test]
async fn connect_with_active_rental_opens_on_buyer_directly() {
    // Reconnect-resume: when an order is already active as the miner connects,
    // the first channel opens straight on the buyer's pool (no idle-then-switch
    // round-trip) and the session reads rented immediately.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap(); // rig idle pool
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap(); // buyer pool
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(db.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    // Rental already active for this worker, targeting buyer pool B.
    let order = orders
        .create(
            "bc1qSELLER.rig1".into(),
            ext_target(&b_addr.to_string(), "acctB"),
            None,
            0,
            0.0,
            0.0,
        )
        .await
        .unwrap();

    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (_down_cid, prefix) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
    assert_eq!(
        prefix,
        vec![0xBB; 8],
        "first channel opened directly on the buyer pool"
    );

    let st = loop {
        if let Some(s) = registry.aggregated_status("bc1qSELLER.rig1").await {
            break s;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(st.routing, "rented", "session is rented on connect");
    assert_eq!(st.order_id.as_deref(), Some(order.id.as_str()));
}

#[tokio::test]
async fn concurrent_switches_leave_a_consistent_session() {
    // Two switches fired at once must serialize (the switch lock) and leave the
    // session internally consistent: `routing`/`order_id` agree with the active
    // upstream, and a submit reaches exactly that pool on its remapped cid.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let pool_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c_addr = pool_c.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel::<u32>();
    let (c_tx, mut c_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));
    tokio::spawn(mock_pool(
        pool_c,
        vec![0xCC; 8],
        199,
        NoiseKeys::generate(),
        c_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, _) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();

    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };

    // Fire both switches concurrently; the switch lock serializes them.
    let b_url = b_addr.to_string();
    let c_url = c_addr.to_string();
    let (rb, rc) = tokio::join!(
        sess.switch_to("oB".to_string(), ext_target(&b_url, "acctB")),
        sess.switch_to("oC".to_string(), ext_target(&c_url, "acctC")),
    );
    rb.unwrap();
    rc.unwrap();

    // Whichever won, routing/order and the active upstream must agree, and a
    // submit must reach that same pool (its remapped upstream cid).
    let st = sess.status().await;
    assert_eq!(st.routing, "rented");
    miner.submit(down_cid, 0).await.unwrap();
    match st.order_id.as_deref() {
        Some("oB") => {
            assert_eq!(
                st.upstream_url, b_url,
                "active matches the winning order (B)"
            );
            assert_eq!(b_rx.recv().await.unwrap(), 99, "submit reached pool B");
        }
        Some("oC") => {
            assert_eq!(
                st.upstream_url, c_url,
                "active matches the winning order (C)"
            );
            assert_eq!(c_rx.recv().await.unwrap(), 199, "submit reached pool C");
        }
        other => panic!("unexpected winning order {other:?}"),
    }
}

#[tokio::test]
async fn same_worker_miners_form_one_rig_switched_together() {
    // MRR model: 2 miners under the SAME worker name = one rig. They are
    // BUNDLED onto one shared upstream (one connection, two channels); renting
    // switches the rig (both members at once) and the status covers both.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool_multi(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    // Two miners, SAME worker name → both bundle onto ONE shared upstream to
    // pool A (the second attaches as a member, no second upstream).
    let mut m1 = MockMiner::connect(proxy_addr).await.unwrap();
    m1.setup().await.unwrap();
    let (cid1, p1) = m1.open("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p1, vec![0xAA; 8], "miner 1 on seller default pool A");
    let mut m2 = MockMiner::connect(proxy_addr).await.unwrap();
    m2.setup().await.unwrap();
    let (_cid2, p2) = m2.open("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p2, vec![0xAA; 8], "miner 2 on seller default pool A");

    // Bundled into ONE rig session (one shared upstream), not two.
    let sessions = loop {
        let s = registry.get_all("bc1qSELLER.farm").await;
        if s.len() == 1 {
            break s;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(sessions.len(), 1, "two same-rig miners → one shared session");

    // Rent the rig: switching the single session re-points BOTH members.
    sessions[0]
        .switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();

    // BOTH miners get re-pointed to pool B (new prefix), same channel id.
    let (rc1, rp1) = m1.read_until_set_extranonce().await.unwrap();
    assert_eq!(rp1, vec![0xBB; 8], "miner 1 switched to pool B");
    assert_eq!(rc1, cid1, "miner 1 keeps its downstream channel id");
    let (_rc2, rp2) = m2.read_until_set_extranonce().await.unwrap();
    assert_eq!(rp2, vec![0xBB; 8], "miner 2 switched to pool B");

    // The rig reads as rented.
    let st = registry.aggregated_status("bc1qSELLER.farm").await.unwrap();
    assert_eq!(st.routing, "rented", "the whole rig is rented");
}

#[tokio::test]
async fn bundled_member_can_leave_and_rejoin_without_dropping_the_rig() {
    // A bundled member disconnecting must NOT tear the rig down: the others
    // keep mining on the shared upstream, and a later (re)connect attaches as
    // a fresh member rather than opening a second upstream.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    // Two same-rig miners bundle onto one shared upstream.
    let mut m1 = MockMiner::connect(proxy_addr).await.unwrap();
    m1.setup().await.unwrap();
    let (_cid1, _) = m1.open("bc1qSELLER.farm", 1).await.unwrap();
    let mut m2 = MockMiner::connect(proxy_addr).await.unwrap();
    m2.setup().await.unwrap();
    let (cid2, _) = m2.open("bc1qSELLER.farm", 1).await.unwrap();

    loop {
        if registry.get_all("bc1qSELLER.farm").await.len() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // Miner 1 leaves the bundle.
    drop(m1);

    // Miner 2 keeps mining on the shared upstream: its share still reaches A.
    m2.submit(cid2, 1).await.unwrap();
    a_rx
        .recv()
        .await
        .expect("miner 2 share reaches pool A after miner 1 left");

    // The rig is still the one shared session (a member leaving didn't drop it).
    assert_eq!(
        registry.get_all("bc1qSELLER.farm").await.len(),
        1,
        "rig survives a member leaving"
    );

    // A new same-rig miner rejoins the SAME rig (attaches; no second session).
    let mut m3 = MockMiner::connect(proxy_addr).await.unwrap();
    m3.setup().await.unwrap();
    let (_cid3, p3) = m3.open("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p3, vec![0xAA; 8], "rejoining miner lands on the shared pool A");
    assert_eq!(
        registry.get_all("bc1qSELLER.farm").await.len(),
        1,
        "rejoin attaches to the existing rig, not a new session"
    );
}

#[tokio::test]
async fn three_same_rig_miners_bundle_and_switch_together() {
    // Three miners under one worker share a single upstream; renting the rig
    // re-points all three members to the buyer pool at once.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let pool_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = pool_b.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    let (b_tx, _b_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));
    tokio::spawn(mock_pool_multi(
        pool_b,
        vec![0xBB; 8],
        99,
        NoiseKeys::generate(),
        b_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    // Three same-rig miners (connected one after another so each bundles onto
    // the rig the first one created).
    let mut miners = Vec::new();
    let mut cids = Vec::new();
    for _ in 0..3 {
        let mut m = MockMiner::connect(proxy_addr).await.unwrap();
        m.setup().await.unwrap();
        let (cid, p) = m.open("bc1qSELLER.farm", 1).await.unwrap();
        assert_eq!(p, vec![0xAA; 8], "miner on shared pool A");
        cids.push(cid);
        miners.push(m);
    }

    let sessions = loop {
        let s = registry.get_all("bc1qSELLER.farm").await;
        if s.len() == 1 {
            break s;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(sessions.len(), 1, "three same-rig miners → one shared session");

    // Rent: switching the single session re-points ALL three members.
    sessions[0]
        .switch_to("o1".to_string(), ext_target(&b_addr.to_string(), "acctB"))
        .await
        .unwrap();
    for (i, m) in miners.iter_mut().enumerate() {
        let (rc, rp) = m.read_until_set_extranonce().await.unwrap();
        assert_eq!(rp, vec![0xBB; 8], "miner {i} switched to pool B");
        assert_eq!(rc, cids[i], "miner {i} keeps its downstream channel id");
    }
}

#[tokio::test]
async fn simultaneous_same_worker_connects_form_one_rig() {
    // Two miners connecting at the same time must still form ONE rig: the
    // per-worker gate serializes create-or-attach so they don't each build an
    // upstream (which would register two sessions).
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    // Drive both connect→setup→open flows concurrently.
    let flow = |addr| async move {
        let mut m = MockMiner::connect(addr).await.unwrap();
        m.setup().await.unwrap();
        m.open("bc1qSELLER.farm", 1).await.unwrap();
        m
    };
    let (_m1, _m2) = tokio::join!(flow(proxy_addr), flow(proxy_addr));

    // Never more than one session, and it settles at exactly one.
    loop {
        let n = registry.get_all("bc1qSELLER.farm").await.len();
        assert!(n <= 1, "the gate must prevent a second rig (saw {n})");
        if n == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn idle_rig_is_reaped_after_grace() {
    // A single-miner rig whose member leaves and does NOT return is reaped
    // after the idle-grace window: the upstream closes and the slot frees.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let (a_tx, _a_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Arc::new(Sv2RigRegistry::with_grace(Duration::from_millis(150))),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    let mut m = MockMiner::connect(proxy_addr).await.unwrap();
    m.setup().await.unwrap();
    m.open("bc1qSELLER.farm", 1).await.unwrap();
    loop {
        if registry.get_all("bc1qSELLER.farm").await.len() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // Member leaves for good → reaped after the grace window.
    drop(m);
    let reaped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if registry.get_all("bc1qSELLER.farm").await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(reaped.is_ok(), "idle rig reaped after the grace window");
}

#[tokio::test]
async fn reconnect_within_grace_reuses_the_warm_rig() {
    // The last member leaves, but a new same-rig miner reconnects within the
    // grace window: it attaches to the still-warm upstream and the reaper does
    // NOT close the rig.
    let pool_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = pool_a.local_addr().unwrap();
    let (a_tx, mut a_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_multi(
        pool_a,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        a_tx,
    ));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Arc::new(Sv2RigRegistry::with_grace(Duration::from_millis(500))),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&a_addr.to_string(), "acctA"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    let mut m1 = MockMiner::connect(proxy_addr).await.unwrap();
    m1.setup().await.unwrap();
    m1.open("bc1qSELLER.farm", 1).await.unwrap();
    loop {
        if registry.get_all("bc1qSELLER.farm").await.len() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // Last member leaves → grace starts. Reconnect well within the window.
    drop(m1);
    let mut m2 = MockMiner::connect(proxy_addr).await.unwrap();
    m2.setup().await.unwrap();
    let (c2, p2) = m2.open("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p2, vec![0xAA; 8], "reconnect attaches to the warm pool A upstream");

    // Past the grace window the rig is still alive (the reaper saw a member).
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        registry.get_all("bc1qSELLER.farm").await.len(),
        1,
        "warm rig survived; the reconnect reused it"
    );
    // And the reused upstream still works: m2's share reaches pool A.
    m2.submit(c2, 1).await.unwrap();
    a_rx
        .recv()
        .await
        .expect("share over the reused warm upstream reaches pool A");
}

/// A mock pool for a mixed rig: replies to an Extended open with a grouped
/// channel (group id 77) and broadcasts a `NewExtendedMiningJob` to that group;
/// replies to a Standard open with an UNGROUPED channel (group id 0). Reports
/// each submit's channel id.
async fn mock_pool_mixed(
    listener: TcpListener,
    keys: NoiseKeys,
    submits: mpsc::UnboundedSender<u32>,
) -> anyhow::Result<()> {
    let (sock, _) = listener.accept().await?;
    let _ = sock.set_nodelay(true);
    let stream =
        accept_noise_connection::<Msg>(sock, keys.public(), keys.secret(), CERT_VALIDITY)
            .await
            .map_err(|e| anyhow!("pool noise: {e:?}"))?;
    let (mut read, mut write) = stream.into_split();
    loop {
        let f = read_one(&mut read).await?;
        if wire::msg_type(&f) == Some(common::MESSAGE_TYPE_SETUP_CONNECTION) {
            break;
        }
    }
    write
        .write_frame(setup_success(0))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    while let Ok(mut f) = read_one(&mut read).await {
        match wire::msg_type(&f) {
            Some(mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) => {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                // Extended channel 10, grouped under group id 77.
                let success = Mining::OpenExtendedMiningChannelSuccess(
                    OpenExtendedMiningChannelSuccess {
                        request_id: open.spec.request_id(),
                        channel_id: 10,
                        target: U256::try_from(diff1_target()).unwrap(),
                        extranonce_size: 8,
                        extranonce_prefix: B032::try_from(vec![0xAA; 8]).unwrap(),
                        group_channel_id: 77,
                    },
                );
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(success)))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
                // Broadcast a job addressed to the GROUP id (77).
                let empty_path: Vec<U256> = vec![];
                let job = mining::NewExtendedMiningJob {
                    channel_id: 77,
                    job_id: 1,
                    min_ntime: stratum_core::binary_sv2::Sv2Option::new(None),
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path: empty_path.into(),
                    coinbase_tx_prefix: stratum_core::binary_sv2::B064K::try_from(vec![])
                        .unwrap(),
                    coinbase_tx_suffix: stratum_core::binary_sv2::B064K::try_from(vec![])
                        .unwrap(),
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::NewExtendedMiningJob(job),
                    )))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL) => {
                let Some(open) = parse_miner_open(&mut f) else {
                    continue;
                };
                // Standard channel 20, UNGROUPED (group_channel_id 0).
                let success = Mining::OpenStandardMiningChannelSuccess(
                    OpenStandardMiningChannelSuccess {
                        request_id: U32AsRef::from(open.spec.request_id()),
                        channel_id: 20,
                        target: U256::try_from(diff1_target()).unwrap(),
                        extranonce_prefix: B032::try_from(vec![0xBB; 8]).unwrap(),
                        group_channel_id: 0,
                    },
                );
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(success)))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD)
            | Some(mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) => {
                let Some(cid) = wire::read_channel_id(&mut f) else {
                    continue;
                };
                let _ = submits.send(cid);
                let ok = SubmitSharesSuccess {
                    channel_id: cid,
                    last_sequence_number: 0,
                    new_submits_accepted_count: 1,
                    new_shares_sum: 1,
                };
                write
                    .write_frame(wire::frame_from(AnyMessage::Mining(
                        Mining::SubmitSharesSuccess(ok),
                    )))
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[tokio::test]
async fn mixed_standard_and_extended_members_share_one_rig() {
    // A Standard miner and an Extended miner under the same worker bundle onto
    // ONE upstream. The Extended member is grouped and receives the group
    // broadcast; the Standard member is ungrouped and must NOT get that
    // group-addressed NewExtendedMiningJob. Both can submit on the shared link.
    let pool = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pool.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool_mixed(pool, NoiseKeys::generate(), tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.farm",
        ext_target(&addr.to_string(), "acct"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = proxy.accept().await.unwrap();
            let ctx = ctx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
            });
        }
    });

    // Standard member first.
    let mut m_std = MockMiner::connect(proxy_addr).await.unwrap();
    m_std.setup().await.unwrap();
    let (cid_std, p_std) = m_std.open_standard("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p_std, vec![0xBB; 8], "standard member sees its prefix");

    // Extended member second → triggers the group broadcast while BOTH are
    // attached, so the fan-out decision sees the Standard member too.
    let mut m_ext = MockMiner::connect(proxy_addr).await.unwrap();
    m_ext.setup().await.unwrap();
    let (cid_ext, down_group, p_ext) = m_ext.open_full("bc1qSELLER.farm", 1).await.unwrap();
    assert_eq!(p_ext, vec![0xAA; 8], "extended member sees its prefix");
    assert_ne!(down_group, 0, "extended member is grouped");

    // Standard + Extended under one worker → one shared session.
    loop {
        if registry.get_all("bc1qSELLER.farm").await.len() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // The Extended member receives the group job (remapped to its group id).
    let job_cid = tokio::time::timeout(
        Duration::from_secs(5),
        m_ext.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await
    .expect("extended member should receive the group job")
    .unwrap();
    assert_eq!(
        job_cid, down_group,
        "group job remapped to the extended member's group id"
    );

    // The Standard member must NOT receive the group-addressed extended job.
    let leaked = tokio::time::timeout(
        Duration::from_millis(300),
        m_std.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await;
    assert!(
        leaked.is_err(),
        "standard member must not receive the group's NewExtendedMiningJob"
    );

    // Both members are live on the shared upstream: their submits reach the
    // pool on distinct channels.
    m_std.submit_standard(cid_std, 1).await.unwrap();
    m_ext.submit(cid_ext, 1).await.unwrap();
    let mut seen = std::collections::HashSet::new();
    seen.insert(rx.recv().await.expect("a submit reaches the pool"));
    seen.insert(rx.recv().await.expect("a submit reaches the pool"));
    assert_eq!(
        seen.len(),
        2,
        "both members' submits reached the pool on distinct channels"
    );
}

/// A mock SV1 pool for the translate path: configure(version-rolling) →
/// subscribe (extranonce1 `deadbeefcafebabe`, en2=8) + a set_difficulty and a
/// `mining.notify`, then accepts every `mining.submit`. Reports each submit.
async fn mock_sv1_pool_translate(listener: TcpListener, submits: mpsc::UnboundedSender<()>) {
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        let submits = submits.clone();
        tokio::spawn(async move {
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let id = v.get("id").cloned().unwrap_or(Value::Null);
                match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
                    "mining.configure" => {
                        let reply = json!({"id": id, "result": {"version-rolling": true, "version-rolling.mask": "1fffe000"}, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    "mining.subscribe" => {
                        let reply = json!({"id": id, "result": [[["mining.notify", "1"]], "deadbeefcafebabe", 8], "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        let sd = json!({"id": Value::Null, "method": "mining.set_difficulty", "params": [1024.0]});
                        let _ = w.write_all(format!("{sd}\n").as_bytes()).await;
                        let notify = json!({"id": Value::Null, "method": "mining.notify", "params": ["j1", "0000000000000000000000000000000000000000000000000000000000000000", "01000000", "00000000", [], "20000000", "17072cf6", "65000000", true]});
                        let _ = w.write_all(format!("{notify}\n").as_bytes()).await;
                    }
                    "mining.authorize" => {
                        let reply = json!({"id": id, "result": true, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    "mining.submit" => {
                        let _ = submits.send(());
                        let reply = json!({"id": id, "result": true, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    _ => {}
                }
            }
        });
    }
}

#[tokio::test]
async fn sv2_miner_rented_onto_sv1_pool_translates_end_to_end() {
    // The rig's idle pool is SV1, so the SV2 miner is served via translation:
    // the proxy is the SV1 client and synthesizes the miner's Extended channel.
    let sv1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sv1_addr = sv1.local_addr().unwrap();
    let (sub_tx, mut sub_rx) = mpsc::unbounded_channel::<()>();
    tokio::spawn(mock_sv1_pool_translate(sv1, sub_tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&sv1_addr.to_string(), "acctSV1"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    // The SV2-native connect probe to the SV1 pool must time out before the
    // proxy falls back to SV1 translation, so allow generous time for open().
    let (down_cid, prefix) =
        tokio::time::timeout(Duration::from_secs(15), miner.open("bc1qSELLER.rig1", 1))
            .await
            .expect("open did not complete")
            .unwrap();
    assert_eq!(
        prefix,
        vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        "Extended channel prefix = the SV1 extranonce1"
    );

    // The translated job (built from the SV1 mining.notify) reaches the miner.
    let job_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await
    .expect("translated job timed out")
    .unwrap();
    assert_eq!(job_cid, down_cid, "job addressed to the miner's channel");

    // Submit → translated to a mining.submit on the SV1 pool.
    miner.submit(down_cid, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), sub_rx.recv())
        .await
        .expect("share never reached the SV1 pool")
        .unwrap();

    // The pool's accept is translated back to a SubmitSharesSuccess.
    let ok_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
    )
    .await
    .expect("share result timed out")
    .unwrap();
    assert_eq!(ok_cid, down_cid, "translated share accepted end to end");

    // Accounting credited the delivered work.
    let sess = registry
        .get_all("bc1qSELLER.rig1")
        .await
        .into_iter()
        .next()
        .unwrap();
    let st = sess.status().await;
    assert!(st.accepted_shares >= 1, "accepted share counted");
    assert!(st.delivered_work > 0.0, "delivered work credited");
}

#[tokio::test]
async fn rent_sv2_miner_switches_onto_sv1_pool() {
    // Idle on an SV2 pool (passthrough), then rented onto an SV1 buyer pool —
    // the switch must translate (swap_to_sv1_translate) and re-point the miner.
    let sv2_idle = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idle_addr = sv2_idle.local_addr().unwrap();
    let (idle_tx, _idle_rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(mock_pool(
        sv2_idle,
        vec![0xAA; 8],
        7,
        NoiseKeys::generate(),
        idle_tx,
    ));
    let sv1_buyer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let buyer_addr = sv1_buyer.local_addr().unwrap();
    let (sub_tx, mut sub_rx) = mpsc::unbounded_channel::<()>();
    tokio::spawn(mock_sv1_pool_translate(sv1_buyer, sub_tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let orders = crate::orders::OrderStore::new(db.clone());
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: orders.clone(),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&idle_addr.to_string(), "acctIdle"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, prefix) = miner.open("bc1qSELLER.rig1", 1).await.unwrap();
    assert_eq!(prefix, vec![0xAA; 8], "idle on the SV2 pool (passthrough)");

    // Rent onto the SV1 buyer pool → translated switch.
    let sess = loop {
        if let Some(s) = registry.get_all("bc1qSELLER.rig1").await.into_iter().next() {
            break s;
        }
        tokio::task::yield_now().await;
    };
    let buyer = ext_target(&buyer_addr.to_string(), "acctBuyer");
    let order = orders
        .create("bc1qSELLER.rig1".into(), buyer.clone(), None, 0, 0.0, 0.0)
        .await
        .unwrap();
    sess.switch_to(order.id.clone(), buyer).await.unwrap();

    // Re-pointed to the SV1 extranonce, then a translated job + accepted share.
    let (re_cid, re_prefix) =
        tokio::time::timeout(Duration::from_secs(15), miner.read_until_set_extranonce())
            .await
            .expect("set_extranonce after the translated switch")
            .unwrap();
    assert_eq!(re_cid, down_cid, "channel id stable across the switch");
    assert_eq!(
        re_prefix,
        vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        "now on the SV1 extranonce1"
    );
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB),
    )
    .await
    .expect("translated job after switch")
    .unwrap();
    miner.submit(down_cid, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), sub_rx.recv())
        .await
        .expect("share reached the SV1 buyer pool")
        .unwrap();
    assert_eq!(sess.status().await.routing, "rented");
}

// ── self-validating combo 4: a real mined share, validated by the pool ──

/// `a <= b` for two 32-byte little-endian numbers (Bitcoin hash vs target).
fn le_leq(a: &[u8], b: &[u8]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    true
}

/// A legacy coinbase split reserving `en_len` bytes for the extranonce so
/// `coinb1 + extranonce + coinb2` deserializes as a valid transaction.
fn legacy_cb_reserving(en_len: usize) -> (Vec<u8>, Vec<u8>) {
    let script_prefix = [0x03u8, 0x33, 0x33, 0x33];
    let ssl = script_prefix.len() + en_len;
    let mut c1 = Vec::new();
    c1.extend_from_slice(&1u32.to_le_bytes());
    c1.push(0x01);
    c1.extend_from_slice(&[0u8; 32]);
    c1.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    c1.push(ssl as u8);
    c1.extend_from_slice(&script_prefix);
    let mut c2 = Vec::new();
    c2.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    c2.push(0x01);
    c2.extend_from_slice(&5_000_000_000u64.to_le_bytes());
    c2.push(0x00);
    c2.extend_from_slice(&0u32.to_le_bytes());
    (c1, c2)
}

/// Read the SV2 job/prev-hash/target, mine a real nonce that meets the target,
/// and submit it — exercising the full coinbase (prefix+extranonce+suffix) and
/// header reconstruction the SV1 pool will independently re-check.
async fn mine_and_submit_one(
    miner: &mut MockMiner,
    channel_id: u32,
    extranonce_prefix: Vec<u8>,
) -> anyhow::Result<()> {
    use stratum_core::bitcoin::hashes::{sha256d, Hash};
    use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;

    let mut job: Option<(u32, u32, Vec<u8>, Vec<u8>)> = None; // job_id, version, cb_prefix, cb_suffix
    let mut prev: Option<([u8; 32], u32, u32)> = None; // prev_hash, min_ntime, nbits
    let mut target: Option<Vec<u8>> = None;
    for _ in 0..50 {
        let mut f = read_one(&mut miner.read).await?;
        match wire::msg_type(&f) {
            Some(mt) if mt == mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB => {
                if let Some(m) = parse_new_extended_job(&mut f) {
                    job = Some((
                        m.job_id,
                        m.version,
                        m.coinbase_tx_prefix.inner_as_ref().to_vec(),
                        m.coinbase_tx_suffix.inner_as_ref().to_vec(),
                    ));
                }
            }
            Some(mt) if mt == mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH => {
                if let Some(m) = parse_set_new_prev_hash(&mut f) {
                    let ph: [u8; 32] = m.prev_hash.inner_as_ref().try_into().unwrap();
                    prev = Some((ph, m.min_ntime, m.nbits));
                }
            }
            Some(mt) if mt == mining::MESSAGE_TYPE_SET_TARGET => {
                if let Some(t) = parse_set_target(&mut f) {
                    target = Some(t);
                }
            }
            _ => {}
        }
        if job.is_some() && prev.is_some() && target.is_some() {
            break;
        }
    }
    let (job_id, version, cb_prefix, cb_suffix) = job.ok_or_else(|| anyhow!("no job"))?;
    let (prev_hash, min_ntime, nbits) = prev.ok_or_else(|| anyhow!("no prev-hash"))?;
    let target = target.ok_or_else(|| anyhow!("no target"))?;

    // Full extranonce = the channel prefix + the miner's rolled part.
    let miner_extranonce = vec![0u8, 0, 0, 1];
    let mut full_en = extranonce_prefix;
    full_en.extend_from_slice(&miner_extranonce);
    let empty: Vec<Vec<u8>> = vec![];
    let merkle_root = merkle_root_from_path(&cb_prefix, &cb_suffix, &full_en, &empty)
        .ok_or_else(|| anyhow!("coinbase did not deserialize"))?;

    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(&version.to_le_bytes());
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&min_ntime.to_le_bytes());
    header.extend_from_slice(&nbits.to_le_bytes());
    let noff = header.len();
    header.extend_from_slice(&0u32.to_le_bytes());
    let mut nonce = None;
    for n in 0u32..5_000_000 {
        header[noff..noff + 4].copy_from_slice(&n.to_le_bytes());
        if le_leq(&sha256d::Hash::hash(&header).to_byte_array(), &target) {
            nonce = Some(n);
            break;
        }
    }
    let nonce = nonce.ok_or_else(|| anyhow!("no winning nonce"))?;

    let m = SubmitSharesExtended {
        channel_id,
        sequence_number: 0,
        job_id,
        nonce,
        ntime: min_ntime,
        version,
        extranonce: B032::try_from(miner_extranonce).unwrap(),
    };
    miner
        .write
        .write_frame(wire::frame_from(AnyMessage::Mining(
            Mining::SubmitSharesExtended(m),
        )))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(())
}

/// A mock SV1 pool that *validates* each submitted share: it reconstructs the
/// coinbase (`coinb1 + extranonce1 + extranonce2 + coinb2`), the merkle root,
/// and the 80-byte header, and accepts only if SHA256d ≤ the share target.
async fn validating_sv1_pool(listener: TcpListener, accepted: mpsc::UnboundedSender<bool>) {
    use stratum_core::bitcoin::hashes::{sha256d, Hash};
    use stratum_core::channels_sv2::merkle_root::merkle_root_from_path;
    use stratum_core::sv1_api::utils::PrevHash as Sv1PrevHash;

    const MASK: u32 = 0x1fff_e000;
    const VERSION: u32 = 0x2000_0000;
    const NBITS: u32 = 0x207f_ffff;
    const NTIME: u32 = 0x6500_0000;
    const DIFFICULTY: f64 = 1e-9;
    let en1: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let (coinb1, coinb2) = legacy_cb_reserving(en1.len() + 4);
    let pv = [0x11u8; 32]; // internal byte order
    let pv_str = String::from(Sv1PrevHash(U256::from(pv)));
    let share_target = translate::target_from_difficulty(DIFFICULTY).to_vec();

    loop {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        let accepted = accepted.clone();
        let (en1, coinb1, coinb2, pv_str, share_target) = (
            en1.clone(),
            coinb1.clone(),
            coinb2.clone(),
            pv_str.clone(),
            share_target.clone(),
        );
        tokio::spawn(async move {
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            // Strict like ckpool: the submit worker must equal the authorized
            // worker, else "Worker mismatch" — catches the authorize≠submit bug.
            let mut authorized_worker: Option<String> = None;
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let id = v.get("id").cloned().unwrap_or(Value::Null);
                let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
                match method {
                    "mining.configure" => {
                        let reply = json!({"id": id, "result": {"version-rolling": true, "version-rolling.mask": "1fffe000"}, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    "mining.subscribe" => {
                        let reply = json!({"id": id, "result": [[["mining.notify", "1"]], hex_string(&en1), 4], "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        let sd = json!({"id": Value::Null, "method": "mining.set_difficulty", "params": [DIFFICULTY]});
                        let _ = w.write_all(format!("{sd}\n").as_bytes()).await;
                        let notify = json!({"id": Value::Null, "method": "mining.notify", "params": [
                            "j1", pv_str, hex_string(&coinb1), hex_string(&coinb2), [],
                            format!("{VERSION:08x}"), format!("{NBITS:08x}"), format!("{NTIME:08x}"), true
                        ]});
                        let _ = w.write_all(format!("{notify}\n").as_bytes()).await;
                    }
                    "mining.authorize" => {
                        authorized_worker = v
                            .get("params")
                            .and_then(|p| p.as_array())
                            .and_then(|a| a.first())
                            .and_then(|x| x.as_str())
                            .map(String::from);
                        let reply = json!({"id": id, "result": true, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    "mining.submit" => {
                        let p = v
                            .get("params")
                            .and_then(|p| p.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let submit_worker = p.first().and_then(|x| x.as_str());
                        if authorized_worker.as_deref() != submit_worker {
                            let _ = accepted.send(false);
                            let reply = json!({"id": id, "result": Value::Null, "error": [24, "Worker mismatch", Value::Null]});
                            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                            continue;
                        }
                        let en2 = p
                            .get(2)
                            .and_then(|x| x.as_str())
                            .map(hex_bytes)
                            .unwrap_or_default();
                        let ntime = p
                            .get(3)
                            .and_then(|x| x.as_str())
                            .and_then(|s| u32::from_str_radix(s, 16).ok())
                            .unwrap_or(0);
                        let nonce = p
                            .get(4)
                            .and_then(|x| x.as_str())
                            .and_then(|s| u32::from_str_radix(s, 16).ok())
                            .unwrap_or(0);
                        let vbits = p
                            .get(5)
                            .and_then(|x| x.as_str())
                            .and_then(|s| u32::from_str_radix(s, 16).ok())
                            .unwrap_or(0);

                        let mut full_en = en1.clone();
                        full_en.extend_from_slice(&en2);
                        let empty: Vec<Vec<u8>> = vec![];
                        let valid =
                            match merkle_root_from_path(&coinb1, &coinb2, &full_en, &empty) {
                                Some(root) => {
                                    let version = (VERSION & !MASK) | (vbits & MASK);
                                    let mut header = Vec::with_capacity(80);
                                    header.extend_from_slice(&version.to_le_bytes());
                                    header.extend_from_slice(&pv);
                                    header.extend_from_slice(&root);
                                    header.extend_from_slice(&ntime.to_le_bytes());
                                    header.extend_from_slice(&NBITS.to_le_bytes());
                                    header.extend_from_slice(&nonce.to_le_bytes());
                                    le_leq(
                                        &sha256d::Hash::hash(&header).to_byte_array(),
                                        &share_target,
                                    )
                                }
                                None => false,
                            };
                        let _ = accepted.send(valid);
                        let reply = json!({"id": id, "result": valid, "error": Value::Null});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    }
                    _ => {}
                }
            }
        });
    }
}

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[tokio::test]
async fn sv2_to_sv1_translated_share_is_cryptographically_valid() {
    // The end-to-end proof: an SV2 miner mines a real share against the
    // translated job; the SV1 pool independently rebuilds the coinbase +
    // header and confirms SHA256d ≤ target. A wrong extranonce split or
    // endianness anywhere makes the two headers diverge and the pool reject.
    let sv1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sv1_addr = sv1.local_addr().unwrap();
    let (acc_tx, mut acc_rx) = mpsc::unbounded_channel::<bool>();
    tokio::spawn(validating_sv1_pool(sv1, acc_tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&sv1_addr.to_string(), "acctSV1"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    let (down_cid, prefix) =
        tokio::time::timeout(Duration::from_secs(15), miner.open("bc1qSELLER.rig1", 1))
            .await
            .expect("open did not complete")
            .unwrap();
    assert_eq!(
        prefix,
        vec![0xaa, 0xbb, 0xcc, 0xdd],
        "channel prefix = SV1 extranonce1"
    );

    // Mine a real share against the translated job and submit it.
    tokio::time::timeout(
        Duration::from_secs(20),
        mine_and_submit_one(&mut miner, down_cid, prefix),
    )
    .await
    .expect("mining timed out")
    .unwrap();

    // The pool validated the reconstructed header and accepted it.
    let valid = tokio::time::timeout(Duration::from_secs(5), acc_rx.recv())
        .await
        .expect("pool never saw the share")
        .unwrap();
    assert!(
        valid,
        "the translated share must be cryptographically valid at the SV1 pool"
    );

    // The acceptance is translated back to the miner.
    let ok_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
    )
    .await
    .expect("share result timed out")
    .unwrap();
    assert_eq!(ok_cid, down_cid);
}

/// A header-only Standard miner: it gets a finished `merkle_root` in
/// `NewMiningJob` (the proxy built the coinbase), grinds a nonce against the
/// header, and submits `SubmitSharesStandard` (no extranonce).
async fn mine_standard_and_submit_one(
    miner: &mut MockMiner,
    channel_id: u32,
) -> anyhow::Result<()> {
    use stratum_core::bitcoin::hashes::{sha256d, Hash};

    let mut job: Option<([u8; 32], u32, u32)> = None; // merkle_root, version, job_id
    let mut prev: Option<([u8; 32], u32, u32)> = None; // prev_hash, min_ntime, nbits
    let mut target: Option<Vec<u8>> = None;
    for _ in 0..50 {
        let mut f = read_one(&mut miner.read).await?;
        match wire::msg_type(&f) {
            Some(mt) if mt == mining::MESSAGE_TYPE_NEW_MINING_JOB => {
                let payload = f.payload();
                if let Ok(Mining::NewMiningJob(m)) = Mining::try_from((mt, payload)) {
                    let root: [u8; 32] = m.merkle_root.inner_as_ref().try_into().unwrap();
                    job = Some((root, m.version, m.job_id));
                }
            }
            Some(mt) if mt == mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH => {
                if let Some(m) = parse_set_new_prev_hash(&mut f) {
                    let ph: [u8; 32] = m.prev_hash.inner_as_ref().try_into().unwrap();
                    prev = Some((ph, m.min_ntime, m.nbits));
                }
            }
            Some(mt) if mt == mining::MESSAGE_TYPE_SET_TARGET => {
                if let Some(t) = parse_set_target(&mut f) {
                    target = Some(t);
                }
            }
            _ => {}
        }
        if job.is_some() && prev.is_some() && target.is_some() {
            break;
        }
    }
    let (merkle_root, version, job_id) = job.ok_or_else(|| anyhow!("no job"))?;
    let (prev_hash, min_ntime, nbits) = prev.ok_or_else(|| anyhow!("no prev-hash"))?;
    let target = target.ok_or_else(|| anyhow!("no target"))?;

    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(&version.to_le_bytes());
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&min_ntime.to_le_bytes());
    header.extend_from_slice(&nbits.to_le_bytes());
    let noff = header.len();
    header.extend_from_slice(&0u32.to_le_bytes());
    let mut nonce = None;
    for n in 0u32..5_000_000 {
        header[noff..noff + 4].copy_from_slice(&n.to_le_bytes());
        if le_leq(&sha256d::Hash::hash(&header).to_byte_array(), &target) {
            nonce = Some(n);
            break;
        }
    }
    let nonce = nonce.ok_or_else(|| anyhow!("no winning nonce"))?;

    let m = mining::SubmitSharesStandard {
        channel_id,
        sequence_number: 0,
        job_id,
        nonce,
        ntime: min_ntime,
        version,
    };
    miner
        .write
        .write_frame(wire::frame_from(AnyMessage::Mining(
            Mining::SubmitSharesStandard(m),
        )))
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(())
}

#[tokio::test]
async fn sv2_standard_miner_onto_sv1_pool_is_cryptographically_valid() {
    // Same proof as the Extended case, but for a header-only Standard miner:
    // the proxy assembles the coinbase + folds the merkle root the miner mines
    // against, and replays its chosen extranonce2 on the submit. The SV1 pool
    // rebuilds the header independently and confirms SHA256d ≤ target.
    let sv1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sv1_addr = sv1.local_addr().unwrap();
    let (acc_tx, mut acc_rx) = mpsc::unbounded_channel::<bool>();
    tokio::spawn(validating_sv1_pool(sv1, acc_tx));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let registry = crate::registry::Registry::new();
    let db = crate::db::test_pool().await;
    let ctx = ProxyContext {
        default_target: None,
        registry: registry.clone(),
        sv2_rigs: Default::default(),
        sellers: crate::store::SellerStore::new(db.clone()),
        orders: crate::orders::OrderStore::new(db.clone()),
    };
    register_rig(
        &ctx.sellers,
        "bc1qSELLER.rig1",
        ext_target(&sv1_addr.to_string(), "acctSV1"),
    )
    .await;
    let keys = NoiseKeys::generate();
    tokio::spawn(async move {
        let (sock, peer) = proxy.accept().await.unwrap();
        let _ = handle_seller_miner_sv2(sock, peer.to_string(), ctx, keys).await;
    });

    let mut miner = MockMiner::connect(proxy_addr).await.unwrap();
    miner.setup().await.unwrap();
    // Open a STANDARD channel (the miner can't roll extranonce).
    let open = Mining::OpenStandardMiningChannel(OpenStandardMiningChannel {
        request_id: U32AsRef::from(1u32),
        user_identity: Str0255::try_from("bc1qSELLER.rig1".to_string()).unwrap(),
        nominal_hash_rate: 1.0e12,
        max_target: U256::from([0xffu8; 32]),
    });
    miner
        .write
        .write_frame(wire::frame_from(AnyMessage::Mining(open)))
        .await
        .unwrap();

    let (channel_id, prefix) = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut f = read_one(&mut miner.read).await?;
            if wire::msg_type(&f)
                == Some(mining::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS)
            {
                let info =
                    parse_open_success(&mut f).ok_or_else(|| anyhow!("bad open success"))?;
                return Ok::<_, anyhow::Error>((info.up_channel_id, info.extranonce_prefix));
            }
        }
    })
    .await
    .expect("standard open did not complete")
    .unwrap();
    assert_eq!(
        prefix,
        vec![0xaa, 0xbb, 0xcc, 0xdd],
        "standard channel prefix = SV1 extranonce1"
    );

    tokio::time::timeout(
        Duration::from_secs(20),
        mine_standard_and_submit_one(&mut miner, channel_id),
    )
    .await
    .expect("mining timed out")
    .unwrap();

    let valid = tokio::time::timeout(Duration::from_secs(5), acc_rx.recv())
        .await
        .expect("pool never saw the share")
        .unwrap();
    assert!(
        valid,
        "the translated standard share must be cryptographically valid at the SV1 pool"
    );

    let ok_cid = tokio::time::timeout(
        Duration::from_secs(5),
        miner.read_until_cid(mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
    )
    .await
    .expect("share result timed out")
    .unwrap();
    assert_eq!(ok_cid, channel_id);
}
