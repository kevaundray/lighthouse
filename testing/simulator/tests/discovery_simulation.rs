#![cfg(madsim)]

use discv5::{ConfigBuilder, Discv5, Enr, ListenConfig, RequestError, SimulationState};
use madsim::runtime::{Handle, NodeHandle, Runtime};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

async fn server(host: &NodeHandle, ip: Ipv4Addr) -> Arc<Discv5> {
    host.spawn(async move {
        let key = enr::CombinedKey::generate_secp256k1();
        let enr = Enr::builder().ip4(ip).udp4(9000).build(&key).unwrap();
        let config = ConfigBuilder::new(ListenConfig::Ipv4 { ip, port: 9000 })
            .enable_packet_filter()
            .request_timeout(Duration::from_secs(1))
            .request_retries(0)
            .build();
        let mut service = Discv5::new(enr, key, config).unwrap();
        service.start().await.unwrap();
        Arc::new(service)
    })
    .await
    .unwrap()
}

#[test]
fn simulated_udp_handshake_and_bans_are_node_local() {
    let runtime = Runtime::new();
    runtime.add_simulator::<SimulationState>();
    runtime.block_on(async {
        let handle = Handle::current();
        let source_ip = Ipv4Addr::new(10, 0, 0, 1);
        let blocked_ip = Ipv4Addr::new(10, 0, 0, 2);
        let allowed_ip = Ipv4Addr::new(10, 0, 0, 3);
        let source_host = handle.create_node().ip(source_ip.into()).build();
        let blocked_host = handle.create_node().ip(blocked_ip.into()).build();
        let source = server(&source_host, source_ip).await;
        let blocked = server(&blocked_host, blocked_ip).await;
        let banning = blocked.clone();
        blocked_host
            .spawn(async move { banning.ban_ip(source_ip.into(), None) })
            .await
            .unwrap();

        // Another process must neither clear the first process's ban nor inherit it.
        let allowed_host = handle.create_node().ip(allowed_ip.into()).build();
        let allowed = server(&allowed_host, allowed_ip).await;
        let target = blocked.local_enr();
        let requester = source.clone();
        let rejected = source_host
            .spawn(async move { requester.send_ping(target).await })
            .await
            .unwrap();
        assert!(matches!(rejected, Err(RequestError::Timeout)));

        let target = allowed.local_enr();
        let requester = source.clone();
        let pong = source_host
            .spawn(async move { requester.send_ping(target).await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pong.ip, source_ip);
        assert_eq!(pong.port, 9000);

        // The real packet filter must also observe unbanning.
        let unbanning = blocked.clone();
        blocked_host
            .spawn(async move { unbanning.ban_ip_remove(&source_ip.into()) })
            .await
            .unwrap();
        let target = blocked.local_enr();
        let pong = source_host
            .spawn(async move { source.send_ping(target).await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pong.ip, source_ip);
        assert_eq!(pong.port, 9000);
    });
}
