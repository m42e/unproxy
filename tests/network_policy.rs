use unproxy::{
    net::ConnectionOptions,
    network_notifications::{NetworkEvent, TransitionState},
    pac::Policy,
    proxy::ContextBuilder,
    route::PathOrUri,
    runtime::handle_network_event,
};
use std::sync::Arc;

#[tokio::test]
async fn native_and_manual_controls_compose_with_multiple_sources_and_ip_override() {
    let dir = tempfile::tempdir().unwrap();
    let direct_file = dir.path().join("direct.pac");
    let proxy_file = dir.path().join("proxy.pac");
    let first = "function FindProxyForURL(){return 'DIRECT';}";
    let second = "const ip=myIpAddress(); function FindProxyForURL(){return ip==='2001:db8::42' ? 'PROXY corporate.test:3128':'BAD';}";
    tokio::fs::write(&direct_file, first).await.unwrap();
    tokio::fs::write(&proxy_file, second).await.unwrap();
    let policy =
        Arc::new(Policy::new_scripts_with_ip(vec![], "2001:db8::42".parse().unwrap()).unwrap());
    let server = ContextBuilder::new(policy.clone(), ConnectionOptions::default())
        .pac_sources(vec![
            PathOrUri::Path(direct_file),
            PathOrUri::Path(proxy_file.clone()),
        ])
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let original_address = server.local_addrs()[0];
    async fn route(policy: &Policy) -> String {
        policy
            .evaluate("http://example.test/".into(), "example.test".into())
            .await
            .unwrap()
            .to_string()
    }
    let mut state = TransitionState::new();
    assert_eq!(route(&policy).await, "HTTP corporate.test:3128");
    assert!(
        !handle_network_event(&server, &mut state, NetworkEvent::Available)
            .await
            .unwrap()
    );
    assert!(
        handle_network_event(&server, &mut state, NetworkEvent::Unavailable)
            .await
            .unwrap()
    );
    assert_eq!(route(&policy).await, "DIRECT");
    // Manual HUP restores all sources while last native state stays unavailable.
    server.reload_pac().await.unwrap();
    assert_eq!(route(&policy).await, "HTTP corporate.test:3128");
    assert!(
        !handle_network_event(&server, &mut state, NetworkEvent::Unavailable)
            .await
            .unwrap()
    );
    assert_eq!(route(&policy).await, "HTTP corporate.test:3128");
    // Manual USR1 clears policy. A failed automatic restore keeps direct mode.
    server.clear_policy().await.unwrap();
    tokio::fs::write(&proxy_file, "function {").await.unwrap();
    assert!(
        handle_network_event(&server, &mut state, NetworkEvent::Available)
            .await
            .is_err()
    );
    assert_eq!(route(&policy).await, "DIRECT");
    assert!(!server.is_shutdown());
    // Retry the same native observation once the complete source set is fixed.
    tokio::fs::write(&proxy_file, second).await.unwrap();
    assert!(
        handle_network_event(&server, &mut state, NetworkEvent::Available)
            .await
            .unwrap()
    );
    assert_eq!(route(&policy).await, "HTTP corporate.test:3128");
    assert!(
        !handle_network_event(&server, &mut state, NetworkEvent::Available)
            .await
            .unwrap()
    );
    assert_eq!(server.local_addrs()[0], original_address);
    server.shutdown();
    server.wait().await;
}
