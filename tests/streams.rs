use unproxy::{
    connection::{Connection, Transport},
    net::{ConnectionOptions, Metered, relay, with_timeout},
    route::{Endpoint, Route},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bidirectional_relay_preserves_half_close_and_all_read_write_counts() {
    let (mut client, middle_client) = tokio::io::duplex(8);
    let (middle_origin, mut origin) = tokio::io::duplex(8);
    let relay_task = tokio::spawn(async move {
        let mut a = Metered::new(middle_client);
        let mut b = Metered::new(middle_origin);
        let result = relay(&mut a, &mut b).await.unwrap();
        (result, a.read, a.written, b.read, b.written)
    });
    let origin_task = tokio::spawn(async move {
        let mut request = Vec::new();
        origin.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, [0, 255, 9, 128]);
        origin.write_all(b"response after EOF").await.unwrap();
        origin.shutdown().await.unwrap();
    });
    client.write_all(&[0, 255, 9, 128]).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response after EOF");
    origin_task.await.unwrap();
    let (counts, ar, aw, br, bw) = relay_task.await.unwrap();
    assert_eq!(counts, (4, 18));
    assert_eq!((ar, aw, br, bw), (4, 18, 18, 4));
}

#[tokio::test]
async fn generic_timeout_bounds_operation_and_direct_connection_keeps_identity() {
    assert!(
        with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await
        .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
    };
    let connection = Connection::direct(
        &endpoint,
        &ConnectionOptions::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(connection.route(), &Route::Direct);
    assert_eq!(connection.transport(), Transport::DirectTcp);
    assert!(listener.accept().await.is_ok());
}

#[tokio::test]
async fn supplied_connection_stream_loads_and_reloads_configured_pac() {
    use unproxy::{pac::Policy, proxy::ContextBuilder, route::PathOrUri};
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.pac");
    tokio::fs::write(
        &path,
        "function FindProxyForURL(u,h){return 'PROXY example.test:8081'}",
    )
    .await
    .unwrap();
    let (mut client, server) = tokio::io::duplex(4096);
    let connections = futures_util::stream::iter([Ok((server, "127.0.0.1:3210".parse().unwrap()))]);
    let context = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .inline_pac(Some(
        "function FindProxyForURL(u,h){return 'PROXY inline.test:8082'}".into(),
    ))
    .unwrap()
    .pac_source(PathOrUri::Path(path))
    .serve_connections(connections)
    .await
    .unwrap();
    let policy = context.policy();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP example.test:8081"
    );
    context.clear_policy().await.unwrap();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
    context.reload_pac().await.unwrap();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP example.test:8081"
    );
    client
        .write_all(b"GET /missing HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 404"));
    context.shutdown();
    context.shutdown_notified().await;
    assert!(context.wait_timeout(Duration::from_secs(1)).await);
}
