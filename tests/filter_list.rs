use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use unproxy::{
    filter_list::FilterList, net::ConnectionOptions, pac::Policy, proxy::ContextBuilder,
};

#[tokio::test]
async fn loads_local_hosts_file_and_reports_missing_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts.txt");
    tokio::fs::write(&path, "0.0.0.0 ads.example.test\n")
        .await
        .unwrap();
    let list = FilterList::load(&[path.to_string_lossy().into_owned()])
        .await
        .unwrap();
    assert!(list.contains("ads.example.test"));

    let missing = dir.path().join("missing.txt");
    let error = FilterList::load(&[missing.to_string_lossy().into_owned()])
        .await
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("reading filter list"));
}

#[tokio::test]
async fn loads_remote_filter_list_over_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = "127.0.0.1 remote-block.example.test\n";
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let list = FilterList::load(&[format!("http://{addr}/hosts.txt")])
        .await
        .unwrap();
    assert!(list.contains("remote-block.example.test"));
    server.await.unwrap();
}

#[tokio::test]
async fn blocked_request_is_rejected_before_policy_routing() {
    let list = FilterList::parse("0.0.0.0 blocked.example.test\n");
    let (mut client, server_io) = tokio::io::duplex(4096);
    let context = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .filter_list(list)
    .serve_stream(server_io, "127.0.0.1:12345".parse::<SocketAddr>().unwrap())
    .await
    .unwrap();

    client.write_all(
        b"GET http://sub.blocked.example.test/resource HTTP/1.1\r\nHost: sub.blocked.example.test\r\nConnection: close\r\n\r\n",
    ).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(String::from_utf8_lossy(&response).contains("Blocked by filter list"));
    context.shutdown();
    context.wait().await;
}

#[tokio::test]
async fn unlisted_request_is_not_rejected_by_filter() {
    let list = FilterList::parse("blocked.example.test\n");
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "upstream proxy closed before receiving a request");
            request.extend_from_slice(&chunk[..count]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(){{return 'PROXY {upstream_addr}';}}"
    )))
    .unwrap();
    let (mut client, server_io) = tokio::io::duplex(4096);
    let context = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .filter_list(list)
        .serve_stream(server_io, "127.0.0.1:12345".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();

    client.write_all(
        b"GET http://safe.example.test/resource HTTP/1.1\r\nHost: safe.example.test\r\nConnection: close\r\n\r\n",
    ).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    upstream.await.unwrap();
    context.shutdown();
    context.wait().await;
}
