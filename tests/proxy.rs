use std::{net::SocketAddr, sync::Arc};

use unproxy::{auth::AuthFactory, net::ConnectionOptions, pac::Policy, proxy::ContextBuilder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn start(policy: Policy) -> unproxy::proxy::Context {
    ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn generated_pac_uses_local_host_header() {
    let server = start(Policy::new(None).unwrap()).await;
    let addr = server.local_addrs()[0];
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            b"GET /proxy.pac HTTP/1.1\r\nHost: proxy.example:4444\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(
        "function FindProxyForURL(url, host) { return \"PROXY proxy.example:4444\"; }\n"
    ));
    server.shutdown();
    server.wait().await;
}

#[tokio::test]
async fn forwards_stream_and_removes_hop_headers() {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let n = socket.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                if request.windows(5).any(|w| w == b"hello") {
                    break;
                }
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        request
    });
    let proxy = start(Policy::new(None).unwrap()).await;
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    let req = format!(
        "POST http://{origin_addr}/upload?q=1 HTTP/1.1\r\nHost: preserved.test\r\nConnection: X-Remove\r\nX-Remove: secret\r\nProxy-Authorization: Basic client\r\nAuthorization: Basic origin\r\nContent-Length: 5\r\n\r\nhello"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("OK"));
    let sent = upstream.await.unwrap();
    let sent = String::from_utf8_lossy(&sent);
    assert!(sent.starts_with("POST /upload?q=1 HTTP/1.1"));
    assert!(sent.contains("Host: preserved.test"));
    assert!(sent.contains("Authorization: Basic origin"));
    assert!(!sent.to_ascii_lowercase().contains("proxy-authorization"));
    assert!(!sent.to_ascii_lowercase().contains("x-remove"));
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn direct_connect_relays_opaque_bytes() {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut io, _) = origin.accept().await.unwrap();
        let mut buf = [0; 4];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        io.write_all(b"pong").await.unwrap();
    });
    let proxy = start(Policy::new(None).unwrap()).await;
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    loop {
        let mut b = [0];
        client.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    client.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    client.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
    drop(client);
    origin_task.await.unwrap();
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn ordinary_407_is_a_local_bad_gateway() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = upstream.local_addr().unwrap();
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {addr}'; }}"
    )))
    .unwrap();
    let fake = tokio::spawn(async move {
        let (mut io, _) = upstream.accept().await.unwrap();
        let mut buf = [0; 2048];
        let _ = io.read(&mut buf).await.unwrap();
        io.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let proxy = start(policy).await;
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client.write_all(b"GET http://example.test/data HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 502"));
    fake.await.unwrap();
    proxy.shutdown();
    proxy.wait().await;
}
