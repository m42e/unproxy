use unproxy::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return head;
        }
    }
}

fn ipv6_listener() -> Option<TcpListener> {
    std::net::TcpListener::bind("[::1]:0")
        .ok()
        .and_then(|l| l.set_nonblocking(true).ok().map(|_| l))
        .and_then(|l| TcpListener::from_std(l).ok())
}

#[tokio::test]
async fn http_proxy_and_target_ipv6_authorities_round_trip() {
    let Some(listener) = ipv6_listener() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        head
    });
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL() {{ return 'HTTP [::1]:{port}'; }}"
    )))
    .unwrap();
    let proxy = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(b"GET http://[2001:db8::9]:8080/item HTTP/1.1\r\nHost: [2001:db8::9]:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"));
    let head = String::from_utf8(upstream.await.unwrap()).unwrap();
    assert!(head.starts_with("GET http://[2001:db8::9]:8080/item HTTP/1.1"));
    drop(client);
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn https_proxy_ipv6_endpoint_connects_to_ipv6_authority() {
    let Some(listener) = ipv6_listener() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let acceptor: tokio_native_tls::TlsAcceptor = {
        let identity = native_tls::Identity::from_pkcs8(
            include_bytes!("fixtures/localhost.pem"),
            include_bytes!("fixtures/localhost.key"),
        )
        .unwrap();
        native_tls::TlsAcceptor::new(identity).unwrap().into()
    };
    let upstream = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        stream.write_all(b"pong").await.unwrap();
        head
    });
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    let options = ConnectionOptions {
        tls: connector.into(),
        ..ConnectionOptions::default()
    };
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL() {{ return 'HTTPS [::1]:{port}'; }}"
    )))
    .unwrap();
    let proxy = ContextBuilder::new(Arc::new(policy), options)
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(b"CONNECT [2001:db8::9]:443 HTTP/1.1\r\nHost: [2001:db8::9]:443\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    let head = String::from_utf8(upstream.await.unwrap()).unwrap();
    assert!(head.starts_with("CONNECT [2001:db8::9]:443 HTTP/1.1"));
    drop(client);
    proxy.shutdown();
    proxy.wait().await;
}
