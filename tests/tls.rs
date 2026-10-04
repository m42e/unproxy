//! Controlled TLS endpoints test native certificate verification and nested tunnels.
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use unproxy::{
    auth::{AuthFactory, CredentialStore},
    net::{ConnectionOptions, connect},
    pac::Policy,
    proxy::ContextBuilder,
    route::{Endpoint, Route},
};

fn tls_options(auth: AuthFactory) -> ConnectionOptions {
    let certificate =
        native_tls::Certificate::from_pem(include_bytes!("fixtures/localhost.pem")).unwrap();
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .build()
        .unwrap();
    ConnectionOptions {
        tls: connector.into(),
        auth,
        ..ConnectionOptions::default()
    }
}
fn acceptor() -> tokio_native_tls::TlsAcceptor {
    let identity = native_tls::Identity::from_pkcs8(
        include_bytes!("fixtures/localhost.pem"),
        include_bytes!("fixtures/localhost.key"),
    )
    .unwrap();
    native_tls::TlsAcceptor::new(identity).unwrap().into()
}
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).unwrap();
        }
        assert!(bytes.len() < 65536);
    }
}

#[tokio::test]
async fn verified_https_proxy_forwards_absolute_target_with_own_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\nConnection: close\r\n\r\nTLS")
            .await
            .unwrap();
        head
    });
    let policy = Arc::new(
        Policy::new(Some(format!(
            "function FindProxyForURL() {{return 'HTTPS 127.0.0.1:{port}';}}"
        )))
        .unwrap(),
    );
    let auth = AuthFactory::basic(
        CredentialStore::parse("machine 127.0.0.1 login alice password fixture").unwrap(),
    );
    let local = ContextBuilder::new(policy, tls_options(auth))
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(local.local_addrs()[0]).await.unwrap();
    client.write_all(b"GET http://destination.invalid/resource?q=1 HTTP/1.1\r\nHost: destination.invalid\r\nProxy-Authorization: Basic client-value\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
    assert!(response.ends_with("TLS"));
    let head = proxy_task.await.unwrap().to_ascii_lowercase();
    assert!(head.starts_with("get http://destination.invalid/resource?q=1 http/1.1"));
    assert!(head.contains("proxy-authorization: basic ywxpy2u6zml4dhvyzq=="));
    assert!(!head.contains("client-value"));
    drop(client);
    local.shutdown();
    local.wait().await;
}

#[tokio::test]
async fn https_proxy_connect_auth_is_only_in_handshake_and_relays_binary_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with("CONNECT destination.invalid:443 HTTP/1.1"));
        assert!(
            head.to_ascii_lowercase()
                .contains("proxy-authorization: basic ywxpy2u6zml4dhvyzq==")
        );
        stream
            .write_all(b"HTTP/1.1 200 Tunnel\r\n\r\n")
            .await
            .unwrap();
        let mut payload = vec![0; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [0, 255, 1, 128, 9]);
        stream.write_all(b"binary reply").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let options = tls_options(AuthFactory::basic(
        CredentialStore::parse("machine 127.0.0.1 login alice password fixture").unwrap(),
    ));
    let mut stream = connect(
        &Route::Https(Endpoint {
            host: "127.0.0.1".into(),
            port,
        }),
        &Endpoint {
            host: "destination.invalid".into(),
            port: 443,
        },
        true,
        &options,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    stream.write_all(&[0, 255, 1, 128, 9]).await.unwrap();
    let mut response = [0; 12];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"binary reply");
    task.await.unwrap();
}

#[tokio::test]
async fn tls_rejects_a_certificate_without_the_fixture_root() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = acceptor().accept(stream).await;
    });
    let result = connect(
        &Route::Https(Endpoint {
            host: "127.0.0.1".into(),
            port,
        }),
        &Endpoint {
            host: "unused.invalid".into(),
            port: 80,
        },
        false,
        &ConnectionOptions::default(),
        Duration::from_secs(3),
    )
    .await;
    assert!(result.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn dns_fallback_posts_original_wire_bytes_inside_verified_nested_tls() {
    let primary = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let primary_addr = primary.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let mut query = vec![0u8; 12];
    query[0] = 0x12;
    query[1] = 0x34;
    query[5] = 1;
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let expected = query.clone();
    let dns_response = vec![0x12, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let response_copy = dns_response.clone();
    let primary_task = tokio::spawn(async move {
        let mut bytes = [0u8; 512];
        let (len, peer) = primary.recv_from(&mut bytes).await.unwrap();
        bytes[2] |= 0x80;
        primary.send_to(&bytes[..len], peer).await.unwrap();
    });
    let proxy_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut outer_tls = acceptor().accept(stream).await.unwrap();
        let connect_head = read_head(&mut outer_tls).await;
        assert!(connect_head.starts_with("CONNECT localhost:8443 HTTP/1.1"));
        assert!(
            !connect_head
                .to_ascii_lowercase()
                .contains("proxy-authorization")
        );
        outer_tls
            .write_all(b"HTTP/1.1 200 Tunnel\r\n\r\n")
            .await
            .unwrap();
        // The second TLS handshake represents the destination inside the proxy tunnel.
        let mut endpoint_tls = acceptor().accept(outer_tls).await.unwrap();
        let head = read_head(&mut endpoint_tls).await.to_ascii_lowercase();
        assert!(head.starts_with("post /dns-query?fixture=1 http/1.1"));
        assert!(head.contains("host: localhost:8443"));
        assert!(head.contains("accept: application/dns-message"));
        assert!(head.contains("content-type: application/dns-message"));
        assert!(!head.contains("proxy-authorization"));
        let mut body = vec![0; expected.len()];
        endpoint_tls.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
        endpoint_tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_copy.len()).as_bytes()).await.unwrap();
        endpoint_tls.write_all(&response_copy).await.unwrap();
    });
    let route = Route::Https(Endpoint {
        host: "127.0.0.1".into(),
        port: proxy_port,
    });
    let options = tls_options(AuthFactory::no_auth());
    let response = unproxy::dns::exchange(
        &query,
        primary_addr,
        &"https://localhost:8443/dns-query?fixture=1"
            .parse()
            .unwrap(),
        &route,
        &options,
    )
    .await
    .unwrap();
    assert_eq!(response, dns_response);
    primary_task.await.unwrap();
    proxy_task.await.unwrap();
}
