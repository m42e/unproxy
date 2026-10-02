//! Controlled TLS endpoints test native certificate verification and nested tunnels.
use unproxy::{auth::{AuthFactory, CredentialStore}, net::{ConnectionOptions, connect}, pac::Policy, proxy::ContextBuilder, route::{Endpoint, Route}};
use std::{sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

fn tls_options(auth: AuthFactory) -> ConnectionOptions {
    let certificate = native_tls::Certificate::from_pem(include_bytes!("fixtures/localhost.pem")).unwrap();
    let connector = native_tls::TlsConnector::builder().add_root_certificate(certificate).build().unwrap();
    ConnectionOptions { tls: connector.into(), auth, ..ConnectionOptions::default() }
}
fn acceptor() -> tokio_native_tls::TlsAcceptor {
    let identity = native_tls::Identity::from_pkcs8(include_bytes!("fixtures/localhost.pem"), include_bytes!("fixtures/localhost.key")).unwrap();
    native_tls::TlsAcceptor::new(identity).unwrap().into()
}
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    loop { let mut byte = [0]; stream.read_exact(&mut byte).await.unwrap(); bytes.push(byte[0]); if bytes.ends_with(b"\r\n\r\n") { return String::from_utf8(bytes).unwrap(); } assert!(bytes.len() < 65536); }
}

#[tokio::test]
async fn verified_https_proxy_forwards_absolute_target_with_own_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\nConnection: close\r\n\r\nTLS").await.unwrap();
        head
    });
    let policy = Arc::new(Policy::new(Some(format!("function FindProxyForURL() {{return 'HTTPS localhost:{port}';}}"))).unwrap());
    let auth = AuthFactory::basic(CredentialStore::parse("machine localhost login alice password fixture").unwrap());
    let local = ContextBuilder::new(policy, tls_options(auth)).listen("127.0.0.1:0".parse().unwrap()).bind().await.unwrap();
    let mut client = TcpStream::connect(local.local_addrs()[0]).await.unwrap();
    client.write_all(b"GET http://destination.invalid/resource?q=1 HTTP/1.1\r\nHost: destination.invalid\r\nProxy-Authorization: Basic client-value\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new(); client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
    assert!(response.ends_with("TLS"));
    let head = proxy_task.await.unwrap().to_ascii_lowercase();
    assert!(head.starts_with("get http://destination.invalid/resource?q=1 http/1.1"));
    assert!(head.contains("proxy-authorization: basic ywxpy2u6zml4dhvyzq=="));
    assert!(!head.contains("client-value"));
    drop(client); local.shutdown(); local.wait().await;
}

#[tokio::test]
async fn https_proxy_connect_auth_is_only_in_handshake_and_half_close_works() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with("CONNECT destination.invalid:443 HTTP/1.1"));
        assert!(head.to_ascii_lowercase().contains("proxy-authorization: basic ywxpy2u6zml4dhvyzq=="));
        stream.write_all(b"HTTP/1.1 200 Tunnel\r\n\r\n").await.unwrap();
        let mut payload = Vec::new(); stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, [0, 255, 1, 128, 9]);
        stream.write_all(b"reply after half close").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let options = tls_options(AuthFactory::basic(CredentialStore::parse("machine localhost login alice password fixture").unwrap()));
    let mut stream = connect(&Route::Https(Endpoint {host: "localhost".into(), port}), &Endpoint {host: "destination.invalid".into(), port:443}, true, &options, Duration::from_secs(3)).await.unwrap();
    stream.write_all(&[0, 255, 1, 128, 9]).await.unwrap(); stream.shutdown().await.unwrap();
    let mut response = Vec::new(); stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"reply after half close"); task.await.unwrap();
}

#[tokio::test]
async fn tls_rejects_a_certificate_without_the_fixture_root() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { let (stream, _) = listener.accept().await.unwrap(); let _ = acceptor().accept(stream).await; });
    let result = connect(&Route::Https(Endpoint {host: "localhost".into(), port}), &Endpoint {host: "unused.invalid".into(), port:80}, false, &ConnectionOptions::default(), Duration::from_secs(3)).await;
    assert!(result.is_err()); task.await.unwrap();
}
