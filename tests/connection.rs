use http_body_util::BodyExt;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use unproxy::{
    auth::{AuthFactory, CredentialStore},
    connection::{Connection, Transport},
    net::ConnectionOptions,
    route::{Endpoint, Route},
};

fn endpoint(address: SocketAddr) -> Endpoint {
    Endpoint {
        host: address.ip().to_string(),
        port: address.port(),
    }
}

async fn capture_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before request headers arrived");
        request.extend_from_slice(&chunk[..read]);
    }
    request
}

async fn reply_ok(stream: &mut TcpStream) {
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
}

#[tokio::test]
async fn direct_stream_exposes_async_read_and_write() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let mut connection = Connection::direct(
        &endpoint(address),
        &ConnectionOptions::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(connection.route(), &Route::Direct);
    assert_eq!(connection.transport(), Transport::DirectTcp);
    connection.write_all(b"ping").await.unwrap();
    let mut response = [0; 4];
    connection.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[tokio::test]
async fn forward_proxy_send_replaces_client_proxy_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = capture_request(&mut stream).await;
        reply_ok(&mut stream).await;
        request
    });
    let mut options = ConnectionOptions::default();
    options.auth = AuthFactory::basic(
        CredentialStore::parse("machine 127.0.0.1 login alice password secret").unwrap(),
    );
    let connection = Connection::proxy(endpoint(address), false, &options, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(connection.transport(), Transport::ForwardProxy);
    let request = http::Request::get("http://example.test/resource?q=1")
        .header(http::header::HOST, "example.test")
        .header(http::header::PROXY_AUTHORIZATION, "Basic client-supplied")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = connection.send(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
    let request = String::from_utf8(server.await.unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(request.starts_with("get http://example.test/resource?q=1 http/1.1\r\n"));
    assert!(request.contains("proxy-authorization: basic ywxpy2u6c2vjcmv0\r\n"));
    assert!(!request.contains("client-supplied"));
    assert!(request.contains("connection: close\r\n"));
}

#[tokio::test]
async fn forward_proxy_send_reports_missing_credentials_before_http_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        let _ = stream.read(&mut byte).await;
    });
    let mut options = ConnectionOptions::default();
    options.auth = AuthFactory::basic(CredentialStore::new());
    let connection = Connection::proxy(endpoint(address), false, &options, Duration::from_secs(1))
        .await
        .unwrap();
    let request = http::Request::get("http://example.test/")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let error = connection.send(request).await.unwrap_err();
    assert!(format!("{error:#}").contains("no credentials configured for 127.0.0.1"));
    server.await.unwrap();
}
