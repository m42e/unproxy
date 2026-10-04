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

async fn reply_ok<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S) {
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
}

fn tls_options() -> ConnectionOptions {
    let certificate =
        native_tls::Certificate::from_pem(include_bytes!("fixtures/localhost.pem")).unwrap();
    let tls = native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .build()
        .unwrap();
    ConnectionOptions {
        tls: tls.into(),
        ..ConnectionOptions::default()
    }
}

fn tls_acceptor() -> tokio_native_tls::TlsAcceptor {
    let identity = native_tls::Identity::from_pkcs8(
        include_bytes!("fixtures/localhost.pem"),
        include_bytes!("fixtures/localhost.key"),
    )
    .unwrap();
    native_tls::TlsAcceptor::new(identity).unwrap().into()
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 65536);
    }
    String::from_utf8(bytes).unwrap()
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
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
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
    connection.flush().await.unwrap();
    let mut response = [0; 4];
    connection.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    connection.shutdown().await.unwrap();
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
    let options = ConnectionOptions {
        auth: AuthFactory::basic(
            CredentialStore::parse("machine 127.0.0.1 login alice password secret").unwrap(),
        ),
        ..ConnectionOptions::default()
    };
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
    let options = ConnectionOptions {
        auth: AuthFactory::basic(CredentialStore::new()),
        ..ConnectionOptions::default()
    };
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

#[tokio::test]
async fn direct_tls_and_https_proxy_constructors_keep_their_transport_identity() {
    let options = tls_options();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let direct_server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tls_acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        reply_ok(&mut stream).await;
        head
    });
    let connection = Connection::direct_tls(
        &Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        &options,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(connection.route(), &Route::Direct);
    assert_eq!(connection.transport(), Transport::DirectTls);
    let request = http::Request::get("https://example.test/direct")
        .header(http::header::PROXY_AUTHORIZATION, "Basic client-value")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = connection.send(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let head = direct_server.await.unwrap().to_ascii_lowercase();
    assert!(!head.contains("proxy-authorization"));
    assert!(head.contains("connection: close"));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy_server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tls_acceptor().accept(stream).await.unwrap();
        let head = read_head(&mut stream).await;
        reply_ok(&mut stream).await;
        head
    });
    let connection = Connection::proxy(
        Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        true,
        &options,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(
        connection.route(),
        &Route::Https(Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        })
    );
    assert_eq!(connection.transport(), Transport::ForwardProxy);
    let request = http::Request::get("https://example.test/proxied")
        .header(http::header::PROXY_AUTHORIZATION, "Basic client-value")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = connection.send(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let head = proxy_server.await.unwrap().to_ascii_lowercase();
    assert!(head.starts_with("get https://example.test/proxied http/1.1"));
    assert!(!head.contains("proxy-authorization"));
}

#[tokio::test]
async fn tunnel_constructor_connects_before_exposing_the_opaque_stream() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let head = capture_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
        String::from_utf8(head).unwrap()
    });
    let proxy_endpoint = endpoint(proxy_addr);
    let destination = Endpoint {
        host: "destination.test".into(),
        port: 443,
    };
    let connection = Connection::tunnel(
        Route::Http(proxy_endpoint.clone()),
        &destination,
        &ConnectionOptions::default(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(connection.route(), &Route::Http(proxy_endpoint));
    assert_eq!(connection.transport(), Transport::ConnectTunnel);
    let mut stream = connection.into_stream();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    assert!(
        server
            .await
            .unwrap()
            .starts_with("CONNECT destination.test:443 HTTP/1.1\r\n")
    );
}

async fn tunnel_error_for(response: Option<Vec<u8>>, timeout: Duration) -> String {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = proxy.local_addr().unwrap();
    let response_times_out = response.as_ref().is_some_and(Vec::is_empty);
    let (request_received, request_received_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let _ = capture_request(&mut stream).await;
        let _ = request_received.send(());
        if response.as_ref().is_some_and(Vec::is_empty) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            return;
        }
        if let Some(response) = response {
            stream.write_all(&response).await.unwrap();
        }
    });
    let error = Connection::tunnel(
        Route::Http(endpoint(address)),
        &Endpoint {
            host: "destination.test".into(),
            port: 443,
        },
        &ConnectionOptions::default(),
        timeout,
    )
    .await
    .err()
    .expect("malformed CONNECT response must fail");
    if response_times_out {
        tokio::time::timeout(Duration::from_secs(1), request_received_rx)
            .await
            .expect("proxy must receive CONNECT before the response timeout")
            .expect("proxy server should report the received request");
        server.abort();
        let _ = server.await;
    } else {
        server.await.unwrap();
    }
    format!("{error:#}")
}

#[tokio::test]
async fn tunnel_rejects_closed_malformed_timed_out_and_oversized_heads() {
    assert!(
        tunnel_error_for(None, Duration::from_secs(1))
            .await
            .contains("closed during CONNECT")
    );
    assert!(
        tunnel_error_for(Some(Vec::new()), Duration::from_millis(250))
            .await
            .contains("timed out")
    );
    assert!(
        tunnel_error_for(
            Some(b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n".to_vec()),
            Duration::from_secs(1),
        )
        .await
        .contains("invalid upstream CONNECT response")
    );
    assert!(
        tunnel_error_for(
            Some(b"HTTP/1.1 not-a-status\r\n\r\n".to_vec()),
            Duration::from_secs(1),
        )
        .await
        .contains("invalid upstream CONNECT status")
    );
    assert!(
        tunnel_error_for(Some(vec![b'x'; 64 * 1024 + 1]), Duration::from_secs(2),)
            .await
            .contains("headers too large")
    );
}

#[tokio::test]
async fn direct_http_driver_failure_is_observed_after_peer_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = capture_request(&mut stream).await;
        drop(stream);
    });
    let connection = Connection::direct(
        &endpoint(address),
        &ConnectionOptions::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let request = http::Request::get("http://example.test/driver-close")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    assert!(connection.send(request).await.is_err());
    server.await.unwrap();
    tokio::task::yield_now().await;
}
