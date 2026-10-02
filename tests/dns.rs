use unproxy::dns::{exchange, exchange_primary, needs_fallback, parse_counts};
use unproxy::{net::ConnectionOptions, route::Route};
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[test]
fn dns_wire_parser_checks_all_declared_sections() {
    let mut packet = vec![0u8; 17];
    assert_eq!(parse_counts(&packet).unwrap().answers, 0);
    packet[5] = 1;
    assert!(needs_fallback(&packet).unwrap());
    packet[5] = 0;
    assert!(!needs_fallback(&packet).unwrap());
    let mut truncated = vec![0u8; 12];
    truncated[5] = 1;
    assert!(parse_counts(&truncated).is_err());
    packet[11] = 1; // one additional record with no body
    assert!(parse_counts(&packet).is_err());
}

#[test]
fn dns_parser_rejects_bad_compression_and_trailing_sections() {
    let mut packet = vec![0u8; 18];
    packet[5] = 1;
    packet[12] = 0xc0;
    packet[13] = 0xff;
    assert!(parse_counts(&packet).is_err());

    let mut cyclic = vec![0u8; 18];
    cyclic[5] = 1;
    cyclic[12] = 0xc0;
    cyclic[13] = 12;
    assert!(parse_counts(&cyclic).is_err());
}

#[tokio::test]
async fn primary_exchange_uses_a_fresh_connected_udp_socket() {
    // This exchange validates primary wire processing, so use a complete empty DNS header.
    let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0; 64];
        let (_, peer) = responder.recv_from(&mut buf).await.unwrap();
        let response = [0u8; 12];
        responder.send_to(&response, peer).await.unwrap();
    });
    let response = exchange_primary(&[0u8; 12], addr).await.unwrap();
    assert_eq!(response, vec![0; 12]);
    task.await.unwrap();
    let _ = addr;
}

#[tokio::test]
async fn primary_exchange_supports_ipv6_server_addresses() {
    let responder = match UdpSocket::bind("[::1]:0").await {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0; 64];
        let (_, peer) = responder.recv_from(&mut buf).await.unwrap();
        responder.send_to(&[0u8; 12], peer).await.unwrap();
    });
    assert_eq!(
        exchange_primary(&[0u8; 12], addr).await.unwrap(),
        vec![0; 12]
    );
    task.await.unwrap();
}

fn doh_tls() -> (
    tokio_native_tls::TlsAcceptor,
    tokio_native_tls::TlsConnector,
) {
    let certificate =
        native_tls::Certificate::from_pem(include_bytes!("fixtures/localhost.pem")).unwrap();
    let identity = native_tls::Identity::from_pkcs8(
        include_bytes!("fixtures/localhost.pem"),
        include_bytes!("fixtures/localhost.key"),
    )
    .unwrap();
    let acceptor = native_tls::TlsAcceptor::new(identity).unwrap().into();
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .build()
        .unwrap()
        .into();
    (acceptor, connector)
}

async fn read_http_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
    }
}

#[tokio::test]
async fn doh_bounds_stalled_and_oversized_response_bodies() {
    use unproxy::{dns::doh_on_stream, net::BoxedIo};
    for oversized in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (acceptor, connector) = doh_tls();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            read_http_head(&mut stream).await;
            let mut query = [0; 12];
            stream.read_exact(&mut query).await.unwrap();
            if oversized {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65508\r\n\r\n")
                    .await
                    .unwrap();
                stream.write_all(&vec![0; 65_508]).await.unwrap();
            } else {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
                    .await
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
        let stream: BoxedIo = Box::new(TcpStream::connect(addr).await.unwrap());
        let result = timeout(
            std::time::Duration::from_secs(3),
            doh_on_stream(
                stream,
                "localhost",
                "localhost",
                "/dns-query",
                &[0; 12],
                &connector,
            ),
        )
        .await
        .unwrap();
        if oversized {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap_err().to_string().contains("timed out"));
        }
        server.abort();
    }
}

#[tokio::test]
async fn exchange_returns_primary_without_fallback_when_it_has_answers() {
    let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut query = [0u8; 512];
        let (_, peer) = responder.recv_from(&mut query).await.unwrap();
        // Valid response with one root-name A record (empty answer body is invalid, so use a
        // complete question and answer RR).
        let mut response = vec![0u8; 12];
        response[5] = 1;
        response[7] = 1;
        response.extend_from_slice(&[0, 0, 1, 0, 1]);
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
        responder.send_to(&response, peer).await.unwrap();
    });
    let uri: http::Uri = "https://127.0.0.1/dns-query".parse().unwrap();
    let response = exchange(
        &[0; 12],
        addr,
        &uri,
        &Route::Direct,
        &ConnectionOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(parse_counts(&response).unwrap().answers, 1);
    task.await.unwrap();
}

#[test]
fn secondary_uri_requires_verified_https_and_usable_authority() {
    let valid: http::Uri = "https://resolver.test/dns-query".parse().unwrap();
    assert!(unproxy::dns::validate_secondary_uri(&valid).is_ok());
    let plain: http::Uri = "http://resolver.test/dns-query".parse().unwrap();
    assert!(unproxy::dns::validate_secondary_uri(&plain).is_err());
    let port_zero: http::Uri = "https://resolver.test:0/dns-query".parse().unwrap();
    assert!(unproxy::dns::validate_secondary_uri(&port_zero).is_err());
    assert!(unproxy::dns::authority_has_explicit_port(
        "resolver.test:bad"
    ));
    assert!(unproxy::dns::authority_has_explicit_port("[::1]:443"));
    assert!(!unproxy::dns::authority_has_explicit_port("[::1]"));
}
