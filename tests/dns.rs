use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use unproxy::dns::{exchange, exchange_primary, needs_fallback, parse_counts};
use unproxy::{net::ConnectionOptions, route::Route};

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
async fn primary_exchange_supports_ipv6_server_addresses() {
    let responder = match UdpSocket::bind("[::1]:0").await {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let addr = responder.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let route = Route::Http(unproxy::route::Endpoint {
        host: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
    });
    let task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with(&format!("CONNECT {addr} "))
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(query, vec![0; 12]);
        stream.write_all(&[0, 12]).await.unwrap();
        stream.write_all(&[0; 12]).await.unwrap();
    });
    assert_eq!(
        exchange_primary(&[0u8; 12], addr, &route, &ConnectionOptions::default())
            .await
            .unwrap(),
        vec![0; 12]
    );
    task.await.unwrap();
}

#[tokio::test]
async fn primary_exchange_sends_dns_tcp_through_selected_proxy_without_udp() {
    let udp_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = udp_target.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let route = Route::Http(unproxy::route::Endpoint {
        host: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
    });
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
        }
        assert!(
            String::from_utf8(headers)
                .unwrap()
                .starts_with(&format!("CONNECT {target} "))
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(query, vec![0; 12]);
        // A primary answer with no fallback condition.
        let response = [
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1,
        ];
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let secondary: http::Uri = "https://127.0.0.1/dns-query".parse().unwrap();
    let response = exchange(
        &[0; 12],
        target,
        &secondary,
        &route,
        &ConnectionOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(parse_counts(&response).unwrap().answers, 1);
    proxy_task.await.unwrap();
    assert!(
        timeout(std::time::Duration::from_millis(50), async {
            let mut buffer = [0; 32];
            udp_target.recv_from(&mut buffer).await
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn primary_exchange_fails_closed_when_selected_proxy_is_unavailable() {
    let udp_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = udp_target.local_addr().unwrap();
    let tcp_target = TcpListener::bind(target).await.unwrap();
    let unavailable_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = unavailable_proxy.local_addr().unwrap();
    drop(unavailable_proxy);
    let route = Route::Http(unproxy::route::Endpoint {
        host: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
    });
    let secondary: http::Uri = "https://127.0.0.1/dns-query".parse().unwrap();

    assert!(
        exchange(
            &[0; 12],
            target,
            &secondary,
            &route,
            &ConnectionOptions::default(),
        )
        .await
        .is_err()
    );
    assert!(
        timeout(std::time::Duration::from_millis(50), tcp_target.accept())
            .await
            .is_err()
    );
    assert!(
        timeout(std::time::Duration::from_millis(50), async {
            let mut buffer = [0; 32];
            udp_target.recv_from(&mut buffer).await
        })
        .await
        .is_err()
    );
}

fn doh_tls() -> (
    tokio_native_tls::TlsAcceptor,
    tokio_native_tls::TlsConnector,
) {
    let certificate =
        native_tls::Certificate::from_pem(include_bytes!("fixtures/localhost.pem")).unwrap();
    let identity =
        native_tls::Identity::from_pkcs12(include_bytes!("fixtures/localhost.p12"), "unproxy-test")
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
    let responder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = responder.accept().await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut query).await.unwrap();
        // Valid response with one root-name A record (empty answer body is invalid, so use a
        // complete question and answer RR).
        let mut response = vec![0u8; 12];
        response[5] = 1;
        response[7] = 1;
        response.extend_from_slice(&[0, 0, 1, 0, 1]);
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
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
