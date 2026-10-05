use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use unproxy::{
    auth::{AuthFactory, CredentialStore},
    connection::{Connection, Transport},
    net::{self, ConnectionOptions},
    pac::Policy,
    proxy::ContextBuilder,
    route::{Endpoint, Route},
};

const TIMEOUT: Duration = Duration::from_secs(2);

async fn bytes(stream: &mut TcpStream, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}
async fn head(stream: &mut TcpStream) -> String {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        result.extend(bytes(stream, 1).await);
    }
    String::from_utf8(result).unwrap()
}
async fn socks5_request(stream: &mut TcpStream, auth: bool) -> Vec<u8> {
    let greeting = if auth {
        vec![5, 2, 0, 2]
    } else {
        vec![5, 1, 0]
    };
    assert_eq!(bytes(stream, greeting.len()).await, greeting);
    stream
        .write_all(&[5, if auth { 2 } else { 0 }])
        .await
        .unwrap();
    if auth {
        assert_eq!(bytes(stream, 14).await, b"\x01\x05alice\x06secret");
        stream.write_all(&[1, 0]).await.unwrap();
    }
    let mut request = bytes(stream, 4).await;
    assert_eq!(&request[..3], &[5, 1, 0]);
    let length = match request[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = bytes(stream, 1).await[0];
            request.push(len);
            usize::from(len)
        }
        other => panic!("unexpected address type {other}"),
    };
    request.extend(bytes(stream, length + 2).await);
    request
}
fn endpoint(listener: &TcpListener) -> Endpoint {
    listener.local_addr().unwrap().to_string().parse().unwrap()
}

#[tokio::test]
async fn socks5_encodes_all_destination_types_and_preserves_early_payload() {
    for (host, address) in [
        ("192.0.2.1", vec![1, 192, 0, 2, 1]),
        ("::1", [vec![4], vec![0; 15], vec![1]].concat()),
        (
            "unresolvable.invalid",
            [vec![3, 20], b"unresolvable.invalid".to_vec()].concat(),
        ),
    ] {
        for reply_address in [
            vec![1, 0, 0, 0, 0],
            vec![3, 3, b'f', b'o', b'o'],
            [vec![4], vec![0; 16]].concat(),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let route = Route::Socks5(endpoint(&listener));
            let expected = [vec![5, 1, 0], address.clone(), vec![1, 187]].concat();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(socks5_request(&mut stream, false).await, expected);
                let reply = [vec![5, 0, 0], reply_address, vec![0, 0], b"ready".to_vec()].concat();
                // Fragment the response to exercise exact-length reads.
                for byte in reply {
                    stream.write_all(&[byte]).await.unwrap();
                }
            });
            let mut connection = Connection::connect(
                route,
                &Endpoint {
                    host: host.into(),
                    port: 443,
                },
                false,
                &ConnectionOptions::default(),
                TIMEOUT,
            )
            .await
            .unwrap();
            assert_eq!(connection.transport(), Transport::SocksTunnel);
            let mut payload = [0; 5];
            connection.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ready");
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn socks4a_and_socks5_forward_http_and_connect_without_http_proxy_credentials() {
    for version5 in [false, true] {
        for connect in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = endpoint(&listener);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                if version5 {
                    let request = socks5_request(&mut stream, true).await;
                    assert_eq!(
                        request,
                        [
                            vec![5, 1, 0, 3, 16],
                            b"destination.test".to_vec(),
                            vec![0, 80]
                        ]
                        .concat()
                    );
                    stream
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                } else {
                    assert_eq!(
                        bytes(&mut stream, 26).await,
                        [
                            vec![4, 1, 0, 80, 0, 0, 0, 1, 0],
                            b"destination.test\0".to_vec()
                        ]
                        .concat()
                    );
                    stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
                }
                if connect {
                    assert_eq!(bytes(&mut stream, 4).await, b"ping");
                    stream.write_all(b"pong").await.unwrap();
                } else {
                    let request = head(&mut stream).await.to_ascii_lowercase();
                    assert!(request.starts_with("get /resource?q=1 http/1.1\r\n"));
                    assert!(request.contains("host: destination.test:80\r\n"));
                    assert!(!request.contains("proxy-authorization"));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                }
            });
            let options = ConnectionOptions {
                auth: AuthFactory::basic(
                    CredentialStore::parse("machine 127.0.0.1 login alice password secret")
                        .unwrap(),
                ),
                ..ConnectionOptions::default()
            };
            let context = ContextBuilder::new(Arc::new(Policy::new(None).unwrap()), options)
                .listen("127.0.0.1:0".parse().unwrap())
                .inline_pac(Some(format!(
                    "function FindProxyForURL() {{ return '{} {proxy}'; }}",
                    if version5 { "SOCKS5" } else { "SOCKS" }
                )))
                .unwrap()
                .bind()
                .await
                .unwrap();
            let mut client = TcpStream::connect(context.local_addrs()[0]).await.unwrap();
            let request = if connect {
                "CONNECT destination.test:80 HTTP/1.1\r\nHost: destination.test:80\r\nProxy-Authorization: Basic client-secret\r\n\r\n"
            } else {
                "GET http://destination.test:80/resource?q=1 HTTP/1.1\r\nHost: wrong.test\r\nProxy-Authorization: Basic client-secret\r\nConnection: close\r\n\r\n"
            };
            client.write_all(request.as_bytes()).await.unwrap();
            if connect {
                assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
                client.write_all(b"ping").await.unwrap();
                assert_eq!(bytes(&mut client, 4).await, b"pong");
            } else {
                let mut response = String::new();
                client.read_to_string(&mut response).await.unwrap();
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(response.ends_with("ok"));
            }
            drop(client);
            server.await.unwrap();
            context.shutdown();
            assert!(context.wait_timeout(TIMEOUT).await);
        }
    }
}

#[tokio::test]
async fn socks_handshakes_reject_invalid_replies_and_timeout() {
    for (reply, expected) in [
        (vec![4, 0], "method version"),
        (vec![5, 255], "unsupported authentication"),
        (vec![5, 2], "unoffered"),
        (vec![5, 0, 5, 5, 0, 1], "CONNECT rejected"),
        (vec![5, 0, 4, 0, 0, 1], "invalid SOCKS5 CONNECT"),
        (vec![5, 0, 5, 0, 1, 1], "invalid SOCKS5 CONNECT"),
        (vec![5, 0, 5, 0, 0, 9], "address type"),
        (vec![5, 0, 5, 0, 0, 3, 0], "hostname length"),
        (vec![5, 0, 5, 0, 0, 1, 0], "bound address"),
        (vec![], "timed out"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = Route::Socks5(endpoint(&listener));
        let stall = reply.is_empty();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(bytes(&mut stream, 3).await, [5, 1, 0]);
            if stall {
                std::future::pending::<()>().await;
            }
            stream.write_all(&reply[..2]).await.unwrap();
            if reply.len() > 2 {
                let _ = bytes(&mut stream, 10).await;
                stream.write_all(&reply[2..]).await.unwrap();
            }
        });
        let error = net::connect(
            &route,
            &"192.0.2.1:80".parse().unwrap(),
            false,
            &ConnectionOptions::default(),
            Duration::from_millis(100),
        )
        .await
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        if stall {
            server.abort();
        } else {
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn socks4_ipv4_and_rejection() {
    for (reply, succeeds) in [
        ([0, 90, 0, 0, 0, 0, 0, 0], true),
        ([0, 91, 0, 0, 0, 0, 0, 0], false),
        ([4, 90, 0, 0, 0, 0, 0, 0], false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = Route::Socks4(endpoint(&listener));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(bytes(&mut stream, 9).await, [4, 1, 1, 187, 192, 0, 2, 1, 0]);
            stream.write_all(&reply).await.unwrap();
        });
        assert_eq!(
            net::connect(
                &route,
                &"192.0.2.1:443".parse().unwrap(),
                true,
                &ConnectionOptions::default(),
                TIMEOUT
            )
            .await
            .is_ok(),
            succeeds
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn rejected_socks_route_falls_back_in_pac_order() {
    let bad = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_endpoint = endpoint(&bad);
    let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_endpoint = endpoint(&good);
    let rejection = tokio::spawn(async move {
        let (mut stream, _) = bad.accept().await.unwrap();
        socks5_request(&mut stream, false).await;
        stream
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let success = tokio::spawn(async move {
        let (mut stream, _) = good.accept().await.unwrap();
        let request = head(&mut stream).await;
        assert!(request.starts_with("GET http://destination.test/ HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let context = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .inline_pac(Some(format!(
        "function FindProxyForURL() {{return 'SOCKS5 {bad_endpoint}; PROXY {good_endpoint}';}}"
    )))
    .unwrap()
    .bind()
    .await
    .unwrap();
    let mut client = TcpStream::connect(context.local_addrs()[0]).await.unwrap();
    client.write_all(b"GET http://destination.test/ HTTP/1.1\r\nHost: destination.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    rejection.await.unwrap();
    success.await.unwrap();
    context.shutdown();
    assert!(context.wait_timeout(TIMEOUT).await);
}

#[tokio::test]
async fn socks5_authentication_rejects_bad_status_versions_and_credential_lengths() {
    for (credentials, reply, expected) in [
        (
            "default login alice password secret".to_owned(),
            [1, 1],
            "authentication rejected",
        ),
        (
            "default login alice password secret".to_owned(),
            [5, 0],
            "authentication rejected",
        ),
        (
            format!("default login {} password secret", "a".repeat(256)),
            [1, 0],
            "1–255 bytes",
        ),
        (
            "default login alice password \"\"".to_owned(),
            [1, 0],
            "1–255 bytes",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = Route::Socks5(endpoint(&listener));
        let options = ConnectionOptions {
            auth: AuthFactory::basic(CredentialStore::parse(&credentials).unwrap()),
            ..ConnectionOptions::default()
        };
        let invalid_length = expected == "1–255 bytes";
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(bytes(&mut stream, 4).await, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            if invalid_length {
                let mut trailing = Vec::new();
                stream.read_to_end(&mut trailing).await.unwrap();
                assert!(trailing.is_empty());
            } else {
                assert_eq!(bytes(&mut stream, 14).await, b"\x01\x05alice\x06secret");
                stream.write_all(&reply).await.unwrap();
            }
        });
        let error = net::connect(
            &route,
            &"destination.test:443".parse().unwrap(),
            true,
            &options,
            TIMEOUT,
        )
        .await
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        server.await.unwrap();
    }
}
