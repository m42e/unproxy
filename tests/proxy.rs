use std::{net::SocketAddr, sync::Arc};

use unproxy::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder};
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
async fn supplied_stream_serves_management_and_notifies_shutdown() {
    let (mut client, server_io) = tokio::io::duplex(4096);
    let context = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .serve_stream(server_io, "127.0.0.1:12345".parse().unwrap())
    .await
    .unwrap();
    client
        .write_all(b"GET /missing HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 1024];
    let count = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.read(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response[..count].starts_with(b"HTTP/1.1 404"));
    context.shutdown();
    context.shutdown_notified().await;
    assert!(
        context
            .wait_timeout(std::time::Duration::from_secs(1))
            .await
    );
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
async fn local_errors_and_self_loop_are_rejected() {
    let proxy = start(Policy::new(None).unwrap()).await;
    let addr = proxy.local_addrs()[0];
    async fn get(addr: SocketAddr, request: String) -> String {
        let mut io = TcpStream::connect(addr).await.unwrap();
        io.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        io.read_to_string(&mut out).await.unwrap();
        out
    }
    let miss = get(
        addr,
        "GET /missing?q=1 HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert!(miss.starts_with("HTTP/1.1 404"));
    let method = get(
        addr,
        "HEAD / HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert!(method.starts_with("HTTP/1.1 405"));
    let malformed = get(
        addr,
        "CONNECT / HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert!(malformed.starts_with("HTTP/1.1 400"));
    let self_request = get(
        addr,
        format!("GET http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(self_request.starts_with("HTTP/1.1 400"));
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn unspecified_listener_is_rejected() {
    let result = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .listen("0.0.0.0:0".parse().unwrap())
    .bind()
    .await;
    assert!(result.is_err());
}

async fn connect_route_order(race: bool, expected: u8) {
    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second.local_addr().unwrap();
    let first_task = tokio::spawn(async move {
        let (mut io, _) = first.accept().await.unwrap();
        let mut head = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let _ = io.write_all(b"HTTP/1.1 200 Established\r\n\r\n").await;
        let mut byte = [0];
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            io.read_exact(&mut byte),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    });
    let second_task = tokio::spawn(async move {
        let (mut io, _) = second.accept().await.unwrap();
        let mut head = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        io.write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0];
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            io.read_exact(&mut byte),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    });
    let policy=Policy::new(Some(format!("function FindProxyForURL(url, host) {{ return 'PROXY {first_addr}; PROXY {second_addr}'; }}"))).unwrap();
    let proxy = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse().unwrap())
        .parallel_connect(2)
        .race_connect(race)
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(b"CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\n\r\n")
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
    client.write_all(b"x").await.unwrap();
    let first_used = first_task.await.unwrap();
    let second_used = second_task.await.unwrap();
    assert_eq!(first_used, expected == 1);
    assert_eq!(second_used, expected == 2);
    drop(client);
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn ordered_parallel_connect_keeps_policy_precedence() {
    connect_route_order(false, 1).await
}
#[tokio::test]
async fn racing_connect_uses_first_success() {
    connect_route_order(true, 2).await
}

#[tokio::test]
async fn parallel_limit_and_connect_failover_are_enforced() {
    use tokio::sync::oneshot;
    let mut listeners = Vec::new();
    for _ in 0..3 {
        listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
    }
    let addresses = listeners
        .iter()
        .map(|l| l.local_addr().unwrap())
        .collect::<Vec<_>>();
    let mut iter = listeners.into_iter();
    let listener1 = iter.next().unwrap();
    let listener2 = iter.next().unwrap();
    let listener3 = iter.next().unwrap();
    let (started1_tx, started1_rx) = oneshot::channel();
    let (release1_tx, release1_rx) = oneshot::channel();
    let first = tokio::spawn(async move {
        let (mut io, _) = listener1.accept().await.unwrap();
        let mut h = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            h.push(b[0]);
            if h.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = started1_tx.send(());
        let _ = release1_rx.await;
        io.write_all(b"HTTP/1.1 502 Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let (started2_tx, started2_rx) = oneshot::channel();
    let (release2_tx, release2_rx) = oneshot::channel();
    let second = tokio::spawn(async move {
        let (mut io, _) = listener2.accept().await.unwrap();
        let mut h = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            h.push(b[0]);
            if h.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = started2_tx.send(());
        let _ = release2_rx.await;
        io.write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await
            .unwrap();
    });
    let (started3_tx, mut started3_rx) = oneshot::channel();
    let (release3_tx, release3_rx) = oneshot::channel();
    let third = tokio::spawn(async move {
        let (mut io, _) = listener3.accept().await.unwrap();
        let mut h = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            h.push(b[0]);
            if h.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = started3_tx.send(());
        let _ = release3_rx.await;
        io.write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await
            .unwrap();
    });
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {}; PROXY {}; PROXY {}'; }}",
        addresses[0], addresses[1], addresses[2]
    )))
    .unwrap();
    let proxy = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse().unwrap())
        .parallel_connect(2)
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(b"CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\n\r\n")
        .await
        .unwrap();
    started1_rx.await.unwrap();
    started2_rx.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(80), &mut started3_rx)
            .await
            .is_err()
    );
    release1_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut started3_rx)
        .await
        .unwrap()
        .unwrap();
    release2_tx.send(()).unwrap();
    release3_tx.send(()).unwrap();
    let mut response = Vec::new();
    loop {
        let mut b = [0];
        client.read_exact(&mut b).await.unwrap();
        response.push(b[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    drop(client);
    let _ = tokio::join!(first, second, third);
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn direct_fallback_runs_after_proxy_connection_failure() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_proxy = closed.local_addr().unwrap();
    drop(closed);
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut io, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        let mut b = [0; 1024];
        loop {
            let n = io.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&b[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {bad_proxy}'; }}"
    )))
    .unwrap();
    let proxy = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse().unwrap())
        .direct_fallback(true)
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client.write_all(format!("GET http://{target}/fallback HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(
        origin_task
            .await
            .unwrap()
            .starts_with("GET /fallback HTTP/1.1")
    );
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn access_sse_emits_records_and_reports_lag() {
    let proxy = start(Policy::new(None).unwrap()).await;
    let addr = proxy.local_addrs()[0];
    let mut sse = TcpStream::connect(addr).await.unwrap();
    sse.write_all(b"GET /access.log HTTP/1.1\r\nHost: proxy.test\r\n\r\n")
        .await
        .unwrap();
    let mut header = Vec::new();
    loop {
        let mut b = [0];
        sse.read_exact(&mut b).await.unwrap();
        header.push(b[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&header).contains("text/event-stream"));
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = closed.local_addr().unwrap();
    drop(closed);
    let mut records = proxy.subscribe();
    for _ in 0..20 {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{target}/x HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 502"));
    }
    let lag = records.try_recv();
    assert!(matches!(
        lag,
        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(4))
    ));
    let mut frame = vec![0; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), sse.read(&mut frame))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&frame[..n]).contains("data:"));
    drop(sse);
    proxy.shutdown();
    proxy.wait().await;
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
            if request.windows(4).any(|w| w == b"\r\n\r\n")
                && request.windows(5).any(|w| w == b"hello")
            {
                break;
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        request
    });
    let proxy = start(Policy::new(None).unwrap()).await;
    let mut events = proxy.subscribe();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    let req = format!(
        "POST http://{origin_addr}/upload?q=1 HTTP/1.1\r\nHost: preserved.test\r\nUser-Agent: test-agent\r\nConnection: X-Remove, close\r\nX-Remove: secret\r\nProxy-Authorization: Basic client\r\nAuthorization: Basic origin\r\nContent-Length: 5\r\n\r\nhello"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("OK"));
    let entry = events.recv().await.unwrap();
    assert!(entry.contains(" 200 2b \"test-agent\""));
    assert!(entry.contains("POST http://"));
    let sent = upstream.await.unwrap();
    let sent = String::from_utf8_lossy(&sent);
    assert!(sent.starts_with("POST /upload?q=1 HTTP/1.1"));
    assert!(sent.to_ascii_lowercase().contains("host: preserved.test"));
    assert!(
        sent.to_ascii_lowercase()
            .contains("authorization: basic origin")
    );
    assert!(!sent.to_ascii_lowercase().contains("proxy-authorization"));
    assert!(!sent.to_ascii_lowercase().contains("x-remove"));
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn chunked_request_body_streams_to_origin() {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut io, _) = origin.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let n = io.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.windows(5).any(|w| w == b"0\r\n\r\n") {
                break;
            }
        }
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        raw
    });
    let proxy = start(Policy::new(None).unwrap()).await;
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client.write_all(format!("POST http://{target}/bulk HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let payloads = [
        vec![b'a'; 32 * 1024],
        vec![b'b'; 32 * 1024],
        vec![b'c'; 32 * 1024],
        vec![b'd'; 32 * 1024],
    ];
    for payload in &payloads {
        client
            .write_all(format!("{:x}\r\n", payload.len()).as_bytes())
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        client.write_all(b"\r\n").await.unwrap();
    }
    client.write_all(b"0\r\n\r\n").await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let raw = origin_task.await.unwrap();
    let raw = String::from_utf8_lossy(&raw);
    assert!(raw.starts_with("POST /bulk HTTP/1.1"));
    assert!(
        raw.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    );
    for byte in b"abcd" {
        assert!(
            raw.as_bytes()
                .windows(32)
                .any(|w| w.iter().all(|b| b == byte))
        );
    }
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
async fn ipv6_connect_authority_reaches_ipv6_destination() {
    let origin = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(v) => v,
        Err(_) => return,
    };
    let target = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut io, _) = origin.accept().await.unwrap();
        let mut data = [0; 1];
        io.read_exact(&mut data).await.unwrap();
        io.write_all(b"v").await.unwrap();
    });
    let proxy = start(Policy::new(None).unwrap()).await;
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT [{}]:{} HTTP/1.1\r\nHost: [{}]:{}\r\n\r\n",
                target.ip(),
                target.port(),
                target.ip(),
                target.port()
            )
            .as_bytes(),
        )
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
    client.write_all(b"x").await.unwrap();
    let mut reply = [0];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"v");
    drop(client);
    origin_task.await.unwrap();
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn upstream_connect_performs_proxy_handshake_before_replying() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = upstream.local_addr().unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    drop(origin);
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {proxy_addr}'; }}"
    )))
    .unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut io, _) = upstream.accept().await.unwrap();
        let mut head = Vec::new();
        loop {
            let mut b = [0];
            io.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&head).starts_with(&format!("CONNECT {target} HTTP/1.1")));
        io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut data = [0; 4];
        io.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        io.write_all(b"pong").await.unwrap();
    });
    let proxy = start(policy).await;
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
    upstream_task.await.unwrap();
    proxy.shutdown();
    proxy.wait().await;
}

#[tokio::test]
async fn forced_tunnel_auth_stays_out_of_origin_request() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = upstream.local_addr().unwrap();
    let policy = Policy::new(Some(format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {proxy_addr}'; }}"
    )))
    .unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut io, _) = upstream.accept().await.unwrap();
        async fn read_head(io: &mut TcpStream) -> String {
            let mut head = Vec::new();
            loop {
                let mut b = [0];
                io.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    return String::from_utf8(head).unwrap();
                }
            }
        }
        let connect = read_head(&mut io).await;
        assert!(connect.starts_with("CONNECT example.test:80 HTTP/1.1"));
        assert!(!connect.to_ascii_lowercase().contains("proxy-authorization"));
        io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let request = read_head(&mut io).await;
        assert!(request.starts_with("GET /path?q=1 HTTP/1.1"));
        assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
    });
    let proxy = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
        .listen("127.0.0.1:0".parse().unwrap())
        .force_tunnel(true)
        .bind()
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).await.unwrap();
    client.write_all(b"GET http://example.test/path?q=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic client\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("OK"));
    upstream_task.await.unwrap();
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

#[tokio::test]
async fn policy_errors_return_502_without_origin_connections_and_publish_access() {
    use std::time::Duration;
    for fallback in [false, true] {
        for body in [
            "throw new Error('policy denied')",
            "return 42",
            "return 'PROXYbroken:3128'",
        ] {
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let policy =
                Policy::new(Some(format!("function FindProxyForURL(){{{body};}}"))).unwrap();
            let context = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
                .listen("127.0.0.1:0".parse().unwrap())
                .direct_fallback(fallback)
                .bind()
                .await
                .unwrap();
            let mut events = context.subscribe();
            let mut client = TcpStream::connect(context.local_addrs()[0]).await.unwrap();
            client.write_all(format!("GET http://{target}/ HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 502"), "{response}");
            assert!(response.contains("PAC evaluation failed"), "{response}");
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                event.contains("error:") && event.contains("PAC evaluation failed"),
                "{event}"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), origin.accept())
                    .await
                    .is_err()
            );
            context.shutdown();
            context.wait().await;
        }
    }
}
