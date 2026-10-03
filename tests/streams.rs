use std::time::Duration;
use std::{
    io,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use unproxy::{
    connection::{Connection, Transport},
    net::{
        ConnectionOptions, IdleIo, Keepalive, Metered, configure_keepalive, relay, with_timeout,
    },
    route::{Endpoint, Route},
};

struct PendingIo;
impl AsyncRead for PendingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for PendingIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct FailedIo;
impl AsyncRead for FailedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "read fixture",
        )))
    }
}
impl AsyncWrite for FailedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "write fixture",
        )))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("flush fixture")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("shutdown fixture")))
    }
}

#[tokio::test]
async fn bidirectional_relay_preserves_half_close_and_all_read_write_counts() {
    let (mut client, middle_client) = tokio::io::duplex(8);
    let (middle_origin, mut origin) = tokio::io::duplex(8);
    let relay_task = tokio::spawn(async move {
        let mut a = Metered::new(middle_client);
        let mut b = Metered::new(middle_origin);
        let result = relay(&mut a, &mut b).await.unwrap();
        (result, a.read, a.written, b.read, b.written)
    });
    let origin_task = tokio::spawn(async move {
        let mut request = Vec::new();
        origin.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, [0, 255, 9, 128]);
        origin.write_all(b"response after EOF").await.unwrap();
        origin.shutdown().await.unwrap();
    });
    client.write_all(&[0, 255, 9, 128]).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response after EOF");
    origin_task.await.unwrap();
    let (counts, ar, aw, br, bw) = relay_task.await.unwrap();
    assert_eq!(counts, (4, 18));
    assert_eq!((ar, aw, br, bw), (4, 18, 18, 4));
}

#[tokio::test]
async fn generic_timeout_bounds_operation_and_direct_connection_keeps_identity() {
    assert!(
        with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await
        .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
    };
    let connection = Connection::direct(
        &endpoint,
        &ConnectionOptions::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(connection.route(), &Route::Direct);
    assert_eq!(connection.transport(), Transport::DirectTcp);
    assert!(listener.accept().await.is_ok());
}

#[tokio::test]
async fn keepalive_applies_individual_and_combined_socket_options() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    for keepalive in [
        Keepalive {
            time: Some(Duration::from_secs(30)),
            ..Keepalive::default()
        },
        Keepalive {
            interval: Some(Duration::from_secs(10)),
            ..Keepalive::default()
        },
        Keepalive {
            retries: Some(3),
            ..Keepalive::default()
        },
        Keepalive {
            time: Some(Duration::from_secs(30)),
            interval: Some(Duration::from_secs(10)),
            retries: Some(3),
        },
    ] {
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        configure_keepalive(&client, &keepalive).unwrap();
        assert!(client.nodelay().unwrap(), "TCP_NODELAY must be enabled");

        let socket = socket2::SockRef::from(&client);
        assert!(socket.keepalive().unwrap(), "SO_KEEPALIVE must be enabled");

        // These getters are available on the Linux and macOS CI runners.
        // Other platforms still verify that TCP keepalive itself was enabled.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Some(time) = keepalive.time {
                assert_eq!(socket.tcp_keepalive_time().unwrap(), time);
            }
            if let Some(interval) = keepalive.interval {
                assert_eq!(socket.tcp_keepalive_interval().unwrap(), interval);
            }
            if let Some(retries) = keepalive.retries {
                assert_eq!(socket.tcp_keepalive_retries().unwrap(), retries);
            }
        }
    }
}

#[tokio::test]
async fn supplied_connection_stream_loads_and_reloads_configured_pac() {
    use std::sync::Arc;
    use unproxy::{pac::Policy, proxy::ContextBuilder, route::PathOrUri};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.pac");
    tokio::fs::write(
        &path,
        "function FindProxyForURL(u,h){return 'PROXY example.test:8081'}",
    )
    .await
    .unwrap();
    let (mut client, server) = tokio::io::duplex(4096);
    let connections = futures_util::stream::iter([Ok((server, "127.0.0.1:3210".parse().unwrap()))]);
    let context = ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .inline_pac(Some(
        "function FindProxyForURL(u,h){return 'PROXY inline.test:8082'}".into(),
    ))
    .unwrap()
    .pac_source(PathOrUri::Path(path))
    .trusted_management_host("fixture")
    .serve_connections(connections)
    .await
    .unwrap();
    let policy = context.policy();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP example.test:8081"
    );
    context.clear_policy().await.unwrap();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
    context.reload_pac().await.unwrap();
    assert_eq!(
        policy
            .evaluate("http://destination.test/".into(), "destination.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP example.test:8081"
    );
    client
        .write_all(b"GET /missing HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 404"));
    context.shutdown();
    context.shutdown_notified().await;
    assert!(context.wait_timeout(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn idle_io_bounds_pending_operations_and_disables_deadlines_after_upgrade() {
    let timeout = Duration::from_millis(10);
    let disabled = Arc::new(AtomicBool::new(false));
    let mut read_io = IdleIo::new(PendingIo, timeout, disabled.clone());
    let mut byte = [0];
    let read_error = tokio::time::timeout(Duration::from_millis(250), read_io.read(&mut byte))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(read_error.kind(), io::ErrorKind::TimedOut);
    assert!(read_error.to_string().contains("read idle timeout"));

    let mut write_io = IdleIo::new(PendingIo, timeout, disabled.clone());
    let write_error = tokio::time::timeout(Duration::from_millis(250), write_io.write_all(b"x"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(write_error.kind(), io::ErrorKind::TimedOut);
    assert!(write_error.to_string().contains("write idle timeout"));

    let mut flush_io = IdleIo::new(PendingIo, timeout, disabled.clone());
    let flush_error = tokio::time::timeout(Duration::from_millis(250), flush_io.flush())
        .await
        .unwrap()
        .unwrap_err();
    assert!(flush_error.to_string().contains("flush idle timeout"));

    let mut shutdown_io = IdleIo::new(PendingIo, timeout, disabled.clone());
    let shutdown_error = tokio::time::timeout(Duration::from_millis(250), shutdown_io.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert!(shutdown_error.to_string().contains("shutdown idle timeout"));

    disabled.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut upgraded = IdleIo::new(PendingIo, timeout, disabled);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), upgraded.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn idle_io_and_metered_streams_preserve_underlying_errors_and_counts() {
    let disabled = Arc::new(AtomicBool::new(false));
    let mut io = IdleIo::new(FailedIo, Duration::from_secs(1), disabled);
    let mut byte = [0];
    assert_eq!(
        io.read(&mut byte).await.unwrap_err().to_string(),
        "read fixture"
    );
    assert_eq!(
        io.write(b"x").await.unwrap_err().to_string(),
        "write fixture"
    );
    assert_eq!(io.flush().await.unwrap_err().to_string(), "flush fixture");
    assert_eq!(
        io.shutdown().await.unwrap_err().to_string(),
        "shutdown fixture"
    );

    let (mut writer, reader) = tokio::io::duplex(8);
    let mut counted = Metered::new(reader);
    writer.write_all(b"metered").await.unwrap();
    drop(writer);
    let mut received = Vec::new();
    counted.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"metered");
    assert_eq!(counted.read, 7);
    let inner = counted.into_inner();
    drop(inner);
    assert_eq!(
        unproxy::net::parse_ip("192.0.2.1"),
        Some("192.0.2.1".parse().unwrap())
    );
    assert_eq!(
        unproxy::net::parse_ip("2001:db8::1"),
        Some("2001:db8::1".parse().unwrap())
    );
    assert_eq!(unproxy::net::parse_ip("proxy.example"), None);
}
