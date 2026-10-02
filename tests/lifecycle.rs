use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};

fn reserve_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
async fn wait_for_listener(address: std::net::SocketAddr, child: &mut Child) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("proxy exited during startup: {status}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn response_status(proxy: std::net::SocketAddr, origin: std::net::SocketAddr) -> u16 {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}
fn process(address: std::net::SocketAddr, pac: &str, netrc: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_unproxy"))
        .env("UNPROXY_NORC", "1")
        .args([
            "--listen",
            &address.to_string(),
            "--pac-file",
            pac,
            "--graceful-shutdown-timeout",
            "1",
            "--netrc-file",
        ])
        .arg(netrc)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
async fn origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                if stream.read(&mut request).await.unwrap_or(0) > 0 {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await;
                }
            });
        }
    });
    (addr, task)
}

#[test]
fn runtime_products_have_usable_help_and_versions() {
    for binary in [
        env!("CARGO_BIN_EXE_unproxy"),
        env!("CARGO_BIN_EXE_dnsdetox"),
        env!("CARGO_BIN_EXE_paceval"),
    ] {
        let output = std::process::Command::new(binary)
            .arg("--help")
            .env("UNPROXY_NORC", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            binary,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
    for (binary, version) in [
        (env!("CARGO_BIN_EXE_unproxy"), unproxy::VERSION),
        (env!("CARGO_BIN_EXE_dnsdetox"), unproxy::DNS_VERSION),
    ] {
        let output = std::process::Command::new(binary)
            .arg("--version")
            .env("UNPROXY_NORC", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains(version));
    }
}

#[tokio::test]
async fn startup_waits_for_remote_policy_before_accepting_connections() {
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    std::fs::write(&netrc, "").unwrap();
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pac_address = remote.local_addr().unwrap();
    let (release, wait) = tokio::sync::oneshot::channel();
    let (requested, request_seen) = tokio::sync::oneshot::channel();
    let fetch_task = tokio::spawn(async move {
        let (mut client, _) = remote.accept().await.unwrap();
        let mut request = [0; 1024];
        let _ = client.read(&mut request).await.unwrap();
        requested.send(()).unwrap();
        wait.await.unwrap();
        let script = "function FindProxyForURL(){return 'DIRECT';}";
        client
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}",
                    script.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let address = reserve_address();
    let mut child = process(address, &format!("http://{pac_address}/proxy.pac"), &netrc);
    tokio::time::timeout(Duration::from_secs(5), request_seen)
        .await
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(address).await.is_err());
    assert!(child.try_wait().unwrap().is_none());
    release.send(()).unwrap();
    fetch_task.await.unwrap();
    wait_for_listener(address, &mut child).await;
    let (origin_address, origin_task) = origin().await;
    assert_eq!(response_status(address, origin_address).await, 200);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    origin_task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn direct_signal_reload_and_failed_reload_preserve_service() {
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    std::fs::write(&netrc, "").unwrap();
    let pac = temp.path().join("proxy.pac");
    std::fs::write(
        &pac,
        "function FindProxyForURL(){return 'PROXY 127.0.0.1:1';}",
    )
    .unwrap();
    let address = reserve_address();
    let mut child = process(address, pac.to_str().unwrap(), &netrc);
    wait_for_listener(address, &mut child).await;
    let (origin_address, origin_task) = origin().await;
    async fn await_status(proxy: std::net::SocketAddr, origin: std::net::SocketAddr, desired: u16) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if response_status(proxy, origin).await == desired {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    await_status(address, origin_address, 502).await;
    let pid = child.id().unwrap() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
    await_status(address, origin_address, 200).await;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    await_status(address, origin_address, 502).await;
    std::fs::remove_file(&pac).unwrap();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(child.try_wait().unwrap().is_none());
    assert_eq!(response_status(address, origin_address).await, 502);
    std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    await_status(address, origin_address, 200).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    origin_task.abort();
}

#[tokio::test]
async fn invalid_configured_startup_policy_exits_unsuccessfully() {
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    std::fs::write(&netrc, "").unwrap();
    let pac = temp.path().join("bad.pac");
    for body in [
        "function {",
        "function FindProxyForUrl(){return 'DIRECT';}",
        "var FindProxyForURL=1;",
    ] {
        std::fs::write(&pac, body).unwrap();
        let address = reserve_address();
        let mut child = process(address, pac.to_str().unwrap(), &netrc);
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        assert!(TcpStream::connect(address).await.is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn explicit_ip_survives_startup_hup_usr1_and_whole_list_restore() {
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    std::fs::write(&netrc, "").unwrap();
    let first = temp.path().join("direct.pac");
    let second = temp.path().join("override.pac");
    std::fs::write(&first, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    std::fs::write(&second, "const startupIP=myIpAddress(); function FindProxyForURL(){return startupIP==='2001:db8::42' && myIpAddress()==='2001:db8::42' ? 'DIRECT; PROXY 127.0.0.1:1':'BAD';}").unwrap();
    let address = reserve_address();
    let mut child = Command::new(env!("CARGO_BIN_EXE_unproxy"))
        .env("UNPROXY_NORC", "1")
        .args([
            "--listen",
            &address.to_string(),
            "--my-ip-address",
            "2001:db8::42",
            "--graceful-shutdown-timeout",
            "1",
            "--netrc-file",
        ])
        .arg(&netrc)
        .arg("--pac-file")
        .arg(&first)
        .arg("--pac-file")
        .arg(&second)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_listener(address, &mut child).await;
    let (origin_address, origin_task) = origin().await;
    assert_eq!(response_status(address, origin_address).await, 200);
    let pid = child.id().unwrap() as i32;
    for signal in [libc::SIGUSR1, libc::SIGHUP] {
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(response_status(address, origin_address).await, 200);
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    origin_task.abort();
}
