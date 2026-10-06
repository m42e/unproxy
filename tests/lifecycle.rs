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
    tokio::time::timeout(Duration::from_secs(15), async {
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
async fn response_status(proxy: std::net::SocketAddr, origin: std::net::SocketAddr) -> Option<u16> {
    let mut client = TcpStream::connect(proxy).await.ok()?;
    client
        .write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .ok()?;
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .ok()?
        .ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}
async fn await_status(proxy: std::net::SocketAddr, origin: std::net::SocketAddr, desired: u16) {
    const STATUS_TIMEOUT: Duration = Duration::from_secs(30);
    tokio::time::timeout(STATUS_TIMEOUT, async {
        loop {
            if response_status(proxy, origin).await == Some(desired) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("proxy did not return HTTP {desired} within {STATUS_TIMEOUT:?}"));
}
fn process(address: std::net::SocketAddr, pac: &str, netrc: &std::path::Path) -> Child {
    process_with_log(address, pac, netrc, None)
}
fn process_with_log(
    address: std::net::SocketAddr,
    pac: &str,
    netrc: &std::path::Path,
    logfile: Option<&std::path::Path>,
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
    command
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
        .kill_on_drop(true);
    if let Some(logfile) = logfile {
        command.arg("--logfile").arg(logfile);
    }
    inherit_coverage_profile(&mut command);
    command.spawn().unwrap()
}

fn inherit_coverage_profile(command: &mut Command) {
    let Some(pattern) = std::env::var_os("LLVM_PROFILE_FILE") else {
        return;
    };
    let pattern = pattern.to_string_lossy();
    if pattern.contains("%p") && pattern.contains("%m") {
        command.env("LLVM_PROFILE_FILE", pattern.as_ref());
    } else {
        command.env(
            "LLVM_PROFILE_FILE",
            format!("{pattern}.child-%p-%m.profraw"),
        );
    }
}

#[cfg(unix)]
async fn stop_child(child: &mut Child) {
    let pid = child.id().expect("child process is running") as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("child did not stop after SIGTERM")
        .unwrap();
    assert!(
        status.success(),
        "child did not shut down cleanly: {status}"
    );
}

#[cfg(not(unix))]
async fn stop_child(child: &mut Child) {
    child.kill().await.unwrap();
    child.wait().await.unwrap();
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
        env!("CARGO_BIN_EXE_undns"),
        env!("CARGO_BIN_EXE_paceval"),
        env!("CARGO_BIN_EXE_toml-query"),
        env!("CARGO_BIN_EXE_unproxy-app"),
        env!("CARGO_BIN_EXE_unproxy-login-helper"),
        env!("CARGO_BIN_EXE_unproxy-register"),
        env!("CARGO_BIN_EXE_unproxy-system-proxy"),
        env!("CARGO_BIN_EXE_unproxy-tray"),
        env!("CARGO_BIN_EXE_unproxy-version"),
        env!("CARGO_BIN_EXE_unproxyctl"),
        env!("CARGO_BIN_EXE_xtask"),
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
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Usage:"),
            "{} did not print a usage synopsis",
            binary
        );
    }
    for (binary, version) in [
        (env!("CARGO_BIN_EXE_unproxy"), unproxy::VERSION),
        (env!("CARGO_BIN_EXE_undns"), unproxy::DNS_VERSION),
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
    await_status(address, origin_address, 200).await;
    stop_child(&mut child).await;
    origin_task.abort();
}

#[tokio::test]
async fn logfile_is_preserved_and_receives_runtime_startup_messages() {
    let temp = tempfile::tempdir().unwrap();
    let netrc = temp.path().join("netrc");
    std::fs::write(&netrc, "").unwrap();
    let pac = temp.path().join("proxy.pac");
    std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    let logfile = temp.path().join("unproxy.log");
    std::fs::write(&logfile, "previous diagnostic history\n").unwrap();
    let address = reserve_address();
    let mut child = process_with_log(address, pac.to_str().unwrap(), &netrc, Some(&logfile));
    wait_for_listener(address, &mut child).await;
    stop_child(&mut child).await;

    let address = reserve_address();
    let mut child = process_with_log(address, pac.to_str().unwrap(), &netrc, Some(&logfile));
    wait_for_listener(address, &mut child).await;
    stop_child(&mut child).await;

    let log = std::fs::read_to_string(logfile).unwrap();
    assert!(log.contains("previous diagnostic history"));
    assert!(log.contains("proxy listening"), "{log}");
    assert_eq!(log.matches("proxy started").count(), 2, "{log}");
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
    await_status(address, origin_address, 502).await;
    std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    await_status(address, origin_address, 200).await;
    stop_child(&mut child).await;
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
        command
            .env("UNPROXY_NORC", "1")
            .args(["--listen", "127.0.0.1:0", "--pac-file"])
            .arg(&pac)
            .args(["--graceful-shutdown-timeout", "1", "--netrc-file"])
            .arg(&netrc)
            .stdout(Stdio::null())
            .kill_on_drop(true);
        inherit_coverage_profile(&mut command);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("PAC"));
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
    command
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
        .kill_on_drop(true);
    inherit_coverage_profile(&mut command);
    let mut child = command.spawn().unwrap();
    wait_for_listener(address, &mut child).await;
    let (origin_address, origin_task) = origin().await;
    await_status(address, origin_address, 200).await;
    let pid = child.id().unwrap() as i32;
    for signal in [libc::SIGUSR1, libc::SIGHUP] {
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        await_status(address, origin_address, 200).await;
    }
    stop_child(&mut child).await;
    origin_task.abort();
}
