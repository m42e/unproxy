use std::process::{Command, Output};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn inherit_coverage_profile(command: &mut Command) {
    let Some(pattern) = std::env::var_os("LLVM_PROFILE_FILE") else {
        return;
    };
    let pattern = pattern.to_string_lossy();
    let unique = if pattern.contains("%p") && pattern.contains("%m") {
        pattern.into_owned()
    } else {
        format!("{pattern}.child-%p-%m.profraw")
    };
    command.env("LLVM_PROFILE_FILE", unique);
}

#[tokio::test]
async fn doctor_checks_routes_authentication_and_live_runtime_state() {
    let temp = tempfile::tempdir().unwrap();
    let pac = temp.path().join("proxy.pac");
    let credentials = temp.path().join("netrc");
    let filter = temp.path().join("hosts.txt");
    let secret = "doctor-secret-value";
    let status = serde_json::json!({
        "pac_loaded": true,
        "pac_files": [pac.to_string_lossy()],
        "authentication_configured": true,
        "upstream_state": "ok",
        "authentication_state": "authenticated",
        "upstream_route": "HTTP 127.0.0.1:1",
        "authentication_sent": true
    })
    .to_string();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let status_body = status.clone();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = upstream.accept().await else {
                break;
            };
            let status_body = status_body.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                loop {
                    let Ok(count) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_body.len(),
                    status_body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    std::fs::write(
        &pac,
        format!("function FindProxyForURL() {{ return 'PROXY {upstream_addr}'; }}"),
    )
    .unwrap();
    std::fs::write(
        &credentials,
        format!("machine 127.0.0.1 login diagnostic password {secret}\n"),
    )
    .unwrap();
    std::fs::write(&filter, "ads.example.test\n").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
    let listen = upstream_addr.to_string();
    command
        .args([
            "--listen",
            listen.as_str(),
            "--pac-file",
            pac.to_str().unwrap(),
            "--netrc-file",
            credentials.to_str().unwrap(),
            "--filter-list",
            filter.to_str().unwrap(),
            "doctor",
            "--json",
            "--url",
            "http://example.test/",
        ])
        .env("UNPROXY_NORC", "1")
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"));
    inherit_coverage_profile(&mut command);
    let output: Output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    server.abort();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    let checks = report["checks"].as_array().unwrap();
    assert!(checks.iter().any(|check| {
        check["name"] == "Routes for http://example.test/" && check["status"] == "pass"
    }));
    assert!(checks.iter().any(|check| {
        check["name"]
            .as_str()
            .unwrap()
            .starts_with("Authentication for HTTP 127.0.0.1:")
            && check["status"] == "pass"
            && check["message"]
                .as_str()
                .unwrap()
                .contains("token can be generated")
    }));
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "Last upstream state")
    );
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "Last authentication state")
    );
    assert!(checks.iter().any(|check| check["name"] == "Filter lists"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
}
