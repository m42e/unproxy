use unproxy::upgrade::{
    ReleaseInfo, UpgradeStatus, evaluate_release, parse_custom_release_info, parse_github_release,
    validate_release_info_url,
};

#[test]
fn custom_release_page_json_has_a_stable_documented_schema() {
    let release = parse_custom_release_info(
        r#"{
            "version": "v1.2.0",
            "url": "https://downloads.example.test/unproxy/1.2.0",
            "notes": "Security and compatibility fixes"
        }"#,
    )
    .unwrap();
    assert_eq!(release.version, "1.2.0");
    assert_eq!(release.url, "https://downloads.example.test/unproxy/1.2.0");
    assert_eq!(
        release.notes.as_deref(),
        Some("Security and compatibility fixes")
    );
    assert!(parse_custom_release_info(r#"{"version":"1.2.0"}"#).is_err());
    assert!(
        parse_custom_release_info(
            r#"{"version":"1.2.0","url":"https://example.test","unknown":true}"#
        )
        .is_err()
    );
}

#[test]
fn github_latest_release_shape_is_supported() {
    let release = parse_github_release(
        r#"{
            "tag_name": "v0.5.0",
            "html_url": "https://github.com/m42e/unproxy/releases/tag/v0.5.0",
            "body": "Release notes"
        }"#,
    )
    .unwrap();
    assert_eq!(release.version, "0.5.0");
    assert_eq!(
        release.url,
        "https://github.com/m42e/unproxy/releases/tag/v0.5.0"
    );
    assert_eq!(release.notes.as_deref(), Some("Release notes"));
}

#[test]
fn an_upgrade_is_reported_only_when_the_remote_version_is_newer() {
    let release = |version: &str| ReleaseInfo {
        version: version.into(),
        url: "https://example.test/releases/latest".into(),
        notes: None,
    };
    assert!(matches!(
        evaluate_release("1.0.0", release("1.1.0")).unwrap(),
        UpgradeStatus::UpgradeAvailable(_)
    ));
    assert!(matches!(
        evaluate_release("1.0.0", release("1.0.0")).unwrap(),
        UpgradeStatus::UpToDate { .. }
    ));
    assert!(matches!(
        evaluate_release("1.0.0", release("0.9.0")).unwrap(),
        UpgradeStatus::UpToDate { .. }
    ));
}

#[test]
fn release_metadata_links_must_be_http_or_https() {
    assert_eq!(
        validate_release_info_url(" HTTPS://updates.example.test/releases.json ").unwrap(),
        "https://updates.example.test/releases.json"
    );
    for value in ["ftp://updates.example.test/release", "file:///release.json"] {
        assert!(validate_release_info_url(value).is_err());
    }
}

#[tokio::test]
async fn check_upgrade_fetches_and_compares_custom_release_json() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut next_version = semver::Version::parse(unproxy::VERSION).unwrap();
    next_version.patch += 1;
    let body = serde_json::json!({
        "version": next_version.to_string(),
        "url": "https://downloads.example.test/unproxy/latest",
        "notes": "Local integration fixture"
    })
    .to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("GET /unproxy.json HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("user-agent: unproxy/")
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let endpoint = format!("http://{address}/unproxy.json");
    let status = unproxy::upgrade::check_for_upgrade(Some(&endpoint))
        .await
        .unwrap();
    server.await.unwrap();
    let UpgradeStatus::UpgradeAvailable(release) = status else {
        panic!("expected an available upgrade, got {status:?}");
    };
    assert_eq!(release.version, next_version.to_string());
    assert_eq!(release.url, "https://downloads.example.test/unproxy/latest");
}
