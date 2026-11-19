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
fn release_metadata_links_require_https() {
    assert_eq!(
        validate_release_info_url(" HTTPS://updates.example.test/releases.json ").unwrap(),
        "https://updates.example.test/releases.json"
    );
    for value in [
        "http://updates.example.test/release",
        "ftp://updates.example.test/release",
        "file:///release.json",
    ] {
        assert!(validate_release_info_url(value).is_err());
    }
}

#[tokio::test]
async fn check_upgrade_rejects_http_metadata_before_contacting_the_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut next_version = semver::Version::parse(unproxy::VERSION).unwrap();
    next_version.patch += 1;
    let body = serde_json::json!({
        "version": next_version.to_string(),
        "url": format!("https://downloads.example.test/unproxy/{next_version}"),
        "notes": "Local integration fixture"
    })
    .to_string();

    let endpoint = format!("http://{address}/unproxy.json");
    let error = unproxy::upgrade::check_for_upgrade(Some(&endpoint))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("must use HTTPS"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "HTTP metadata endpoint was contacted"
    );

    let release = parse_custom_release_info(&body).unwrap();
    assert_eq!(release.version, next_version.to_string());
    assert_eq!(
        release.url,
        format!("https://downloads.example.test/unproxy/{next_version}")
    );
}
