use std::sync::Arc;
use unproxy::{
    access::{AccessEntry, AccessOutcome},
    net::ConnectionOptions,
    pac::Policy,
    proxy::ContextBuilder,
    route::PathOrUri,
};

fn builder() -> ContextBuilder {
    ContextBuilder::new(
        Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .listen("127.0.0.1:0".parse().unwrap())
}

#[tokio::test]
async fn returned_context_has_loaded_its_local_policy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    tokio::fs::write(
        &file,
        "function FindProxyForURL(){return 'PROXY configured.test:8080';}",
    )
    .await
    .unwrap();
    let context = builder()
        .pac_source(PathOrUri::Path(file))
        .bind()
        .await
        .unwrap();
    assert_eq!(
        context
            .policy()
            .evaluate("http://example.test/".into(), "example.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP configured.test:8080"
    );
    context.shutdown();
    context.wait().await;
}

#[tokio::test]
async fn missing_or_invalid_sources_fail_before_binding_or_serving() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pac");
    assert!(
        builder()
            .pac_source(PathOrUri::Path(missing))
            .bind()
            .await
            .is_err()
    );
    let file = dir.path().join("invalid.pac");
    for script in [
        "function {",
        "function FindProxyForUrl(){return 'DIRECT';}",
        "throw new Error('top level');",
    ] {
        tokio::fs::write(&file, script).await.unwrap();
        assert!(
            builder()
                .pac_source(PathOrUri::Path(file.clone()))
                .bind()
                .await
                .is_err()
        );
        let (_, stream) = tokio::io::duplex(1024);
        assert!(
            builder()
                .pac_source(PathOrUri::Path(file.clone()))
                .serve_stream(stream, "127.0.0.1:1".parse().unwrap())
                .await
                .is_err()
        );
        assert!(
            builder()
                .inline_pac(Some(script.into()))
                .unwrap()
                .bind()
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn supplied_listener_context_exposes_policy_and_access_operations() {
    let dir = tempfile::tempdir().unwrap();
    let pac = dir.path().join("loaded.pac");
    tokio::fs::write(
        &pac,
        "function FindProxyForURL(){return 'PROXY loaded.test:8081';}",
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let context = ContextBuilder::new(
        std::sync::Arc::new(Policy::new(None).unwrap()),
        ConnectionOptions::default(),
    )
    .bind_listener(listener)
    .trusted_management_host("management.fixture")
    .exchange_timeout(std::time::Duration::from_secs(2))
    .bind()
    .await
    .unwrap();
    assert_eq!(context.local_addrs(), [address]);

    context.set_ip("192.0.2.99".parse().unwrap()).await.unwrap();
    context
        .set_script(Some(
            "function FindProxyForURL(){return 'PROXY first.test:8080';}".into(),
        ))
        .await
        .unwrap();
    context
        .set_scripts(vec![
            "function FindProxyForURL(){return 'PROXY second.test:8080';}".into(),
        ])
        .await
        .unwrap();
    context
        .load_pac(&PathOrUri::Path(pac.clone()))
        .await
        .unwrap();
    context.load_pacs(&[PathOrUri::Path(pac)]).await.unwrap();
    assert_eq!(
        context
            .policy()
            .evaluate("http://loaded.test/".into(), "loaded.test".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP loaded.test:8081"
    );

    let mut events = context.subscribe();
    context.publish_access(AccessEntry {
        timestamp: chrono::Local::now().fixed_offset(),
        peer: "127.0.0.1:1234".parse().unwrap(),
        route: None,
        method: http::Method::GET,
        uri: "/probe".parse().unwrap(),
        version: http::Version::HTTP_11,
        elapsed: std::time::Duration::from_millis(2),
        outcome: AccessOutcome::Response {
            status: http::StatusCode::OK,
            content_length: Some(3),
        },
        user_agent: Some("coverage-fixture".into()),
    });
    let event = events.recv().await.unwrap();
    assert!(event.contains("/probe"));
    assert!(event.contains("coverage-fixture"));

    context.clear_policy().await.unwrap();
    context.reload_pac().await.unwrap();
    assert!(
        context
            .wait_timeout(std::time::Duration::from_secs(1))
            .await
    );
}
