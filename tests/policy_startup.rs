use unproxy::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder, route::PathOrUri};
use std::sync::Arc;

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
