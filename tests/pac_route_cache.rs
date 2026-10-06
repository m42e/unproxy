use unproxy::pac::Policy;

#[tokio::test]
async fn route_cache_does_not_skip_stateful_pac_evaluation() {
    let policy = Policy::new(Some(
        "let n=0; function FindProxyForURL(){ n++; return n % 2 === 1 ? 'DIRECT' : 'PROXY proxy.example:8080'; }".into(),
    )).unwrap();
    for expected in [
        "DIRECT",
        "HTTP proxy.example:8080",
        "DIRECT",
        "HTTP proxy.example:8080",
    ] {
        assert_eq!(
            policy
                .evaluate("https://same.example/".into(), "same.example".into())
                .await
                .unwrap()
                .to_string(),
            expected
        );
    }
}

#[tokio::test]
async fn route_cache_preserves_non_string_error_and_recovers() {
    let policy = Policy::new(Some(
        "let n=0; function FindProxyForURL(){ n++; return n === 1 ? 42 : 'DIRECT'; }".into(),
    ))
    .unwrap();

    assert!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap_err()
            .to_string()
            .contains("non-string")
    );
    assert_eq!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
}

#[tokio::test]
async fn replacing_scripts_starts_with_fresh_routes() {
    let policy = Policy::new(Some(
        "function FindProxyForURL(){ return 'DIRECT'; }".into(),
    ))
    .unwrap();
    assert_eq!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );

    policy
        .set_scripts(vec![
            "function FindProxyForURL(){ return 'PROXY replacement.example:8080'; }".into(),
        ])
        .await
        .unwrap();
    assert_eq!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP replacement.example:8080"
    );
}

#[tokio::test]
async fn many_distinct_route_results_remain_correct() {
    let policy = Policy::new(Some(
        "function FindProxyForURL(url){ return 'PROXY proxy' + url.substr(1) + '.example:8080'; }"
            .into(),
    ))
    .unwrap();

    for index in 0..96 {
        let url = format!("x{index}");
        let expected = format!("HTTP proxy{index}.example:8080");
        assert_eq!(
            policy
                .evaluate(url, "many.example".into())
                .await
                .unwrap()
                .to_string(),
            expected
        );
    }
}

#[tokio::test]
async fn route_cache_preserves_invalid_route_error_and_recovers() {
    let policy = Policy::new(Some(
        "let n=0; function FindProxyForURL(){ n++; return n === 1 ? 'PROXY invalid' : 'DIRECT'; }"
            .into(),
    ))
    .unwrap();

    assert!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap_err()
            .to_string()
            .contains("missing port")
    );
    assert_eq!(
        policy
            .evaluate("https://same.example/".into(), "same.example".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
}
