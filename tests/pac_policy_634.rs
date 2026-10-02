use unproxy::pac::Policy;

#[tokio::test]
async fn ordered_pac_sources_fall_through_direct_and_replace_atomically() {
    let policy = Policy::new_scripts(vec![
        "function FindProxyForURL(){return 'DIRECT';}".into(),
        "function FindProxyForURL(){return 'PROXY second:80';}".into(),
    ])
    .unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP second:80"
    );
    assert!(
        policy
            .set_scripts(vec![
                "function FindProxyForURL(){return 'PROXY first:80';}".into(),
                "var nope=;".into(),
            ])
            .await
            .is_err()
    );
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP second:80"
    );
    policy.set_scripts(vec![]).await.unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
}
