use unproxy::pac::{Pac, Policy};
use std::net::IpAddr;

#[tokio::test]
async fn policy_runtimes_are_isolated_and_direct_policies_fall_through() {
    let policy = Policy::new_scripts(vec![
        "var privateName='first'; function privateHelper(){return true;} function FindProxyForURL(){return 'DIRECT';}".into(),
        "function FindProxyForURL(){return typeof privateName==='undefined' && typeof privateHelper==='undefined' ? 'PROXY second:80' : 'DIRECT';}".into(),
    ]).unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP second:80"
    );
}

#[test]
fn pac_sources_keep_separate_dns_caches() {
    let host = "cache-isolation-check.invalid";
    let script = format!("function FindProxyForURL(){{dnsResolve('{host}'); return 'DIRECT';}}");
    let mut first = Pac::new(Some(&script)).unwrap();
    let mut second = Pac::new(Some(&script)).unwrap();

    first.evaluate("x", "x").unwrap();
    assert!(first.cache_snapshot().contains_key(host));
    assert!(second.cache_snapshot().is_empty());

    second.evaluate("x", "x").unwrap();
    assert!(second.cache_snapshot().contains_key(host));
}

#[tokio::test]
async fn selected_route_list_keeps_direct_before_proxy() {
    let policy = Policy::new_scripts(vec![
        "function FindProxyForURL(){return 'DIRECT; PROXY first:80';}".into(),
        "function FindProxyForURL(){return 'PROXY second:80';}".into(),
    ])
    .unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT; HTTP first:80"
    );
}

#[tokio::test]
async fn invalid_first_policy_stops_collection_evaluation() {
    let policy = Policy::new_scripts(vec![
        "function FindProxyForURL(){throw new Error('first failed');}".into(),
        "function FindProxyForURL(){return 'PROXY second:80';}".into(),
    ])
    .unwrap();
    assert!(policy.evaluate("x".into(), "x".into()).await.is_err());
}

#[tokio::test]
async fn configured_ip_is_visible_during_top_level_script_execution() {
    let ip: IpAddr = "192.0.2.42".parse().unwrap();
    let policy = Policy::new_scripts_with_ip(vec![
        "var ipAtLoad=myIpAddress(); function FindProxyForURL(){return ipAtLoad==='192.0.2.42' ? 'DIRECT' : 'PROXY wrong:80';}".into(),
    ], ip).unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
}

#[tokio::test]
async fn failed_collection_replacement_preserves_globals_and_dns_cache() {
    let host = "policy-atomicity-check.invalid";
    let policy = Policy::new_scripts(vec![
        format!("let n=0; function FindProxyForURL(){{ n++; dnsResolve('{host}'); return n===1 ? 'DIRECT' : 'PROXY persisted:80'; }}"),
        "function FindProxyForURL(){return 'PROXY second:80';}".into(),
    ]).unwrap();
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP second:80"
    );
    assert!(policy.cache_snapshot().await.unwrap().contains_key(host));

    assert!(
        policy
            .set_scripts(vec![
                "function FindProxyForURL(){return 'PROXY candidate:80';}".into(),
                "var broken=;".into(),
            ])
            .await
            .is_err()
    );
    assert!(policy.cache_snapshot().await.unwrap().contains_key(host));
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP persisted:80"
    );
}

#[tokio::test]
async fn successful_replacement_resets_runtime_globals_and_cache() {
    let host = "policy-success-reset.invalid";
    let policy = Policy::new_scripts(vec![format!(
        "let n=0; function FindProxyForURL(){{ n++; dnsResolve('{host}'); return 'PROXY old:80'; }}"
    )])
    .unwrap();
    policy.evaluate("x".into(), "x".into()).await.unwrap();
    assert!(policy.cache_snapshot().await.unwrap().contains_key(host));

    policy.set_scripts(vec![format!(
        "let n=0; function FindProxyForURL(){{ n++; dnsResolve('{host}'); return n===1 ? 'PROXY fresh:80' : 'PROXY stale:80'; }}"
    )]).await.unwrap();
    assert!(policy.cache_snapshot().await.unwrap().is_empty());
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "HTTP fresh:80"
    );
}

#[tokio::test]
async fn runaway_replacement_keeps_active_policy_and_new_runtime_is_limited() {
    let policy = Policy::new_scripts(vec![
        "function FindProxyForURL(){return 'PROXY active:80';}".into(),
    ])
    .unwrap();
    assert!(
        policy
            .set_scripts(vec![
                "while(true){} function FindProxyForURL(){return 'DIRECT';}".into()
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
        "HTTP active:80"
    );

    policy
        .set_scripts(vec![
            "let n=0; function FindProxyForURL(){if(n++===0){while(true){}} return 'DIRECT';}"
                .into(),
        ])
        .await
        .unwrap();
    assert!(policy.evaluate("x".into(), "x".into()).await.is_err());
    assert_eq!(
        policy
            .evaluate("x".into(), "x".into())
            .await
            .unwrap()
            .to_string(),
        "DIRECT"
    );
    assert!(Policy::new_scripts(vec!["while(true){}".into()]).is_err());
}
