use unproxy::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder, route::PathOrUri};
use std::sync::Arc;

const URL: &str = "http://example.test/";
async fn route(policy: &Policy) -> String {
    policy
        .evaluate(URL.into(), "example.test".into())
        .await
        .unwrap()
        .to_string()
}
fn script(route: &str) -> String {
    format!("function FindProxyForURL(){{return '{route}';}}")
}
#[tokio::test]
async fn whole_source_set_load_reload_and_ip_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.pac");
    let second = dir.path().join("second.pac");
    tokio::fs::write(&first, script("DIRECT")).await.unwrap();
    tokio::fs::write(&second, "const startupIP=myIpAddress(); function FindProxyForURL(){return startupIP==='2001:db8::7' ? 'PROXY second.test:8080':'BAD';}").await.unwrap();
    let sources = vec![
        PathOrUri::Path(first.clone()),
        PathOrUri::Path(second.clone()),
    ];
    let policy =
        Arc::new(Policy::new_scripts_with_ip(vec![], "2001:db8::7".parse().unwrap()).unwrap());
    let context = ContextBuilder::new(policy.clone(), ConnectionOptions::default())
        .pac_sources(sources.clone())
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    assert_eq!(route(&policy).await, "HTTP second.test:8080");
    tokio::fs::write(&first, script("PROXY updated.test:8081"))
        .await
        .unwrap();
    tokio::fs::write(&second, "function {").await.unwrap();
    assert!(context.reload_pac().await.is_err());
    assert_eq!(route(&policy).await, "HTTP second.test:8080");
    tokio::fs::remove_file(&second).await.unwrap();
    assert!(context.load_pacs(&sources).await.is_err());
    assert_eq!(route(&policy).await, "HTTP second.test:8080");
    tokio::fs::write(&second, script("DIRECT")).await.unwrap();
    context.reload_pac().await.unwrap();
    assert_eq!(route(&policy).await, "HTTP updated.test:8081");
    context.clear_policy().await.unwrap();
    assert_eq!(route(&policy).await, "DIRECT");
    context.reload_pac().await.unwrap();
    assert_eq!(route(&policy).await, "HTTP updated.test:8081");
    context.shutdown();
    context.wait().await;
}

#[tokio::test]
async fn inline_context_preserves_ip_before_executing_top_level_code() {
    let policy =
        Arc::new(Policy::new_scripts_with_ip(vec![], "192.0.2.42".parse().unwrap()).unwrap());
    let context = ContextBuilder::new(policy.clone(), ConnectionOptions::default())
        .inline_pacs(vec![script("DIRECT"), "const ip=myIpAddress(); function FindProxyForURL(){return ip==='192.0.2.42'?'PROXY inline.test:80':'BAD';}".into()]).unwrap()
        .listen("127.0.0.1:0".parse().unwrap()).bind().await.unwrap();
    assert_eq!(route(&policy).await, "HTTP inline.test:80");
    context.clear_policy().await.unwrap();
    context.reload_pac().await.unwrap();
    assert_eq!(route(&policy).await, "HTTP inline.test:80");
    context.shutdown();
    context.wait().await;
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_sources_mix_symlink_and_http() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("direct.pac");
    let link = dir.path().join("link.pac");
    tokio::fs::write(&file, script("DIRECT")).await.unwrap();
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/proxy.pac", remote.local_addr().unwrap());
    let fetch = tokio::spawn(async move {
        let (mut stream, _) = remote.accept().await.unwrap();
        let mut head = [0; 4096];
        stream.read(&mut head).await.unwrap();
        let body = script("PROXY remote.test:3128");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let policy = Arc::new(Policy::new(None).unwrap());
    let context = ContextBuilder::new(policy.clone(), ConnectionOptions::default())
        .pac_sources(vec![PathOrUri::Path(link), url.parse().unwrap()])
        .listen("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    assert_eq!(route(&policy).await, "HTTP remote.test:3128");
    fetch.await.unwrap();
    context.shutdown();
    context.wait().await;
}
