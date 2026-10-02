use unproxy::auth::{AuthFactory, CredentialStore};
#[test]
fn credentials_replace_atomically_and_hide_secrets() {
    let store = CredentialStore::parse(
        "machine corp.test login alice password secret\ndefault login guest",
    )
    .unwrap();
    assert_eq!(store.hosts(), vec!["corp.test"]);
    assert!(!format!("{store:?}").contains("secret"));
    assert!(store.replace_netrc("machine broken").is_err());
    assert_eq!(store.hosts(), vec!["corp.test"]);
}
#[tokio::test]
async fn basic_and_no_auth_headers() {
    let store = CredentialStore::parse("machine proxy.test login u password p").unwrap();
    let v = AuthFactory::basic(store)
        .authorization("proxy.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v, "Basic dTpw");
    assert!(
        AuthFactory::default()
            .authorization("proxy.test")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn netrc_supports_an_explicitly_empty_password_and_rejects_missing_default_login() {
    let store = CredentialStore::parse("machine proxy.test login user password \"\"").unwrap();
    let value = AuthFactory::basic(store)
        .authorization("proxy.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value, "Basic dXNlcjo=");
    assert!(CredentialStore::parse("default password empty").is_err());
}
