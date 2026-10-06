//! Upstream proxy authentication.
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue};
use std::{
    collections::HashMap,
    fmt, fs,
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Clone, Default)]
pub struct CredentialStore(Arc<RwLock<Credentials>>);
#[derive(Default)]
struct Credentials {
    hosts: HashMap<String, (String, String)>,
    default: Option<(String, String)>,
}
impl fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialStore")
            .field("hosts", &self.hosts())
            .field(
                "has_default",
                &self.0.read().map(|x| x.default.is_some()).unwrap_or(false),
            )
            .finish()
    }
}
impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_netrc(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse(&fs::read_to_string(path)?)
    }
    pub fn parse(input: &str) -> Result<Self> {
        let t = netrc_tokens(input)?;
        let (mut h, mut d) = (HashMap::new(), None);
        let mut i = 0;
        while i < t.len() {
            let kind = t[i].as_str();
            if kind != "machine" && kind != "default" {
                return Err(anyhow!("expected machine or default, found {kind}"));
            }
            i += 1;
            let host = if kind == "machine" {
                let x = t
                    .get(i)
                    .ok_or_else(|| anyhow!("missing machine name"))?
                    .clone();
                i += 1;
                Some(x)
            } else {
                None
            };
            let (mut login, mut password) = (None, None);
            while i < t.len() && t[i] != "machine" && t[i] != "default" {
                let key = t[i].as_str();
                i += 1;
                match key {
                    "login" | "user" => {
                        let value = t
                            .get(i)
                            .filter(|v| v.as_str() != "machine" && v.as_str() != "default")
                            .ok_or_else(|| anyhow!("missing login"))?;
                        login = Some(value.clone());
                        i += 1
                    }
                    "password" | "passwd" => {
                        if i < t.len() && t[i] != "machine" && t[i] != "default" {
                            password = Some(t[i].clone());
                            i += 1;
                        } else {
                            password = Some(String::new());
                        }
                    }
                    "account" => {
                        if i < t.len() {
                            i += 1
                        }
                    }
                    x => return Err(anyhow!("unsupported netrc token {x}")),
                }
            }
            if let Some(host) = host {
                let u = login.ok_or_else(|| anyhow!("machine {host} has no login"))?;
                h.insert(host, (u, password.unwrap_or_default()));
            } else {
                let u = login.ok_or_else(|| anyhow!("default entry has no login"))?;
                d = Some((u, password.unwrap_or_default()));
            }
        }
        Ok(Self(Arc::new(RwLock::new(Credentials {
            hosts: h,
            default: d,
        }))))
    }
    pub fn replace_netrc(&self, input: &str) -> Result<()> {
        let next = Self::parse(input)?;
        let replacement = next
            .0
            .read()
            .map_err(|_| anyhow!("credential store poisoned"))?;
        *self
            .0
            .write()
            .map_err(|_| anyhow!("credential store poisoned"))? = Credentials {
            hosts: replacement.hosts.clone(),
            default: replacement.default.clone(),
        };
        Ok(())
    }
    pub fn replace_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.replace_netrc(&fs::read_to_string(path)?)
    }
    pub fn hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .0
            .read()
            .map(|m| m.hosts.keys().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v
    }
    fn is_configured(&self) -> bool {
        self.0
            .read()
            .map(|credentials| !credentials.hosts.is_empty() || credentials.default.is_some())
            .unwrap_or(false)
    }
    fn get(&self, host: &str) -> Option<(String, String)> {
        let m = self.0.read().ok()?;
        m.hosts.get(host).cloned().or_else(|| m.default.clone())
    }
}
fn netrc_tokens(input: &str) -> Result<Vec<String>> {
    let (mut tokens, mut current) = (Vec::new(), String::new());
    let (mut quote, mut escaped, mut active) = (None, false, false);
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            active = true;
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            active = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None
            } else {
                current.push(ch)
            };
            active = true;
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            active = true;
            continue;
        }
        if ch == '#' {
            if active {
                tokens.push(std::mem::take(&mut current));
                active = false
            }
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        if ch.is_whitespace() {
            if active {
                tokens.push(std::mem::take(&mut current));
                active = false
            }
        } else {
            current.push(ch);
            active = true
        }
    }
    if escaped {
        return Err(anyhow!("unterminated netrc escape"));
    }
    if quote.is_some() {
        return Err(anyhow!("unterminated netrc quote"));
    }
    if active {
        tokens.push(current)
    }
    Ok(tokens)
}

/// Decode the first Negotiate challenge token in a proxy authentication response.
pub fn negotiate_server_token(headers: &HeaderMap) -> Option<Vec<u8>> {
    headers
        .get_all(http::header::PROXY_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|challenge| {
            let mut parts = challenge.split_ascii_whitespace();
            if !parts.next()?.eq_ignore_ascii_case("Negotiate") {
                return None;
            }
            STANDARD.decode(parts.next()?).ok()
        })
}

#[derive(Clone, Default)]
pub struct AuthFactory {
    mode: AuthMode,
}
#[derive(Clone, Default)]
enum AuthMode {
    #[default]
    None,
    Basic(CredentialStore),
    #[cfg(feature = "negotiate")]
    Negotiate(Vec<String>),
}
impl fmt::Debug for AuthFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            AuthMode::None => f.write_str("AuthFactory(None)"),
            AuthMode::Basic(s) => f.debug_tuple("AuthFactory(Basic)").field(s).finish(),
            #[cfg(feature = "negotiate")]
            AuthMode::Negotiate(h) => f.debug_tuple("AuthFactory(Negotiate)").field(h).finish(),
        }
    }
}
impl AuthFactory {
    pub fn no_auth() -> Self {
        Self::default()
    }
    pub fn basic(store: CredentialStore) -> Self {
        Self {
            mode: AuthMode::Basic(store),
        }
    }
    #[cfg(feature = "negotiate")]
    pub fn negotiate(hosts: Vec<String>) -> Self {
        Self {
            mode: AuthMode::Negotiate(hosts),
        }
    }
    /// Whether this process has an authentication mode or credentials available.
    /// This does not imply that every upstream host has matching credentials.
    pub fn is_configured(&self) -> bool {
        match &self.mode {
            AuthMode::None => false,
            AuthMode::Basic(credentials) => credentials.is_configured(),
            #[cfg(feature = "negotiate")]
            AuthMode::Negotiate(_) => true,
        }
    }
    /// Username/password credentials for SOCKS5; HTTP Negotiate is separate.
    pub(crate) fn socks_credentials(&self, host: &str) -> Option<(String, String)> {
        match &self.mode {
            AuthMode::Basic(store) => store.get(host),
            _ => None,
        }
    }
    pub(crate) fn socks_gss_enabled(&self, host: &str) -> bool {
        #[cfg(feature = "negotiate")]
        if let AuthMode::Negotiate(hosts) = &self.mode {
            return hosts.is_empty() || hosts.iter().any(|allowed| allowed == host);
        }
        let _ = host;
        false
    }
    #[cfg(feature = "negotiate")]
    pub(crate) fn socks_gss_context(&self, host: &str) -> Result<Option<NegotiateContext>> {
        if self.socks_gss_enabled(host) {
            Ok(Some(NegotiateContext::new_socks(host)?))
        } else {
            Ok(None)
        }
    }
    pub async fn authorization(&self, host: &str) -> Result<Option<HeaderValue>> {
        #[cfg(feature = "negotiate")]
        {
            self.authorization_with(host, native::initial_token).await
        }
        #[cfg(not(feature = "negotiate"))]
        {
            self.authorization_with(host, |_| {
                Err(anyhow!("native Negotiate is unavailable in this build"))
            })
            .await
        }
    }

    async fn authorization_with<F>(
        &self,
        host: &str,
        negotiate_token: F,
    ) -> Result<Option<HeaderValue>>
    where
        F: Fn(&str) -> Result<Option<Vec<u8>>> + Copy + Send + 'static,
    {
        #[cfg(not(feature = "negotiate"))]
        let _ = negotiate_token;
        let mode = self.mode.clone();
        let host = host.to_owned();
        let timeout_host = host.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::task::spawn_blocking(move || -> Result<Option<HeaderValue>> {
                match mode {
                    AuthMode::None => Ok(None),
                    AuthMode::Basic(s) => {
                        let (u, p) = s
                            .get(&host)
                            .ok_or_else(|| anyhow!("no credentials configured for {host}"))?;
                        let v = format!("Basic {}", STANDARD.encode(format!("{u}:{p}")));
                        Ok(Some(
                            HeaderValue::from_str(&v)
                                .context("invalid Basic authorization value")?,
                        ))
                    }
                    #[cfg(feature = "negotiate")]
                    AuthMode::Negotiate(hosts) => {
                        negotiate_header(&host, &hosts, || negotiate_token(&host))
                    }
                }
            }),
        )
        .await
        .map_err(|_| anyhow!("authorization timed out for {timeout_host}"))?
        .with_context(|| format!("generating authorization for upstream {timeout_host}"))?
    }
}

#[cfg(feature = "negotiate")]
fn negotiate_header(
    host: &str,
    allowed_hosts: &[String],
    initial_token: impl FnOnce() -> Result<Option<Vec<u8>>>,
) -> Result<Option<HeaderValue>> {
    if !allowed_hosts.is_empty() && !allowed_hosts.iter().any(|allowed| allowed == host) {
        return Ok(None);
    }
    let token = initial_token()
        .with_context(|| format!("generating Negotiate authorization for upstream {host}"))?;
    token
        .map(|token| {
            HeaderValue::from_str(&format!("Negotiate {}", STANDARD.encode(token)))
                .context("invalid Negotiate header")
        })
        .transpose()
}

#[cfg(feature = "negotiate")]
#[path = "auth/native.rs"]
mod native;
#[cfg(feature = "negotiate")]
pub use native::NegotiateContext;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_negotiate_token_is_decoded_from_proxy_authenticate() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=proxy"),
        );
        headers.append(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Negotiate SGVsbG8gV29ybGQh"),
        );
        assert_eq!(
            negotiate_server_token(&headers),
            Some(b"Hello World!".to_vec())
        );
    }
    #[test]
    fn netrc_default_replace() {
        let c = CredentialStore::parse("machine a login joe\ndefault login d password p").unwrap();
        assert_eq!(c.get("a"), Some(("joe".into(), "".into())));
        assert_eq!(c.get("b"), Some(("d".into(), "p".into())));
        assert!(c.replace_netrc("machine broken").is_err());
        assert_eq!(c.get("a").unwrap().0, "joe")
    }

    #[test]
    fn netrc_quoting_escaping_comments_and_account_tokens_are_parsed() {
        let store = CredentialStore::parse(
            "machine 'corp host' login \"alice name\" password 'p # ss' account billing\n\
             machine escaped login foo\\ bar password x\\#y # ignored comment\n\
             default user fallback passwd",
        )
        .unwrap();
        assert_eq!(
            store.get("corp host"),
            Some(("alice name".into(), "p # ss".into()))
        );
        assert_eq!(store.get("escaped"), Some(("foo bar".into(), "x#y".into())));
        assert_eq!(store.get("other"), Some(("fallback".into(), "".into())));

        let adjacent_comment = CredentialStore::parse(
            "machine inline login person#discarded until newline\npassword secret",
        )
        .unwrap();
        assert_eq!(
            adjacent_comment.get("inline"),
            Some(("person".into(), "secret".into()))
        );
        assert!(CredentialStore::parse("machine terminal user person account").is_ok());
        assert_eq!(
            CredentialStore::parse("machine  spaced login person")
                .unwrap()
                .get("spaced"),
            Some(("person".into(), "".into()))
        );

        for input in [
            "machine host",
            "machine host password secret",
            "default password secret",
            "machine host login user unsupported value",
            "nonsense host login user",
            "machine host login user \\",
            "machine host login 'unterminated",
        ] {
            assert!(CredentialStore::parse(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn auth_factory_debug_identifies_modes_without_exposing_passwords() {
        assert_eq!(format!("{:?}", AuthFactory::no_auth()), "AuthFactory(None)");
        assert!(!AuthFactory::no_auth().is_configured());
        let credentials =
            CredentialStore::parse("machine proxy.example login alice password confidential")
                .unwrap();
        assert!(AuthFactory::basic(credentials.clone()).is_configured());
        let debug = format!("{:?}", AuthFactory::basic(credentials));
        assert!(debug.contains("AuthFactory(Basic)"));
        assert!(debug.contains("proxy.example"));
        assert!(!debug.contains("confidential"));
    }

    #[test]
    fn credential_files_replace_and_surface_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netrc");
        std::fs::write(&path, "machine first login user password one").unwrap();
        let store = CredentialStore::from_netrc(&path).unwrap();
        assert_eq!(store.get("first"), Some(("user".into(), "one".into())));
        std::fs::write(&path, "machine second login user password two").unwrap();
        store.replace_file(&path).unwrap();
        assert_eq!(store.hosts(), ["second"]);
        assert!(store.replace_file(dir.path().join("missing")).is_err());
        assert!(CredentialStore::from_netrc(dir.path().join("missing")).is_err());
    }

    #[test]
    fn poisoned_credential_lock_returns_empty_safe_views_and_a_replace_error() {
        let store = CredentialStore::parse("machine host login user password secret").unwrap();
        let poisoned = store.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.0.write().unwrap();
            panic!("poison credential store for this test");
        })
        .join();
        assert!(store.hosts().is_empty());
        assert!(!format!("{store:?}").contains("secret"));
        assert!(store.replace_netrc("default login replacement").is_err());
        assert_eq!(store.get("host"), None);
    }

    #[test]
    fn negotiate_challenge_parser_skips_bad_and_non_text_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Negotiate !invalid, Basic realm=proxy"),
        );
        headers.append(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("nEgOtIaTe SGVsbG8="),
        );
        headers.append(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert_eq!(negotiate_server_token(&headers), Some(b"Hello".to_vec()));
        let mut invalid = HeaderMap::new();
        invalid.insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Negotiate invalid-token"),
        );
        assert_eq!(negotiate_server_token(&invalid), None);
    }
    #[tokio::test]
    #[cfg(feature = "negotiate")]
    async fn negotiate_host_restriction_skips_unlisted_hosts_before_native_setup() {
        let auth = AuthFactory::negotiate(vec!["proxy.corp.test".into()]);
        assert!(auth.is_configured());
        assert_eq!(auth.authorization("proxy.public.test").await.unwrap(), None);
        assert!(format!("{auth:?}").contains("proxy.corp.test"));
    }

    #[tokio::test]
    #[cfg(feature = "negotiate")]
    async fn negotiate_factory_uses_injected_token_provider_after_host_check() {
        let allowed = AuthFactory::negotiate(vec!["proxy.corp.test".into()]);
        let header = allowed
            .authorization_with("proxy.corp.test", |_| Ok(Some(b"fixture".to_vec())))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header, "Negotiate Zml4dHVyZQ==");

        let blocked = allowed
            .authorization_with("proxy.public.test", |_| {
                panic!("a disallowed host must not request a token")
            })
            .await
            .unwrap();
        assert!(blocked.is_none());
    }

    #[tokio::test]
    #[cfg(feature = "negotiate")]
    async fn allowed_negotiate_host_runs_the_native_authorization_path() {
        let auth = AuthFactory::negotiate(Vec::new());
        match auth.authorization("localhost").await {
            Ok(Some(value)) => assert!(value.to_str().unwrap().starts_with("Negotiate ")),
            Ok(None) => panic!("global Negotiate mode should attempt an initial token"),
            Err(error) => assert!(format!("{error:#}").contains("localhost"), "{error:#}"),
        }
    }

    #[test]
    #[cfg(all(feature = "negotiate", windows))]
    fn socks_negotiate_context_checks_the_host_before_acquiring_sspi_credentials() {
        let auth = AuthFactory::negotiate(vec!["proxy.corp.test".into()]);
        assert!(
            auth.socks_gss_context("proxy.public.test")
                .unwrap()
                .is_none()
        );

        let context = auth
            .socks_gss_context("proxy.corp.test")
            .unwrap()
            .expect("allowed host should acquire an SSPI context");
        assert!(!context.is_complete());
    }

    #[test]
    #[cfg(feature = "negotiate")]
    fn negotiate_header_enforces_host_allowlist_and_formats_or_omits_tokens() {
        let allowed = vec!["proxy.corp.test".to_owned()];
        assert_eq!(
            negotiate_header("proxy.public.test", &allowed, || {
                panic!("disallowed hosts must not create native contexts")
            })
            .unwrap(),
            None
        );
        assert_eq!(
            negotiate_header("proxy.corp.test", &allowed, || Ok(Some(b"hello".to_vec())))
                .unwrap()
                .unwrap(),
            HeaderValue::from_static("Negotiate aGVsbG8=")
        );
        assert!(
            negotiate_header("any.host", &[], || Ok(None))
                .unwrap()
                .is_none()
        );
        let error =
            negotiate_header("broken.host", &[], || Err(anyhow!("fixture error"))).unwrap_err();
        assert!(format!("{error:#}").contains("broken.host"));
    }
}
