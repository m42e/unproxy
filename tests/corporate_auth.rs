//! Opt-in real identity tests. The dedicated jobs run every ignored test in this
//! target; missing configuration is a failure, never a successful skip.
#![cfg(all(feature = "negotiate", any(unix, windows)))]

use http_body_util::{BodyExt, Empty};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unproxy::{
    auth::{AuthFactory, NegotiateContext},
    connection::Connection,
    net::ConnectionOptions,
    route::{Endpoint, Route},
};

const DEADLINE: Duration = Duration::from_secs(30);

struct Fixture {
    proxy: Endpoint,
    origin: Endpoint,
    body: String,
}

fn required(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("missing identity fixture: {name}"));
    assert!(!value.trim().is_empty(), "empty identity fixture: {name}");
    value
}

impl Fixture {
    fn load() -> Self {
        let backend = required("UNPROXY_AUTH_BACKEND");
        assert_eq!(backend, if cfg!(windows) { "sspi" } else { "gssapi" });
        Self {
            proxy: Endpoint {
                host: required("UNPROXY_AUTH_PROXY_HOST"),
                port: required("UNPROXY_AUTH_PROXY_PORT").parse().unwrap(),
            },
            origin: Endpoint {
                host: required("UNPROXY_AUTH_ORIGIN_HOST"),
                port: required("UNPROXY_AUTH_ORIGIN_PORT").parse().unwrap(),
            },
            body: required("UNPROXY_AUTH_EXPECTED_BODY"),
        }
    }

    fn options(&self, authenticated: bool) -> ConnectionOptions {
        ConnectionOptions {
            auth: if authenticated {
                AuthFactory::negotiate(vec![self.proxy.host.clone()])
            } else {
                AuthFactory::no_auth()
            },
            ..ConnectionOptions::default()
        }
    }

    async fn forward(
        &self,
        options: &ConnectionOptions,
    ) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
        let connection = Connection::proxy(self.proxy.clone(), false, options, DEADLINE)
            .await
            .expect("connect to authenticated proxy");
        let request = http::Request::get(format!("http://{}/identity.txt", self.origin))
            .header(http::header::HOST, self.origin.to_string())
            .body(Empty::<bytes::Bytes>::new())
            .unwrap();
        let response = connection.send(request).await.expect("proxy HTTP exchange");
        let (parts, body) = response.into_parts();
        let body = body.collect().await.expect("origin body").to_bytes();
        (parts.status, parts.headers, body.to_vec())
    }
}

#[test]
#[ignore = "dedicated corporate-auth job supplies a real native identity and proxy"]
fn native_identity_creates_spnego_and_releases_repeated_contexts() {
    let fixture = Fixture::load();
    // Exercise real handle teardown and subsequent acquisition, not a seam.
    for _ in 0..3 {
        let mut context = NegotiateContext::new(&fixture.proxy.host).expect("native context");
        let token = context.step(None).expect("native initial SPNEGO step");
        assert!(!token.expect("initial SPNEGO token").is_empty());
        drop(context);
    }
}

#[tokio::test]
#[ignore = "dedicated corporate-auth job supplies a real native identity and proxy"]
async fn native_identity_authenticates_http_forwarding() {
    tokio::time::timeout(DEADLINE, async {
        let fixture = Fixture::load();
        let (status, headers, _) = fixture.forward(&fixture.options(false)).await;
        assert_eq!(status, http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(
            headers
                .get_all(http::header::PROXY_AUTHENTICATE)
                .iter()
                .any(|value| {
                    value
                        .to_str()
                        .unwrap()
                        .split_ascii_whitespace()
                        .next()
                        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Negotiate"))
                }),
            "proxy must advertise Negotiate"
        );

        // Host restrictions must not offer the process identity to this proxy.
        let mut restricted = fixture.options(false);
        restricted.auth = AuthFactory::negotiate(vec!["excluded.invalid".into()]);
        assert_eq!(
            fixture.forward(&restricted).await.0,
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        for _ in 0..2 {
            let (status, _, body) = fixture.forward(&fixture.options(true)).await;
            assert_eq!(status, http::StatusCode::OK, "native identity rejected");
            assert_eq!(
                body,
                fixture.body.as_bytes(),
                "authenticated origin response"
            );
        }
    })
    .await
    .expect("bounded native HTTP authentication test");
}

#[tokio::test]
#[ignore = "dedicated corporate-auth job supplies a real native identity and proxy"]
async fn native_identity_authenticates_connect_tunnel() {
    tokio::time::timeout(DEADLINE, async {
        let fixture = Fixture::load();
        let route = Route::Http(fixture.proxy.clone());
        let error = match Connection::tunnel(
            route.clone(),
            &fixture.origin,
            &fixture.options(false),
            DEADLINE,
        )
        .await
        {
            Ok(_) => panic!("proxy accepted unauthenticated CONNECT"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("HTTP 407"),
            "expected authentication rejection: {error}"
        );
        let mut connection =
            Connection::tunnel(route, &fixture.origin, &fixture.options(true), DEADLINE)
                .await
                .expect("authenticated CONNECT");
        connection
            .write_all(
                format!(
                    "GET /identity.txt HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    fixture.origin
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        connection.read_to_string(&mut response).await.unwrap();
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("origin response headers");
        assert!(headers.starts_with("HTTP/1.1 200") || headers.starts_with("HTTP/1.0 200"));
        assert_eq!(
            body, fixture.body,
            "CONNECT relays the authenticated origin body"
        );
    })
    .await
    .expect("bounded native CONNECT authentication test");
}
