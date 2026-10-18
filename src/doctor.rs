//! Health checks for the effective Unproxy configuration and a running instance.

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::Args;
use http::{Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpStream;

use crate::{
    config::{self, MainArgs},
    pac::Policy,
    proxy,
    route::{Destination, Endpoint, PathOrUri, Route},
};

const DEFAULT_URL: &str = "https://example.com/";
const MAX_STATUS_BYTES: usize = 64 * 1024;

#[derive(Args, Debug, Clone, Default)]
pub struct DoctorArgs {
    /// URL used to evaluate PAC routing and probe the selected route; may be repeated.
    #[arg(long = "url", action = clap::ArgAction::Append, value_name = "URL")]
    pub urls: Vec<String>,
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new() -> Self {
        Self {
            ok: true,
            checks: Vec::new(),
        }
    }

    fn add(&mut self, name: impl Into<String>, status: CheckStatus, message: impl Into<String>) {
        if matches!(status, CheckStatus::Fail) {
            self.ok = false;
        }
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            message: message.into(),
        });
    }

    fn counts(&self) -> (usize, usize, usize) {
        self.checks.iter().fold((0, 0, 0), |mut counts, check| {
            match check.status {
                CheckStatus::Pass => counts.0 += 1,
                CheckStatus::Warn => counts.1 += 1,
                CheckStatus::Fail => counts.2 += 1,
            }
            counts
        })
    }
}

#[derive(Debug, Deserialize)]
struct LiveStatus {
    pac_loaded: Option<bool>,
    #[serde(default)]
    pac_files: Vec<String>,
    authentication_configured: Option<bool>,
    upstream_state: Option<String>,
    authentication_state: Option<String>,
    upstream_route: Option<String>,
    authentication_sent: Option<bool>,
}

/// Run health checks and print a human-readable or JSON report. Returns false
/// when a required check failed so the CLI can exit with status 1.
pub async fn run(args: MainArgs, doctor: DoctorArgs) -> Result<bool> {
    let report = inspect(args, doctor.urls).await;
    if doctor.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(report.ok)
}

async fn inspect(args: MainArgs, urls: Vec<String>) -> DoctorReport {
    let mut report = DoctorReport::new();
    let settings = if std::env::var_os("UNPROXY_NORC").is_none_or(|value| value.is_empty()) {
        config::settings_path()
    } else {
        None
    };
    match settings {
        Some(path) => report.add(
            "Settings",
            CheckStatus::Pass,
            format!("loaded settings from {}", path.display()),
        ),
        None => report.add(
            "Settings",
            CheckStatus::Pass,
            "no settings file found; using command-line options and defaults",
        ),
    }

    if args.max_sessions == 0 {
        report.add(
            "Session limit",
            CheckStatus::Fail,
            "--max-sessions must be greater than zero",
        );
    } else {
        report.add(
            "Session limit",
            CheckStatus::Pass,
            format!("{} simultaneous client sessions", args.max_sessions),
        );
    }

    let sources = match config::pac_sources(&args) {
        Ok(sources) => {
            if sources.is_empty() {
                if args.strict_policy {
                    report.add(
                        "PAC configuration",
                        CheckStatus::Fail,
                        "strict policy is enabled but no PAC source is configured",
                    );
                } else {
                    report.add(
                        "PAC configuration",
                        CheckStatus::Pass,
                        "no PAC source configured; requests use DIRECT routing",
                    );
                }
            } else {
                let names = sources
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                report.add(
                    "PAC configuration",
                    CheckStatus::Pass,
                    format!("{} source(s): {names}", sources.len()),
                );
            }
            sources
        }
        Err(error) => {
            report.add(
                "PAC configuration",
                CheckStatus::Fail,
                format!("could not resolve PAC sources: {error:#}"),
            );
            Vec::new()
        }
    };

    let scripts = if sources.is_empty() {
        Ok(Vec::new())
    } else {
        proxy::load_pac_sources(&sources).await
    };
    let policy = match scripts {
        Ok(scripts) => match Policy::new_scripts_with_ip(
            scripts,
            args.my_ip_address
                .unwrap_or_else(crate::platform::default_interface_ipv4),
        ) {
            Ok(policy) => {
                if !sources.is_empty() {
                    report.add(
                        "PAC loading",
                        CheckStatus::Pass,
                        format!("loaded and compiled {} PAC source(s)", sources.len()),
                    );
                }
                Some(policy)
            }
            Err(error) => {
                report.add(
                    "PAC loading",
                    CheckStatus::Fail,
                    format!("could not initialize PAC policy: {error:#}"),
                );
                None
            }
        },
        Err(error) => {
            report.add(
                "PAC loading",
                CheckStatus::Fail,
                format!("could not load PAC source: {error:#}"),
            );
            None
        }
    };

    check_filter_lists(&args, &mut report).await;

    let auth = match crate::runtime::load_auth(&args) {
        Ok(auth) => {
            report.add(
                "Authentication configuration",
                CheckStatus::Pass,
                if auth.is_configured() {
                    "credentials or Negotiate authentication are configured"
                } else {
                    "no upstream credentials configured; unauthenticated upstreams can still work"
                },
            );
            Some(auth)
        }
        Err(error) => {
            report.add(
                "Authentication configuration",
                CheckStatus::Fail,
                format!("could not load authentication settings: {error:#}"),
            );
            None
        }
    };
    let configured_auth = auth.as_ref().is_some_and(|factory| factory.is_configured());

    let urls = if urls.is_empty() {
        vec![DEFAULT_URL.to_owned()]
    } else {
        urls
    };
    let mut proxy_routes = Vec::new();
    let mut routed_any = false;

    if let Some(policy) = policy {
        for raw_url in urls {
            let uri = match raw_url.parse::<Uri>() {
                Ok(uri) => uri,
                Err(error) => {
                    report.add(
                        format!("Route {raw_url}"),
                        CheckStatus::Fail,
                        format!("invalid URL: {error}"),
                    );
                    continue;
                }
            };
            let destination = match Destination::from_uri(&uri) {
                Ok(destination) => destination,
                Err(error) => {
                    report.add(
                        format!("Route {raw_url}"),
                        CheckStatus::Fail,
                        format!("invalid destination: {error:#}"),
                    );
                    continue;
                }
            };
            let evaluation = if args.strict_policy {
                policy
                    .evaluate_strict(raw_url.clone(), destination.endpoint.host.clone())
                    .await
            } else {
                policy
                    .evaluate(raw_url.clone(), destination.endpoint.host.clone())
                    .await
            };
            let mut routes = match evaluation {
                Ok(routes) => routes,
                Err(error) => {
                    report.add(
                        format!("Route {raw_url}"),
                        CheckStatus::Fail,
                        format!("PAC evaluation failed: {error:#}"),
                    );
                    continue;
                }
            };
            if args.direct_fallback && !routes.0.iter().any(|route| matches!(route, Route::Direct))
            {
                routes.0.push(Route::Direct);
            }
            routed_any = true;
            let timeout = args.connect_timeout.min(Duration::from_secs(3));
            let mut successes = 0usize;
            let mut results = Vec::new();
            for route in &routes.0 {
                let target = match route {
                    Route::Direct => &destination.endpoint,
                    Route::Http(endpoint)
                    | Route::Https(endpoint)
                    | Route::Socks4(endpoint)
                    | Route::Socks5(endpoint) => {
                        if !proxy_routes.contains(route) {
                            proxy_routes.push(route.clone());
                        }
                        endpoint
                    }
                };
                match probe_endpoint(target, timeout).await {
                    Ok(()) => {
                        successes += 1;
                        results.push(format!("{route}: reachable"));
                    }
                    Err(error) => results.push(format!("{route}: {error}")),
                }
            }
            let status = if successes == routes.0.len() {
                CheckStatus::Pass
            } else if successes > 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            };
            report.add(
                format!("Routes for {raw_url}"),
                status,
                format!("PAC selected {}; {}", routes, results.join("; ")),
            );
        }
    }

    if !routed_any {
        report.add(
            "Route evaluation",
            CheckStatus::Fail,
            "no URL could be evaluated; pass a valid --url or fix the PAC configuration",
        );
    }

    if proxy_routes.is_empty() {
        report.add(
            "Upstream authentication",
            CheckStatus::Pass,
            "the selected routes do not use an upstream proxy",
        );
    } else if let Some(auth) = auth {
        for route in proxy_routes {
            check_route_authentication(&route, &auth, &mut report).await;
        }
    }

    check_listeners(&args, &sources, configured_auth, &mut report).await;
    report
}

async fn check_route_authentication(
    route: &Route,
    auth: &crate::auth::AuthFactory,
    report: &mut DoctorReport,
) {
    let name = format!("Authentication for {route}");
    match route {
        Route::Direct => {}
        Route::Socks4(_) => report.add(
            name,
            CheckStatus::Pass,
            "SOCKS4 uses an empty user ID and does not use HTTP proxy authentication",
        ),
        Route::Socks5(endpoint) => {
            if auth.socks_credentials(&endpoint.host).is_some() {
                report.add(
                    name,
                    CheckStatus::Pass,
                    "SOCKS5 username/password credentials are available; secrets were not displayed",
                );
                return;
            }
            #[cfg(feature = "negotiate")]
            if auth.socks_gss_enabled(&endpoint.host) {
                match auth.socks_gss_context(&endpoint.host) {
                    Ok(Some(_)) => report.add(
                        name,
                        CheckStatus::Pass,
                        "a SOCKS5 Negotiate context can be created; tokens were not sent or displayed",
                    ),
                    Ok(None) => report.add(
                        name,
                        CheckStatus::Warn,
                        "Negotiate is enabled but not for this SOCKS5 host",
                    ),
                    Err(error) => report.add(
                        name,
                        CheckStatus::Fail,
                        format!("could not create a SOCKS5 Negotiate context: {error:#}"),
                    ),
                }
                return;
            }
            report.add(
                name,
                CheckStatus::Warn,
                if auth.is_configured() {
                    "no SOCKS5 credentials match this host; the route works if the upstream allows unauthenticated access"
                } else {
                    "no SOCKS5 credentials configured; the route works if the upstream allows unauthenticated access"
                },
            );
        }
        Route::Http(endpoint) | Route::Https(endpoint) => {
            if !auth.is_configured() {
                report.add(
                    name,
                    CheckStatus::Warn,
                    "no credentials are configured; this route works only if the upstream allows unauthenticated access",
                );
                return;
            }
            match auth.authorization(&endpoint.host).await {
                Ok(Some(_)) => report.add(
                    name,
                    CheckStatus::Pass,
                    "an authorization token can be generated; the token was not sent or displayed",
                ),
                Ok(None) => report.add(
                    name,
                    CheckStatus::Warn,
                    "authentication is configured but is not enabled for this host",
                ),
                Err(error) => {
                    let message = format!("{error:#}");
                    let missing_host_credentials =
                        message.contains("no credentials configured for");
                    report.add(
                        name,
                        if missing_host_credentials {
                            CheckStatus::Warn
                        } else {
                            CheckStatus::Fail
                        },
                        if missing_host_credentials {
                            format!("no credentials match this host; the route works if the upstream allows unauthenticated access ({message})")
                        } else {
                            format!("could not generate authorization: {message}")
                        },
                    );
                }
            }
        }
    }
}

async fn check_filter_lists(args: &MainArgs, report: &mut DoctorReport) {
    if args.filter_list.is_empty() {
        report.add(
            "Filter lists",
            CheckStatus::Pass,
            "no filter lists configured",
        );
        return;
    }
    match crate::filter_list::FilterList::load(&args.filter_list).await {
        Ok(list) => report.add(
            "Filter lists",
            CheckStatus::Pass,
            format!(
                "loaded {} source(s), covering {} domains",
                args.filter_list.len(),
                list.domain_count()
            ),
        ),
        Err(error) => report.add(
            "Filter lists",
            CheckStatus::Warn,
            format!("one or more optional lists are unavailable: {error:#}"),
        ),
    }
}

async fn check_listeners(
    args: &MainArgs,
    sources: &[PathOrUri],
    configured_auth: bool,
    report: &mut DoctorReport,
) {
    if let Some(name) = args.activate_socket.as_deref() {
        report.add(
            "Listeners",
            CheckStatus::Warn,
            format!("listener {name:?} is supplied by socket activation and cannot be discovered from this command"),
        );
        return;
    }

    let addresses = match args.listen_addrs() {
        Ok(addresses) => addresses,
        Err(error) => {
            report.add(
                "Listeners",
                CheckStatus::Fail,
                format!("invalid listener configuration: {error:#}"),
            );
            return;
        }
    };
    let timeout = args.connect_timeout.min(Duration::from_secs(3));
    let mut reachable = 0usize;
    let mut checked = 0usize;
    let mut details = Vec::new();
    let mut runtime = None;
    let mut status_unavailable = Vec::new();

    for address in addresses {
        if address.port() == 0 {
            details.push(format!(
                "{address}: port 0 is ephemeral and cannot be rediscovered"
            ));
            continue;
        }
        checked += 1;
        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                reachable += 1;
                drop(stream);
                if address.ip().is_loopback() && runtime.is_none() {
                    match read_runtime_status(address, timeout).await {
                        Ok(status) => runtime = Some(status),
                        Err(error) => status_unavailable.push(format!("{address}: {error:#}")),
                    }
                }
                details.push(format!("{address}: accepts TCP connections"));
            }
            Ok(Err(error)) => details.push(format!("{address}: {error}")),
            Err(_) => details.push(format!("{address}: connection timed out")),
        }
    }

    let listener_status = if checked == 0 {
        CheckStatus::Warn
    } else if reachable == checked {
        CheckStatus::Pass
    } else if reachable > 0 {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    report.add("Listeners", listener_status, details.join("; "));

    if !status_unavailable.is_empty() {
        report.add(
            "Runtime status endpoint",
            CheckStatus::Warn,
            format!(
                "could not read /status.json: {}",
                status_unavailable.join("; ")
            ),
        );
    }
    if let Some(status) = runtime {
        check_live_state(&status, configured_auth, sources, report);
    }
}

async fn read_runtime_status(address: SocketAddr, timeout: Duration) -> Result<LiveStatus> {
    tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(address)
            .await
            .with_context(|| format!("connecting to {address}"))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("starting HTTP client")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri("/status.json")
            .header(header::HOST, address.to_string())
            .body(Empty::<Bytes>::new())?;
        let response = sender
            .send_request(request)
            .await
            .context("requesting /status.json")?;
        if response.status() != StatusCode::OK {
            bail!("/status.json returned HTTP {}", response.status());
        }
        let mut incoming = response.into_body();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.context("reading /status.json")?;
            if let Some(data) = frame.data_ref() {
                if body.len().saturating_add(data.len()) > MAX_STATUS_BYTES {
                    bail!("/status.json exceeded {MAX_STATUS_BYTES} bytes");
                }
                body.extend_from_slice(data);
            }
        }
        let status: LiveStatus = serde_json::from_slice(&body).context("parsing /status.json")?;
        if status.pac_loaded.is_none()
            || status.authentication_configured.is_none()
            || status.upstream_state.is_none()
        {
            bail!("/status.json is missing expected Unproxy state fields");
        }
        Ok(status)
    })
    .await
    .map_err(|_| anyhow!("request timed out"))?
}

fn check_live_state(
    status: &LiveStatus,
    configured_auth: bool,
    sources: &[PathOrUri],
    report: &mut DoctorReport,
) {
    let expected_sources = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
    let live_loaded = status.pac_loaded.unwrap_or(false);
    let expected_loaded = !expected_sources.is_empty();
    if live_loaded == expected_loaded && (!live_loaded || status.pac_files == expected_sources) {
        report.add(
            "Running PAC state",
            CheckStatus::Pass,
            if live_loaded {
                format!(
                    "running instance has loaded {} configured PAC source(s)",
                    status.pac_files.len()
                )
            } else {
                "running instance has no PAC policy loaded".to_owned()
            },
        );
    } else {
        report.add(
            "Running PAC state",
            CheckStatus::Warn,
            format!(
                "running instance reports loaded={} with sources [{}], while current settings select [{}]; restart the service to apply changed settings",
                live_loaded,
                status.pac_files.join(", "),
                expected_sources.join(", ")
            ),
        );
    }

    let auth_configured = status.authentication_configured.unwrap_or(false);
    if auth_configured == configured_auth {
        report.add(
            "Running authentication state",
            CheckStatus::Pass,
            if auth_configured {
                "running instance has upstream authentication configured"
            } else {
                "running instance has no upstream authentication configured"
            },
        );
    } else {
        report.add(
            "Running authentication state",
            CheckStatus::Warn,
            "running instance authentication differs from the settings loaded by doctor; restart the service to apply changes",
        );
    }

    match status.upstream_state.as_deref().unwrap_or("unknown") {
        "ok" => report.add(
            "Last upstream state",
            CheckStatus::Pass,
            format!(
                "last upstream exchange succeeded{}",
                status
                    .upstream_route
                    .as_ref()
                    .map(|route| format!(" via {route}"))
                    .unwrap_or_default()
            ),
        ),
        "error" => report.add(
            "Last upstream state",
            CheckStatus::Fail,
            format!(
                "last upstream exchange failed{}",
                status
                    .upstream_route
                    .as_ref()
                    .map(|route| format!(" via {route}"))
                    .unwrap_or_default()
            ),
        ),
        _ => report.add(
            "Last upstream state",
            CheckStatus::Warn,
            "the running instance has not recorded an upstream exchange yet",
        ),
    }

    match status.authentication_state.as_deref().unwrap_or("unknown") {
        "authenticated" => report.add(
            "Last authentication state",
            CheckStatus::Pass,
            if status.authentication_sent.unwrap_or(false) {
                "the last upstream exchange accepted an authentication token"
            } else {
                "the last upstream exchange completed with authentication accepted"
            },
        ),
        "rejected" => report.add(
            "Last authentication state",
            CheckStatus::Fail,
            "the last upstream exchange was rejected with an authentication challenge",
        ),
        "configured" => report.add(
            "Last authentication state",
            CheckStatus::Warn,
            "authentication is configured, but the running instance has not confirmed acceptance",
        ),
        "disabled" => report.add(
            "Last authentication state",
            CheckStatus::Pass,
            "no upstream authentication token was needed or configured",
        ),
        _ => report.add(
            "Last authentication state",
            CheckStatus::Warn,
            "the running instance has no authentication result to report",
        ),
    }
}

async fn probe_endpoint(endpoint: &Endpoint, timeout: Duration) -> Result<()> {
    let connect = TcpStream::connect((endpoint.host.as_str(), endpoint.port));
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(error)) => Err(anyhow!("unreachable ({error})")),
        Err(_) => Err(anyhow!("connection timed out")),
    }
}

fn print_report(report: &DoctorReport) {
    for check in &report.checks {
        let label = match check.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        };
        println!("{label} {}: {}", check.name, check.message);
    }
    let (passed, warnings, failed) = report.counts();
    println!("doctor: {passed} passed, {warnings} warning(s), {failed} failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_only_fails_for_failed_checks() {
        let mut report = DoctorReport::new();
        report.add("warning", CheckStatus::Warn, "pending");
        assert!(report.ok);
        report.add("failed", CheckStatus::Fail, "unavailable");
        assert!(!report.ok);
        assert_eq!(report.counts(), (0, 1, 1));
    }

    #[test]
    fn status_state_requires_unproxy_fields() {
        let status: LiveStatus = serde_json::from_str(
            r#"{"pac_loaded":false,"pac_files":[],"authentication_configured":false,"upstream_state":"unknown"}"#,
        )
        .unwrap();
        assert_eq!(status.pac_loaded, Some(false));
        assert_eq!(status.authentication_configured, Some(false));
        assert_eq!(status.upstream_state.as_deref(), Some("unknown"));
    }
}
