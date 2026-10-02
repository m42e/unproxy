//! HTTP/1 forward proxy and embedded management endpoints.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use futures_util::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{broadcast, watch},
    task::JoinHandle,
};
use tokio_util::task::TaskTracker;

use crate::{
    access::{AccessEntry, AccessOutcome},
    net::{self, BoxedIo, ConnectionOptions},
    pac::Policy,
    route::{Destination, Endpoint, PathOrUri, Route, Routes},
};

type OutBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub struct ContextBuilder {
    policy: Arc<Policy>,
    options: ConnectionOptions,
    listens: Vec<SocketAddr>,
    sockets: Vec<TcpListener>,
    timeout: Duration,
    direct_fallback: bool,
    race: bool,
    parallel: usize,
    force_tunnel: bool,
    server_keepalive: net::Keepalive,
    shutdown_timeout: Duration,
    bound_addrs: Vec<SocketAddr>,
    pac_sources: Vec<PathOrUri>,
    inline_scripts: Vec<String>,
    initialize_inline: bool,
}
impl Clone for ContextBuilder {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            options: self.options.clone(),
            listens: self.listens.clone(),
            sockets: vec![],
            timeout: self.timeout,
            direct_fallback: self.direct_fallback,
            race: self.race,
            parallel: self.parallel,
            force_tunnel: self.force_tunnel,
            server_keepalive: self.server_keepalive.clone(),
            shutdown_timeout: self.shutdown_timeout,
            bound_addrs: self.bound_addrs.clone(),
            pac_sources: self.pac_sources.clone(),
            inline_scripts: self.inline_scripts.clone(),
            initialize_inline: self.initialize_inline,
        }
    }
}
impl ContextBuilder {
    pub fn new(policy: Arc<Policy>, options: ConnectionOptions) -> Self {
        Self {
            policy,
            options,
            listens: vec![],
            sockets: vec![],
            timeout: Duration::from_secs(30),
            direct_fallback: false,
            race: false,
            parallel: 1,
            force_tunnel: false,
            server_keepalive: net::Keepalive::default(),
            shutdown_timeout: Duration::from_secs(30),
            bound_addrs: vec![],
            pac_sources: vec![],
            inline_scripts: vec![],
            initialize_inline: false,
        }
    }
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listens.push(addr);
        self
    }
    /// Serve sockets supplied by a service manager or embedding application.
    pub fn listeners(mut self, sockets: Vec<TcpListener>) -> Self {
        self.sockets.extend(sockets);
        self
    }
    pub fn bind_listener(self, socket: TcpListener) -> Self {
        self.listeners(vec![socket])
    }
    pub fn server_keepalive(mut self, options: net::Keepalive) -> Self {
        self.server_keepalive = options;
        self
    }
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }
    pub fn connect_timeout(mut self, v: Duration) -> Self {
        self.timeout = v;
        self
    }
    pub fn direct_fallback(mut self, v: bool) -> Self {
        self.direct_fallback = v;
        self
    }
    pub fn race_connect(mut self, v: bool) -> Self {
        self.race = v;
        self
    }
    pub fn parallel_connect(mut self, v: usize) -> Self {
        self.parallel = v.max(1);
        self
    }
    pub fn force_tunnel(mut self, v: bool) -> Self {
        self.force_tunnel = v;
        self
    }
    /// Configure an inline script; validation is awaited before serving.
    pub fn inline_pac(self, source: Option<String>) -> Result<Self> {
        self.inline_pacs(source.into_iter().collect())
    }
    /// Each inline script gets an isolated runtime, in the supplied order.
    pub fn inline_pacs(mut self, sources: Vec<String>) -> Result<Self> {
        self.pac_sources.clear();
        self.inline_scripts = sources;
        self.initialize_inline = true;
        Ok(self)
    }
    pub fn pac_source(self, source: PathOrUri) -> Self {
        self.pac_sources(vec![source])
    }
    pub fn pac_sources(mut self, sources: Vec<PathOrUri>) -> Self {
        self.pac_sources = sources;
        self.inline_scripts.clear();
        self.initialize_inline = self.pac_sources.is_empty();
        self
    }
    async fn initialize_policy(&self) -> Result<()> {
        if !self.pac_sources.is_empty() {
            let scripts = load_pac_sources(&self.pac_sources).await?;
            self.policy.set_scripts(scripts).await?;
        } else if self.initialize_inline {
            self.policy.set_scripts(self.inline_scripts.clone()).await?;
        }
        Ok(())
    }
    pub async fn bind(mut self) -> Result<Context> {
        self.initialize_policy().await?;
        let mut listeners = std::mem::take(&mut self.sockets);
        let addrs = if !listeners.is_empty() {
            vec![]
        } else if self.listens.is_empty() {
            vec!["127.0.0.1:3128".parse().unwrap()]
        } else {
            self.listens.clone()
        };
        for addr in addrs {
            listeners.push(
                TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("binding {addr}"))?,
            );
        }
        let local_addrs = listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect::<std::io::Result<Vec<_>>>()?;
        if local_addrs.iter().any(|addr| addr.ip().is_unspecified()) {
            anyhow::bail!("unspecified listener addresses are not allowed")
        }
        if listeners.is_empty() {
            anyhow::bail!("no proxy listeners were configured or supplied")
        }
        let (shutdown, rx) = watch::channel(false);
        let (events, _) = broadcast::channel(16);
        let tracker = TaskTracker::new();
        let mut joins = Vec::new();
        self.bound_addrs = local_addrs.clone();
        for listener in listeners {
            let cfg = self.clone();
            let rx = rx.clone();
            let events = events.clone();
            let tracker = tracker.clone();
            let shutdown_tx = shutdown.clone();
            joins.push(tokio::spawn(async move {
                accept_loop(listener, cfg, rx, shutdown_tx, events, tracker).await
            }));
        }
        let pac_sources = self.pac_sources.clone();
        Ok(Context {
            local_addrs,
            events,
            shutdown,
            tracker,
            joins,
            policy: self.policy.clone(),
            pac_sources,
            inline_scripts: self.inline_scripts.clone(),
        })
    }
    /// Serve one already-connected client stream. The returned context exposes
    /// shutdown and completion just like a listener-backed server.
    pub async fn serve_stream<S>(self, stream: S, peer: SocketAddr) -> Result<Context>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.initialize_policy().await?;
        let (shutdown, rx) = watch::channel(false);
        let (events, _) = broadcast::channel(16);
        let tracker = TaskTracker::new();
        let policy = self.policy.clone();
        let pac_sources = self.pac_sources.clone();
        let inline_scripts = self.inline_scripts.clone();
        let cfg = self;
        let ev = events.clone();
        let task_tracker = tracker.clone();
        let join = tokio::spawn(async move {
            serve_io(stream, peer, None, cfg, ev, task_tracker, rx).await;
        });
        Ok(Context {
            local_addrs: vec![],
            events,
            shutdown,
            tracker,
            joins: vec![join],
            policy,
            pac_sources,
            inline_scripts,
        })
    }

    pub async fn serve_connections<S, St>(self, mut input: St) -> Result<Context>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        St: futures_util::Stream<Item = std::io::Result<(S, SocketAddr)>> + Unpin + Send + 'static,
    {
        self.initialize_policy().await?;
        let (shutdown, mut rx) = watch::channel(false);
        let (events, _) = broadcast::channel(16);
        let tracker = TaskTracker::new();
        let cfg = self.clone();
        let ev = events.clone();
        let tasks = tracker.clone();
        let policy = self.policy.clone();
        let sources = self.pac_sources.clone();
        let join = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {_=rx.changed()=>break,Some(_)=sessions.join_next(),if !sessions.is_empty()=>{},next=input.next()=>match next{Some(Ok((stream,peer)))=>{let cfg=cfg.clone();let ev=ev.clone();let tracker=tasks.clone();let session_shutdown=rx.clone();sessions.spawn(async move{serve_io(stream,peer,None,cfg,ev,tracker,session_shutdown).await;});},Some(Err(e))=>tracing::warn!("supplied connection stream failed: {e}"),None=>break}}
            }
            while sessions.join_next().await.is_some() {}
        });
        Ok(Context {
            local_addrs: vec![],
            events,
            shutdown,
            tracker,
            joins: vec![join],
            policy,
            pac_sources: sources,
            inline_scripts: self.inline_scripts.clone(),
        })
    }
}

pub struct Context {
    local_addrs: Vec<SocketAddr>,
    events: broadcast::Sender<String>,
    shutdown: watch::Sender<bool>,
    tracker: TaskTracker,
    joins: Vec<JoinHandle<()>>,
    policy: Arc<Policy>,
    pac_sources: Vec<PathOrUri>,
    inline_scripts: Vec<String>,
}

async fn load_pac_source(source: &PathOrUri) -> Result<String> {
    match source {
        PathOrUri::Path(path) => {
            let bytes = tokio::fs::read(path)
                .await
                .with_context(|| format!("reading PAC file {}", path.display()))?;
            String::from_utf8(bytes)
                .with_context(|| format!("PAC file {} is not UTF-8", path.display()))
        }
        PathOrUri::Uri(uri) => net::fetch_remote_pac(&uri.to_string()).await,
    }
}

/// Read all sources before publishing a replacement collection.
pub async fn load_pac_sources(sources: &[PathOrUri]) -> Result<Vec<String>> {
    let mut scripts = Vec::with_capacity(sources.len());
    for source in sources {
        scripts.push(
            load_pac_source(source)
                .await
                .with_context(|| format!("loading PAC source {source}"))?,
        );
    }
    Ok(scripts)
}

impl Context {
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.events.subscribe()
    }
    pub fn publish_access(&self, entry: AccessEntry) {
        let _ = self.events.send(entry.to_string());
    }
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }
    pub fn is_shutdown(&self) -> bool {
        *self.shutdown.subscribe().borrow()
    }
    /// Wait until the proxy has been explicitly stopped or an accept loop
    /// has terminated after repeated fatal socket errors.
    pub async fn shutdown_notified(&self) {
        let mut receiver = self.shutdown.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.clone()
    }
    pub async fn set_script(&self, script: Option<String>) -> Result<()> {
        self.policy.set_script(script).await
    }
    pub async fn set_ip(&self, ip: std::net::IpAddr) -> Result<()> {
        self.policy.set_ip(ip).await
    }
    pub async fn set_scripts(&self, scripts: Vec<String>) -> Result<()> {
        self.policy.set_scripts(scripts).await
    }
    pub async fn load_pac(&self, source: &PathOrUri) -> Result<()> {
        self.load_pacs(std::slice::from_ref(source)).await
    }
    pub async fn load_pacs(&self, sources: &[PathOrUri]) -> Result<()> {
        let scripts = load_pac_sources(sources).await?;
        self.policy.set_scripts(scripts).await
    }
    pub async fn reload_pac(&self) -> Result<()> {
        if !self.pac_sources.is_empty() {
            self.load_pacs(&self.pac_sources).await
        } else {
            self.policy.set_scripts(self.inline_scripts.clone()).await
        }
    }
    pub async fn clear_policy(&self) -> Result<()> {
        self.policy.set_scripts(vec![]).await
    }
    pub async fn wait(mut self) {
        for j in self.joins.drain(..) {
            let _ = j.await;
        }
        self.tracker.close();
        self.tracker.wait().await;
    }
    pub async fn wait_timeout(self, d: Duration) -> bool {
        let mut this = self;
        this.shutdown();
        let started = tokio::time::Instant::now();
        let listeners = tokio::time::timeout(d, async {
            for join in &mut this.joins {
                let _ = join.await;
            }
        })
        .await
        .is_ok();
        if !listeners {
            for join in &this.joins {
                join.abort();
            }
            for join in &mut this.joins {
                let _ = join.await;
            }
        }
        this.tracker.close();
        let remaining = d.saturating_sub(started.elapsed());
        let tracked = tokio::time::timeout(remaining, this.tracker.wait())
            .await
            .is_ok();
        listeners && tracked
    }
}

async fn accept_loop(
    listener: TcpListener,
    cfg: ContextBuilder,
    mut shutdown: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
    events: broadcast::Sender<String>,
    tracker: TaskTracker,
) {
    let mut active = tokio::task::JoinSet::new();
    let mut failures = 0u32;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            Some(_)=active.join_next(),if !active.is_empty()=>{},
            result=listener.accept()=>match result {
                Ok((stream,peer))=>{failures=0;let cfg=cfg.clone();let events=events.clone();let tracker=tracker.clone();let rx=shutdown.clone();active.spawn(async move {serve_client(stream,peer,cfg,events,tracker,rx).await;});},
                Err(e)=>{tracing::warn!("accept failed: {e}");if !matches!(e.kind(),std::io::ErrorKind::ConnectionAborted|std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::OutOfMemory){failures+=1;if failures>=32{tracing::error!("stopping after 32 consecutive accept failures");shutdown_tx.send_replace(true);break;}}tokio::time::sleep(Duration::from_millis(500)).await;}
            }
        }
    }
    tracker.close();
    let _ = tokio::time::timeout(cfg.shutdown_timeout, async {
        while active.join_next().await.is_some() {}
        tracker.wait().await
    })
    .await;
}
async fn serve_client(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: ContextBuilder,
    events: broadcast::Sender<String>,
    tracker: TaskTracker,
    shutdown: watch::Receiver<bool>,
) {
    let _ = net::configure_keepalive(&stream, &cfg.server_keepalive);
    let local = stream.local_addr().ok();
    serve_io(stream, peer, local, cfg, events, tracker, shutdown).await;
}
async fn serve_io<S>(
    stream: S,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    cfg: ContextBuilder,
    events: broadcast::Sender<String>,
    tracker: TaskTracker,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shutdown_timeout = cfg.shutdown_timeout;
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let cfg = cfg.clone();
        let events = events.clone();
        let tracker = tracker.clone();
        async move { handle(req, peer, local, cfg, events, tracker).await }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();
    tokio::pin!(connection);
    if *shutdown.borrow() {
        connection.as_mut().graceful_shutdown();
        let _ = tokio::time::timeout(shutdown_timeout, &mut connection).await;
        return;
    }
    tokio::select! {
        _=&mut connection=>{},
        _=shutdown.changed()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(shutdown_timeout,&mut connection).await;}
    }
}

fn full(status: StatusCode, content_type: &str, body: String) -> Response<OutBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONNECTION, "close")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn error_response(status: StatusCode, err: impl std::fmt::Display) -> Response<OutBody> {
    let err = html_escape(&err.to_string());
    let body = format!(
        "<!doctype html><html><head><title>{status}</title></head><body><h1>{status}</h1><p>{err}</p><footer>unproxy {}</footer></body></html>",
        crate::VERSION
    );
    full(status, "text/html; charset=utf-8", body)
}
fn sanitize(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for n in [
        "connection",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(n);
    }
    for n in nominated {
        headers.remove(n);
    }
}

async fn handle(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    cfg: ContextBuilder,
    events: broadcast::Sender<String>,
    tracker: TaskTracker,
) -> Result<Response<OutBody>, std::convert::Infallible> {
    let start = Instant::now();
    let method = req.method().clone();
    let request_uri = req.uri().clone();
    let request_version = req.version();
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let connect = method == Method::CONNECT;
    if !connect && req.uri().authority().is_none() {
        let path = req.uri().path();
        if method != Method::GET {
            return Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "Only GET is supported for local resources",
            ));
        }
        return Ok(match path {
            "/" => full(
                StatusCode::OK,
                "text/html; charset=utf-8",
                format!(
                    "<!doctype html><title>unproxy</title><h1>unproxy</h1><p>{}</p>",
                    crate::VERSION
                ),
            ),
            "/proxy.pac" => {
                let host = req
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .filter(|h| h.parse::<http::uri::Authority>().is_ok())
                    .unwrap_or("127.0.0.1:3128");
                full(
                    StatusCode::OK,
                    "application/x-ns-proxy-autoconfig",
                    format!("function FindProxyForURL(url, host) {{ return \"PROXY {host}\"; }}\n"),
                )
            }
            "/access.html" => full(
                StatusCode::OK,
                "text/html; charset=utf-8",
                access_html().into(),
            ),
            "/access.log" => event_response(events),
            _ => error_response(StatusCode::NOT_FOUND, "Resource not found"),
        });
    }
    let destination = if connect {
        connect_destination(req.uri())
    } else {
        Destination::from_uri(req.uri()).ok()
    };
    let Some(destination) = destination else {
        let status = if connect {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::BAD_GATEWAY
        };
        return Ok(error_response(status, "Invalid destination URI"));
    };
    {
        let host = destination.endpoint.host.trim_matches(['[', ']']);
        let candidates = cfg.bound_addrs.iter().copied().chain(local);
        let port = destination.endpoint.port;
        let loops_back = host.parse::<std::net::IpAddr>().ok().is_some_and(|ip| {
            candidates.clone().any(|addr| {
                addr.port() == port
                    && (addr.ip() == ip || (addr.ip().is_loopback() && ip.is_loopback()))
            })
        }) || (host.eq_ignore_ascii_case("localhost")
            && candidates
                .clone()
                .any(|addr| addr.port() == port && addr.ip().is_loopback()));
        if loops_back {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "proxy request targets this listener",
            ));
        }
    }
    let route_input = if connect {
        let scheme = if destination.endpoint.port == 443 {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}/", destination.endpoint)
    } else {
        destination.pac_url.clone()
    };
    let mut routes = match cfg
        .policy
        .evaluate(route_input.clone(), destination.endpoint.host.clone())
        .await
    {
        Ok(routes) => routes,
        Err(error) => {
            let message = format!("PAC evaluation failed: {error:#}");
            tracing::warn!("{message}");
            publish(
                &events,
                AccessEntry::for_request(
                    peer,
                    None,
                    &req,
                    start.elapsed(),
                    AccessOutcome::Error(message.clone()),
                ),
            );
            return Ok(error_response(StatusCode::BAD_GATEWAY, message));
        }
    };
    if cfg.direct_fallback && !routes.0.iter().any(|r| matches!(r, Route::Direct)) {
        routes.0.push(Route::Direct)
    }
    // Preserve policy order. Sequential selection also bounds socket use and gives deterministic behavior.
    let attempt_timeout = if connect || cfg.force_tunnel {
        cfg.timeout.saturating_mul(2)
    } else {
        cfg.timeout
    };
    let chosen = select_route(
        &routes,
        &destination.endpoint,
        connect,
        cfg.force_tunnel,
        &cfg.options,
        attempt_timeout,
        cfg.parallel,
        cfg.race,
    )
    .await;
    let Some((route, stream, tunneled)) = chosen else {
        publish(
            &events,
            AccessEntry::for_request(
                peer,
                Some(Route::Direct),
                &req,
                start.elapsed(),
                AccessOutcome::Error(format!("could not connect to {}", destination.endpoint)),
            ),
        );
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            format!("Could not connect to {}", destination.endpoint),
        ));
    };
    if connect {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();
        let on = hyper::upgrade::on(&mut req);
        tracker.spawn(async move {
            if let Ok(upgraded) = on.await {
                let mut client = TokioIo::new(upgraded);
                let mut upstream = stream;
                if let Err(error) = net::relay(&mut client, &mut upstream).await {
                    match error.source.kind() {
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                            tracing::debug!(%error,"CONNECT relay ended")
                        }
                        std::io::ErrorKind::NotConnected
                            if error.a_read == error.b_written
                                && error.b_read == error.a_written =>
                        {
                            tracing::debug!(%error,"CONNECT relay ended without lost bytes")
                        }
                        _ => tracing::warn!(elapsed=?start.elapsed(),%error,"CONNECT relay failed"),
                    }
                }
            }
        });
        publish(
            &events,
            AccessEntry::for_request(
                peer,
                Some(route.clone()),
                &req,
                start.elapsed(),
                AccessOutcome::Response {
                    status: StatusCode::OK,
                    content_length: None,
                },
            ),
        );
        return Ok(response);
    }
    match forward(
        req,
        stream,
        &destination,
        &route,
        tunneled,
        &cfg.options,
        peer,
        &method,
        &request_uri,
        request_version,
        start,
        user_agent.as_deref(),
        &events,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::debug!("forward failed: {e:#}");
            publish(
                &events,
                AccessEntry {
                    timestamp: chrono::Local::now().fixed_offset(),
                    peer,
                    route: Some(route.clone()),
                    method: method.clone(),
                    uri: request_uri,
                    version: request_version,
                    elapsed: start.elapsed(),
                    outcome: AccessOutcome::Error(format!("{e:#}")),
                    user_agent,
                },
            );
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                format!("Upstream exchange failed: {e:#}"),
            ))
        }
    }
}

// Each argument is an independent input to the request-scoped route selector.
#[allow(clippy::too_many_arguments)]
async fn select_route(
    routes: &Routes,
    destination: &Endpoint,
    connect: bool,
    force_tunnel: bool,
    options: &ConnectionOptions,
    timeout: Duration,
    parallel: usize,
    race: bool,
) -> Option<(Route, BoxedIo, bool)> {
    type Attempt = BoxFuture<'static, (usize, Route, bool, anyhow::Result<BoxedIo>)>;
    let mut pending: FuturesUnordered<Attempt> = FuturesUnordered::new();
    let mut next = 0usize;
    let mut in_flight = 0usize;
    let mut results: Vec<Option<Option<(Route, BoxedIo, bool)>>> = std::iter::repeat_with(|| None)
        .take(routes.0.len())
        .collect();
    let mut next_ordered = 0usize;
    let max = parallel.max(1);
    let launch = |idx: usize, pending: &mut FuturesUnordered<Attempt>, in_flight: &mut usize| {
        let route = routes.0[idx].clone();
        let dest = destination.clone();
        let options = options.clone();
        let tunnel = (connect || force_tunnel) && !matches!(route, Route::Direct);
        pending.push(Box::pin(async move {
            let result = net::connect(&route, &dest, tunnel, &options, timeout).await;
            (idx, route, tunnel, result)
        }));
        *in_flight += 1;
    };
    while next < routes.0.len() && in_flight < max {
        launch(next, &mut pending, &mut in_flight);
        next += 1;
    }
    while let Some((idx, route, tunnel, result)) = pending.next().await {
        in_flight -= 1;
        let failed = match result {
            Ok(stream) => {
                if race {
                    return Some((route, stream, tunnel));
                }
                results[idx] = Some(Some((route, stream, tunnel)));
                false
            }
            Err(e) => {
                tracing::debug!("route {route} failed for {destination}: {e:#}");
                results[idx] = Some(None);
                true
            }
        };
        // A failed attempt frees a slot for the next policy entry.
        if failed {
            while next < routes.0.len() && in_flight < max {
                launch(next, &mut pending, &mut in_flight);
                next += 1;
            }
        }
        if !race {
            while next_ordered < results.len() {
                match results[next_ordered].take() {
                    Some(Some(winner)) => return Some(winner),
                    Some(None) => next_ordered += 1,
                    None => break,
                }
            }
        }
    }
    None
}

fn connect_destination(uri: &Uri) -> Option<Destination> {
    let auth = uri.authority()?;
    let host = auth.host().trim_start_matches('[').trim_end_matches(']');
    let port = auth.port_u16()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    let scheme = if port == 443 { "https" } else { "http" };
    let endpoint = Endpoint {
        host: host.into(),
        port,
    };
    Some(Destination {
        pac_url: format!("{scheme}://{endpoint}/"),
        endpoint,
        path: "/".into(),
        scheme: scheme.into(),
    })
}
// This private adapter needs request metadata for routing, auth, and access reporting.
#[allow(clippy::too_many_arguments)]
async fn forward(
    req: Request<Incoming>,
    stream: BoxedIo,
    dest: &Destination,
    route: &Route,
    tunneled: bool,
    options: &ConnectionOptions,
    peer: SocketAddr,
    method: &Method,
    original_uri: &Uri,
    client_version: Version,
    start: Instant,
    user_agent: Option<&str>,
    events: &broadcast::Sender<String>,
) -> Result<Response<OutBody>> {
    let (mut parts, body) = req.into_parts();
    sanitize(&mut parts.headers);
    if !parts.headers.contains_key(http::header::HOST) {
        let host = if dest.endpoint.host.contains(':') {
            format!("[{}]", dest.endpoint.host)
        } else {
            dest.endpoint.host.clone()
        };
        parts
            .headers
            .insert(http::header::HOST, HeaderValue::from_str(&host)?);
    }
    let proxy = match route {
        Route::Http(e) | Route::Https(e) => Some(e),
        Route::Direct => None,
    };
    if let Some(proxy) = proxy.filter(|_| !tunneled)
        && let Some(v) = options.auth.authorization(&proxy.host).await?
    {
        parts.headers.insert("proxy-authorization", v);
    }
    parts
        .headers
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    let uri = if matches!(route, Route::Direct) || tunneled {
        format!(
            "{}{}",
            if dest.path.starts_with('/') { "" } else { "/" },
            dest.path
        )
        .parse::<Uri>()?
    } else {
        parts.uri.clone()
    };
    parts.uri = uri;
    let request = Request::from_parts(parts, body);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let response = sender.send_request(request).await?;
    let status = response.status();
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        anyhow::bail!("upstream returned HTTP 407");
    }
    let len = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let mut response = response.map(http_body_util::BodyExt::boxed);
    sanitize(response.headers_mut());
    let mut entry = AccessEntry::for_request(
        peer,
        Some(route.clone()),
        &Request::builder()
            .method(method.clone())
            .uri(original_uri.clone())
            .version(client_version)
            .body(())
            .unwrap(),
        start.elapsed(),
        AccessOutcome::Response {
            status,
            content_length: len,
        },
    );
    entry.elapsed = start.elapsed();
    entry.timestamp = chrono::Local::now().fixed_offset();
    entry.user_agent = user_agent.map(str::to_owned);
    publish(events, entry);
    Ok(response)
}
fn publish(events: &broadcast::Sender<String>, entry: AccessEntry) {
    let _ = events.send(entry.to_string());
}
fn event_response(events: broadcast::Sender<String>) -> Response<OutBody> {
    let mut rx = events.subscribe();
    let stream = async_stream::stream! {loop {match rx.recv().await {Ok(s)=>yield Ok::<hyper::body::Frame<Bytes>,hyper::Error>(hyper::body::Frame::data(Bytes::from(format!("data:{s}\n\n")))),Err(broadcast::error::RecvError::Lagged(n))=>yield Ok(hyper::body::Frame::data(Bytes::from(format!("event:lagged\ndata:{n}\n\n")))),Err(_)=>break}}};
    let body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(stream));
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header("cache-control", "no-store")
        .body(body)
        .unwrap()
}
fn access_html() -> &'static str {
    "<!doctype html><meta charset=utf-8><title>unproxy access log</title><h1>Access log</h1><button id=stop>Stop</button><pre id=log></pre><script>const s=new EventSource('access.log');s.onmessage=e=>{const p=document.createElement('div');p.textContent=e.data;document.querySelector('#log').append(p)};s.addEventListener('lagged',e=>console.warn('access events dropped',e.data));s.onerror=e=>console.warn('access stream error',e);document.querySelector('#stop').onclick=()=>s.close();</script>"
}
