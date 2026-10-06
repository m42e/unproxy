//! HTTP/1 forward proxy and embedded management endpoints.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::AtomicBool},
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
    logging::LogStream,
    net::{self, BoxedIo, ConnectionOptions},
    pac::Policy,
    route::{Destination, Endpoint, PathOrUri, Route, Routes},
};

type OutBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;
type ConnectedRoute = (Route, BoxedIo, bool, bool);
type OrderedRouteResult = Option<Option<ConnectedRoute>>;

#[derive(Clone)]
struct RuntimeStatus(Arc<Mutex<RuntimeStatusData>>);

#[derive(Clone)]
struct RuntimeStatusData {
    pac_files: Vec<String>,
    authentication_configured: bool,
    upstream_state: String,
    authentication_state: String,
    upstream_checked_at: Option<i64>,
    upstream_route: Option<String>,
    authentication_sent: bool,
}

impl RuntimeStatus {
    fn new(authentication_configured: bool) -> Self {
        Self(Arc::new(Mutex::new(RuntimeStatusData {
            pac_files: Vec::new(),
            authentication_configured,
            upstream_state: "unknown".into(),
            authentication_state: if authentication_configured {
                "configured".into()
            } else {
                "disabled".into()
            },
            upstream_checked_at: None,
            upstream_route: None,
            authentication_sent: false,
        })))
    }

    fn observe(
        &self,
        route: &Route,
        success: bool,
        authentication_sent: bool,
        error: Option<&str>,
    ) {
        if matches!(route, Route::Direct) {
            return;
        }
        let Ok(mut status) = self.0.lock() else {
            return;
        };
        status.upstream_state = if success { "ok" } else { "error" }.into();
        status.upstream_route = Some(route.to_string());
        status.authentication_sent = authentication_sent;
        status.authentication_state = if error.is_some_and(|e| e.contains("HTTP 407")) {
            "rejected"
        } else if success && authentication_sent {
            "authenticated"
        } else if status.authentication_configured {
            "configured"
        } else {
            "disabled"
        }
        .into();
        status.upstream_checked_at = Some(chrono::Utc::now().timestamp());
    }

    fn snapshot(&self) -> RuntimeStatusData {
        self.0
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| RuntimeStatusData {
                pac_files: Vec::new(),
                authentication_configured: false,
                upstream_state: "unknown".into(),
                authentication_state: "unknown".into(),
                upstream_checked_at: None,
                upstream_route: None,
                authentication_sent: false,
            })
    }

    fn set_pac_files(&self, pac_files: Vec<String>) {
        if let Ok(mut status) = self.0.lock() {
            status.pac_files = pac_files;
        }
    }
}

type SharedFilterList = Arc<std::sync::RwLock<crate::filter_list::FilterList>>;

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
    trusted_management_hosts: Vec<String>,
    session_limit: Arc<tokio::sync::Semaphore>,
    exchange_timeout: Duration,
    relay_handles: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    header_timeout: Duration,
    idle_timeout: Duration,
    strict_policy: bool,
    runtime_status: RuntimeStatus,
    log_stream: LogStream,
    pac_cache: Arc<tokio::sync::Mutex<HashMap<String, net::CachedRemotePac>>>,
    filter_list: SharedFilterList,
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
            trusted_management_hosts: self.trusted_management_hosts.clone(),
            session_limit: self.session_limit.clone(),
            exchange_timeout: self.exchange_timeout,
            relay_handles: self.relay_handles.clone(),
            header_timeout: self.header_timeout,
            idle_timeout: self.idle_timeout,
            strict_policy: self.strict_policy,
            runtime_status: self.runtime_status.clone(),
            log_stream: self.log_stream.clone(),
            pac_cache: self.pac_cache.clone(),
            filter_list: self.filter_list.clone(),
        }
    }
}
impl ContextBuilder {
    pub fn new(policy: Arc<Policy>, options: ConnectionOptions) -> Self {
        let runtime_status = RuntimeStatus::new(options.auth.is_configured());
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
            trusted_management_hosts: vec![],
            session_limit: Arc::new(tokio::sync::Semaphore::new(256)),
            exchange_timeout: Duration::from_secs(30),
            relay_handles: Arc::new(std::sync::Mutex::new(Vec::new())),
            header_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
            strict_policy: false,
            runtime_status,
            log_stream: LogStream::new(),
            pac_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            filter_list: Arc::new(std::sync::RwLock::new(
                crate::filter_list::FilterList::default(),
            )),
        }
    }
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listens.push(addr);
        self
    }
    pub(crate) fn log_stream(mut self, log_stream: LogStream) -> Self {
        self.log_stream = log_stream;
        self
    }
    pub fn filter_list(mut self, list: crate::filter_list::FilterList) -> Self {
        self.filter_list = Arc::new(std::sync::RwLock::new(list));
        self
    }
    /// Trust an additional Host authority for local management resources.
    /// This is intended for reverse-proxy and embedded deployments.
    pub fn trusted_management_host(mut self, authority: impl Into<String>) -> Self {
        self.trusted_management_hosts.push(authority.into());
        self
    }
    pub fn exchange_timeout(mut self, timeout: Duration) -> Self {
        self.exchange_timeout = timeout;
        self
    }
    pub fn header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }
    pub fn strict_policy(mut self, strict: bool) -> Self {
        self.strict_policy = strict;
        self
    }
    pub fn max_sessions(mut self, maximum: usize) -> Self {
        self.session_limit = Arc::new(tokio::sync::Semaphore::new(maximum.max(1)));
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
            let scripts = load_pac_sources_cached(&self.pac_sources, &self.pac_cache).await?;
            self.policy.set_scripts(scripts).await?;
            self.runtime_status
                .set_pac_files(self.pac_sources.iter().map(ToString::to_string).collect());
        } else if self.initialize_inline {
            self.policy.set_scripts(self.inline_scripts.clone()).await?;
            self.runtime_status.set_pac_files(Vec::new());
        }
        Ok(())
    }
    pub async fn bind(mut self) -> Result<Context> {
        self.initialize_policy().await?;
        let mut listeners = std::mem::take(&mut self.sockets);
        let addrs = if !listeners.is_empty() {
            vec![]
        } else if self.listens.is_empty() {
            vec![
                "127.0.0.1:3128".parse().unwrap(),
                "[::1]:3128".parse().unwrap(),
            ]
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
        let inline_scripts = self.inline_scripts.clone();
        Ok(Context {
            shutdown_timeout: self.shutdown_timeout,
            local_addrs,
            events,
            shutdown,
            tracker,
            joins,
            policy: self.policy.clone(),
            pac_sources,
            inline_scripts,
            runtime_status: self.runtime_status.clone(),
            pac_cache: self.pac_cache.clone(),
            relay_handles: self.relay_handles.clone(),
            filter_list: self.filter_list.clone(),
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
        let runtime_status = self.runtime_status.clone();
        let pac_cache = self.pac_cache.clone();
        let filter_list = self.filter_list.clone();
        let shutdown_timeout = self.shutdown_timeout;
        let relay_handles = self.relay_handles.clone();
        let cfg = self;
        let ev = events.clone();
        let task_tracker = tracker.clone();
        let join = tokio::spawn(async move {
            serve_io(stream, peer, None, cfg, ev, task_tracker, rx).await;
        });
        Ok(Context {
            shutdown_timeout,
            local_addrs: vec![],
            events,
            shutdown,
            tracker,
            joins: vec![join],
            policy,
            pac_sources,
            inline_scripts,
            runtime_status,
            pac_cache,
            relay_handles,
            filter_list,
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
        let shutdown_timeout = self.shutdown_timeout;
        let sources = self.pac_sources.clone();
        let inline_scripts = self.inline_scripts.clone();
        let runtime_status = self.runtime_status.clone();
        let pac_cache = self.pac_cache.clone();
        let filter_list = self.filter_list.clone();
        let relay_handles = self.relay_handles.clone();
        let join = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {_=rx.changed()=>break,Some(_)=sessions.join_next(),if !sessions.is_empty()=>{},next=input.next()=>match next{Some(Ok((stream,peer)))=>{let cfg=cfg.clone();let ev=ev.clone();let tracker=tasks.clone();let session_shutdown=rx.clone();sessions.spawn(async move{serve_io(stream,peer,None,cfg,ev,tracker,session_shutdown).await;});},Some(Err(e))=>tracing::warn!("supplied connection stream failed: {e}"),None=>break}}
            }
            while sessions.join_next().await.is_some() {}
        });
        Ok(Context {
            shutdown_timeout,
            local_addrs: vec![],
            events,
            shutdown,
            tracker,
            joins: vec![join],
            policy,
            pac_sources: sources,
            inline_scripts,
            runtime_status,
            pac_cache,
            relay_handles,
            filter_list,
        })
    }
}

pub struct Context {
    shutdown_timeout: Duration,
    local_addrs: Vec<SocketAddr>,
    events: broadcast::Sender<String>,
    shutdown: watch::Sender<bool>,
    tracker: TaskTracker,
    joins: Vec<JoinHandle<()>>,
    policy: Arc<Policy>,
    pac_sources: Vec<PathOrUri>,
    inline_scripts: Vec<String>,
    runtime_status: RuntimeStatus,
    pac_cache: Arc<tokio::sync::Mutex<HashMap<String, net::CachedRemotePac>>>,
    relay_handles: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    filter_list: SharedFilterList,
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

async fn load_pac_sources_cached(
    sources: &[PathOrUri],
    cache: &Arc<tokio::sync::Mutex<HashMap<String, net::CachedRemotePac>>>,
) -> Result<Vec<String>> {
    let mut updated = HashMap::new();
    let mut scripts = Vec::with_capacity(sources.len());
    for source in sources {
        let loaded = match source {
            PathOrUri::Path(_) => load_pac_source(source).await,
            PathOrUri::Uri(uri) => {
                let key = uri.to_string();
                let previous = cache.lock().await.get(&key).cloned();
                net::fetch_remote_pac_cached(&key, previous.as_ref())
                    .await
                    .map(|entry| {
                        let script = entry.script.clone();
                        updated.insert(key, entry);
                        script
                    })
            }
        }
        .with_context(|| format!("loading PAC source {source}"))?;
        scripts.push(loaded);
    }
    cache.lock().await.extend(updated);
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
    pub(crate) fn retry_filter_lists_after(&self, sources: Vec<String>, initial_delay: Duration) {
        let Some(proxy) = self.local_addrs.first().copied() else {
            return;
        };
        tracing::info!(
            sources = ?sources,
            %proxy,
            retry_after = ?initial_delay,
            "filter list load incomplete; scheduling PAC-routed retry"
        );
        let filter_list = self.filter_list.clone();
        let mut shutdown = self.shutdown.subscribe();
        tokio::spawn(async move {
            let mut delay = initial_delay;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
                tracing::info!(
                    sources = ?sources,
                    %proxy,
                    "retrying filter list download through PAC"
                );
                let (loaded, complete) = tokio::select! {
                    result = crate::filter_list::FilterList::load_best_effort_via_proxy(&sources, proxy) => result,
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                };
                let Ok(mut current) = filter_list.write() else {
                    return;
                };
                if complete {
                    *current = loaded;
                } else {
                    *current = current.union(&loaded);
                }
                drop(current);
                if complete {
                    tracing::info!(sources = ?sources, "filter list retry completed successfully");
                    return;
                }
                delay = delay.saturating_mul(2).min(Duration::from_secs(300));
                tracing::info!(
                    sources = ?sources,
                    retry_after = ?delay,
                    "filter list retry incomplete; scheduling another PAC-routed retry"
                );
            }
        });
    }
    pub async fn set_script(&self, script: Option<String>) -> Result<()> {
        self.policy.set_script(script).await?;
        self.runtime_status.set_pac_files(Vec::new());
        Ok(())
    }
    pub async fn set_ip(&self, ip: std::net::IpAddr) -> Result<()> {
        self.policy.set_ip(ip).await
    }
    pub async fn set_scripts(&self, scripts: Vec<String>) -> Result<()> {
        self.policy.set_scripts(scripts).await?;
        self.runtime_status.set_pac_files(Vec::new());
        Ok(())
    }
    pub async fn load_pac(&self, source: &PathOrUri) -> Result<()> {
        self.load_pacs(std::slice::from_ref(source)).await
    }
    pub async fn load_pacs(&self, sources: &[PathOrUri]) -> Result<()> {
        let scripts = load_pac_sources_cached(sources, &self.pac_cache).await?;
        self.policy.set_scripts(scripts).await?;
        self.runtime_status
            .set_pac_files(sources.iter().map(ToString::to_string).collect());
        Ok(())
    }
    pub async fn reload_pac(&self) -> Result<()> {
        if !self.pac_sources.is_empty() {
            self.load_pacs(&self.pac_sources).await
        } else {
            self.policy.set_scripts(self.inline_scripts.clone()).await?;
            self.runtime_status.set_pac_files(Vec::new());
            Ok(())
        }
    }
    pub async fn clear_policy(&self) -> Result<()> {
        self.policy.set_scripts(vec![]).await?;
        self.runtime_status.set_pac_files(Vec::new());
        Ok(())
    }
    pub async fn wait(mut self) {
        // `wait` observes lifecycle; callers choose when to request shutdown.
        for join in self.joins.drain(..) {
            let _ = join.await;
        }
        self.tracker.close();
        let timeout = self.shutdown_timeout;
        let drained = tokio::time::timeout(timeout, async {
            self.tracker.wait().await;
        })
        .await
        .is_ok();
        if !drained {
            for relay in self.relay_handles.lock().unwrap().iter() {
                relay.abort();
            }
            self.tracker.wait().await;
            tracing::warn!(
                ?timeout,
                "proxy drain timed out; remaining relay tasks were cancelled"
            );
        }
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
            // Some earlier handles may already have been awaited by the timed
            // drain; drop all handles after aborting, without polling twice.
            this.joins.clear();
        }
        this.tracker.close();
        let remaining = d.saturating_sub(started.elapsed());
        let tracked = tokio::time::timeout(remaining, this.tracker.wait())
            .await
            .is_ok();
        if !listeners || !tracked {
            {
                let relays = this.relay_handles.lock().unwrap();
                for relay in relays.iter() {
                    relay.abort();
                }
            }
            this.tracker.wait().await;
        }
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
    let Ok(session_permit) = cfg.session_limit.clone().try_acquire_owned() else {
        return;
    };
    let session = SessionLease {
        permit: Arc::new(session_permit),
        idle_disabled: Arc::new(AtomicBool::new(false)),
    };
    let header_timeout = cfg.header_timeout;
    let io = TokioIo::new(net::IdleIo::new(
        stream,
        cfg.idle_timeout,
        session.idle_disabled.clone(),
    ));
    let service = service_fn(move |req| {
        let cfg = cfg.clone();
        let events = events.clone();
        let tracker = tracker.clone();
        let session = session.clone();
        async move { handle(req, peer, local, cfg, events, tracker, session).await }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(header_timeout);
    let connection = builder.serve_connection(io, service).with_upgrades();
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

#[derive(Clone)]
struct SessionLease {
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    idle_disabled: Arc<AtomicBool>,
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

fn json_error(status: StatusCode, message: &str) -> Response<OutBody> {
    full(
        status,
        "application/json; charset=utf-8",
        serde_json::json!({"error": message}).to_string(),
    )
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16)? as u8;
                let lo = (bytes[index + 2] as char).to_digit(16)? as u8;
                decoded.push((hi << 4) | lo);
                index += 3;
            }
            b'%' => return None,
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod management_url_tests {
    use super::percent_decode;

    #[test]
    fn percent_decode_handles_encoded_urls_and_rejects_invalid_input() {
        assert_eq!(
            percent_decode("https%3A%2F%2Fexample.test%2Fa+b"),
            Some("https://example.test/a b".into())
        );
        assert_eq!(percent_decode("bad%2"), None);
        assert_eq!(percent_decode("%FF"), None);
    }
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
        "keep-alive",
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
    _tracker: TaskTracker,
    session: SessionLease,
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
    let origin_form = req.uri().authority().is_none();
    let trusted_management = trusted_management_request(&req, peer, local, &cfg);
    if !connect && (origin_form || trusted_management) {
        let path = req.uri().path();
        if method != Method::GET {
            return Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "Only GET is supported for local resources",
            ));
        }
        if !trusted_management {
            return Ok(error_response(
                StatusCode::FORBIDDEN,
                "Untrusted management authority",
            ));
        }
        return Ok(match path {
            "/" if user_agent
                .as_deref()
                .is_some_and(|agent| agent.to_ascii_lowercase().contains("curl")) =>
            {
                full(
                    StatusCode::OK,
                    "text/plain; charset=utf-8",
                    status_text(&cfg),
                )
            }
            "/" => full(StatusCode::OK, "text/html; charset=utf-8", status_html()),
            "/index.html" => full(StatusCode::OK, "text/html; charset=utf-8", status_html()),
            "/proxy.pac" => {
                let host = req
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
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
            "/log.html" => full(
                StatusCode::OK,
                "text/html; charset=utf-8",
                log_html().into(),
            ),
            "/log" => log_response(cfg.log_stream.clone()),
            "/status.json" => {
                let status = cfg.runtime_status.snapshot();
                let pac_loaded = cfg.policy.is_loaded();
                let blocked_domain_count = cfg
                    .filter_list
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .domain_count();
                full(
                    StatusCode::OK,
                    "application/json; charset=utf-8",
                    serde_json::json!({
                        "pac_loaded": pac_loaded,
                        "pac_files": if pac_loaded { status.pac_files } else { Vec::new() },
                        "blocked_domain_count": blocked_domain_count,
                        "authentication_configured": status.authentication_configured,
                        "upstream_state": status.upstream_state,
                        "authentication_state": status.authentication_state,
                        "upstream_checked_at": status.upstream_checked_at,
                        "upstream_route": status.upstream_route,
                        "authentication_sent": status.authentication_sent,
                    })
                    .to_string(),
                )
            }
            "/resolve.json" => {
                let Some(url) = req.uri().query().and_then(|query| {
                    query.split('&').find_map(|part| {
                        let (key, value) = part.split_once('=')?;
                        (key == "url").then(|| percent_decode(value)).flatten()
                    })
                }) else {
                    return Ok(json_error(
                        StatusCode::BAD_REQUEST,
                        "Provide a URL in the url query parameter",
                    ));
                };
                let uri: Uri = match url.parse::<Uri>() {
                    Ok(uri) if matches!(uri.scheme_str(), Some("http" | "https")) => uri,
                    _ => {
                        return Ok(json_error(
                            StatusCode::BAD_REQUEST,
                            "URL must be an absolute HTTP or HTTPS URL",
                        ));
                    }
                };
                let destination = match Destination::from_uri(&uri) {
                    Ok(destination) => destination,
                    Err(error) => {
                        return Ok(json_error(
                            StatusCode::BAD_REQUEST,
                            &format!("Invalid URL: {error}"),
                        ));
                    }
                };
                let host = destination.endpoint.host;
                let filter_list_blocked = cfg
                    .filter_list
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&host);
                let status = cfg.runtime_status.snapshot();
                let results = match cfg
                    .policy
                    .evaluate_each(destination.pac_url, host.clone())
                    .await
                {
                    Ok(results) => results,
                    Err(error) => {
                        return Ok(json_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &format!("PAC evaluation unavailable: {error}"),
                        ));
                    }
                };
                let pacs: Vec<_> = results
                    .into_iter()
                    .enumerate()
                    .map(|(index, result)| {
                        let name = status
                            .pac_files
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| format!("PAC {}", index + 1));
                        match result {
                            Ok(routes) => {
                                serde_json::json!({"pac": name, "routes": routes.to_string()})
                            }
                            Err(error) => serde_json::json!({"pac": name, "error": error}),
                        }
                    })
                    .collect();
                full(
                    StatusCode::OK,
                    "application/json; charset=utf-8",
                    serde_json::json!({
                        "url": url,
                        "filter_list": {
                            "host": host,
                            "blocked": filter_list_blocked,
                        },
                        "results": pacs,
                    })
                    .to_string(),
                )
            }
            "/access.log" => event_response(events),
            _ => error_response(StatusCode::NOT_FOUND, "Resource not found"),
        });
    }
    if !connect && req.uri().scheme_str() == Some("https") {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "HTTPS requests must use CONNECT for end-to-end TLS",
        ));
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
        if cfg
            .filter_list
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(host)
        {
            return Ok(error_response(
                StatusCode::FORBIDDEN,
                "Blocked by filter list",
            ));
        }
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
    if cfg.strict_policy && !cfg.policy.is_loaded() {
        return Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Routing policy has not loaded",
        ));
    }
    let evaluation = if cfg.strict_policy {
        cfg.policy
            .evaluate_strict(route_input.clone(), destination.endpoint.host.clone())
            .await
    } else {
        cfg.policy
            .evaluate(route_input.clone(), destination.endpoint.host.clone())
            .await
    };
    let mut routes = match evaluation {
        Ok(routes) => routes,
        Err(e) => {
            tracing::warn!("PAC evaluation failed: {e:#}");
            let message = format!("PAC evaluation failed: {e:#}");
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
        &cfg.runtime_status,
        attempt_timeout,
        cfg.parallel,
        cfg.race,
    )
    .await;
    let Some((route, stream, tunneled, mut authentication_sent)) = chosen else {
        publish(
            &events,
            AccessEntry::for_request(
                peer,
                None,
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
        session
            .idle_disabled
            .store(true, std::sync::atomic::Ordering::Release);
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();
        let on = hyper::upgrade::on(&mut req);
        let relay = _tracker.spawn(async move {
            let _session_hold = session.permit;
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
        let mut relays = cfg.relay_handles.lock().unwrap();
        relays.retain(|relay| !relay.is_finished());
        relays.push(relay.abort_handle());
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
        cfg.exchange_timeout,
        cfg.idle_timeout,
        peer,
        &method,
        &request_uri,
        request_version,
        start,
        user_agent.as_deref(),
        &events,
        &mut authentication_sent,
    )
    .await
    {
        Ok(response) => {
            cfg.runtime_status
                .observe(&route, true, authentication_sent, None);
            Ok(response)
        }
        Err(e) => {
            cfg.runtime_status
                .observe(&route, false, authentication_sent, Some(&format!("{e:#}")));
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

fn trusted_management_request(
    req: &Request<Incoming>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    cfg: &ContextBuilder,
) -> bool {
    if !peer.ip().is_loopback() {
        return false;
    }
    if req.uri().authority().is_some() {
        return false;
    }
    let Some(host) = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    cfg.trusted_management_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
        || cfg.bound_addrs.iter().copied().chain(local).any(|addr| {
            let expected = addr.to_string();
            authority.as_str().eq_ignore_ascii_case(&expected)
                || (addr.ip().is_loopback()
                    && authority.port_u16() == Some(addr.port())
                    && authority.host().eq_ignore_ascii_case("localhost"))
        })
}

// Each argument is an independent input to the request-scoped route selector.
#[allow(clippy::too_many_arguments)]
async fn select_route(
    routes: &Routes,
    destination: &Endpoint,
    connect: bool,
    force_tunnel: bool,
    options: &ConnectionOptions,
    runtime_status: &RuntimeStatus,
    timeout: Duration,
    parallel: usize,
    race: bool,
) -> Option<ConnectedRoute> {
    type Attempt = BoxFuture<'static, (usize, Route, bool, anyhow::Result<(BoxedIo, bool)>)>;
    let mut pending: FuturesUnordered<Attempt> = FuturesUnordered::new();
    let mut next = 0usize;
    let mut in_flight = 0usize;
    let mut results: Vec<OrderedRouteResult> = std::iter::repeat_with(|| None)
        .take(routes.0.len())
        .collect();
    let mut next_ordered = 0usize;
    let max = parallel.max(1);
    let launch = |idx: usize, pending: &mut FuturesUnordered<Attempt>, in_flight: &mut usize| {
        let route = routes.0[idx].clone();
        let dest = destination.clone();
        let options = options.clone();
        let tunnel =
            route.is_socks() || ((connect || force_tunnel) && !matches!(route, Route::Direct));
        pending.push(Box::pin(async move {
            let result = net::connect_observed(&route, &dest, tunnel, &options, timeout).await;
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
            Ok((stream, authentication_sent)) => {
                if tunnel {
                    runtime_status.observe(&route, true, authentication_sent, None);
                }
                if race {
                    return Some((route, stream, tunnel, authentication_sent));
                }
                results[idx] = Some(Some((route, stream, tunnel, authentication_sent)));
                false
            }
            Err(e) => {
                runtime_status.observe(&route, false, false, Some(&format!("{e:#}")));
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
    exchange_timeout: Duration,
    idle_timeout: Duration,
    peer: SocketAddr,
    method: &Method,
    original_uri: &Uri,
    client_version: Version,
    start: Instant,
    user_agent: Option<&str>,
    events: &broadcast::Sender<String>,
    authentication_sent: &mut bool,
) -> Result<Response<OutBody>> {
    let (mut parts, body) = req.into_parts();
    sanitize(&mut parts.headers);
    let authority = original_uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("request authority missing"))?;
    let mut host = authority.host().to_owned();
    if let Some(port) = authority.port() {
        host.push(':');
        host.push_str(port.as_str());
    }
    parts
        .headers
        .insert(http::header::HOST, HeaderValue::from_str(&host)?);
    let proxy = match route {
        Route::Http(e) | Route::Https(e) => Some(e),
        Route::Direct | Route::Socks4(_) | Route::Socks5(_) => None,
    };
    if let Some(proxy) = proxy.filter(|_| !tunneled)
        && let Some(v) = options.auth.authorization(&proxy.host).await?
    {
        *authentication_sent = true;
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
    let io = TokioIo::new(net::IdleIo::new(
        stream,
        idle_timeout,
        Arc::new(AtomicBool::new(false)),
    ));
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let response = tokio::time::timeout(exchange_timeout, sender.send_request(request))
        .await
        .context("upstream response headers timed out")??;
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
fn log_response(log_stream: LogStream) -> Response<OutBody> {
    let (history, mut rx) = log_stream.subscribe_with_history();
    let stream = async_stream::stream! {
        for line in history {
            yield Ok::<hyper::body::Frame<Bytes>, hyper::Error>(hyper::body::Frame::data(Bytes::from(format!("data:{line}\n\n"))));
        }
        loop {
            match rx.recv().await {
                Ok(line) => yield Ok(hyper::body::Frame::data(Bytes::from(format!("data:{line}\n\n")))),
                Err(broadcast::error::RecvError::Lagged(n)) => yield Ok(hyper::body::Frame::data(Bytes::from(format!("event:lagged\ndata:{n}\n\n")))),
                Err(_) => break,
            }
        }
    };
    let body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(stream));
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header("cache-control", "no-store")
        .body(body)
        .unwrap()
}
fn access_html() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Unproxy live access log</title>
    <style>
        :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
        body { max-width: 80rem; margin: 2rem auto; padding: 0 1rem; }
        header { display: flex; align-items: center; flex-wrap: wrap; gap: .75rem 1.5rem; }
        h1 { margin: 0; font-size: 1.5rem; }
        #state { color: GrayText; }
        #log { height: min(70vh, 48rem); min-height: 12rem; margin-top: 1rem; padding: .75rem; overflow: auto; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: .25rem; font: .82rem/1.45 ui-monospace, monospace; }
        #log div { white-space: pre-wrap; overflow-wrap: anywhere; }
    </style>
</head>
<body>
    <header>
        <h1>Live access log</h1>
        <span id="state" aria-live="polite">Connecting…</span>
        <button id="stop" type="button">Stop</button>
        <a href="/">Status</a>
    </header>
    <div id="log" role="log" aria-label="Live access log"></div>
    <script>
        const output = document.querySelector('#log');
        const state = document.querySelector('#state');
        const source = new EventSource('/access.log');
        source.onopen = () => { state.textContent = 'Connected'; };
        source.onmessage = event => {
            const line = document.createElement('div');
            line.textContent = event.data;
            output.append(line);
            while (output.childElementCount > 500) output.firstElementChild.remove();
            output.scrollTop = output.scrollHeight;
        };
        source.addEventListener('lagged', event => {
            state.textContent = 'Some access messages were skipped (' + event.data + ').';
        });
        source.onerror = () => { state.textContent = 'Connection interrupted; reconnecting…'; };
        document.querySelector('#stop').onclick = () => {
            source.close();
            state.textContent = 'Stopped';
        };
    </script>
</body>
</html>"#
}
fn log_html() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Unproxy application log</title>
    <style>
        :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
        body { max-width: 80rem; margin: 2rem auto; padding: 0 1rem; }
        header { display: flex; align-items: center; flex-wrap: wrap; gap: .75rem 1.5rem; }
        h1 { margin: 0; font-size: 1.5rem; }
        #state { color: GrayText; }
        #log { height: min(70vh, 48rem); min-height: 12rem; margin-top: 1rem; padding: .75rem; overflow: auto; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: .25rem; font: .82rem/1.45 ui-monospace, monospace; }
        #log div { white-space: pre-wrap; overflow-wrap: anywhere; }
    </style>
</head>
<body>
    <header>
        <h1>Application log</h1>
        <span id="state" aria-live="polite">Connecting…</span>
        <button id="stop" type="button">Stop</button>
        <a href="/">Status</a>
    </header>
    <div id="log" role="log" aria-label="Application log"></div>
    <script>
        const output = document.querySelector('#log');
        const state = document.querySelector('#state');
        const palette = [
            '#000000', '#cd0000', '#00cd00', '#cdcd00', '#0000ee', '#cd00cd', '#00cdcd', '#e5e5e5',
            '#7f7f7f', '#ff0000', '#00ff00', '#ffff00', '#5c5cff', '#ff00ff', '#00ffff', '#ffffff'
        ];
        const colors = Array.from({length: 256}, (_, index) => {
            if (index < 16) return palette[index];
            if (index < 232) {
                const levels = [0, 95, 135, 175, 215, 255];
                const cube = index - 16;
                return `rgb(${levels[Math.floor(cube / 36)]}, ${levels[Math.floor(cube / 6) % 6]}, ${levels[cube % 6]})`;
            }
            const gray = 8 + (index - 232) * 10;
            return `rgb(${gray}, ${gray}, ${gray})`;
        });
        const style = {};
        function applySgr(parameters) {
            for (let index = 0; index < parameters.length; index++) {
                const code = parameters[index];
                if (code === 0) {
                    Object.assign(style, {foreground: null, background: null, bold: false, dim: false, italic: false, underline: false, strike: false, inverse: false});
                } else if (code === 1) style.bold = true;
                else if (code === 2) style.dim = true;
                else if (code === 3) style.italic = true;
                else if (code === 4) style.underline = true;
                else if (code === 7) style.inverse = true;
                else if (code === 9) style.strike = true;
                else if (code === 22) { style.bold = false; style.dim = false; }
                else if (code === 23) style.italic = false;
                else if (code === 24) style.underline = false;
                else if (code === 27) style.inverse = false;
                else if (code === 29) style.strike = false;
                else if (code === 39) style.foreground = null;
                else if (code === 49) style.background = null;
                else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
                    style.foreground = palette[code >= 90 ? code - 90 + 8 : code - 30];
                } else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) {
                    style.background = palette[code >= 100 ? code - 100 + 8 : code - 40];
                } else if (code === 38 || code === 48) {
                    const property = code === 38 ? 'foreground' : 'background';
                    const mode = parameters[++index];
                    if (mode === 5 && parameters[index + 1] !== undefined) {
                        const color = parameters[++index];
                        if (color >= 0 && color < colors.length) style[property] = colors[color];
                    } else if (mode === 2 && parameters.length > index + 3) {
                        const rgb = parameters.slice(index + 1, index + 4);
                        index += 3;
                        if (rgb.every(value => value >= 0 && value <= 255)) {
                            style[property] = `rgb(${rgb.join(', ')})`;
                        }
                    }
                }
            }
        }
        function appendAnsiText(element, text) {
            if (!text) return;
            const span = document.createElement('span');
            span.textContent = text;
            const foreground = style.inverse ? (style.background || 'Canvas') : style.foreground;
            const background = style.inverse ? (style.foreground || 'CanvasText') : style.background;
            if (foreground || style.inverse) span.style.color = foreground || 'CanvasText';
            if (background) span.style.backgroundColor = background;
            if (style.bold) span.style.fontWeight = '700';
            if (style.dim) span.style.opacity = '0.7';
            if (style.italic) span.style.fontStyle = 'italic';
            const decorations = [];
            if (style.underline) decorations.push('underline');
            if (style.strike) decorations.push('line-through');
            if (decorations.length) span.style.textDecorationLine = decorations.join(' ');
            element.append(span);
        }
        function renderAnsi(element, text) {
            Object.assign(style, {foreground: null, background: null, bold: false, dim: false, italic: false, underline: false, strike: false, inverse: false});
            const sgr = /\x1b\[([0-9;]*)m/g;
            let start = 0;
            for (const match of text.matchAll(sgr)) {
                appendAnsiText(element, text.slice(start, match.index));
                const parameters = match[1] ? match[1].split(';').map(Number) : [0];
                applySgr(parameters);
                start = match.index + match[0].length;
            }
            appendAnsiText(element, text.slice(start));
        }
        const source = new EventSource('/log');
        source.onopen = () => { state.textContent = 'Connected'; };
        source.onmessage = event => {
            const line = document.createElement('div');
            renderAnsi(line, event.data);
            output.append(line);
            while (output.childElementCount > 500) output.firstElementChild.remove();
            output.scrollTop = output.scrollHeight;
        };
        source.addEventListener('lagged', event => {
            state.textContent = 'Some log messages were skipped (' + event.data + ').';
        });
        source.onerror = () => { state.textContent = 'Connection interrupted; reconnecting…'; };
        document.querySelector('#stop').onclick = () => {
            source.close();
            state.textContent = 'Stopped';
        };
    </script>
</body>
</html>"#
}
fn status_html() -> String {
    const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Unproxy status</title>
  <style>
    :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
    body { max-width: 54rem; margin: 3rem auto; padding: 0 1.25rem; }
    h1 { margin-bottom: .25rem; }
    .muted, small { color: GrayText; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: 1rem; margin: 2rem 0; }
    article { border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: .75rem; padding: 1rem; }
    h2 { font-size: .9rem; margin: 0 0 .5rem; }
    article p { font-size: 1.15rem; margin: 0 0 .25rem; }
    #pac-files { margin: .5rem 0 0; padding-left: 1.25rem; font-size: .85rem; overflow-wrap: anywhere; }
    #negotiation-details { margin: .5rem 0 0; padding-left: 1.25rem; font-size: .85rem; overflow-wrap: anywhere; }
    #resolve-results { overflow-wrap: anywhere; }
    nav { display: flex; flex-wrap: wrap; gap: 1rem; }
  </style>
</head>
<body>
  <h1>Unproxy</h1>
  <p class="muted">Local proxy status · version __VERSION__</p>
  <section class="grid" aria-live="polite">
    <article><h2>Proxy</h2><p>Running</p><small>This page is served by the active proxy.</small></article>
    <article><h2>PAC policy</h2><p id="pac">Loading…</p><small>Whether a PAC policy is currently loaded. Loaded PAC files:</small><ul id="pac-files" aria-label="Loaded PAC files"><li>Loading…</li></ul></article>
    <article><h2>Blocked domains</h2><p id="blocked-domain-count">Loading…</p><small>Unique domains in the active filter lists.</small></article>
    <article><h2>Upstream</h2><p id="upstream">Loading…</p><small id="checked">Checking latest request…</small></article>
    <article><h2>Authentication negotiation</h2><p id="auth">Loading…</p><small>Negotiate creates an OS-backed token for an eligible upstream proxy. Unproxy sends the initial token with CONNECT; the token itself is never displayed.</small><ul id="negotiation-details"><li>Loading…</li></ul></article>
  </section>
  <section aria-labelledby="resolve-heading">
    <h2 id="resolve-heading">Check URL against every loaded PAC</h2>
    <form id="resolve-form"><label for="resolve-url">HTTP or HTTPS URL</label> <input id="resolve-url" type="url" required placeholder="https://example.com/path" style="width:min(32rem,70vw)"> <button>Check</button></form>
    <ul id="resolve-results" aria-live="polite"></ul>
  </section>
  <nav aria-label="Proxy resources">
    <a href="/access.html">Live access log</a>
        <a href="/log.html">Application log</a>
    <a href="/status.json">Status JSON</a>
    <a href="/proxy.pac">Generated PAC file</a>
  </nav>
  <script>
    async function refreshStatus() {
      try {
        const response = await fetch('/status.json', {cache: 'no-store'});
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const status = await response.json();
        document.querySelector('#pac').textContent = status.pac_loaded ? 'Loaded' : 'Not loaded';
                document.querySelector('#blocked-domain-count').textContent = Number.isInteger(status.blocked_domain_count)
                    ? status.blocked_domain_count.toLocaleString() : 'Unavailable';
        const pacFiles = document.querySelector('#pac-files');
        pacFiles.replaceChildren();
        const files = Array.isArray(status.pac_files) ? status.pac_files : [];
        if (files.length) {
          for (const file of files) {
            const item = document.createElement('li');
            item.textContent = file;
            pacFiles.append(item);
          }
        } else {
          const item = document.createElement('li');
          item.textContent = status.pac_loaded ? 'No PAC files (inline policy)' : 'None';
          pacFiles.append(item);
        }
        const upstream = status.upstream_state;
        document.querySelector('#upstream').textContent = upstream === 'ok' ? 'Last request succeeded'
          : upstream === 'error' ? 'Last request failed' : 'No upstream result yet';
        document.querySelector('#checked').textContent = status.upstream_checked_at
          ? 'Last checked ' + new Date(status.upstream_checked_at * 1000).toLocaleString()
          : 'No upstream request has been checked yet';
        const auth = status.authentication_state;
        document.querySelector('#auth').textContent = auth === 'authenticated' ? 'Authenticated'
          : auth === 'rejected' ? 'Rejected by upstream'
          : status.authentication_configured ? 'Configured, not verified' : 'Not configured';
        const details = document.querySelector('#negotiation-details');
        details.replaceChildren();
        const addDetail = text => { const item = document.createElement('li'); item.textContent = text; details.append(item); };
        addDetail(status.upstream_route ? 'Route: ' + status.upstream_route : 'No upstream route tried yet');
        addDetail(status.authentication_sent ? 'Authorization token sent' : 'No authorization token sent');
        addDetail(auth === 'rejected' ? 'Upstream rejected authentication (HTTP 407)' :
          auth === 'authenticated' ? 'Upstream accepted the authenticated request' :
          status.authentication_configured ? 'Authentication is configured; acceptance is not confirmed' :
          'Authentication is disabled');
      } catch (_) {
        document.querySelector('#pac').textContent = 'Unavailable';
            document.querySelector('#blocked-domain-count').textContent = 'Unavailable';
        document.querySelector('#pac-files').replaceChildren();
        document.querySelector('#upstream').textContent = 'Status unavailable';
        document.querySelector('#checked').textContent = 'Could not read status.json';
        document.querySelector('#auth').textContent = 'Unavailable';
        document.querySelector('#negotiation-details').replaceChildren();
      }
    }
    refreshStatus();
    setInterval(refreshStatus, 5000);
    document.querySelector('#resolve-form').addEventListener('submit', async event => {
      event.preventDefault();
      const output = document.querySelector('#resolve-results');
      output.replaceChildren();
      const item = document.createElement('li'); item.textContent = 'Checking…'; output.append(item);
      try {
        const url = document.querySelector('#resolve-url').value;
        const response = await fetch('/resolve.json?url=' + encodeURIComponent(url), {cache: 'no-store'});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || ('HTTP ' + response.status));
        output.replaceChildren();
                const filterListRow = document.createElement('li');
                filterListRow.textContent = data.filter_list.blocked
                    ? 'Filter list: Blocked (' + data.filter_list.host + ')'
                    : 'Filter list: Not blocked (' + data.filter_list.host + ')';
                output.append(filterListRow);
        if (!data.results.length) { const empty = document.createElement('li'); empty.textContent = 'No PACs are loaded.'; output.append(empty); }
        for (const result of data.results) {
          const row = document.createElement('li');
          row.textContent = result.pac + ': ' + (result.routes || ('Error: ' + result.error));
          output.append(row);
        }
      } catch (error) {
        output.replaceChildren(); const row = document.createElement('li'); row.textContent = error.message; output.append(row);
      }
    });
  </script>
</body>
</html>"#;
    PAGE.replace("__VERSION__", crate::VERSION)
}

fn status_text(cfg: &ContextBuilder) -> String {
    let status = cfg.runtime_status.snapshot();
    let pac_loaded = cfg.policy.is_loaded();
    let pac_files = if pac_loaded && !status.pac_files.is_empty() {
        status.pac_files.join(", ")
    } else if pac_loaded {
        "(inline policy)".to_owned()
    } else {
        "none".to_owned()
    };
    let upstream = match status.upstream_state.as_str() {
        "ok" => "Last request succeeded",
        "error" => "Last request failed",
        _ => "No upstream result yet",
    };
    let authentication = match status.authentication_state.as_str() {
        "authenticated" => "Authenticated",
        "rejected" => "Rejected by upstream",
        _ if status.authentication_configured => "Configured, not verified",
        _ => "Not configured",
    };
    format!(
        "Unproxy status\nVersion: {}\nProxy: Running\nPAC policy: {}\nPAC files: {}\nUpstream: {}\nAuthentication: {}\nHTML status page: /index.html\nJSON status: /status.json\n",
        crate::VERSION,
        if pac_loaded { "Loaded" } else { "Not loaded" },
        pac_files,
        upstream,
        authentication,
    )
}

#[cfg(test)]
mod wait_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn builder_normalizes_zero_session_and_parallel_limits() {
        let builder = ContextBuilder::new(
            Arc::new(Policy::new(None).unwrap()),
            ConnectionOptions::default(),
        )
        .max_sessions(0)
        .parallel_connect(0);
        assert_eq!(builder.session_limit.available_permits(), 1);
        assert_eq!(builder.parallel, 1);
    }

    #[tokio::test]
    async fn wait_observes_shutdown_without_triggering_it() {
        let policy = Arc::new(Policy::new(None).unwrap());
        let server = ContextBuilder::new(policy, ConnectionOptions::default())
            .listen("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .unwrap();
        let addr = server.local_addrs()[0];
        let shutdown = server.shutdown.clone();
        let waiter = tokio::spawn(server.wait());
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!("GET /missing HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 404"));
        assert!(!waiter.is_finished());

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }
}
