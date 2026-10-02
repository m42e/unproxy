use crate::route::Routes;
use anyhow::{Context as _, Result, anyhow, bail};
use boa_engine::{Context, JsString, JsValue, NativeFunction, Script, Source};
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const DEFAULT_SCRIPT: &str = "function FindProxyForURL(url, host) { return 'DIRECT'; }";
const PAC_LOOP_LIMIT: u64 = 100_000;
const PAC_QUEUE_CAPACITY: usize = 64;
const PAC_EVAL_BUDGET: u32 = 256;
const PAC_EVAL_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PAC_SCRIPT_BYTES: usize = 8 * 1024 * 1024;
const DNS_RESOLVE_BUDGET: usize = 4;
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
struct CacheEntry {
    value: Option<IpAddr>,
    at: Instant,
}
pub struct Pac {
    context: Context,
    ip: Arc<Mutex<IpAddr>>,
    source: Option<String>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    last_prune: Instant,
    dns_budget: Arc<AtomicUsize>,
}
impl Pac {
    pub fn new(source: Option<&str>) -> Result<Self> {
        let mut pac = Self {
            context: limited_context(),
            ip: Arc::new(Mutex::new("127.0.0.1".parse().unwrap())),
            source: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
            last_prune: Instant::now(),
            dns_budget: Arc::new(AtomicUsize::new(0)),
        };
        pac.set_script(source)?;
        Ok(pac)
    }
    pub fn set_script(&mut self, source: Option<&str>) -> Result<()> {
        self.prepare_script_context(source)?;
        eval_script_sync(source.unwrap_or(DEFAULT_SCRIPT), &mut self.context)
            .map_err(|e| anyhow!("PAC script: {e}"))?;
        eval_script_sync(
            "if (typeof _dnsCache === 'undefined') var _dnsCache = new _DnsCache();",
            &mut self.context,
        )
        .map_err(|e| anyhow!("PAC cache initialization: {e}"))?;
        Ok(())
    }
    async fn set_script_bounded(&mut self, source: Option<&str>) -> Result<()> {
        if source.is_some_and(|s| s.len() > MAX_PAC_SCRIPT_BYTES) {
            bail!("PAC script exceeds 8 MiB");
        }
        self.prepare_script_context(source)?;
        tokio::time::timeout(PAC_EVAL_TIMEOUT, async {
            let script = Script::parse(
                Source::from_bytes(source.unwrap_or(DEFAULT_SCRIPT)),
                None,
                &mut self.context,
            )
            .map_err(|e| anyhow!("PAC script parse: {e}"))?;
            script
                .evaluate_async_with_budget(&mut self.context, PAC_EVAL_BUDGET)
                .await
                .map_err(|e| anyhow!("PAC script: {e}"))?;
            let cache = Script::parse(
                Source::from_bytes(
                    "if (typeof _dnsCache === 'undefined') var _dnsCache = new _DnsCache();",
                ),
                None,
                &mut self.context,
            )
            .map_err(|e| anyhow!("PAC cache initialization parse: {e}"))?;
            cache
                .evaluate_async_with_budget(&mut self.context, PAC_EVAL_BUDGET)
                .await
                .map_err(|e| anyhow!("PAC cache initialization: {e}"))?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("PAC script initialization exceeded its time limit")??;
        Ok(())
    }
    fn prepare_script_context(&mut self, source: Option<&str>) -> Result<()> {
        if source.is_some_and(|s| s.len() > MAX_PAC_SCRIPT_BYTES) {
            bail!("PAC script exceeds 8 MiB");
        }
        self.context = limited_context();
        self.cache.lock().unwrap().clear();
        self.last_prune = Instant::now();
        self.source = source.map(str::to_owned);
        let dns_cache = self.cache.clone();
        let dns_budget = self.dns_budget.clone();
        let dns = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                let Some(arg) = args.first() else {
                    return Err(boa_engine::JsNativeError::typ()
                        .with_message("dnsResolve requires a hostname")
                        .into());
                };
                let host = arg.to_string(ctx)?.to_std_string_escaped();
                let now = Instant::now();
                let value = {
                    let mut c = dns_cache.lock().unwrap();
                    c.retain(|_, v| now.duration_since(v.at) < Duration::from_secs(300));
                    if let Some(v) = c.get(&host) {
                        v.value
                    } else if dns_budget.fetch_add(1, Ordering::Relaxed) >= DNS_RESOLVE_BUDGET {
                        None
                    } else {
                        let ip = resolve_hostname(&host);
                        c.insert(host, CacheEntry { value: ip, at: now });
                        ip
                    }
                };
                Ok(value
                    .map(|v| JsValue::from(JsString::from(v.to_string())))
                    .unwrap_or(JsValue::null()))
            })
        };
        self.context
            .register_global_builtin_callable(JsString::from("dnsResolve"), 1, dns)
            .map_err(|e| anyhow!("register dnsResolve: {e}"))?;
        let ip = self.ip.clone();
        let ipfn = unsafe {
            NativeFunction::from_closure(move |_, _, _| {
                Ok(JsValue::from(JsString::from(
                    ip.lock().unwrap().to_string(),
                )))
            })
        };
        self.context
            .register_global_builtin_callable(JsString::from("myIpAddress"), 0, ipfn)
            .map_err(|e| anyhow!("register myIpAddress: {e}"))?;
        self.context
            .register_global_callable(
                JsString::from("_DnsCache"),
                0,
                NativeFunction::from_copy_closure(|_, _, _| Ok(JsValue::undefined())),
            )
            .map_err(|e| anyhow!("register _DnsCache: {e}"))?;
        self.context
            .register_global_builtin_callable(
                JsString::from("alert"),
                1,
                NativeFunction::from_copy_closure(|_, args, ctx| {
                    if let Some(v) = args.first() {
                        if v.is_string() {
                            println!("{}", v.as_string().unwrap().to_std_string_escaped());
                        } else {
                            println!();
                        }
                    } else {
                        println!();
                    }
                    let _ = ctx;
                    Ok(JsValue::undefined())
                }),
            )
            .map_err(|e| anyhow!("register alert: {e}"))?;
        self.context
            .eval(Source::from_bytes(include_str!("pac_helpers.js")))
            .map_err(|e| anyhow!("PAC helper initialization: {e}"))?;
        let _ = source;
        Ok(())
    }
    pub fn set_ip(&mut self, ip: IpAddr) {
        *self.ip.lock().unwrap() = ip;
    }
    pub fn evaluate(&mut self, url: &str, host: &str) -> Result<Routes> {
        self.dns_budget.store(0, Ordering::Relaxed);
        self.prune_cache();
        let source = eval_source(url, host)?;
        let val = eval_script_sync(&source, &mut self.context)
            .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        routes_from_value(val)
    }
    async fn evaluate_bounded(&mut self, url: &str, host: &str) -> Result<Routes> {
        self.dns_budget.store(0, Ordering::Relaxed);
        self.prune_cache();
        let source = eval_source(url, host)?;
        let script = Script::parse(Source::from_bytes(&source), None, &mut self.context)
            .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        let val = tokio::time::timeout(
            PAC_EVAL_TIMEOUT,
            script.evaluate_async_with_budget(&mut self.context, PAC_EVAL_BUDGET),
        )
        .await
        .context("PAC evaluation exceeded its time limit")?
        .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        routes_from_value(val)
    }
    fn prune_cache(&mut self) {
        if self.last_prune.elapsed() >= Duration::from_secs(300) {
            self.cache
                .lock()
                .unwrap()
                .retain(|_, v| v.at.elapsed() < Duration::from_secs(300));
            self.last_prune = Instant::now();
        }
    }
    pub fn cache_snapshot(&self) -> HashMap<String, Option<IpAddr>> {
        self.cache
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.value))
            .collect()
    }
}

fn eval_source(url: &str, host: &str) -> Result<String> {
    Ok(format!(
        "FindProxyForURL({}, {})",
        serde_json::to_string(url)?,
        serde_json::to_string(host)?
    ))
}
fn routes_from_value(val: JsValue) -> Result<Routes> {
    if !val.is_string() {
        bail!("FindProxyForURL returned a non-string value")
    }
    val.as_string().unwrap().to_std_string_escaped().parse()
}

fn eval_script_sync(source: &str, context: &mut Context) -> Result<JsValue> {
    let script = Script::parse(Source::from_bytes(source), None, context)
        .map_err(|e| anyhow!("script parse: {e}"))?;
    let future = script.evaluate_async_with_budget(context, PAC_EVAL_BUDGET);
    let result = poll_with_deadline(future, PAC_EVAL_TIMEOUT)
        .context("script execution exceeded its time limit")?;
    result.map_err(|e| anyhow!("script evaluation: {e}"))
}

fn poll_with_deadline<F: std::future::Future>(future: F, limit: Duration) -> Result<F::Output> {
    let waker = std::task::Waker::noop();
    let mut task_context = std::task::Context::from_waker(waker);
    let mut future = Box::pin(future);
    let started = Instant::now();
    loop {
        if started.elapsed() >= limit {
            bail!("operation exceeded its time limit");
        }
        match future.as_mut().poll(&mut task_context) {
            std::task::Poll::Ready(output) => return Ok(output),
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn limited_context() -> Context {
    let mut context = Context::builder()
        .can_block(false)
        .build()
        .expect("PAC context");
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(PAC_LOOP_LIMIT);
    context
}

fn resolve_hostname(host: &str) -> Option<IpAddr> {
    static RESOLVER: OnceLock<SyncSender<(String, SyncSender<Option<IpAddr>>)>> = OnceLock::new();
    let resolver = RESOLVER.get_or_init(|| {
        let (tx, rx) = sync_channel::<(String, SyncSender<Option<IpAddr>>)>(1);
        std::thread::Builder::new()
            .name("pac-dns-resolver".into())
            .spawn(move || {
                while let Ok((host, reply)) = rx.recv() {
                    let value = (host.as_str(), 0)
                        .to_socket_addrs()
                        .ok()
                        .and_then(|mut addresses| addresses.next().map(|addr| addr.ip()));
                    let _ = reply.send(value);
                }
            })
            .expect("start bounded PAC resolver");
        tx
    });
    let (reply_tx, reply_rx) = sync_channel(1);
    resolver.try_send((host.to_owned(), reply_tx)).ok()?;
    reply_rx.recv_timeout(DNS_RESOLVE_TIMEOUT).ok().flatten()
}

enum Job {
    Eval(String, String, bool, oneshot::Sender<Result<Routes>>),
    Script(Option<String>, oneshot::Sender<Result<()>>),
    Ip(IpAddr, oneshot::Sender<()>),
    Snapshot(oneshot::Sender<HashMap<String, Option<IpAddr>>>),
}
#[derive(Clone)]
pub struct Policy {
    tx: tokio::sync::mpsc::Sender<Job>,
    loaded: Arc<AtomicBool>,
}
impl Policy {
    pub fn new(source: Option<String>) -> Result<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(PAC_QUEUE_CAPACITY);
        let loaded = Arc::new(AtomicBool::new(false));
        let worker_loaded = loaded.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("pac-policy".into())
            .spawn(move || {
                let mut pac = match Pac::new(None) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                worker_loaded.store(source.is_some(), Ordering::Release);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("PAC worker runtime");
                if let Err(e) = runtime.block_on(pac.set_script_bounded(source.as_deref())) {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
                let _ = ready_tx.send(Ok(()));
                while let Some(job) = rx.blocking_recv() {
                    match job {
                        Job::Eval(u, h, strict, r) => {
                            if strict && !worker_loaded.load(Ordering::Acquire) {
                                let _ = r.send(Err(anyhow!("routing policy is unavailable")));
                                continue;
                            }
                            let result = runtime.block_on(pac.evaluate_bounded(&u, &h));
                            if result.is_err() {
                                // Discard potentially corrupted VM state after budget/error paths.
                                let source = pac.source.clone();
                                if let Err(e) =
                                    runtime.block_on(pac.set_script_bounded(source.as_deref()))
                                {
                                    tracing::error!(
                                        "failed to reset PAC after evaluation error: {e:#}"
                                    );
                                    let _ = runtime.block_on(pac.set_script_bounded(None));
                                    pac.source = None;
                                    worker_loaded.store(false, Ordering::Release);
                                }
                            }
                            let _ = r.send(result);
                        }
                        Job::Script(s, r) => {
                            worker_loaded.store(false, Ordering::Release);
                            let result = runtime.block_on(pac.set_script_bounded(s.as_deref()));
                            worker_loaded.store(result.is_ok(), Ordering::Release);
                            if result.is_err() {
                                // Never let later requests execute a half-loaded script.
                                let _ = runtime.block_on(pac.set_script_bounded(None));
                                pac.source = None;
                            }
                            let _ = r.send(result);
                        }
                        Job::Ip(ip, r) => {
                            pac.set_ip(ip);
                            let _ = r.send(());
                        }
                        Job::Snapshot(r) => {
                            let _ = r.send(pac.cache_snapshot());
                        }
                    }
                }
            })
            .context("start PAC worker")?;
        ready_rx
            .recv()
            .map_err(|_| anyhow!("PAC worker failed to start"))?
            .map_err(|e| anyhow!(e))?;
        Ok(Self { tx, loaded })
    }
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }
    pub fn mark_unloaded(&self) {
        self.loaded.store(false, Ordering::Release);
    }
    pub async fn evaluate(&self, url: String, host: String) -> Result<Routes> {
        self.evaluate_with_policy(url, host, false).await
    }
    pub async fn evaluate_strict(&self, url: String, host: String) -> Result<Routes> {
        self.evaluate_with_policy(url, host, true).await
    }
    async fn evaluate_with_policy(
        &self,
        url: String,
        host: String,
        strict: bool,
    ) -> Result<Routes> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Eval(url, host, strict, tx))
            .await
            .map_err(|_| anyhow!("PAC worker stopped"))?;
        rx.await.context("PAC worker stopped")?
    }
    pub async fn set_script(&self, script: Option<String>) -> Result<()> {
        self.mark_unloaded();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Script(script, tx))
            .await
            .map_err(|_| anyhow!("PAC worker stopped"))?;
        rx.await.context("PAC worker stopped")?
    }
    pub async fn set_ip(&self, ip: IpAddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Ip(ip, tx))
            .await
            .map_err(|_| anyhow!("PAC worker stopped"))?;
        rx.await.context("PAC worker stopped")?;
        Ok(())
    }
    pub async fn cache_snapshot(&self) -> Result<HashMap<String, Option<IpAddr>>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Snapshot(tx))
            .await
            .map_err(|_| anyhow!("PAC worker stopped"))?;
        rx.await.context("PAC worker stopped")
    }
}
