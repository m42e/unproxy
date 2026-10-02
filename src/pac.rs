use crate::route::{Route, Routes};
use anyhow::{Context as _, Result, anyhow, bail};
use boa_engine::{Context, JsString, JsValue, NativeFunction, Script, Source};
use std::{
    collections::HashMap,
    future::Future as _,
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
fn preferred_ip(ips: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    let mut first = None;
    for ip in ips {
        if ip.is_ipv4() {
            return Some(ip);
        }
        first.get_or_insert(ip);
    }
    first
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
        Self::new_with_ip(source, "127.0.0.1".parse().unwrap())
    }
    pub fn new_with_ip(source: Option<&str>, ip: IpAddr) -> Result<Self> {
        let mut pac = Self {
            context: Context::default(),
            ip: Arc::new(Mutex::new(ip)),
            source: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
            last_prune: Instant::now(),
            dns_budget: Arc::new(AtomicUsize::new(0)),
        };
        pac.install_script(source)?;
        Ok(pac)
    }
    pub fn set_script(&mut self, source: Option<&str>) -> Result<()> {
        let mut candidate = Self {
            context: Context::default(),
            ip: self.ip.clone(),
            source: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
            last_prune: Instant::now(),
            dns_budget: Arc::new(AtomicUsize::new(0)),
        };
        candidate.install_script(source)?;
        *self = candidate;
        Ok(())
    }
    fn install_script(&mut self, source: Option<&str>) -> Result<()> {
        if source.is_some_and(|s| s.len() > MAX_PAC_SCRIPT_BYTES) {
            bail!("PAC script exceeds 8 MiB");
        }
        self.context = limited_context();
        self.context
            .runtime_limits_mut()
            .set_loop_iteration_limit(PAC_LOOP_LIMIT);
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
        eval_script_sync(include_str!("pac_helpers.js"), &mut self.context)
            .map_err(|e| anyhow!("PAC helper initialization: {e}"))?;
        let script = source.unwrap_or(DEFAULT_SCRIPT);
        eval_script_sync(script, &mut self.context).map_err(|e| anyhow!("PAC script: {e}"))?;
        if source.is_some() {
            let callable =
                eval_script_sync("typeof FindProxyForURL === 'function'", &mut self.context)
                    .map_err(|e| anyhow!("PAC entry point validation: {e}"))?;
            if !callable.as_boolean().unwrap_or(false) {
                bail!("PAC script is missing callable FindProxyForURL")
            }
        }
        eval_script_sync(
            "if (typeof _dnsCache === 'undefined') var _dnsCache = new _DnsCache();",
            &mut self.context,
        )
        .map_err(|e| anyhow!("PAC cache initialization: {e}"))?;
        Ok(())
    }
    pub fn set_ip(&mut self, ip: IpAddr) {
        *self.ip.lock().unwrap() = ip;
    }
    pub fn evaluate(&mut self, url: &str, host: &str) -> Result<Routes> {
        if self.last_prune.elapsed() >= Duration::from_secs(300) {
            self.cache
                .lock()
                .unwrap()
                .retain(|_, v| v.at.elapsed() < Duration::from_secs(300));
            self.last_prune = Instant::now();
        }
        self.dns_budget.store(0, Ordering::Relaxed);
        let source = format!(
            "FindProxyForURL({}, {})",
            serde_json::to_string(url)?,
            serde_json::to_string(host)?
        );
        let val = eval_script_sync(&source, &mut self.context)
            .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        if !val.is_string() {
            bail!("FindProxyForURL returned a non-string value")
        }
        val.as_string().unwrap().to_std_string_escaped().parse()
    }
    async fn evaluate_bounded(&mut self, url: &str, host: &str) -> Result<Routes> {
        self.dns_budget.store(0, Ordering::Relaxed);
        let source = format!(
            "FindProxyForURL({}, {})",
            serde_json::to_string(url)?,
            serde_json::to_string(host)?
        );
        let script = Script::parse(Source::from_bytes(&source), None, &mut self.context)
            .map_err(|e| anyhow!("PAC evaluation parse: {e}"))?;
        let value = tokio::time::timeout(
            PAC_EVAL_TIMEOUT,
            script.evaluate_async_with_budget(&mut self.context, PAC_EVAL_BUDGET),
        )
        .await
        .context("PAC evaluation exceeded its time limit")?
        .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        if !value.is_string() {
            bail!("FindProxyForURL returned a non-string value");
        }
        value.as_string().unwrap().to_std_string_escaped().parse()
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

enum Job {
    Eval(String, String, bool, oneshot::Sender<Result<Routes>>),
    Scripts(Vec<String>, oneshot::Sender<Result<()>>),
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
        Self::new_scripts(source.into_iter().collect())
    }
    pub fn new_scripts(scripts: Vec<String>) -> Result<Self> {
        Self::new_scripts_with_ip(scripts, "127.0.0.1".parse().unwrap())
    }
    pub fn new_scripts_with_ip(scripts: Vec<String>, ip: IpAddr) -> Result<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(PAC_QUEUE_CAPACITY);
        let loaded = Arc::new(AtomicBool::new(!scripts.is_empty()));
        let worker_loaded = loaded.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("pac-policy".into())
            .spawn(move || {
                let mut active_ip = ip;
                let mut pacs = match scripts
                    .iter()
                    .map(|s| Pac::new_with_ip(Some(s), ip))
                    .collect::<Result<Vec<_>>>()
                {
                    Ok(pacs) => {
                        let _ = ready_tx.send(Ok(()));
                        pacs
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("PAC worker runtime");
                while let Some(job) = rx.blocking_recv() {
                    match job {
                        Job::Eval(u, h, strict, r) => {
                            let result = if strict && !worker_loaded.load(Ordering::Acquire) {
                                Err(anyhow!("routing policy is unavailable"))
                            } else {
                                evaluate_scripts_bounded(&mut pacs, &u, &h, &runtime)
                            };
                            let _ = r.send(result);
                        }
                        Job::Scripts(scripts, r) => {
                            worker_loaded.store(false, Ordering::Release);
                            let replacement = scripts
                                .iter()
                                .map(|s| Pac::new_with_ip(Some(s), active_ip))
                                .collect::<Result<Vec<_>>>();
                            match replacement {
                                Ok(new_pacs) => {
                                    pacs = new_pacs;
                                    worker_loaded.store(!scripts.is_empty(), Ordering::Release);
                                    let _ = r.send(Ok(()));
                                }
                                Err(e) => {
                                    worker_loaded.store(!pacs.is_empty(), Ordering::Release);
                                    let _ = r.send(Err(e));
                                }
                            }
                        }
                        Job::Ip(ip, r) => {
                            active_ip = ip;
                            for pac in &mut pacs {
                                pac.set_ip(ip);
                            }
                            let _ = r.send(());
                        }
                        Job::Snapshot(r) => {
                            let mut snapshot = HashMap::new();
                            for pac in &pacs {
                                snapshot.extend(pac.cache_snapshot());
                            }
                            let _ = r.send(snapshot);
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
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }
    pub fn mark_unloaded(&self) {
        self.loaded.store(false, Ordering::Release);
    }
    pub async fn set_script(&self, script: Option<String>) -> Result<()> {
        self.set_scripts(script.into_iter().collect()).await
    }
    pub async fn set_scripts(&self, scripts: Vec<String>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Scripts(scripts, tx))
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

fn evaluate_scripts_bounded(
    pacs: &mut [Pac],
    url: &str,
    host: &str,
    runtime: &tokio::runtime::Runtime,
) -> Result<Routes> {
    for pac in pacs {
        let routes = runtime.block_on(pac.evaluate_bounded(url, host))?;
        if routes.0.iter().any(|route| !matches!(route, Route::Direct)) {
            return Ok(routes);
        }
    }
    Ok("DIRECT".parse().expect("DIRECT is valid"))
}

fn eval_script_sync(source: &str, context: &mut Context) -> Result<JsValue> {
    let script = Script::parse(Source::from_bytes(source), None, context)
        .map_err(|e| anyhow!("script parse: {e}"))?;
    let future = script.evaluate_async_with_budget(context, PAC_EVAL_BUDGET);
    let waker = std::task::Waker::noop();
    let mut task_context = std::task::Context::from_waker(waker);
    let mut future = Box::pin(future);
    let started = Instant::now();
    loop {
        if started.elapsed() >= PAC_EVAL_TIMEOUT {
            bail!("script execution exceeded its time limit");
        }
        match future.as_mut().poll(&mut task_context) {
            std::task::Poll::Ready(value) => {
                return value.map_err(|e| anyhow!("script evaluation: {e}"));
            }
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
                        .and_then(|ips| preferred_ip(ips.map(|addr| addr.ip())));
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

#[cfg(test)]
mod tests {
    use super::preferred_ip;
    use std::net::IpAddr;

    #[test]
    fn dns_prefers_first_ipv4_then_falls_back_to_first_ipv6() {
        let ips = ["::1", "192.0.2.2", "192.0.2.3"].map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(preferred_ip(ips), Some("192.0.2.2".parse().unwrap()));
        let ips = ["::1", "2001:db8::1"].map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(preferred_ip(ips), Some("::1".parse().unwrap()));
        assert_eq!(preferred_ip([]), None);
    }
}
