use crate::route::{Route, Routes};
use anyhow::{Context as _, Result, anyhow, bail};
use boa_engine::{Context, JsString, JsValue, NativeFunction, Script, Source};
use std::{
    cell::RefCell,
    collections::HashMap,
    future::Future as _,
    net::{IpAddr, ToSocketAddrs},
    rc::Rc,
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
const SH_EXP_MATCH_CACHE_CAPACITY: usize = 512;
const PAC_EVAL_BUDGET: u32 = 256;
const PAC_EVAL_TIMEOUT: Duration = Duration::from_secs(2);
const PAC_RECURSION_LIMIT: usize = 64;
const PAC_WORKER_STACK_SIZE: usize = 8 * 1024 * 1024;
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
    evaluation_script: Script,
    ip: Arc<Mutex<IpAddr>>,
    ip_string: Rc<RefCell<JsString>>,
    source: Option<String>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    glob_cache: Arc<Mutex<HashMap<String, std::result::Result<glob::Pattern, ShellPatternError>>>>,
    last_prune: Instant,
    dns_budget: Arc<AtomicUsize>,
}
impl Pac {
    pub fn new(source: Option<&str>) -> Result<Self> {
        Self::new_with_ip(source, "127.0.0.1".parse().unwrap())
    }
    pub fn new_with_ip(source: Option<&str>, ip: IpAddr) -> Result<Self> {
        let mut context = limited_context();
        let evaluation_script = Script::parse(
            Source::from_bytes("FindProxyForURL(__unproxyUrl, __unproxyHost)"),
            None,
            &mut context,
        )
        .expect("constant PAC evaluator parses");
        let mut pac = Self {
            context,
            evaluation_script,
            ip: Arc::new(Mutex::new(ip)),
            ip_string: Rc::new(RefCell::new(JsString::from(ip.to_string()))),
            source: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
            glob_cache: Arc::new(Mutex::new(HashMap::new())),
            last_prune: Instant::now(),
            dns_budget: Arc::new(AtomicUsize::new(0)),
        };
        pac.install_script(source)?;
        Ok(pac)
    }
    pub fn set_script(&mut self, source: Option<&str>) -> Result<()> {
        let mut context = limited_context();
        let evaluation_script = Script::parse(
            Source::from_bytes("FindProxyForURL(__unproxyUrl, __unproxyHost)"),
            None,
            &mut context,
        )
        .expect("constant PAC evaluator parses");
        let mut candidate = Self {
            context,
            evaluation_script,
            ip: self.ip.clone(),
            ip_string: self.ip_string.clone(),
            source: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
            glob_cache: Arc::new(Mutex::new(HashMap::new())),
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
                    // Expire only this hostname; bulk pruning runs periodically.
                    if c.get(&host)
                        .is_some_and(|v| now.duration_since(v.at) >= Duration::from_secs(300))
                    {
                        c.remove(&host);
                    }
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
        let glob_cache = self.glob_cache.clone();
        let sh_exp_match = unsafe {
            NativeFunction::from_closure(move |_, args, _| {
                let value = args
                    .first()
                    .and_then(JsValue::as_string)
                    .ok_or_else(|| {
                        boa_engine::JsNativeError::typ().with_message("shExpMatch expects strings")
                    })?
                    .to_std_string_escaped();
                let pattern = args
                    .get(1)
                    .and_then(JsValue::as_string)
                    .ok_or_else(|| {
                        boa_engine::JsNativeError::typ().with_message("shExpMatch expects strings")
                    })?
                    .to_std_string_escaped();
                let compiled = {
                    let mut cache = glob_cache.lock().unwrap();
                    if let Some(compiled) = cache.get(&pattern) {
                        compiled.clone()
                    } else {
                        let compiled = compile_shell_pattern(&pattern);
                        if cache.len() < SH_EXP_MATCH_CACHE_CAPACITY {
                            cache.insert(pattern, compiled.clone());
                        }
                        compiled
                    }
                };
                let compiled = compiled.map_err(|error| match error {
                    ShellPatternError::InvalidGlob => {
                        boa_engine::JsNativeError::error().with_message("invalid glob")
                    }
                    ShellPatternError::InvalidPattern(message) => {
                        boa_engine::JsNativeError::syntax().with_message(message)
                    }
                })?;
                Ok(JsValue::from(
                    compiled.matches_with(&value, glob::MatchOptions::new()),
                ))
            })
        };
        self.context
            .register_global_builtin_callable(JsString::from("shExpMatch"), 2, sh_exp_match)
            .map_err(|e| anyhow!("register shExpMatch: {e}"))?;
        let ip = self.ip_string.clone();
        let ipfn = unsafe {
            NativeFunction::from_closure(move |_, _, _| Ok(JsValue::from(ip.borrow().clone())))
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
        let substr = unsafe {
            NativeFunction::from_closure(move |this, args, context| {
                let value = this.to_string(context)?;
                let size = value.len();
                let start = args
                    .first()
                    .cloned()
                    .unwrap_or_else(JsValue::undefined)
                    .to_numeric_number(context)?;
                let offset = if start.is_nan() || start == 0.0 {
                    0.0
                } else {
                    start
                };
                let from = if offset < 0.0 {
                    (size as f64 + offset.ceil()).max(0.0) as usize
                } else {
                    offset.floor().min(size as f64) as usize
                };
                let end = match args.get(1) {
                    None => size,
                    Some(length) if length.is_undefined() => size,
                    Some(length) => {
                        let count = length.to_numeric_number(context)?;
                        if count <= 0.0 {
                            return Ok(JsValue::from(JsString::from("")));
                        }
                        let end = from as f64 + count.floor();
                        if end.is_nan() {
                            0
                        } else {
                            end.max(0.0).min(size as f64) as usize
                        }
                    }
                };
                Ok(JsValue::from(value.slice(from, end)))
            })
        };
        self.context
            .register_global_builtin_callable(JsString::from("__unproxySubstr"), 2, substr)
            .map_err(|e| anyhow!("register substr: {e}"))?;
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
        self.evaluation_script = Script::parse(
            Source::from_bytes("FindProxyForURL(__unproxyUrl, __unproxyHost)"),
            None,
            &mut self.context,
        )
        .map_err(|e| anyhow!("PAC evaluator initialization: {e}"))?;
        Ok(())
    }
    pub fn set_ip(&mut self, ip: IpAddr) {
        *self.ip.lock().unwrap() = ip;
        *self.ip_string.borrow_mut() = JsString::from(ip.to_string());
    }
    pub fn evaluate(&mut self, url: &str, host: &str) -> Result<Routes> {
        self.prune_dns_cache();
        self.dns_budget.store(0, Ordering::Relaxed);
        self.set_evaluation_arguments(url, host)?;
        let val = eval_compiled_script_sync(&self.evaluation_script, &mut self.context)
            .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        if !val.is_string() {
            bail!("FindProxyForURL returned a non-string value")
        }
        val.as_string().unwrap().to_std_string_escaped().parse()
    }
    async fn evaluate_bounded(&mut self, url: &str, host: &str) -> Result<Routes> {
        self.prune_dns_cache();
        self.dns_budget.store(0, Ordering::Relaxed);
        self.set_evaluation_arguments(url, host)?;
        let value = tokio::time::timeout(
            PAC_EVAL_TIMEOUT,
            self.evaluation_script
                .evaluate_async_with_budget(&mut self.context, PAC_EVAL_BUDGET),
        )
        .await
        .context("PAC evaluation exceeded its time limit")?
        .map_err(|e| anyhow!("PAC evaluation: {e}"))?;
        if !value.is_string() {
            bail!("FindProxyForURL returned a non-string value");
        }
        value.as_string().unwrap().to_std_string_escaped().parse()
    }
    fn set_evaluation_arguments(&mut self, url: &str, host: &str) -> Result<()> {
        let global = self.context.global_object();
        global
            .set(
                JsString::from("__unproxyUrl"),
                JsString::from(url),
                true,
                &mut self.context,
            )
            .map_err(|e| anyhow!("set PAC URL: {e}"))?;
        global
            .set(
                JsString::from("__unproxyHost"),
                JsString::from(host),
                true,
                &mut self.context,
            )
            .map_err(|e| anyhow!("set PAC host: {e}"))?;
        Ok(())
    }
    fn prune_dns_cache(&mut self) {
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

enum Job {
    Eval(String, String, bool, oneshot::Sender<Result<Routes>>),
    EvalEach(String, String, oneshot::Sender<Vec<Result<Routes, String>>>),
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
            .stack_size(PAC_WORKER_STACK_SIZE)
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
                        Job::EvalEach(u, h, r) => {
                            let results = pacs
                                .iter_mut()
                                .map(|pac| {
                                    runtime
                                        .block_on(pac.evaluate_bounded(&u, &h))
                                        .map_err(|e| format!("{e:#}"))
                                })
                                .collect();
                            let _ = r.send(results);
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
    pub async fn evaluate_each(
        &self,
        url: String,
        host: String,
    ) -> Result<Vec<Result<Routes, String>>> {
        if !self.is_loaded() {
            bail!("routing policy is unavailable")
        }
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::EvalEach(url, host, tx))
            .await
            .map_err(|_| anyhow!("PAC worker stopped"))?;
        rx.await.context("PAC worker stopped")
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
    eval_compiled_script_sync(&script, context)
}

fn eval_compiled_script_sync(script: &Script, context: &mut Context) -> Result<JsValue> {
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
        .runtime_limits_mut()
        .set_recursion_limit(PAC_RECURSION_LIMIT);
    context
}

#[derive(Clone)]
enum ShellPatternError {
    InvalidGlob,
    InvalidPattern(String),
}

fn compile_shell_pattern(source: &str) -> std::result::Result<glob::Pattern, ShellPatternError> {
    let chars = source.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(source.len());
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' => {
                normalized.push('*');
                while index + 1 < chars.len() && chars[index + 1] == '*' {
                    index += 1;
                }
                index += 1;
            }
            '[' => {
                let Some(offset) = chars[index + 1..].iter().position(|ch| *ch == ']') else {
                    return Err(ShellPatternError::InvalidGlob);
                };
                let end = index + 1 + offset;
                let class = &chars[index + 1..end];
                if class.is_empty() {
                    return Err(ShellPatternError::InvalidGlob);
                }
                let negated = matches!(class[0], '!' | '^');
                let contents = if negated { &class[1..] } else { class };
                if contents
                    .windows(3)
                    .any(|range| range[1] == '-' && range[0] > range[2])
                {
                    return Err(ShellPatternError::InvalidGlob);
                }
                if contents.is_empty() {
                    normalized.push('?');
                } else {
                    normalized.push('[');
                    if negated {
                        normalized.push('!');
                    }
                    normalized.extend(contents);
                    normalized.push(']');
                }
                index = end + 1;
            }
            ch => {
                normalized.push(ch);
                index += 1;
            }
        }
    }
    glob::Pattern::new(&normalized)
        .map_err(|error| ShellPatternError::InvalidPattern(error.to_string()))
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
    use super::{CacheEntry, Pac, Policy, preferred_ip};
    use std::{
        collections::HashMap,
        net::IpAddr,
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    };

    #[tokio::test]
    async fn policy_can_report_each_pac_without_short_circuiting() {
        let policy = Policy::new_scripts(vec![
            "function FindProxyForURL(){return 'DIRECT';}".into(),
            "function FindProxyForURL(){return 'PROXY second.example:8080';}".into(),
        ])
        .unwrap();
        let results = policy
            .evaluate_each("http://example.test/".into(), "example.test".into())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().to_string(), "DIRECT");
        assert_eq!(
            results[1].as_ref().unwrap().to_string(),
            "HTTP second.example:8080"
        );
    }

    #[tokio::test]
    async fn timed_out_evaluation_does_not_poison_pac_context() {
        let mut pac = Pac::new(Some(
            "function FindProxyForURL(url, host) { if (host === 'slow.test') { while (true) {} } return 'DIRECT'; }",
        ))
        .unwrap();
        pac.context
            .runtime_limits_mut()
            .set_loop_iteration_limit(u64::MAX);

        let error = pac
            .evaluate_bounded("http://slow.test/", "slow.test")
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("deadline has elapsed"));

        for _ in 0..super::PAC_RECURSION_LIMIT + 1 {
            assert_eq!(
                pac.evaluate_bounded("http://example.test/", "example.test")
                    .await
                    .unwrap()
                    .to_string(),
                "DIRECT"
            );
        }
    }

    #[tokio::test]
    async fn bounded_evaluation_prunes_expired_dns_entries() {
        let mut pac = Pac::new(None).unwrap();
        pac.cache.lock().unwrap().insert(
            "expired.test".into(),
            CacheEntry {
                value: None,
                at: Instant::now() - Duration::from_secs(301),
            },
        );
        pac.last_prune = Instant::now() - Duration::from_secs(301);

        pac.evaluate_bounded("http://example.test/", "example.test")
            .await
            .unwrap();

        assert!(!pac.cache.lock().unwrap().contains_key("expired.test"));
    }

    #[test]
    fn pac_substr_supports_standard_start_and_length_semantics() {
        let mut pac = Pac::new(Some(
            "function FindProxyForURL(url, host) { const value='A\\uD83D\\uDE00B'; return host.substr(host.length - 3, 3) === 'com' && host.substr(-3) === 'com' && host.substr(0, 0) === '' && host.substr(0, -1) === '' && value.substr(1, 1) === value.slice(1, 2) && value.substr('3.9') === value.slice(3) && value.substr(1, 2.9) === value.slice(1, 3) && value.substr(0, NaN) === '' ? 'PROXY substr.test:80' : 'DIRECT'; }",
        ))
        .unwrap();
        assert_eq!(
            pac.evaluate("http://example.com", "example.com")
                .unwrap()
                .to_string(),
            "HTTP substr.test:80"
        );
    }

    #[test]
    fn compiled_evaluator_handles_repeated_arguments_without_source_interpolation() {
        let mut pac = Pac::new(Some(
            "function FindProxyForURL(url, host) { return url.includes(\"'\") && host === 'second.test' ? 'PROXY matched.test:80' : 'DIRECT'; }",
        ))
        .unwrap();
        assert_eq!(
            pac.evaluate("first", "first.test").unwrap().to_string(),
            "DIRECT"
        );
        assert_eq!(
            pac.evaluate("url with ' quote", "second.test")
                .unwrap()
                .to_string(),
            "HTTP matched.test:80"
        );
    }

    #[test]
    fn dns_prefers_first_ipv4_then_falls_back_to_first_ipv6() {
        let ips = ["::1", "192.0.2.2", "192.0.2.3"].map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(preferred_ip(ips), Some("192.0.2.2".parse().unwrap()));
        let ips = ["::1", "2001:db8::1"].map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(preferred_ip(ips), Some("::1".parse().unwrap()));
        assert_eq!(preferred_ip([]), None);
    }

    #[test]
    fn pac_cache_snapshot_includes_positive_and_negative_entries() {
        let pac = Pac::new(None).unwrap();
        let ip: IpAddr = "192.0.2.99".parse().unwrap();
        let mut entries = HashMap::new();
        entries.insert(
            "positive.test".to_owned(),
            CacheEntry {
                value: Some(ip),
                at: Instant::now(),
            },
        );
        entries.insert(
            "negative.test".to_owned(),
            CacheEntry {
                value: None,
                at: Instant::now(),
            },
        );
        *pac.cache.lock().unwrap() = entries;
        let snapshot = pac.cache_snapshot();
        assert_eq!(snapshot.get("positive.test"), Some(&Some(ip)));
        assert_eq!(snapshot.get("negative.test"), Some(&None));
        assert_eq!(snapshot.len(), 2);
    }

    #[test]
    fn pac_alert_ip_override_and_oversized_scripts_are_handled() {
        let mut pac = Pac::new(Some(
            "function FindProxyForURL(){ alert(); alert(42); alert('ready'); return myIpAddress() === '192.0.2.8' ? 'DIRECT' : 'PROXY wrong.test:80'; }",
        ))
        .unwrap();
        pac.set_ip("192.0.2.8".parse().unwrap());
        assert_eq!(
            pac.evaluate("http://example.test", "example.test")
                .unwrap()
                .to_string(),
            "DIRECT"
        );

        let oversized = "x".repeat(super::MAX_PAC_SCRIPT_BYTES + 1);
        assert!(
            Pac::new(Some(&oversized))
                .err()
                .unwrap()
                .to_string()
                .contains("8 MiB")
        );
    }

    #[test]
    fn pac_dns_resolution_budget_is_bounded_per_evaluation() {
        let source = "function FindProxyForURL(){ let a=dnsResolve('192.0.2.1'); let b=dnsResolve('192.0.2.2'); let c=dnsResolve('192.0.2.3'); let d=dnsResolve('192.0.2.4'); let e=dnsResolve('192.0.2.5'); return a && b && c && d && e === null ? 'DIRECT' : 'PROXY unexpected.test:80'; }";
        let mut pac = Pac::new(Some(source)).unwrap();
        assert_eq!(
            pac.evaluate("http://example.test", "example.test")
                .unwrap()
                .to_string(),
            "DIRECT"
        );
        assert_eq!(pac.cache_snapshot().len(), super::DNS_RESOLVE_BUDGET);
    }

    #[test]
    #[ignore = "performance measurement; run release ignored PAC tests"]
    fn warm_dns_cache_performance() {
        for size in [64, 4096] {
            let mut pac = Pac::new(Some(
                "function FindProxyForURL(){ for(var i=0;i<32;i++) dnsResolve('warm.test'); return 'DIRECT'; }",
            )).unwrap();
            let now = Instant::now();
            for index in 0..size {
                pac.cache.lock().unwrap().insert(
                    format!("entry{index}.test"),
                    CacheEntry {
                        value: None,
                        at: now,
                    },
                );
            }
            pac.cache.lock().unwrap().insert(
                "warm.test".into(),
                CacheEntry {
                    value: Some("192.0.2.1".parse().unwrap()),
                    at: now,
                },
            );
            for _ in 0..20 {
                pac.evaluate("x", "x").unwrap();
            }
            let mut samples = Vec::new();
            for _ in 0..500 {
                let start = Instant::now();
                assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
                samples.push(start.elapsed());
            }
            samples.sort_unstable();
            println!(
                "warm DNS cache ({size} entries, 32 hits): median {:?}, mean {:?}",
                samples[250],
                samples.iter().sum::<Duration>() / 500
            );
        }
    }

    #[test]
    fn dns_lookup_expires_requested_entry_without_scanning_cache() {
        let mut pac = Pac::new(Some(
            "function FindProxyForURL(){ return dnsResolve('stale.invalid')===null && dnsResolve('positive.test')==='192.0.2.9' && dnsResolve('negative.test')===null ? 'DIRECT' : 'PROXY wrong:80'; }",
        )).unwrap();
        let now = Instant::now();
        for (host, value, expired) in [
            ("stale.invalid", Some("192.0.2.1".parse().unwrap()), true),
            ("unrequested.test", None, true),
            ("positive.test", Some("192.0.2.9".parse().unwrap()), false),
            ("negative.test", None, false),
        ] {
            pac.cache.lock().unwrap().insert(
                host.into(),
                CacheEntry {
                    value,
                    at: if expired {
                        now - Duration::from_secs(301)
                    } else {
                        now
                    },
                },
            );
        }
        assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
        let cache = pac.cache.lock().unwrap();
        assert!(cache["stale.invalid"].at >= now);
        assert!(cache["stale.invalid"].value.is_none());
        assert!(cache["unrequested.test"].at < now);
    }

    #[test]
    fn pac_evaluation_prunes_only_expired_cache_entries() {
        let mut pac = Pac::new(None).unwrap();
        let now = Instant::now();
        let mut entries = HashMap::new();
        entries.insert(
            "expired.test".to_owned(),
            CacheEntry {
                value: None,
                at: now - Duration::from_secs(301),
            },
        );
        entries.insert(
            "fresh.test".to_owned(),
            CacheEntry {
                value: None,
                at: now,
            },
        );
        *pac.cache.lock().unwrap() = entries;
        pac.last_prune = now - Duration::from_secs(301);

        pac.evaluate("http://example.test", "example.test").unwrap();

        let cache = pac.cache.lock().unwrap();
        assert!(!cache.contains_key("expired.test"));
        assert!(cache.contains_key("fresh.test"));
    }

    #[tokio::test]
    async fn policy_strict_unloaded_replacement_and_worker_shutdown_are_reported() {
        let policy = Policy::new(Some(
            "function FindProxyForURL(){return 'PROXY active.test:8080';}".into(),
        ))
        .unwrap();
        policy.mark_unloaded();
        let strict = policy
            .evaluate_strict("http://example.test/".into(), "example.test".into())
            .await
            .unwrap_err();
        assert!(strict.to_string().contains("routing policy is unavailable"));
        assert_eq!(
            policy
                .evaluate("http://example.test/".into(), "example.test".into())
                .await
                .unwrap()
                .to_string(),
            "HTTP active.test:8080"
        );

        assert!(policy.set_script(Some("function {".into())).await.is_err());
        assert!(policy.is_loaded());
        policy
            .set_script(Some("function FindProxyForURL(){return 'DIRECT';}".into()))
            .await
            .unwrap();
        assert!(policy.is_loaded());
        assert_eq!(
            policy
                .evaluate("http://example.test/".into(), "example.test".into())
                .await
                .unwrap()
                .to_string(),
            "DIRECT"
        );

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let closed = Policy {
            tx,
            loaded: Arc::new(AtomicBool::new(false)),
        };
        assert!(
            closed
                .evaluate("http://example.test/".into(), "example.test".into())
                .await
                .unwrap_err()
                .to_string()
                .contains("PAC worker stopped")
        );
    }

    #[tokio::test]
    async fn worker_dns_snapshot_records_numeric_cache_and_script_sets_merge() {
        let policy = Policy::new_scripts(vec![
            "function FindProxyForURL(){dnsResolve('192.0.2.42');return myIpAddress()==='192.0.2.44'?'PROXY active.test:80':'DIRECT';}".into(),
            "function FindProxyForURL(){dnsResolve('192.0.2.43');return 'DIRECT';}".into(),
        ])
        .unwrap();
        policy
            .evaluate("http://example.test/".into(), "example.test".into())
            .await
            .unwrap();
        let snapshot = policy.cache_snapshot().await.unwrap();
        assert_eq!(
            snapshot.get("192.0.2.42"),
            Some(&Some("192.0.2.42".parse().unwrap()))
        );
        assert_eq!(
            snapshot.get("192.0.2.43"),
            Some(&Some("192.0.2.43".parse().unwrap()))
        );
        policy.set_ip("192.0.2.44".parse().unwrap()).await.unwrap();
        assert_eq!(
            policy
                .evaluate("http://example.test/".into(), "example.test".into())
                .await
                .unwrap()
                .to_string(),
            "HTTP active.test:80"
        );
        policy.set_scripts(Vec::new()).await.unwrap();
        assert!(!policy.is_loaded());
        assert!(policy.cache_snapshot().await.unwrap().is_empty());
    }
}
