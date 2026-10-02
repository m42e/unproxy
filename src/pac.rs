use anyhow::{anyhow, bail, Context as _, Result};
use boa_engine::{Context, JsValue, Source, NativeFunction, JsString};
use crate::route::Routes;
use std::{collections::HashMap, net::{IpAddr, ToSocketAddrs}, sync::{Arc,Mutex,mpsc}, time::{Duration,Instant}};
use tokio::sync::oneshot;

const DEFAULT_SCRIPT: &str = "function FindProxyForURL(url, host) { return 'DIRECT'; }";

#[derive(Clone,Debug)] struct CacheEntry { value: Option<IpAddr>, at: Instant }
pub struct Pac { context: Context, ip: IpAddr, source: Option<String>, cache: Arc<Mutex<HashMap<String,CacheEntry>>>, last_prune: Instant }
impl Pac {
    pub fn new(source:Option<&str>)->Result<Self>{
        let mut pac=Self{context:Context::default(),ip:"127.0.0.1".parse().unwrap(),source:None,cache:Arc::new(Mutex::new(HashMap::new())),last_prune:Instant::now()};
        pac.set_script(source)?; Ok(pac)
    }
    pub fn set_script(&mut self,source:Option<&str>)->Result<()> {
        self.context=Context::default(); self.cache.lock().unwrap().clear(); self.last_prune=Instant::now();
        let dns_cache=self.cache.clone();
        let dns=unsafe { NativeFunction::from_closure(move |_this,args,ctx| {
            let Some(arg)=args.first() else {return Err(boa_engine::JsNativeError::typ().with_message("dnsResolve requires a hostname").into())};
            let host=arg.to_string(ctx)?.to_std_string_escaped(); let now=Instant::now(); let value={let mut c=dns_cache.lock().unwrap(); c.retain(|_,v|now.duration_since(v.at)<Duration::from_secs(300)); if let Some(v)=c.get(&host){v.value}else{let ip=(host.as_str(),0).to_socket_addrs().ok().and_then(|mut i|i.next().map(|s|s.ip()));c.insert(host,CacheEntry{value:ip,at:now});ip}};
            Ok(value.map(|v|JsValue::from(v.to_string())).unwrap_or(JsValue::null()))
        })};
        self.context.register_global_builtin_callable(JsString::from("dnsResolve"),1,dns).map_err(|e|anyhow!("register dnsResolve: {e}"))?;
        let ip=self.ip.to_string();
        let ipfn=unsafe { NativeFunction::from_closure(move |_,_,_|Ok(JsValue::from(ip.clone()))) };
        self.context.register_global_builtin_callable(JsString::from("myIpAddress"),0,ipfn).map_err(|e|anyhow!("register myIpAddress: {e}"))?;
        self.context.register_global_callable(JsString::from("_DnsCache"),0,NativeFunction::from_copy_closure(|_,_,_|Ok(JsValue::undefined()))).map_err(|e|anyhow!("register _DnsCache: {e}"))?;
        self.context.register_global_builtin_callable(JsString::from("alert"),1,NativeFunction::from_copy_closure(|_,args,ctx|{if let Some(v)=args.first(){if v.is_string(){println!("{}",v.as_string().unwrap().to_std_string_escaped());}else{println!();}}else{println!();}let _=ctx;Ok(JsValue::undefined())})).map_err(|e|anyhow!("register alert: {e}"))?;
        self.context.eval(Source::from_bytes(include_str!("pac_helpers.js"))).map_err(|e|anyhow!("PAC helper initialization: {e}"))?;
        let script=source.unwrap_or(DEFAULT_SCRIPT);
        self.context.eval(Source::from_bytes(script)).map_err(|e|anyhow!("PAC script: {e}"))?;
        self.context.eval(Source::from_bytes("if (typeof _dnsCache === 'undefined') var _dnsCache = new _DnsCache();")).map_err(|e|anyhow!("PAC cache initialization: {e}"))?;
        self.source=source.map(str::to_owned);
        Ok(())
    }
    pub fn set_ip(&mut self,ip:IpAddr){self.ip=ip; let src=self.source.clone(); let _=self.set_script(src.as_deref());}
    pub fn evaluate(&mut self,url:&str,host:&str)->Result<Routes>{
        if self.last_prune.elapsed()>=Duration::from_secs(300){self.cache.lock().unwrap().retain(|_,v|v.at.elapsed()<Duration::from_secs(300));self.last_prune=Instant::now();}
        let val=self.context.eval(Source::from_bytes(format!("FindProxyForURL({}, {})",serde_json::to_string(url)?,serde_json::to_string(host)?).as_str())).map_err(|e|anyhow!("PAC evaluation: {e}"))?;
        if !val.is_string(){bail!("FindProxyForURL returned a non-string value")}
        val.as_string().unwrap().to_std_string_escaped().parse()
    }
    pub fn cache_snapshot(&self)->HashMap<String,Option<IpAddr>> { self.cache.lock().unwrap().iter().map(|(k,v)|(k.clone(),v.value)).collect() }
}

enum Job { Eval(String,String,oneshot::Sender<Result<Routes>>), Script(Option<String>,oneshot::Sender<Result<()>>), Ip(IpAddr,oneshot::Sender<()>), Snapshot(oneshot::Sender<HashMap<String,Option<IpAddr>>>) }
#[derive(Clone)] pub struct Policy { tx:mpsc::Sender<Job> }
impl Policy {
    pub fn new(source:Option<String>)->Result<Self>{ let (tx,rx)=mpsc::channel(); let (ready_tx,ready_rx)=std::sync::mpsc::sync_channel(1); std::thread::Builder::new().name("pac-policy".into()).spawn(move||{let mut pac=Pac::new(source.as_deref()); let _=ready_tx.send(pac.as_ref().map(|_|()).map_err(|e|e.to_string())); let Ok(mut pac)=pac.take() else{return}; for job in rx {match job {Job::Eval(u,h,r)=>{let _=r.send(pac.evaluate(&u,&h));},Job::Script(s,r)=>{let _=r.send(pac.set_script(s.as_deref()));},Job::Ip(ip,r)=>{pac.set_ip(ip);let _=r.send(());},Job::Snapshot(r)=>{let _=r.send(pac.cache_snapshot());}}}}).context("start PAC worker")?; ready_rx.recv().map_err(|_|anyhow!("PAC worker failed to start"))?.map_err(|e|anyhow!(e))?; Ok(Self{tx}) }
    pub async fn evaluate(&self,url:String,host:String)->Result<Routes>{let(tx,rx)=oneshot::channel();self.tx.send(Job::Eval(url,host,tx)).map_err(|_|anyhow!("PAC worker stopped"))?;rx.await.context("PAC worker stopped")?}
    pub async fn set_script(&self,script:Option<String>)->Result<()>{let(tx,rx)=oneshot::channel();self.tx.send(Job::Script(script,tx)).map_err(|_|anyhow!("PAC worker stopped"))?;rx.await.context("PAC worker stopped")?}
    pub async fn set_ip(&self,ip:IpAddr)->Result<()>{let(tx,rx)=oneshot::channel();self.tx.send(Job::Ip(ip,tx)).map_err(|_|anyhow!("PAC worker stopped"))?;rx.await.context("PAC worker stopped")?;Ok(())}
    pub async fn cache_snapshot(&self)->Result<HashMap<String,Option<IpAddr>>>{let(tx,rx)=oneshot::channel();self.tx.send(Job::Snapshot(tx)).map_err(|_|anyhow!("PAC worker stopped"))?;rx.await.context("PAC worker stopped")}
}
