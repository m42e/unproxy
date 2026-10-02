//! Process controller for the reusable proxy server.
use crate::{
    auth::{AuthFactory, CredentialStore},
    config::{self, MainArgs},
    net::{ConnectionOptions, Keepalive},
    pac::Policy,
    proxy::ContextBuilder,
};
use anyhow::{Context, Result, anyhow};
use std::{ffi::OsString, fs, path::Path, sync::Arc, time::Duration};

/// Run the primary proxy process with already parsed settings.
pub async fn run(a: MainArgs) -> Result<()> {
    let filter = std::env::var("UNPROXY_LOG")
        .ok()
        .and_then(|s| tracing_subscriber::EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| {
            tracing_subscriber::EnvFilter::new(
                config::verbosity_level(a.verbose, a.quiet).unwrap_or("off"),
            )
        });
    if let Some(file) = a.logfile.as_ref().and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(p)
            .ok()
    }) {
        tracing_subscriber::fmt()
            .compact()
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_env_filter(filter)
            .with_writer(move || -> Box<dyn std::io::Write + Send> {
                file.try_clone()
                    .map(|f| Box::new(f) as Box<dyn std::io::Write + Send>)
                    .unwrap_or_else(|_| Box::new(std::io::stderr()))
            })
            .try_init()
            .ok();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_env_filter(filter)
            .try_init()
            .ok();
    }
    let discovered = if a.pac_file.is_none() {
        config::pac_path()
    } else {
        None
    };
    if let Some(p) = a.pac_file.as_deref()
        && !p.starts_with("http://")
        && !p.starts_with("https://")
        && !Path::new(p).is_file()
    {
        return Err(anyhow!("PAC file does not exist: {p}"));
    }
    let policy = Arc::new(Policy::new(None)?);
    if let Some(ip) = a.my_ip_address.as_deref() {
        policy.set_ip(ip.parse()?).await?;
    }
    let auth = load_auth(&a)?;
    let options = ConnectionOptions {
        auth,
        keepalive: Keepalive {
            time: a.client_tcp_keepalive_time,
            interval: a.client_tcp_keepalive_interval,
            retries: a.client_tcp_keepalive_retries,
        },
        ..ConnectionOptions::default()
    };
    let server_keepalive = Keepalive {
        time: a.server_tcp_keepalive_time,
        interval: a.server_tcp_keepalive_interval,
        retries: a.server_tcp_keepalive_retries,
    };
    let mut builder = ContextBuilder::new(policy.clone(), options)
        .connect_timeout(a.connect_timeout)
        .direct_fallback(a.direct_fallback)
        .race_connect(a.race_connect)
        .parallel_connect(a.parallel_connect)
        .force_tunnel(a.proxytunnel)
        .server_keepalive(server_keepalive)
        .shutdown_timeout(Duration::from_secs(a.graceful_shutdown_timeout));
    if let Some(name) = a.activate_socket.as_deref() {
        builder = builder.listeners(crate::platform::activated_listeners(name)?)
    } else {
        for addr in a.listen_addrs()? {
            builder = builder.listen(addr)
        }
    }
    let context = builder.bind().await?;
    for addr in context.local_addrs() {
        tracing::info!(%addr,"proxy listening")
    }
    tracing::info!(pac_source=?a.pac_file.as_deref().or_else(||discovered.as_ref().and_then(|p|p.to_str())),"proxy started");

    #[cfg(unix)]
    use tokio::signal::unix::{SignalKind, signal};
    #[cfg(unix)]
    let mut hup = signal(SignalKind::hangup())?;
    #[cfg(unix)]
    let mut direct = signal(SignalKind::user_defined1())?;
    #[cfg(unix)]
    let mut term = signal(SignalKind::terminate())?;
    let mut initial = Box::pin(load_pac(a.pac_file.as_deref(), discovered.as_deref()));
    #[allow(unused_mut)]
    let mut initial_pending = a.pac_file.is_some() || discovered.is_some();
    #[cfg(unix)]
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=term.recv()=>break,
            loaded=&mut initial,if initial_pending=>{initial_pending=false;match loaded{Ok(s)=>if let Err(e)=policy.set_script(s).await{tracing::error!(%e,"PAC load failed; using direct policy")},Err(e)=>tracing::error!(%e,"PAC load failed; using direct policy")}},
            _=hup.recv()=>{match load_pac(a.pac_file.as_deref(),discovered.as_deref()).await{Ok(s)=>if let Err(e)=policy.set_script(s).await{context.shutdown();let _=context.wait_timeout(Duration::from_secs(a.graceful_shutdown_timeout)).await;return Err(e).context("PAC reload failed")},Err(e)=>{context.shutdown();let _=context.wait_timeout(Duration::from_secs(a.graceful_shutdown_timeout)).await;return Err(e).context("PAC reload failed")}};policy.set_ip(crate::platform::default_interface_ipv4()).await?;},
            _=direct.recv()=>{policy.set_script(None).await?;policy.set_ip(crate::platform::default_interface_ipv4()).await?;}
        }
    }
    #[cfg(not(unix))]
    if initial_pending {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>{let _=drain(context,Duration::from_secs(a.graceful_shutdown_timeout)).await;return Ok(())},
            loaded=&mut initial=>{match loaded{Ok(s)=>if let Err(e)=policy.set_script(s).await{tracing::error!(%e,"PAC load failed; using direct policy")},Err(e)=>tracing::error!(%e,"PAC load failed; using direct policy")}}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    if !drain(context, Duration::from_secs(a.graceful_shutdown_timeout)).await {
        tracing::warn!("graceful shutdown timed out");
    }
    Ok(())
}

async fn drain(context: crate::proxy::Context, timeout: Duration) -> bool {
    context.shutdown();
    context.wait_timeout(timeout).await
}

fn load_auth(a: &MainArgs) -> Result<AuthFactory> {
    #[cfg(feature = "negotiate")]
    if !a.negotiate.is_empty() {
        return Ok(AuthFactory::negotiate(
            a.negotiate
                .iter()
                .filter(|h| !h.is_empty())
                .cloned()
                .collect(),
        ));
    }
    let path = a.netrc_file.clone().or_else(config::netrc_default);
    let store = if let Some(p) = path {
        if a.netrc_file.is_some() && !p.is_file() {
            return Err(anyhow!("netrc file does not exist: {}", p.display()));
        }
        match fs::read_to_string(&p) {
            Ok(input) => CredentialStore::parse(&input)
                .with_context(|| format!("parsing {}", p.display()))?,
            Err(_) => CredentialStore::new(),
        }
    } else {
        CredentialStore::new()
    };
    Ok(AuthFactory::basic(store))
}
async fn load_pac(explicit: Option<&str>, discovered: Option<&Path>) -> Result<Option<String>> {
    if let Some(p) = explicit {
        if p.starts_with("http://") || p.starts_with("https://") {
            return Ok(Some(crate::net::fetch_remote_pac(p).await?));
        }
        return Ok(Some(
            fs::read_to_string(p).with_context(|| format!("reading PAC file {p}"))?,
        ));
    }
    if let Some(p) = discovered {
        return Ok(Some(
            fs::read_to_string(p).with_context(|| format!("reading PAC file {}", p.display()))?,
        ));
    }
    Ok(None)
}

/// Callable process entry used by embedded applications. It deliberately skips rc files.
pub fn embedded_entry(args: Vec<OsString>) -> Result<()> {
    let a = match config::try_parse_main_from(args, false) {
        Ok(a) => a,
        Err(e) => {
            let success = matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            e.print()?;
            if success {
                return Ok(());
            }
            return Err(anyhow!("invalid unproxy arguments"));
        }
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(a))
}
