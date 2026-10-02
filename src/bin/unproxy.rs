use anyhow::{Context, Result, anyhow};
use unproxy::{
    auth::{AuthFactory, CredentialStore},
    config,
    net::{ConnectionOptions, Keepalive},
    pac::Policy,
    proxy::ContextBuilder,
};
use std::{fs, sync::Arc, time::Duration};
#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(windows)]
    {
        let early = std::env::args_os().any(|x| x == "--attach-console");
        if early {
            unproxy::platform::attach_console()?
        }
    }
    let a = config::parse_main()?;
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
            .with_env_filter(filter)
            .with_writer(move || file.try_clone().unwrap_or_else(|_| std::io::stderr()))
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let source = if let Some(p) = a.pac_file.as_deref() {
        if p.starts_with("http://") || p.starts_with("https://") {
            Some(unproxy::net::fetch_remote_pac(p).await?)
        } else {
            Some(fs::read_to_string(p).with_context(|| format!("reading PAC file {p}"))?)
        }
    } else {
        config::pac_path().and_then(|p| fs::read_to_string(p).ok())
    };
    let policy = Arc::new(Policy::new(source)?);
    #[allow(unused_mut)]
    let mut auth = AuthFactory::default();
    #[cfg(feature = "negotiate")]
    if !a.negotiate.is_empty() {
        auth = AuthFactory::negotiate(a.negotiate.clone())
    } else {
        let path = a.netrc_file.clone().or_else(config::netrc_default);
        let store = if let Some(p) = path {
            if p.exists() {
                CredentialStore::from_netrc(&p)
                    .with_context(|| format!("parsing {}", p.display()))?
            } else if a.netrc_file.is_some() {
                return Err(anyhow!("netrc file does not exist: {}", p.display()));
            } else {
                CredentialStore::new()
            }
        } else {
            CredentialStore::new()
        };
        auth = AuthFactory::basic(store)
    }
    #[cfg(not(feature = "negotiate"))]
    {
        let path = a.netrc_file.clone().or_else(config::netrc_default);
        let store = if let Some(p) = path {
            if p.exists() {
                CredentialStore::from_netrc(&p)?
            } else if a.netrc_file.is_some() {
                return Err(anyhow!("netrc file does not exist: {}", p.display()));
            } else {
                CredentialStore::new()
            }
        } else {
            CredentialStore::new()
        };
        auth = AuthFactory::basic(store)
    }
    let mut options = ConnectionOptions::default();
    options.auth = auth;
    options.keepalive = Keepalive {
        time: a.client_tcp_keepalive_time,
        interval: a.client_tcp_keepalive_interval,
        retries: a.client_tcp_keepalive_retries,
    };
    let server_keepalive = Keepalive {
        time: a.server_tcp_keepalive_time,
        interval: a.server_tcp_keepalive_interval,
        retries: a.server_tcp_keepalive_retries,
    };
    let mut builder = ContextBuilder::new(policy, options)
        .connect_timeout(a.connect_timeout)
        .direct_fallback(a.direct_fallback)
        .race_connect(a.race_connect)
        .parallel_connect(a.parallel_connect)
        .force_tunnel(a.proxytunnel)
        .server_keepalive(server_keepalive);
    if let Some(name) = a.activate_socket.as_deref() {
        builder = builder.listeners(unproxy::platform::activated_listeners(name)?)
    } else {
        for addr in a.listen_addrs()? {
            builder = builder.listen(addr)
        }
    }
    let context = builder.bind().await?;
    for addr in context.local_addrs() {
        tracing::info!(%addr,"proxy listening")
    }
    tokio::signal::ctrl_c().await?;
    context.shutdown();
    let _ = context
        .wait_timeout(Duration::from_secs(a.graceful_shutdown_timeout))
        .await;
    Ok(())
}
