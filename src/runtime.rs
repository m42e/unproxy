//! Process controller for the reusable proxy server.
use crate::{
    auth::{AuthFactory, CredentialStore},
    config::{self, MainArgs},
    net::{ConnectionOptions, Keepalive},
    pac::Policy,
    proxy::ContextBuilder,
};
use anyhow::{Context, Result, anyhow};
use std::{ffi::OsString, fs, sync::Arc, time::Duration};

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
    let sources: Vec<crate::route::PathOrUri> = if a.pac_file.is_empty() {
        config::pac_path()
            .into_iter()
            .map(crate::route::PathOrUri::Path)
            .collect()
    } else {
        a.pac_file
            .iter()
            .map(|source| source.parse())
            .collect::<Result<_>>()?
    };
    let effective_ip = select_pac_ip(a.my_ip_address, crate::platform::default_interface_ipv4);
    let policy = Arc::new(Policy::new_scripts_with_ip(vec![], effective_ip)?);
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
        .strict_policy(a.strict_policy)
        .header_timeout(a.header_timeout)
        .idle_timeout(a.idle_timeout)
        .exchange_timeout(a.exchange_timeout)
        .max_sessions(a.max_sessions)
        .race_connect(a.race_connect)
        .parallel_connect(a.parallel_connect)
        .force_tunnel(a.proxytunnel)
        .server_keepalive(server_keepalive)
        .shutdown_timeout(Duration::from_secs(a.graceful_shutdown_timeout))
        .pac_sources(sources.clone());
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
    tracing::info!(pac_sources=?sources,"proxy started");

    #[cfg(unix)]
    use tokio::signal::unix::{SignalKind, signal};
    #[cfg(unix)]
    let mut hup = signal(SignalKind::hangup())?;
    #[cfg(unix)]
    let mut direct = signal(SignalKind::user_defined1())?;
    #[cfg(unix)]
    let mut term = signal(SignalKind::terminate())?;
    #[cfg(target_os = "macos")]
    let mut notifications = crate::network_notifications::NotificationAdapter::start()
        .context("starting native network notification adapter")?;
    #[cfg(target_os = "macos")]
    let mut notification_ticks = tokio::time::interval(Duration::from_millis(100));
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut notification_ticks = ();
    #[cfg(target_os = "macos")]
    let mut native_state = crate::network_notifications::TransitionState::new();
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut notifications = ();
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut native_state = crate::network_notifications::TransitionState::new();
    #[cfg(unix)]
    let listener_failed = loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break false,
            _=term.recv()=>break false,
            _=context.shutdown_notified()=>break true,
            _=next_network_tick(&mut notification_ticks)=>{
                pump_network_events(&mut notifications);
            },
            Some(event)=next_network_event(&mut notifications)=>{
                if let Err(error) = handle_network_event(&context, &mut native_state, event).await {
                    tracing::error!(sources=?sources, error=%format!("{error:#}"), "native policy update failed; retaining previous policy");
                }
            },
            _=hup.recv()=>{
                let result = context.reload_pac().await;
                if let Err(error) = result {
                    tracing::error!(sources=?sources, %error, "PAC reload failed; retaining previous policy");
                }
            },
            _=direct.recv()=>{
                if let Err(error) = policy.set_script(None).await {
                    tracing::error!(%error, "direct mode failed; retaining previous policy");
                }
            }
        }
    };
    #[cfg(not(unix))]
    let listener_failed = loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break false,
            _=context.shutdown_notified()=>break true,
        }
    };
    if !drain(context, Duration::from_secs(a.graceful_shutdown_timeout)).await {
        tracing::warn!("graceful shutdown timed out");
    }
    if listener_failed {
        return Err(anyhow!(
            "proxy listener terminated after repeated accept failures"
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn next_network_event(
    adapter: &mut crate::network_notifications::NotificationAdapter,
) -> Option<crate::network_notifications::NetworkEvent> {
    adapter.recv().await
}
#[cfg(all(unix, not(target_os = "macos")))]
async fn next_network_event(_: &mut ()) -> Option<crate::network_notifications::NetworkEvent> {
    std::future::pending().await
}

#[cfg(target_os = "macos")]
async fn next_network_tick(interval: &mut tokio::time::Interval) {
    interval.tick().await;
}
#[cfg(all(unix, not(target_os = "macos")))]
async fn next_network_tick(_: &mut ()) {
    std::future::pending::<()>().await;
}
#[cfg(target_os = "macos")]
fn pump_network_events(adapter: &mut crate::network_notifications::NotificationAdapter) {
    adapter.pump();
}
#[cfg(all(unix, not(target_os = "macos")))]
fn pump_network_events(_: &mut ()) {}

/// Apply a native observation using the same atomic operations as manual controls.
/// A failed restore leaves service running and retries on the next available event.
pub async fn handle_network_event(
    context: &crate::proxy::Context,
    state: &mut crate::network_notifications::TransitionState,
    event: crate::network_notifications::NetworkEvent,
) -> Result<bool> {
    use crate::network_notifications::NetworkEvent;
    let Some(event) = state.observe(event) else {
        return Ok(false);
    };
    let result = match event {
        NetworkEvent::Available => context.reload_pac().await,
        NetworkEvent::Unavailable => context.clear_policy().await,
    };
    state.complete(event, result.is_ok());
    result?;
    Ok(true)
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

/// Detect once at startup; manual and native updates retain this effective address.
fn select_pac_ip(
    override_ip: Option<std::net::IpAddr>,
    detect: impl FnOnce() -> std::net::IpAddr,
) -> std::net::IpAddr {
    override_ip.unwrap_or_else(detect)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_ip_prefers_override_and_detects_only_when_needed() {
        for ip in ["192.0.2.42", "2001:db8::42"] {
            let ip = ip.parse().unwrap();
            assert_eq!(
                select_pac_ip(Some(ip), || panic!("override must avoid detection")),
                ip
            );
        }
        for ip in ["192.0.2.7", "127.0.0.1"] {
            let ip = ip.parse().unwrap();
            assert_eq!(select_pac_ip(None, || ip), ip);
        }
    }
}
