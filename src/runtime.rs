//! Process controller for the reusable proxy server.
use crate::{
    auth::{AuthFactory, CredentialStore},
    config::{self, MainArgs},
    logging::{CapturedWriter, LogStream},
    net::{ConnectionOptions, Keepalive},
    pac::Policy,
    proxy::ContextBuilder,
};
use anyhow::{Context, Result, anyhow};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

const LOG_FILE_MAX_BYTES: u64 = 10 * 1024 * 1024;
const LOG_FILE_BACKUPS: usize = 3;

#[derive(Clone)]
struct RotatingLog {
    state: Arc<Mutex<RotatingLogState>>,
}

struct RotatingLogState {
    path: PathBuf,
    file: Option<fs::File>,
    size: u64,
    max_bytes: u64,
    backups: usize,
}

struct RotatingLogGuard<'a>(MutexGuard<'a, RotatingLogState>);

impl RotatingLog {
    fn open(path: &Path, max_bytes: u64, backups: usize) -> io::Result<Self> {
        assert!(max_bytes > 0, "log size limit must be nonzero");
        for index in 1..=backups {
            trim_path_to_limit(&backup_path(path, index), max_bytes)?;
        }
        trim_path_to_limit(path, max_bytes)?;
        let file = open_log_file(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            state: Arc::new(Mutex::new(RotatingLogState {
                path: path.to_owned(),
                file: Some(file),
                size,
                max_bytes,
                backups,
            })),
        })
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for RotatingLog {
    type Writer = RotatingLogGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingLogGuard(self.state.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

impl Write for RotatingLogGuard<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let written = bytes.len();
        while !bytes.is_empty() {
            if self.0.size >= self.0.max_bytes && self.0.rotate().is_err() {
                self.0.compact()?;
            }
            let available = (self.0.max_bytes - self.0.size) as usize;
            let count = bytes.len().min(available);
            let written_now = self
                .0
                .file
                .as_mut()
                .expect("rotating log file is open")
                .write(&bytes[..count])?;
            if written_now == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            self.0.size += written_now as u64;
            bytes = &bytes[written_now..];
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .file
            .as_mut()
            .expect("rotating log file is open")
            .flush()
    }
}

impl RotatingLogState {
    fn rotate(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        drop(self.file.take());

        let rotation = rotate_paths(&self.path, self.backups);
        let reopened = open_log_file(&self.path);
        match reopened {
            Ok(file) => {
                let size = file.metadata().map(|metadata| metadata.len());
                self.file = Some(file);
                self.size = size?;
                rotation
            }
            Err(error) => Err(error),
        }
    }

    fn compact(&mut self) -> io::Result<()> {
        drop(self.file.take());
        let compacted = (|| {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)?;
            trim_open_file_to_limit(&mut file, self.max_bytes / 2)?;
            file.metadata().map(|metadata| metadata.len())
        })();
        self.file = Some(open_log_file(&self.path)?);
        self.size = self
            .file
            .as_ref()
            .expect("rotating log file is open")
            .metadata()?
            .len();
        compacted?;
        Ok(())
    }
}

fn open_log_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
}

fn backup_path(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn trim_path_to_limit(path: &Path, max_bytes: u64) -> io::Result<()> {
    let mut file = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    trim_open_file_to_limit(&mut file, max_bytes)
}

fn trim_open_file_to_limit(file: &mut fs::File, max_bytes: u64) -> io::Result<()> {
    let size = file.metadata()?.len();
    if size <= max_bytes {
        return Ok(());
    }
    file.seek(SeekFrom::Start(size - max_bytes))?;
    let mut tail = Vec::with_capacity(max_bytes as usize);
    file.read_to_end(&mut tail)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail)?;
    file.flush()
}

fn rotate_paths(path: &Path, backups: usize) -> io::Result<()> {
    if backups == 0 {
        let _file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        return Ok(());
    }
    remove_if_exists(&backup_path(path, backups))?;
    for index in (1..backups).rev() {
        let source = backup_path(path, index);
        if source.exists() {
            let destination = backup_path(path, index + 1);
            remove_if_exists(&destination)?;
            fs::rename(source, destination)?;
        }
    }
    if path.exists() {
        let first_backup = backup_path(path, 1);
        remove_if_exists(&first_backup)?;
        fs::rename(path, first_backup)?;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Run the primary proxy process with already parsed settings.
pub async fn run(a: MainArgs) -> Result<()> {
    run_until(a, std::future::pending(), || {}).await
}

#[cfg(windows)]
pub async fn run_windows_service(
    a: MainArgs,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    run_until(
        a,
        async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        },
        move || {
            let _ = ready.send(());
        },
    )
    .await
}

async fn run_until(
    a: MainArgs,
    shutdown: impl std::future::Future<Output = ()>,
    on_ready: impl FnOnce(),
) -> Result<()> {
    let log_stream = LogStream::new();
    let filter = std::env::var("UNPROXY_LOG")
        .ok()
        .and_then(|s| tracing_subscriber::EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| {
            tracing_subscriber::EnvFilter::new(
                config::verbosity_level(a.verbose, a.quiet).unwrap_or("off"),
            )
        });
    if let Some(log) = a
        .logfile
        .as_ref()
        .and_then(|path| RotatingLog::open(path, LOG_FILE_MAX_BYTES, LOG_FILE_BACKUPS).ok())
    {
        tracing_subscriber::fmt()
            .compact()
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_env_filter(filter)
            .with_writer(CapturedWriter::new(log, log_stream.clone()))
            .try_init()
            .ok();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_env_filter(filter)
            .with_writer(CapturedWriter::new(std::io::stderr, log_stream.clone()))
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
    let (filter_list, filter_lists_complete) =
        crate::filter_list::FilterList::load_best_effort_with_status(&a.filter_list).await;
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
    #[cfg(unix)]
    use tokio::signal::unix::{SignalKind, signal};
    #[cfg(unix)]
    let mut hup = signal(SignalKind::hangup())?;
    #[cfg(unix)]
    let mut direct = signal(SignalKind::user_defined1())?;
    #[cfg(unix)]
    let mut term = signal(SignalKind::terminate())?;
    let mut builder = ContextBuilder::new(policy.clone(), options)
        .log_stream(log_stream)
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
    builder = builder.filter_list(filter_list);
    if let Some(name) = a.activate_socket.as_deref() {
        builder = builder.listeners(crate::platform::activated_listeners(name)?)
    } else {
        for addr in a.listen_addrs()? {
            builder = builder.listen(addr)
        }
    }
    let context = builder.bind().await?;
    if !filter_lists_complete {
        context.retry_filter_lists_after(a.filter_list.clone(), Duration::from_secs(5));
    }
    on_ready();
    for addr in context.local_addrs() {
        tracing::info!(%addr,"proxy listening")
    }
    tracing::info!(pac_sources=?sources,"proxy started");

    #[cfg(target_os = "macos")]
    let mut notifications = crate::network_notifications::NotificationAdapter::start()
        .context("starting native network notification adapter")?;
    #[cfg(target_os = "macos")]
    let mut notification_ticks = tokio::time::interval(Duration::from_millis(100));
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut notification_ticks = ();
    let mut native_state = crate::network_notifications::TransitionState::new();
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut notifications = ();
    let mut observed_network_ip = if a.reload_pac_on_network_change {
        Some(crate::platform::default_interface_ipv4())
    } else {
        None
    };
    let mut pending_network_change: Option<(std::net::IpAddr, tokio::time::Instant)> = None;
    let mut network_poll = tokio::time::interval(Duration::from_millis(250));
    network_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    #[cfg(unix)]
    let listener_failed = {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _= &mut shutdown => break false,
                _=tokio::signal::ctrl_c()=>break false,
                _=term.recv()=>break false,
                _=context.shutdown_notified()=>break true,
                _=next_network_tick(&mut notification_ticks)=>{
                    pump_network_events(&mut notifications);
                },
                _=network_poll.tick(), if a.reload_pac_on_network_change => {
                    poll_network_change(
                        &context,
                        &mut native_state,
                        &mut observed_network_ip,
                        &mut pending_network_change,
                    ).await;
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
        }
    };
    #[cfg(not(unix))]
    let listener_failed = {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break false,
                _ = tokio::signal::ctrl_c() => break false,
                _ = context.shutdown_notified() => break true,
                _ = network_poll.tick(), if a.reload_pac_on_network_change => {
                    poll_network_change(
                        &context,
                        &mut native_state,
                        &mut observed_network_ip,
                        &mut pending_network_change,
                    ).await;
                },
            }
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
        NetworkEvent::Changed => context.reload_pac().await,
    };
    state.complete(event, result.is_ok());
    result?;
    Ok(true)
}

async fn poll_network_change(
    context: &crate::proxy::Context,
    state: &mut crate::network_notifications::TransitionState,
    observed: &mut Option<std::net::IpAddr>,
    pending: &mut Option<(std::net::IpAddr, tokio::time::Instant)>,
) {
    let current = crate::platform::default_interface_ipv4();
    if observed.is_some_and(|previous| previous != current) {
        *pending = Some((current, tokio::time::Instant::now()));
    }
    *observed = Some(current);

    // Wait for the observed address to settle before fetching, coalescing the
    // several interface/address updates produced by a network handoff.
    if let Some((address, since)) = *pending
        && address == current
        && since.elapsed() >= Duration::from_secs(1)
    {
        *pending = None;
        if let Err(error) = handle_network_event(
            context,
            state,
            crate::network_notifications::NetworkEvent::Changed,
        )
        .await
        {
            tracing::error!(%error, "PAC reload after network change failed; retaining previous policy");
        }
    }
}

async fn drain(context: crate::proxy::Context, timeout: Duration) -> bool {
    context.shutdown();
    context.wait_timeout(timeout).await
}

fn load_auth(a: &MainArgs) -> Result<AuthFactory> {
    load_auth_with_default_netrc(a, config::netrc_default())
}

fn load_auth_with_default_netrc(
    a: &MainArgs,
    default_netrc: Option<std::path::PathBuf>,
) -> Result<AuthFactory> {
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
    let path = a.netrc_file.clone().or(default_netrc);
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
    use clap::Parser;
    use tracing_subscriber::fmt::writer::MakeWriter;

    #[test]
    fn captured_log_lines_are_written_to_file_and_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        let stream = LogStream::new();
        let writer = CapturedWriter::new(RotatingLog::open(&path, 128, 2).unwrap(), stream.clone());
        writer
            .make_writer()
            .write_all(b"INFO startup\nWARN request failed\n")
            .unwrap();

        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "INFO startup\nWARN request failed\n"
        );
        let (history, _) = stream.subscribe_with_history();
        assert_eq!(history, ["INFO startup", "WARN request failed"]);
    }

    #[test]
    fn logfile_appends_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        {
            let log = RotatingLog::open(&path, 32, 2).unwrap();
            log.make_writer().write_all(b"first session\n").unwrap();
        }
        {
            let log = RotatingLog::open(&path, 32, 2).unwrap();
            log.make_writer().write_all(b"second session\n").unwrap();
        }
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "first session\nsecond session\n"
        );
    }

    #[test]
    fn logfile_rotation_bounds_active_and_backup_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        let log = RotatingLog::open(&path, 8, 2).unwrap();
        for chunk in [b"12345678", b"ABCDEFGH", b"abcdefgh", b"ijklmnop"] {
            log.make_writer().write_all(chunk).unwrap();
        }

        assert_eq!(fs::read(&path).unwrap(), b"ijklmnop");
        assert_eq!(fs::read(backup_path(&path, 1)).unwrap(), b"abcdefgh");
        assert_eq!(fs::read(backup_path(&path, 2)).unwrap(), b"ABCDEFGH");
        assert!(!backup_path(&path, 3).exists());
        for log_path in [&path, &backup_path(&path, 1), &backup_path(&path, 2)] {
            assert!(fs::metadata(log_path).unwrap().len() <= 8);
        }
    }

    #[test]
    fn logfile_open_trims_oversized_active_and_backup_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        fs::write(&path, b"abcdefghij").unwrap();
        fs::write(backup_path(&path, 1), b"0123456789").unwrap();

        let _log = RotatingLog::open(&path, 4, 1).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"ghij");
        assert_eq!(fs::read(backup_path(&path, 1)).unwrap(), b"6789");
    }

    #[test]
    fn logfile_without_backups_restarts_the_active_file_at_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        let log = RotatingLog::open(&path, 4, 0).unwrap();

        log.make_writer().write_all(b"abcdefghij").unwrap();

        assert_eq!(fs::read(path).unwrap(), b"ij");
    }

    #[test]
    fn logfile_compacts_when_rotation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unproxy.log");
        let log = RotatingLog::open(&path, 8, 1).unwrap();
        fs::create_dir(backup_path(&path, 1)).unwrap();

        log.make_writer().write_all(b"12345678ABCDEFGH").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"ABCDEFGH");
        assert!(backup_path(&path, 1).is_dir());
    }

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

    #[tokio::test]
    async fn server_binds_before_ready_and_drains_after_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        let args = MainArgs::try_parse_from([
            "unproxy",
            "--listen",
            "127.0.0.1:0",
            "--pac-file",
            pac.to_str().unwrap(),
            "--graceful-shutdown-timeout",
            "1",
        ])
        .unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        run_until(
            args,
            async move {
                let _ = shutdown_rx.await;
            },
            move || {
                ready_tx.send(()).unwrap();
                shutdown_tx.send(()).unwrap();
            },
        )
        .await
        .unwrap();
        ready_rx.await.unwrap();
    }

    #[tokio::test]
    async fn explicit_netrc_credentials_build_a_basic_authorization_header() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("netrc");
        fs::write(
            &path,
            "machine proxy.example login test-user password test-pass",
        )
        .unwrap();
        let args =
            MainArgs::try_parse_from(["unproxy", "--netrc-file", path.to_str().unwrap()]).unwrap();

        let auth = load_auth(&args).unwrap();
        let header = auth.authorization("proxy.example").await.unwrap().unwrap();
        assert_eq!(header, "Basic dGVzdC11c2VyOnRlc3QtcGFzcw==");
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn negotiate_startup_filters_global_empty_host_and_keeps_restrictions() {
        let args =
            MainArgs::try_parse_from(["unproxy", "--negotiate", "--negotiate", "proxy.corp.test"])
                .unwrap();
        let auth = load_auth(&args).unwrap();
        let debug = format!("{auth:?}");
        assert!(debug.contains("proxy.corp.test"));
        assert!(!debug.contains("\"\","));
    }

    #[tokio::test]
    async fn native_network_events_clear_reload_and_retry_policy_transactionally() {
        use crate::{
            network_notifications::{NetworkEvent, TransitionState},
            route::PathOrUri,
        };
        use futures_util::stream;
        use std::{net::SocketAddr, sync::Arc};

        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        let policy = Arc::new(crate::pac::Policy::new(None).unwrap());
        let input = stream::empty::<std::io::Result<(tokio::io::DuplexStream, SocketAddr)>>();
        let context =
            crate::proxy::ContextBuilder::new(policy, crate::net::ConnectionOptions::default())
                .pac_source(PathOrUri::Path(pac.clone()))
                .serve_connections(input)
                .await
                .unwrap();
        let mut state = TransitionState::default();
        assert!(
            !handle_network_event(&context, &mut state, NetworkEvent::Available)
                .await
                .unwrap()
        );
        assert!(
            handle_network_event(&context, &mut state, NetworkEvent::Unavailable)
                .await
                .unwrap()
        );
        assert!(!context.policy().is_loaded());
        assert!(
            !handle_network_event(&context, &mut state, NetworkEvent::Unavailable)
                .await
                .unwrap()
        );

        fs::write(
            &pac,
            "function FindProxyForURL(){return 'PROXY restored.test:8080';}",
        )
        .unwrap();
        assert!(
            handle_network_event(&context, &mut state, NetworkEvent::Available)
                .await
                .unwrap()
        );
        assert!(context.policy().is_loaded());

        assert!(
            handle_network_event(&context, &mut state, NetworkEvent::Unavailable)
                .await
                .unwrap()
        );
        fs::write(&pac, "function {").unwrap();
        for _ in 0..2 {
            let error = handle_network_event(&context, &mut state, NetworkEvent::Available)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("PAC"));
            assert!(!context.policy().is_loaded());
        }
        fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        assert!(
            handle_network_event(&context, &mut state, NetworkEvent::Available)
                .await
                .unwrap()
        );
        assert!(context.policy().is_loaded());
        assert!(state.is_available());
        context.shutdown();
        assert!(context.wait_timeout(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn network_address_changes_are_coalesced_before_reloading_pac() {
        use crate::{net::ConnectionOptions, route::PathOrUri};
        use futures_util::stream;
        use std::{net::SocketAddr, sync::Arc};

        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        let policy = Arc::new(crate::pac::Policy::new(None).unwrap());
        let input = stream::empty::<std::io::Result<(tokio::io::DuplexStream, SocketAddr)>>();
        let context =
            crate::proxy::ContextBuilder::new(policy.clone(), ConnectionOptions::default())
                .pac_source(PathOrUri::Path(pac.clone()))
                .serve_connections(input)
                .await
                .unwrap();
        let current = crate::platform::default_interface_ipv4();
        let other = match current {
            std::net::IpAddr::V4(ip) if ip == std::net::Ipv4Addr::LOCALHOST => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            }
            _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        let mut observed = Some(other);
        let mut pending = None;
        let mut state = crate::network_notifications::TransitionState::new();

        poll_network_change(&context, &mut state, &mut observed, &mut pending).await;
        assert_eq!(observed, Some(current));
        assert_eq!(pending.map(|(address, _)| address), Some(current));

        pending = Some((
            current,
            tokio::time::Instant::now() - Duration::from_secs(2),
        ));
        poll_network_change(&context, &mut state, &mut observed, &mut pending).await;
        assert!(pending.is_none());
        assert!(policy.is_loaded());

        fs::write(&pac, "function {").unwrap();
        pending = Some((
            current,
            tokio::time::Instant::now() - Duration::from_secs(2),
        ));
        poll_network_change(&context, &mut state, &mut observed, &mut pending).await;
        assert!(pending.is_none());
        assert!(policy.is_loaded());

        context.shutdown();
        assert!(context.wait_timeout(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn logfile_receives_runtime_startup_messages() {
        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        let logfile = dir.path().join("unproxy.log");
        fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        let args = MainArgs::try_parse_from([
            "unproxy",
            "--listen",
            "127.0.0.1:0",
            "--pac-file",
            pac.to_str().unwrap(),
            "--logfile",
            logfile.to_str().unwrap(),
        ])
        .unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        run_until(
            args,
            async move {
                let _ = shutdown_rx.await;
            },
            move || {
                ready_tx.send(()).unwrap();
                shutdown_tx.send(()).unwrap();
            },
        )
        .await
        .unwrap();
        ready_rx.await.unwrap();
        let log = fs::read_to_string(logfile).unwrap();
        assert!(log.contains("proxy listening"));
        assert!(log.contains("proxy started"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_service_signals_ready_and_drains_on_shutdown() {
        let args = MainArgs::try_parse_from(["unproxy", "--listen", "127.0.0.1:0"]).unwrap();
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let (ready, started) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(run_windows_service(args, receiver, ready));

        tokio::time::timeout(Duration::from_secs(5), started)
            .await
            .expect("service did not report readiness")
            .expect("service dropped its readiness signal");
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("service did not stop after the shutdown signal")
            .expect("service task panicked")
            .unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_service_stops_when_shutdown_sender_is_dropped() {
        let args = MainArgs::try_parse_from(["unproxy", "--listen", "127.0.0.1:0"]).unwrap();
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let (ready, started) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(run_windows_service(args, receiver, ready));

        tokio::time::timeout(Duration::from_secs(5), started)
            .await
            .expect("service did not report readiness")
            .expect("service dropped its readiness signal");
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("service did not stop after its shutdown sender was dropped")
            .expect("service task panicked")
            .unwrap();
    }

    #[test]
    fn explicit_netrc_path_errors_for_missing_and_malformed_files() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.netrc");
        let args = MainArgs::try_parse_from(["unproxy", "--netrc-file", missing.to_str().unwrap()])
            .unwrap();
        assert!(
            load_auth(&args)
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );

        let malformed = temp.path().join("malformed.netrc");
        fs::write(&malformed, "machine proxy.example unsupported value").unwrap();
        let args =
            MainArgs::try_parse_from(["unproxy", "--netrc-file", malformed.to_str().unwrap()])
                .unwrap();
        assert!(load_auth(&args).is_err());
    }

    #[test]
    fn missing_default_netrc_uses_unconfigured_authentication() {
        let args = MainArgs::try_parse_from(["unproxy"]).unwrap();
        let auth = load_auth_with_default_netrc(&args, None).unwrap();
        assert!(!auth.is_configured());
    }

    #[test]
    fn embedded_entry_handles_help_version_and_invalid_arguments_without_running() {
        assert!(embedded_entry(vec!["unproxy".into(), "--help".into()]).is_ok());
        assert!(embedded_entry(vec!["unproxy".into(), "--version".into()]).is_ok());
        assert!(embedded_entry(vec!["unproxy".into(), "--unknown-option".into()]).is_err());
    }
}
