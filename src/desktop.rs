//! Native macOS menu-bar adapter and its platform-independent preference model.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub const APP_BUNDLE_ID: &str = "de.m42e.unproxy.app";
pub const HELPER_BUNDLE_ID: &str = "de.m42e.unproxy.login-helper";
pub const HELPER_TERMINATE_NOTIFICATION: &str = "de.m42e.unproxy.login-helper.terminate";
pub const INTERNAL_AVAILABLE_NOTIFICATION: &str =
    "com.apple.KerberosPlugin.InternalNetworkAvailable";
pub const INTERNAL_UNAVAILABLE_NOTIFICATION: &str =
    "com.apple.KerberosPlugin.InternalNetworkNotAvailable";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Preferences {
    pub port: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<String>>,
    pub pac_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pac_files: Option<Vec<PathBuf>>,
    pub negotiate: bool,
    pub proxytunnel: bool,
    pub direct_fallback: bool,
    pub autostart: bool,
}

/// Optional first-run preferences embedded in a company-specific build.
///
/// The build tool serializes this structure into the binaries and package
/// metadata. Relative PAC paths are resolved under the user's support folder.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DesktopDefaults {
    pub port: Option<u32>,
    pub pac_file: Option<PathBuf>,
    pub negotiate: Option<bool>,
    pub proxytunnel: Option<bool>,
    pub direct_fallback: Option<bool>,
    pub autostart: Option<bool>,
}

impl DesktopDefaults {
    fn apply(&self, preferences: &mut Preferences) {
        if let Some(port) = self.port {
            preferences.port = port;
        }
        if let Some(pac_file) = &self.pac_file {
            preferences.pac_file = if pac_file.is_absolute() {
                pac_file.clone()
            } else {
                support_dir().join(pac_file)
            };
        }
        if let Some(negotiate) = self.negotiate {
            preferences.negotiate = negotiate;
        }
        if let Some(proxytunnel) = self.proxytunnel {
            preferences.proxytunnel = proxytunnel;
        }
        if let Some(direct_fallback) = self.direct_fallback {
            preferences.direct_fallback = direct_fallback;
        }
        if let Some(autostart) = self.autostart {
            preferences.autostart = autostart;
        }
    }
}

fn apply_desktop_defaults_json(preferences: &mut Preferences, json: Option<&str>) {
    if let Some(defaults) = json.and_then(|json| serde_json::from_str::<DesktopDefaults>(json).ok())
    {
        defaults.apply(preferences);
    }
}

impl Default for Preferences {
    fn default() -> Self {
        let mut preferences = Self {
            port: 3128,
            listeners: None,
            pac_file: default_pac_path(),
            pac_files: None,
            negotiate: false,
            proxytunnel: false,
            direct_fallback: false,
            autostart: true,
        };
        apply_desktop_defaults_json(
            &mut preferences,
            option_env!("UNPROXY_DESKTOP_DEFAULTS_JSON"),
        );
        preferences
    }
}
pub fn support_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Application Support/Unproxy")
    }
    #[cfg(windows)]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Unproxy")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Unproxy")
    }
}
pub fn default_pac_path() -> PathBuf {
    support_dir().join("proxy.pac")
}

fn parse_remote_pac_uri(source: &str) -> Result<Option<http::Uri>> {
    let source = source.trim();
    let Some((scheme, remainder)) = source.split_once("://") else {
        return Ok(None);
    };
    let scheme = if scheme.eq_ignore_ascii_case("http") {
        "http"
    } else if scheme.eq_ignore_ascii_case("https") {
        "https"
    } else {
        return Ok(None);
    };
    let normalized = format!("{scheme}://{remainder}");
    let uri = normalized
        .parse::<http::Uri>()
        .with_context(|| format!("invalid PAC URL {source:?}"))?;
    anyhow::ensure!(uri.host().is_some(), "PAC URL must include a host");
    anyhow::ensure!(
        !uri.authority()
            .is_some_and(|authority| authority.as_str().contains('@')),
        "PAC URL must not include embedded credentials"
    );
    Ok(Some(uri))
}

#[cfg(any(target_os = "macos", test))]
fn resolve_pac_source(path: PathBuf) -> Result<PathBuf> {
    let source = path.to_string_lossy();
    if let Some(uri) = parse_remote_pac_uri(&source)? {
        return Ok(PathBuf::from(uri.to_string()));
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePaths {
    pub child: PathBuf,
    pub login_helper: PathBuf,
}
impl BundlePaths {
    pub fn from_main_executable(executable: &Path) -> Result<Self> {
        let contents = executable
            .parent()
            .and_then(Path::parent)
            .context("main executable must be in Contents/MacOS")?;
        Ok(Self {
            child: contents.join("MacOS/unproxy"),
            login_helper: contents.join(
                "Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper",
            ),
        })
    }
}
impl Preferences {
    fn legacy_port(&self) -> u16 {
        if (1024..=65534).contains(&self.port) {
            self.port as u16
        } else {
            3128
        }
    }
    pub fn effective_port(&self) -> u16 {
        self.listeners
            .as_ref()
            .and_then(|listeners| listeners.first())
            .and_then(|listener| listener.parse::<std::net::SocketAddr>().ok())
            .map(|listener| listener.port())
            .filter(|port| (1024..=65534).contains(port))
            .unwrap_or_else(|| self.legacy_port())
    }
    pub fn effective_listeners(&self) -> Vec<String> {
        if let Some(listeners) = self
            .listeners
            .as_ref()
            .filter(|listeners| !listeners.is_empty())
        {
            return listeners.clone();
        }
        let port = self.legacy_port();
        vec![format!("127.0.0.1:{port}"), format!("[::1]:{port}")]
    }
    pub fn primary_listener(&self) -> String {
        self.effective_listeners()
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.legacy_port()))
    }
    pub fn effective_pac_files(&self) -> Vec<PathBuf> {
        if let Some(files) = self.pac_files.as_ref().filter(|files| !files.is_empty()) {
            return files.clone();
        }
        vec![self.pac_file.clone()]
    }
    pub fn child_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        for listener in self.effective_listeners() {
            a.push("--listen".into());
            a.push(listener);
        }
        a.extend(["--graceful-shutdown-timeout".into(), "0".into()]);
        for pac_file in self.effective_pac_files() {
            a.push("--pac-file".into());
            let value = pac_file.to_string_lossy();
            let source = parse_remote_pac_uri(&value)
                .ok()
                .flatten()
                .map(|uri| uri.to_string())
                .unwrap_or_else(|| value.into_owned());
            a.push(source);
        }
        if self.proxytunnel {
            a.push("--proxytunnel".into())
        }
        if self.direct_fallback {
            a.push("--direct-fallback".into())
        }
        #[cfg(feature = "negotiate")]
        if self.negotiate {
            a.push("--negotiate".into())
        }
        a
    }
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            let p = Self::default();
            p.save(path)?;
            return Ok(p);
        }
        let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if let Some(port) = value.get_mut("port") {
            let saved = port.as_u64();
            if saved.is_none() || saved.is_some_and(|n| n > u32::MAX as u64) {
                *port = serde_json::Value::from(u32::MAX);
            }
        }
        Ok(serde_json::from_value(value)?)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn parse_listener(value: &str) -> Result<std::net::SocketAddr> {
    let address = value
        .trim()
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid numeric listener address {value:?}"))?;
    anyhow::ensure!(
        !address.ip().is_unspecified(),
        "listener address must not be unspecified: {address}"
    );
    anyhow::ensure!(
        (1024..=65534).contains(&address.port()),
        "listener port must be from 1024 through 65534: {address}"
    );
    Ok(address)
}

pub struct ChildLifecycle {
    child: Option<Child>,
    pub last_exit: Option<String>,
    support_dir: Option<PathBuf>,
    stop_timeout: std::time::Duration,
}
impl Default for ChildLifecycle {
    fn default() -> Self {
        Self {
            child: None,
            last_exit: None,
            support_dir: None,
            stop_timeout: std::time::Duration::from_secs(5),
        }
    }
}
impl ChildLifecycle {
    fn log_path(&self) -> PathBuf {
        self.support_dir
            .as_ref()
            .map(|dir| dir.join("unproxy.log"))
            .unwrap_or_else(log_path)
    }

    #[cfg(all(test, unix))]
    fn for_test(support_dir: PathBuf, stop_timeout: std::time::Duration) -> Self {
        Self {
            child: None,
            last_exit: None,
            support_dir: Some(support_dir),
            stop_timeout,
        }
    }

    #[doc(hidden)]
    pub fn with_support_dir(support_dir: PathBuf) -> Self {
        Self {
            child: None,
            last_exit: None,
            support_dir: Some(support_dir),
            stop_timeout: std::time::Duration::from_secs(5),
        }
    }

    pub fn is_running(&mut self) -> bool {
        let log_path = self.log_path();
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let message = format!("Proxy exited unexpectedly ({status})");
                    self.last_exit = Some(message.clone());
                    if let Ok(mut log) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                    {
                        use std::io::Write;
                        let _ = writeln!(log, "{} {message}", chrono::Local::now().to_rfc3339());
                    }
                    self.child = None;
                }
                Ok(None) => {}
                Err(error) => {
                    self.last_exit = Some(format!("Could not query proxy process: {error}"));
                    self.child = None;
                }
            }
        }
        self.child.is_some()
    }
    pub fn start(&mut self, exe: &Path, prefs: &Preferences) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        for pac_file in prefs.effective_pac_files() {
            let source = pac_file.to_string_lossy();
            if parse_remote_pac_uri(&source)?.is_some() {
                continue;
            }
            anyhow::ensure!(pac_file.is_absolute(), "PAC path must be absolute");
            anyhow::ensure!(
                pac_file.is_file(),
                "PAC file is missing: {}",
                pac_file.display()
            );
            std::fs::File::open(&pac_file)
                .with_context(|| format!("read PAC file {}", pac_file.display()))?;
        }
        if let Some(parent) = self.log_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())?;
        let log_err = log.try_clone()?;
        self.last_exit = None;
        let mut c = Command::new(exe);
        c.args(prefs.child_args())
            .env("UNPROXY_NORC", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        self.child = Some(
            c.spawn()
                .with_context(|| format!("start {}", exe.display()))?,
        );
        Ok(())
    }
    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut c) = self.child.take() {
            #[cfg(unix)]
            unsafe {
                libc::kill(c.id() as i32, libc::SIGTERM);
            }
            #[cfg(windows)]
            {
                let _ = c.kill();
            }
            let deadline = std::time::Instant::now() + self.stop_timeout;
            loop {
                match c.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(error) => {
                        let _ = c.kill();
                        let _ = c.wait();
                        return Err(error).context("wait for proxy child");
                    }
                }
                if std::time::Instant::now() >= deadline {
                    if let Ok(mut log) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(self.log_path())
                    {
                        use std::io::Write;
                        let _ = writeln!(
                            log,
                            "{} proxy stop timed out; forcing termination",
                            chrono::Local::now().to_rfc3339()
                        );
                    }
                    c.kill()?;
                    let _ = c.wait();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        Ok(())
    }
    pub fn restart(&mut self, exe: &Path, prefs: &Preferences) -> Result<()> {
        self.stop()?;
        self.start(exe, prefs)
    }
}
pub fn log_path() -> PathBuf {
    support_dir().join("unproxy.log")
}
impl Drop for ChildLifecycle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(target_os = "macos")]
pub fn run_app() -> Result<()> {
    native::run()
}
#[cfg(not(target_os = "macos"))]
pub fn run_app() -> Result<()> {
    anyhow::bail!("the menu-bar application is available only on macOS")
}
#[cfg(windows)]
pub fn run_tray() -> Result<()> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe()?;
    run_tray_with(&exe, |program, args, flags| {
        Command::new(program)
            .args(args)
            .creation_flags(flags)
            .status()
    })
}

#[cfg(windows)]
fn run_tray_with(
    exe: &Path,
    execute: impl FnOnce(
        &std::ffi::OsStr,
        &[std::ffi::OsString],
        u32,
    ) -> std::io::Result<std::process::ExitStatus>,
) -> Result<()> {
    let script = exe
        .parent()
        .context("tray executable has no parent directory")?
        .join("unproxy-tray.ps1");
    anyhow::ensure!(
        script.is_file(),
        "tray controller script is missing: {}",
        script.display()
    );
    let args = [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-STA",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .chain(std::iter::once(script.into_os_string()))
    .collect::<Vec<_>>();
    let status = execute(std::ffi::OsStr::new("powershell.exe"), &args, 0x08000000)?;
    anyhow::ensure!(status.success(), "tray controller exited with {status}");
    Ok(())
}
#[cfg(not(windows))]
pub fn run_tray() -> Result<()> {
    anyhow::bail!("the tray application is available only on Windows")
}
#[cfg(target_os = "macos")]
pub fn run_login_helper() -> Result<()> {
    native::run_helper()
}
#[cfg(target_os = "macos")]
pub fn validate_native_bindings() -> Result<()> {
    native::validate_bindings()
}
#[cfg(not(target_os = "macos"))]
pub fn validate_native_bindings() -> Result<()> {
    anyhow::bail!("Objective-C bindings are available only on macOS")
}
#[cfg(not(target_os = "macos"))]
pub fn run_login_helper() -> Result<()> {
    anyhow::bail!("the login helper is available only on macOS")
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn run_native_main_thread_probe(
    support_dir: &Path,
    child_exe: &Path,
    pac_file: &Path,
) -> Result<()> {
    native::run_main_thread_probe(support_dir, child_exe, pac_file)
}

#[cfg(target_os = "macos")]
mod native {
    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}
    use super::*;
    use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
    use objc2::{msg_send, sel};
    use std::sync::{Arc, Mutex};
    use std::{ffi::CString, ptr};

    // The menu is rebuilt whenever the native status item opens. Child process
    // and preference updates stay in Rust; Cocoa only owns presentation/events.
    static STATE: Mutex<Option<Arc<Mutex<State>>>> = Mutex::new(None);
    static EDITOR_LISTENERS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static EDITOR_PAC_FILES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static EDITOR_PREFS: Mutex<Option<Preferences>> = Mutex::new(None);
    static LISTENER_TABLE: Mutex<usize> = Mutex::new(0);
    static PAC_FILE_TABLE: Mutex<usize> = Mutex::new(0);
    #[derive(Clone, Default)]
    struct TrayStatus {
        pac_loaded: Option<bool>,
        authentication_configured: bool,
        upstream_state: String,
        authentication_state: String,
        upstream_checked_at: Option<i64>,
    }
    struct State {
        prefs: Preferences,
        prefs_path: PathBuf,
        defaults: usize,
        child: ChildLifecycle,
        child_exe: PathBuf,
        network_available: Option<bool>,
        _instance_lock: std::fs::File,
        status_button: usize,
        last_running: bool,
        start_failed: bool,
        notice: Option<String>,
        tray_status: TrayStatus,
        last_icon_key: String,
    }
    unsafe extern "C-unwind" fn action(_this: *mut AnyObject, _cmd: Sel, sender: *mut AnyObject) {
        let tag: i64 = unsafe { msg_send![sender, tag] };
        if tag == 12 {
            let shared = STATE.lock().unwrap().as_ref().cloned();
            if let Some(shared) = shared {
                shared.lock().unwrap().notice = None;
                if let Err(error) = show_settings(&shared) {
                    let message = format!("Could not apply Unproxy settings: {error:#}");
                    shared.lock().unwrap().notice = Some(message.clone());
                    show_message("Could not apply Unproxy settings", &message);
                }
                let mut state = shared.lock().unwrap();
                let running = state.child.is_running();
                state.last_running = running;
                refresh_runtime_status(&mut state, running);
                update_status_button(&mut state, running);
            }
            return;
        }
        let mut terminate = false;
        if let Some(shared) = STATE.lock().unwrap().as_ref() {
            let mut s = shared.lock().unwrap();
            s.notice = None;
            let mut notice = None;
            match tag {
                10 => {
                    if let Err(error) = open_path(&log_path()) {
                        let message = format!("Could not open the Unproxy log: {error:#}");
                        notice = Some(message.clone());
                        show_message("Could not open the Unproxy log", &message);
                    }
                }
                11 => {
                    let address = s.prefs.primary_listener();
                    if let Err(error) = copy_to_clipboard(&address) {
                        let message = format!("Could not copy the proxy address: {error:#}");
                        notice = Some(message.clone());
                        show_message("Could not copy the proxy address", &message);
                    }
                }
                _ => {
                    let mut services = ActionServices {
                        prompt,
                        alert: |message: &str| {
                            notice = Some(message.to_owned());
                            show_message("Unproxy", message);
                        },
                        save: |prefs: &Preferences, path: &Path, defaults: usize| {
                            save_native_preferences(prefs, path, defaults as *mut AnyObject)
                        },
                        login_item: set_login_item,
                    };
                    terminate = handle_action(&mut s, tag, &mut services);
                }
            }
            if notice.is_some() {
                s.notice = notice;
            }
            let running = s.child.is_running();
            s.last_running = running;
            refresh_runtime_status(&mut s, running);
            update_status_button(&mut s, running);
        }
        if terminate {
            let app: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
            let _: () = unsafe { msg_send![app, terminate:ptr::null_mut::<AnyObject>()] };
        }
    }
    struct ActionServices<P, A, S, L> {
        prompt: P,
        alert: A,
        save: S,
        login_item: L,
    }
    fn handle_action<P, A, S, L>(
        state: &mut State,
        tag: i64,
        services: &mut ActionServices<P, A, S, L>,
    ) -> bool
    where
        P: FnMut(&str, &str) -> Option<String>,
        A: FnMut(&str),
        S: for<'a, 'b> FnMut(&'a Preferences, &'b Path, usize) -> Result<()>,
        L: FnMut(bool) -> Result<()>,
    {
        let mut terminate = false;
        state.notice = None;
        match tag {
            1 => {
                let exe = state.child_exe.clone();
                let prefs = state.prefs.clone();
                match state.child.start(&exe, &prefs) {
                    Ok(()) => {
                        state.start_failed = false;
                        reset_runtime_status(state);
                    }
                    Err(error) => {
                        state.start_failed = true;
                        (services.alert)(&format!("Could not start Unproxy: {error:#}"));
                    }
                }
                state.last_running = state.child.is_running();
                if !state.last_running
                    && let Some(exit) = &state.child.last_exit
                {
                    (services.alert)(exit);
                }
            }
            2 => {
                let _ = state.child.stop();
                state.last_running = false;
                state.start_failed = false;
            }
            3..=5 => {
                let running = state.child.is_running();
                match tag {
                    3 => state.prefs.proxytunnel = !state.prefs.proxytunnel,
                    4 => state.prefs.direct_fallback = !state.prefs.direct_fallback,
                    _ => state.prefs.negotiate = !state.prefs.negotiate,
                }
                let _ = (services.save)(&state.prefs, &state.prefs_path, state.defaults);
                let exe = state.child_exe.clone();
                let prefs = state.prefs.clone();
                if running {
                    match state.child.restart(&exe, &prefs) {
                        Ok(()) => {
                            state.start_failed = false;
                            reset_runtime_status(state);
                        }
                        Err(error) => {
                            state.start_failed = true;
                            (services.alert)(&format!("Could not restart Unproxy: {error:#}"));
                        }
                    }
                }
                state.last_running = state.child.is_running();
            }
            7 | 8 => {
                let running = state.child.is_running();
                let current = if tag == 7 {
                    state.prefs.port.to_string()
                } else {
                    state.prefs.pac_file.to_string_lossy().into_owned()
                };
                if let Some(value) = (services.prompt)(
                    if tag == 7 {
                        "Listener port (1024–65534)"
                    } else {
                        "Absolute PAC file path"
                    },
                    &current,
                ) {
                    if tag == 7 {
                        match value.parse::<u32>() {
                            Ok(port) if (1024..=65534).contains(&port) => state.prefs.port = port,
                            _ => {
                                (services.alert)("Port must be an integer from 1024 through 65534.")
                            }
                        }
                    } else {
                        let path = PathBuf::from(value);
                        if !path.is_absolute() {
                            (services.alert)("PAC path must be absolute.");
                        } else {
                            state.prefs.pac_file = path;
                        }
                    }
                    let _ = (services.save)(&state.prefs, &state.prefs_path, state.defaults);
                    if running {
                        let exe = state.child_exe.clone();
                        let prefs = state.prefs.clone();
                        match state.child.restart(&exe, &prefs) {
                            Ok(()) => {
                                state.start_failed = false;
                                reset_runtime_status(state);
                            }
                            Err(error) => {
                                state.start_failed = true;
                                (services.alert)(&format!("Could not restart Unproxy: {error:#}"));
                            }
                        }
                    }
                    state.last_running = state.child.is_running();
                }
            }
            9 => {
                state.prefs.autostart = !state.prefs.autostart;
                let enabled = state.prefs.autostart;
                let _ = (services.save)(&state.prefs, &state.prefs_path, state.defaults);
                if let Err(error) = (services.login_item)(enabled) {
                    state.prefs.autostart = !enabled;
                    let _ = (services.save)(&state.prefs, &state.prefs_path, state.defaults);
                    (services.alert)(&format!("Could not update login startup: {error:#}"));
                }
            }
            6 => {
                let _ = state.child.stop();
                terminate = true;
            }
            _ => {}
        }
        terminate
    }
    fn auth_is_configured(prefs: &Preferences) -> bool {
        let netrc = super::super::config::netrc_default().is_some_and(|path| path.is_file());
        #[cfg(feature = "negotiate")]
        {
            prefs.negotiate || netrc
        }
        #[cfg(not(feature = "negotiate"))]
        {
            let _ = prefs;
            netrc
        }
    }
    fn probe_runtime_status(address: std::net::SocketAddr) -> Option<TrayStatus> {
        use std::{
            io::{Read, Write},
            net::TcpStream,
            time::Duration,
        };
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(180)).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_millis(180)))
            .ok()?;
        stream
            .set_write_timeout(Some(Duration::from_millis(180)))
            .ok()?;
        write!(
            stream,
            "GET /status.json HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        )
        .ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).ok()?;
        parse_runtime_status_response(&response)
    }
    fn parse_runtime_status_response(response: &[u8]) -> Option<TrayStatus> {
        let body_start = response.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let status: serde_json::Value = serde_json::from_slice(&response[body_start..]).ok()?;
        Some(TrayStatus {
            pac_loaded: status
                .get("pac_loaded")
                .and_then(serde_json::Value::as_bool),
            authentication_configured: status
                .get("authentication_configured")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            upstream_state: status
                .get("upstream_state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            authentication_state: status
                .get("authentication_state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            upstream_checked_at: status
                .get("upstream_checked_at")
                .and_then(serde_json::Value::as_i64),
        })
    }
    fn refresh_runtime_status(state: &mut State, running: bool) {
        if running {
            let status = state
                .prefs
                .effective_listeners()
                .iter()
                .filter_map(|listener| listener.parse::<std::net::SocketAddr>().ok())
                .find_map(probe_runtime_status);
            if let Some(status) = status {
                state.tray_status = status;
            } else {
                state.tray_status.pac_loaded = None;
                state.tray_status.authentication_configured = auth_is_configured(&state.prefs);
            }
        } else {
            state.tray_status.pac_loaded = None;
            state.tray_status.authentication_configured = auth_is_configured(&state.prefs);
        }
    }
    fn reset_runtime_status(state: &mut State) {
        let configured = auth_is_configured(&state.prefs);
        state.tray_status = TrayStatus {
            authentication_configured: configured,
            authentication_state: if configured {
                "configured".into()
            } else {
                "disabled".into()
            },
            ..TrayStatus::default()
        };
    }
    fn upstream_is_recent(status: &TrayStatus) -> bool {
        status.upstream_checked_at.is_some_and(|checked| {
            let age = chrono::Utc::now().timestamp().saturating_sub(checked);
            (0..=300).contains(&age)
        })
    }
    fn icon_statuses(
        state: &State,
        running: bool,
    ) -> (&'static str, &'static str, &'static str, &'static str) {
        let service = if running {
            "running"
        } else if state.start_failed || state.child.last_exit.is_some() {
            "failed"
        } else {
            "stopped"
        };
        let pac = if !running {
            "unloaded"
        } else {
            match state.tray_status.pac_loaded {
                Some(true) => "loaded",
                Some(false) => "unloaded",
                None => "unknown",
            }
        };
        let upstream = if !upstream_is_recent(&state.tray_status) {
            "unknown"
        } else if state.tray_status.upstream_state == "ok" {
            "ok"
        } else {
            "error"
        };
        let authentication = if !state.tray_status.authentication_configured {
            "disabled"
        } else if upstream_is_recent(&state.tray_status)
            && state.tray_status.authentication_state == "authenticated"
        {
            "authenticated"
        } else if upstream_is_recent(&state.tray_status)
            && state.tray_status.authentication_state == "rejected"
        {
            "rejected"
        } else {
            "configured"
        };
        (service, pac, upstream, authentication)
    }
    fn status_labels(state: &State, running: bool) -> (String, String, String, String) {
        let process = if running {
            "Running"
        } else if state.start_failed || state.child.last_exit.is_some() {
            "Stopped unexpectedly"
        } else {
            "Stopped"
        }
        .to_owned();
        let pac = match if running {
            state.tray_status.pac_loaded
        } else {
            Some(false)
        } {
            Some(true) => "Loaded".to_owned(),
            Some(false) => "Not loaded".to_owned(),
            None => "Unknown".to_owned(),
        };
        let upstream = if !upstream_is_recent(&state.tray_status) {
            "No recent proxy request".to_owned()
        } else if state.tray_status.upstream_state == "ok" {
            "Last proxy request succeeded".to_owned()
        } else {
            "Last proxy request failed".to_owned()
        };
        let authentication = match icon_statuses(state, running).3 {
            "authenticated" => "Accepted on last request",
            "rejected" => "Rejected by upstream (407)",
            "configured" => "Configured; not verified yet",
            _ => "Not configured",
        }
        .to_owned();
        (process, pac, upstream, authentication)
    }
    fn update_status_button(state: &mut State, running: bool) {
        let (service, pac, upstream, authentication) = icon_statuses(state, running);
        let key = format!("{service}-{pac}-{upstream}-{authentication}");
        let button = state.status_button as *mut AnyObject;
        if button.is_null() {
            return;
        }
        if key != state.last_icon_key {
            let path = state
                .child_exe
                .parent()
                .and_then(Path::parent)
                .map(|contents| {
                    contents
                        .join("Resources/tray-icons")
                        .join(format!("{key}.png"))
                });
            if let Some(path) = path.filter(|path| path.is_file()) {
                let image: *mut AnyObject = unsafe {
                    let allocated: *mut AnyObject = msg_send![objc2::class!(NSImage), alloc];
                    let initialized: *mut AnyObject = msg_send![allocated, initWithContentsOfFile:cocoa_string(&path.to_string_lossy())];
                    if initialized.is_null() {
                        initialized
                    } else {
                        msg_send![initialized, autorelease]
                    }
                };
                if !image.is_null() {
                    #[repr(C)]
                    struct Size {
                        width: f64,
                        height: f64,
                    }
                    unsafe impl objc2::encode::Encode for Size {
                        const ENCODING: objc2::encode::Encoding = objc2::encode::Encoding::Struct(
                            "CGSize",
                            &[f64::ENCODING, f64::ENCODING],
                        );
                    }
                    let _: () =
                        unsafe { msg_send![image, setSize:Size { width: 18.0, height: 18.0 }] };
                    let _: () = unsafe { msg_send![button, setImage:image] };
                    state.last_icon_key = key;
                }
            }
        }
        let (process, pac, upstream, authentication) = status_labels(state, running);
        #[cfg(feature = "negotiate")]
        let network = if state.prefs.negotiate {
            let status = match state.network_available {
                Some(true) => "available",
                Some(false) => "unavailable",
                None => "unknown",
            };
            format!(" · Internal network: {status}")
        } else {
            String::new()
        };
        #[cfg(not(feature = "negotiate"))]
        let network = String::new();
        let tooltip = format!(
            "Unproxy {process} · PAC {pac} · Upstream: {upstream} · Auth: {authentication}{network}{}",
            state
                .notice
                .as_ref()
                .map(|message| format!(" · {message}"))
                .unwrap_or_default()
        );
        let _: () = unsafe { msg_send![button, setTitle:cocoa_string("")] };
        let _: () = unsafe { msg_send![button, setToolTip:cocoa_string(&tooltip)] };
    }
    unsafe extern "C-unwind" fn poll_child(
        _this: *mut AnyObject,
        _cmd: Sel,
        _timer: *mut AnyObject,
    ) {
        if let Some(shared) = STATE.lock().unwrap().as_ref() {
            let Ok(mut s) = shared.try_lock() else {
                return;
            };
            let running = s.child.is_running();
            if s.last_running && !running {
                s.notice = Some(
                    s.child
                        .last_exit
                        .clone()
                        .unwrap_or_else(|| "Proxy stopped".to_owned()),
                );
            }
            s.last_running = running;
            refresh_runtime_status(&mut s, running);
            update_status_button(&mut s, running);
        }
    }
    unsafe extern "C-unwind" fn rebuild_menu(
        _this: *mut AnyObject,
        _cmd: Sel,
        menu: *mut AnyObject,
    ) {
        let n: isize = unsafe { msg_send![menu, numberOfItems] };
        for _ in 0..n {
            let _: () = unsafe { msg_send![menu, removeItemAtIndex:0isize] };
        }
        if let Some(s) = STATE.lock().unwrap().as_ref() {
            let mut s = s.lock().unwrap();
            let running = s.child.is_running();
            refresh_runtime_status(&mut s, running);
            update_status_button(&mut s, running);
            let target: *mut AnyObject = unsafe { msg_send![menu, delegate] };
            let (process, _, _, _) = status_labels(&s, running);
            let status_action = if running { 2 } else { 1 };
            let status_line = if running {
                format!("Proxy: {process} (click to stop)")
            } else {
                format!("Proxy: {process} (click to start)")
            };
            menu_item(menu, &status_line, status_action, false, true, target);
            menu_item(menu, "Open Log", 10, false, true, target);
            menu_item(menu, "Start with Login", 9, s.prefs.autostart, true, target);
            menu_item(menu, "Copy Proxy Address", 11, false, true, target);
            menu_item(menu, "Settings…", 12, false, true, target);
            menu_item(menu, "Quit Unproxy", 6, false, true, target);
        }
    }
    unsafe extern "C-unwind" fn network_available(
        _this: *mut AnyObject,
        _cmd: Sel,
        _note: *mut AnyObject,
    ) {
        if let Some(s) = STATE.lock().unwrap().as_ref() {
            s.lock().unwrap().network_available = Some(true);
        }
    }
    unsafe extern "C-unwind" fn network_unavailable(
        _this: *mut AnyObject,
        _cmd: Sel,
        _note: *mut AnyObject,
    ) {
        if let Some(s) = STATE.lock().unwrap().as_ref() {
            s.lock().unwrap().network_available = Some(false);
        }
    }
    unsafe extern "C-unwind" fn helper_terminate(
        _this: *mut AnyObject,
        _cmd: Sel,
        _note: *mut AnyObject,
    ) {
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: () = unsafe { msg_send![app,terminate:ptr::null_mut::<AnyObject>()] };
    }
    unsafe extern "C-unwind" fn application_will_terminate(
        _this: *mut AnyObject,
        _cmd: Sel,
        _notification: *mut AnyObject,
    ) {
        if let Some(shared) = STATE.lock().unwrap().as_ref() {
            let mut s = shared.lock().unwrap();
            let _ = s.child.stop();
        }
    }
    fn main_app_is_running() -> bool {
        let apps: *mut AnyObject = unsafe {
            msg_send![objc2::class!(NSRunningApplication),runningApplicationsWithBundleIdentifier:cocoa_string(APP_BUNDLE_ID)]
        };
        let count: usize = unsafe { msg_send![apps, count] };
        count > 0
    }
    fn action_class() -> &'static AnyClass {
        if let Some(c) = AnyClass::get(c"UnproxyMenuActions") {
            return c;
        }
        let superclass = AnyClass::get(c"NSObject").unwrap();
        let mut cb = ClassBuilder::new(c"UnproxyMenuActions", superclass).unwrap();
        unsafe {
            cb.add_method(
                sel!(clicked:),
                action as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(listEditorAction:),
                list_editor_action as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(windowWillClose:),
                list_editor_window_will_close as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(numberOfRowsInTableView:),
                list_row_count
                    as unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject) -> isize,
            );
            cb.add_method(
                sel!(tableView:objectValueForTableColumn:row:),
                list_object_value
                    as unsafe extern "C-unwind" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        isize,
                    ) -> *mut AnyObject,
            );
            cb.add_method(
                sel!(tableView:setObjectValue:forTableColumn:row:),
                list_set_object_value
                    as unsafe extern "C-unwind" fn(
                        *mut AnyObject,
                        Sel,
                        *mut AnyObject,
                        *mut AnyObject,
                        *mut AnyObject,
                        isize,
                    ),
            );
            cb.add_method(
                sel!(menuNeedsUpdate:),
                rebuild_menu as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(pollChild:),
                poll_child as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(networkAvailable:),
                network_available as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(networkUnavailable:),
                network_unavailable as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(terminateHelper:),
                helper_terminate as unsafe extern "C-unwind" fn(_, _, _),
            );
            cb.add_method(
                sel!(applicationWillTerminate:),
                application_will_terminate as unsafe extern "C-unwind" fn(_, _, _),
            );
        }
        cb.register()
    }
    pub fn validate_bindings() -> Result<()> {
        let cls = action_class();
        for selector in [
            sel!(clicked:),
            sel!(listEditorAction:),
            sel!(windowWillClose:),
            sel!(menuNeedsUpdate:),
            sel!(pollChild:),
            sel!(networkAvailable:),
            sel!(networkUnavailable:),
            sel!(terminateHelper:),
            sel!(applicationWillTerminate:),
        ] {
            let method = cls.instance_method(selector).ok_or_else(|| {
                anyhow::anyhow!("missing Objective-C selector {:?}", selector.name())
            })?;
            if method.arguments_count() != 3 {
                anyhow::bail!(
                    "selector {:?} has {} args; expected 3",
                    selector.name(),
                    method.arguments_count()
                )
            }
            let ret = method.return_type();
            if ret.to_str()? != "v" {
                anyhow::bail!("selector {:?} must return void", selector.name())
            }
            let object_arg = method
                .argument_type(2)
                .context("Objective-C method missing sender argument")?;
            if object_arg.to_str()? != "@" {
                anyhow::bail!(
                    "selector {:?} sender must be an Objective-C object",
                    selector.name()
                )
            }
        }
        let row_count = cls
            .instance_method(sel!(numberOfRowsInTableView:))
            .context("NSTableView row-count callback missing")?;
        anyhow::ensure!(
            row_count.arguments_count() == 3
                && row_count.return_type().to_str()? == "q"
                && row_count
                    .argument_type(2)
                    .context("NSTableView row-count callback is missing its table argument")?
                    .to_str()?
                    == "@",
            "invalid NSTableView row-count callback ABI"
        );
        let row_value = cls
            .instance_method(sel!(tableView:objectValueForTableColumn:row:))
            .context("NSTableView value callback missing")?;
        anyhow::ensure!(
            row_value.arguments_count() == 5
                && row_value.return_type().to_str()? == "@"
                && row_value
                    .argument_type(2)
                    .context("NSTableView value callback is missing its table argument")?
                    .to_str()?
                    == "@"
                && row_value
                    .argument_type(3)
                    .context("NSTableView value callback is missing its column argument")?
                    .to_str()?
                    == "@"
                && row_value
                    .argument_type(4)
                    .context("NSTableView value callback is missing its row argument")?
                    .to_str()?
                    == "q",
            "invalid NSTableView value callback ABI"
        );
        let set_row_value = cls
            .instance_method(sel!(tableView:setObjectValue:forTableColumn:row:))
            .context("NSTableView edit callback missing")?;
        anyhow::ensure!(
            set_row_value.arguments_count() == 6
                && set_row_value.return_type().to_str()? == "v"
                && set_row_value
                    .argument_type(2)
                    .context("missing table argument")?
                    .to_str()?
                    == "@"
                && set_row_value
                    .argument_type(3)
                    .context("missing object value argument")?
                    .to_str()?
                    == "@"
                && set_row_value
                    .argument_type(4)
                    .context("missing column argument")?
                    .to_str()?
                    == "@"
                && set_row_value
                    .argument_type(5)
                    .context("missing row argument")?
                    .to_str()?
                    == "q",
            "invalid NSTableView edit callback ABI"
        );
        let defaults = AnyClass::get(c"NSUserDefaults").context("NSUserDefaults class missing")?;
        for sel in [
            sel!(standardUserDefaults),
            sel!(objectForKey:),
            sel!(setObject:forKey:),
            sel!(setBool:forKey:),
            sel!(setInteger:forKey:),
            sel!(removeObjectForKey:),
            sel!(synchronize),
        ] {
            let method = if sel.name().to_bytes() == b"standardUserDefaults" {
                defaults.class_method(sel)
            } else {
                defaults.instance_method(sel)
            };
            if method.is_none() {
                anyhow::bail!("missing NSUserDefaults selector {:?}", sel.name())
            }
        }
        let array = AnyClass::get(c"NSArray").context("NSArray class missing")?;
        for selector in [sel!(count), sel!(objectAtIndex:)] {
            if array.instance_method(selector).is_none() {
                anyhow::bail!("missing NSArray selector {:?}", selector.name())
            }
        }
        let mutable_array =
            AnyClass::get(c"NSMutableArray").context("NSMutableArray class missing")?;
        for selector in [sel!(new), sel!(addObject:)] {
            let method = if selector.name().to_bytes() == b"new" {
                mutable_array.class_method(selector)
            } else {
                mutable_array.instance_method(selector)
            };
            if method.is_none() {
                anyhow::bail!("missing NSMutableArray selector {:?}", selector.name())
            }
        }
        // ServiceManagement exposes a C Boolean (one byte), not ObjC BOOL.
        if std::mem::size_of::<u8>() != 1 {
            anyhow::bail!("unexpected Core Foundation Boolean ABI")
        }
        Ok(())
    }
    fn cocoa_string(s: &str) -> *mut AnyObject {
        let c = CString::new(s).unwrap();
        let cls = objc2::class!(NSString);
        unsafe { msg_send![cls, stringWithUTF8String:c.as_ptr()] }
    }
    fn cocoa_text(value: *mut AnyObject) -> Option<String> {
        if value.is_null() {
            return None;
        }
        let bytes: *const std::ffi::c_char = unsafe { msg_send![value, UTF8String] };
        (!bytes.is_null()).then(|| {
            unsafe { std::ffi::CStr::from_ptr(bytes) }
                .to_string_lossy()
                .into_owned()
        })
    }
    fn prompt(message: &str, default: &str) -> Option<String> {
        prompt_with(message, default, |script| {
            Command::new("osascript").args(["-e", script]).output()
        })
    }
    fn prompt_with(
        message: &str,
        default: &str,
        execute: impl FnOnce(&str) -> std::io::Result<std::process::Output>,
    ) -> Option<String> {
        let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "display dialog \"{}\" default answer \"{}\" buttons {{\"Cancel\", \"Save\"}} default button \"Save\"",
            escape(message),
            escape(default)
        );
        let out = execute(&script).ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Some(text.split_once("text returned:")?.1.trim().to_owned())
    }
    #[repr(C)]
    struct Point {
        x: f64,
        y: f64,
    }
    unsafe impl objc2::encode::Encode for Point {
        const ENCODING: objc2::encode::Encoding =
            objc2::encode::Encoding::Struct("CGPoint", &[f64::ENCODING, f64::ENCODING]);
    }
    #[repr(C)]
    struct Size {
        width: f64,
        height: f64,
    }
    unsafe impl objc2::encode::Encode for Size {
        const ENCODING: objc2::encode::Encoding =
            objc2::encode::Encoding::Struct("CGSize", &[f64::ENCODING, f64::ENCODING]);
    }
    #[repr(C)]
    struct Rect {
        origin: Point,
        size: Size,
    }
    unsafe impl objc2::encode::Encode for Rect {
        const ENCODING: objc2::encode::Encoding =
            objc2::encode::Encoding::Struct("CGRect", &[Point::ENCODING, Size::ENCODING]);
    }
    fn rect(x: f64, y: f64, width: f64, height: f64) -> Rect {
        Rect {
            origin: Point { x, y },
            size: Size { width, height },
        }
    }
    fn settings_label(
        parent: *mut AnyObject,
        title: &str,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
        emphasized: bool,
    ) {
        let allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSTextField), alloc] };
        let label: *mut AnyObject =
            unsafe { msg_send![allocated, initWithFrame:rect(x, y, width, height)] };
        let _: () = unsafe { msg_send![label, setStringValue:cocoa_string(title)] };
        let _: () = unsafe { msg_send![label, setEditable:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![label, setBordered:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![label, setDrawsBackground:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![label, setAlignment:0isize] };
        let _: () = unsafe { msg_send![label, setUsesSingleLineMode:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![label, setLineBreakMode:0isize] };
        if emphasized {
            let font: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSFont), boldSystemFontOfSize:15.0f64] };
            let _: () = unsafe { msg_send![label, setFont:font] };
        }
        let _: () = unsafe { msg_send![parent, addSubview:label] };
    }
    fn settings_button(
        parent: *mut AnyObject,
        target: *mut AnyObject,
        title: &str,
        tooltip: &str,
        tag: isize,
        frame: Rect,
        key_equivalent: Option<&str>,
    ) -> *mut AnyObject {
        let allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSButton), alloc] };
        let button: *mut AnyObject = unsafe { msg_send![allocated, initWithFrame:frame] };
        let _: () = unsafe { msg_send![button, setTitle:cocoa_string(title)] };
        if !tooltip.is_empty() {
            let _: () = unsafe { msg_send![button, setToolTip:cocoa_string(tooltip)] };
        }
        let _: () = unsafe { msg_send![button, setTag:tag] };
        let _: () = unsafe { msg_send![button, setTarget:target] };
        let _: () = unsafe { msg_send![button, setAction:sel!(listEditorAction:)] };
        if let Some(key) = key_equivalent {
            let _: () = unsafe { msg_send![button, setKeyEquivalent:cocoa_string(key)] };
        }
        let _: () = unsafe { msg_send![parent, addSubview:button] };
        button
    }
    fn settings_checkbox(
        parent: *mut AnyObject,
        target: *mut AnyObject,
        title: &str,
        enabled: bool,
        tag: isize,
        x: f64,
        width: f64,
    ) -> *mut AnyObject {
        let allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSButton), alloc] };
        let button: *mut AnyObject =
            unsafe { msg_send![allocated, initWithFrame:rect(x, 82.0, width, 24.0)] };
        let _: () = unsafe { msg_send![button, setButtonType:3isize] };
        let _: () = unsafe { msg_send![button, setTitle:cocoa_string(title)] };
        let _: () = unsafe { msg_send![button, setState:if enabled {1isize}else{0isize}] };
        let _: () = unsafe { msg_send![button, setTag:tag] };
        let _: () = unsafe { msg_send![button, setTarget:target] };
        let _: () = unsafe { msg_send![button, setAction:sel!(listEditorAction:)] };
        let _: () = unsafe { msg_send![parent, addSubview:button] };
        button
    }
    fn settings_list_table(
        content: *mut AnyObject,
        target: *mut AnyObject,
        tag: isize,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    ) -> *mut AnyObject {
        let scroll_allocated: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSScrollView), alloc] };
        let scroll: *mut AnyObject =
            unsafe { msg_send![scroll_allocated, initWithFrame:rect(x, y, width, height)] };
        let _: () = unsafe { msg_send![scroll, setBorderType:2isize] };
        let _: () = unsafe { msg_send![scroll, setHasVerticalScroller:objc2::runtime::Bool::YES] };

        let table_allocated: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSTableView), alloc] };
        let table: *mut AnyObject = unsafe {
            msg_send![table_allocated, initWithFrame:rect(0.0, 0.0, width - 2.0, height - 2.0)]
        };
        let column_allocated: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSTableColumn), alloc] };
        let column: *mut AnyObject =
            unsafe { msg_send![column_allocated, initWithIdentifier:cocoa_string("value")] };
        let _: () = unsafe { msg_send![column, setWidth:width - 2.0] };
        let cell: *mut AnyObject = unsafe { msg_send![column, dataCell] };
        let _: () = unsafe { msg_send![cell, setEditable:objc2::runtime::Bool::YES] };
        let _: () = unsafe { msg_send![table, addTableColumn:column] };
        let _: () = unsafe { msg_send![table, setHeaderView:ptr::null_mut::<AnyObject>()] };
        let _: () = unsafe { msg_send![table, setRowHeight:32.0f64] };
        let _: () = unsafe { msg_send![table, setTag:tag] };
        let _: () = unsafe { msg_send![table, setDataSource:target] };
        let _: () = unsafe { msg_send![scroll, setDocumentView:table] };
        let _: () = unsafe { msg_send![table, reloadData] };
        let _: () = unsafe { msg_send![content, addSubview:scroll] };
        let count = if tag == 1 {
            EDITOR_LISTENERS.lock().unwrap().len()
        } else {
            EDITOR_PAC_FILES.lock().unwrap().len()
        };
        if count > 0 {
            let _: () = unsafe {
                msg_send![table, selectRowIndexes:index_set(0), byExtendingSelection:objc2::runtime::Bool::NO]
            };
        }
        table
    }
    fn settings_toolbar(content: *mut AnyObject, target: *mut AnyObject, tag_base: isize, x: f64) {
        for (label, tooltip, action, offset) in [
            ("+", "Add an item", 2isize, 0.0),
            ("−", "Remove the selected item", 3isize, 30.0),
            ("↑", "Move the selected item up", 4isize, 60.0),
            ("↓", "Move the selected item down", 5isize, 90.0),
        ] {
            settings_button(
                content,
                target,
                label,
                tooltip,
                tag_base + action,
                rect(x + offset, 168.0, 28.0, 26.0),
                None,
            );
        }
    }
    fn index_set(index: usize) -> *mut AnyObject {
        unsafe { msg_send![objc2::class!(NSIndexSet), indexSetWithIndex:index] }
    }
    fn choose_pac_file() -> Option<String> {
        let panel: *mut AnyObject = unsafe { msg_send![objc2::class!(NSOpenPanel), openPanel] };
        let _: () = unsafe { msg_send![panel, setTitle:cocoa_string("Choose a PAC file")] };
        let _: () = unsafe { msg_send![panel, setPrompt:cocoa_string("Add")] };
        let _: () = unsafe { msg_send![panel, setCanChooseFiles:objc2::runtime::Bool::YES] };
        let _: () = unsafe { msg_send![panel, setCanChooseDirectories:objc2::runtime::Bool::NO] };
        let _: () =
            unsafe { msg_send![panel, setAllowsMultipleSelection:objc2::runtime::Bool::NO] };
        let response: isize = unsafe { msg_send![panel, runModal] };
        if response != 1 {
            return None;
        }
        let url: *mut AnyObject = unsafe { msg_send![panel, URL] };
        let path: *mut AnyObject = unsafe { msg_send![url, path] };
        cocoa_text(path)
    }
    fn add_remote_pac_file() -> Result<()> {
        let Some(value) = prompt("HTTP or HTTPS PAC URL", "https://") else {
            return Ok(());
        };
        let uri = parse_remote_pac_uri(&value)?.context("enter a valid HTTP or HTTPS PAC URL")?;
        let mut values = EDITOR_PAC_FILES.lock().unwrap();
        values.push(uri.to_string());
        let index = values.len() - 1;
        drop(values);

        let table = *PAC_FILE_TABLE.lock().unwrap() as *mut AnyObject;
        if !table.is_null() {
            let _: () = unsafe { msg_send![table, reloadData] };
            let _: () = unsafe {
                msg_send![table, selectRowIndexes:index_set(index), byExtendingSelection:objc2::runtime::Bool::NO]
            };
            let _: () = unsafe { msg_send![table, scrollRowToVisible:index as isize] };
        }
        commit_editor_preferences()
    }
    fn show_pac_content(target: *mut AnyObject, source: &str, content: &str) -> Result<()> {
        let allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSWindow), alloc] };
        let window: *mut AnyObject = unsafe {
            msg_send![allocated, initWithContentRect:rect(0.0, 0.0, 900.0, 640.0), styleMask:15isize, backing:2isize, defer:objc2::runtime::Bool::NO]
        };
        anyhow::ensure!(!window.is_null(), "could not create the PAC viewer");
        let _: () = unsafe { msg_send![window, setReleasedWhenClosed:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![window, setDelegate:target] };
        let _: () =
            unsafe { msg_send![window, setTitle:cocoa_string(&format!("PAC · {source}"))] };
        let _: () = unsafe { msg_send![window, center] };

        let view: *mut AnyObject = unsafe { msg_send![window, contentView] };
        let scroll_allocated: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSScrollView), alloc] };
        let scroll: *mut AnyObject =
            unsafe { msg_send![scroll_allocated, initWithFrame:rect(18.0, 55.0, 864.0, 565.0)] };
        let _: () = unsafe { msg_send![scroll, setBorderType:2isize] };
        let _: () = unsafe { msg_send![scroll, setHasVerticalScroller:objc2::runtime::Bool::YES] };
        let _: () =
            unsafe { msg_send![scroll, setHasHorizontalScroller:objc2::runtime::Bool::YES] };

        let text_allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSTextView), alloc] };
        let text: *mut AnyObject =
            unsafe { msg_send![text_allocated, initWithFrame:rect(0.0, 0.0, 860.0, 560.0)] };
        let _: () = unsafe { msg_send![text, setEditable:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![text, setSelectable:objc2::runtime::Bool::YES] };
        let _: () = unsafe { msg_send![text, setRichText:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![text, setString:cocoa_string(content)] };
        let font: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSFont), userFixedPitchFontOfSize:12.0f64] };
        let _: () = unsafe { msg_send![text, setFont:font] };
        let _: () = unsafe { msg_send![text, setHorizontallyResizable:objc2::runtime::Bool::YES] };
        let _: () = unsafe { msg_send![text, setVerticallyResizable:objc2::runtime::Bool::YES] };
        let _: () = unsafe { msg_send![text, setAutoresizingMask:18usize] };
        let container: *mut AnyObject = unsafe { msg_send![text, textContainer] };
        let _: () = unsafe {
            msg_send![container, setContainerSize:Size { width: 100_000.0, height: 100_000.0 }]
        };
        let _: () =
            unsafe { msg_send![container, setWidthTracksTextView:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![scroll, setDocumentView:text] };
        let _: () = unsafe { msg_send![view, addSubview:scroll] };
        settings_button(
            view,
            target,
            "Close",
            "Close PAC viewer",
            1001,
            rect(790.0, 14.0, 92.0, 30.0),
            Some("\r"),
        );

        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: () = unsafe { msg_send![window, makeKeyAndOrderFront:ptr::null_mut::<AnyObject>()] };
        let _: isize = unsafe { msg_send![app, runModalForWindow:window] };
        let _: () = unsafe { msg_send![window, orderOut:ptr::null_mut::<AnyObject>()] };
        Ok(())
    }
    fn open_selected_pac(target: *mut AnyObject) -> Result<()> {
        let table = *PAC_FILE_TABLE.lock().unwrap() as *mut AnyObject;
        anyhow::ensure!(!table.is_null(), "PAC file table is unavailable");
        let row: isize = unsafe { msg_send![table, selectedRow] };
        anyhow::ensure!(row >= 0, "select a PAC source first");
        let value = EDITOR_PAC_FILES
            .lock()
            .unwrap()
            .get(row as usize)
            .cloned()
            .context("selected PAC source is unavailable")?;
        if let Some(uri) = parse_remote_pac_uri(&value)? {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("start PAC download runtime")?;
            let content = runtime.block_on(crate::net::fetch_remote_pac(&uri.to_string()))?;
            show_pac_content(target, &uri.to_string(), &content)
        } else {
            let path = PathBuf::from(value);
            anyhow::ensure!(path.is_absolute(), "PAC path must be absolute");
            anyhow::ensure!(path.is_file(), "PAC file is missing: {}", path.display());
            open_pac_file(&path)
        }
    }
    unsafe extern "C-unwind" fn list_row_count(
        _this: *mut AnyObject,
        _cmd: Sel,
        table: *mut AnyObject,
    ) -> isize {
        let tag: isize = unsafe { msg_send![table, tag] };
        if tag == 1 {
            EDITOR_LISTENERS.lock().unwrap().len() as isize
        } else {
            EDITOR_PAC_FILES.lock().unwrap().len() as isize
        }
    }
    unsafe extern "C-unwind" fn list_object_value(
        _this: *mut AnyObject,
        _cmd: Sel,
        table: *mut AnyObject,
        _column: *mut AnyObject,
        row: isize,
    ) -> *mut AnyObject {
        if row < 0 {
            return ptr::null_mut();
        }
        let tag: isize = unsafe { msg_send![table, tag] };
        if tag == 1 {
            EDITOR_LISTENERS
                .lock()
                .unwrap()
                .get(row as usize)
                .map(|value| cocoa_string(value))
                .unwrap_or(ptr::null_mut())
        } else {
            EDITOR_PAC_FILES
                .lock()
                .unwrap()
                .get(row as usize)
                .map(|value| cocoa_string(value))
                .unwrap_or(ptr::null_mut())
        }
    }
    unsafe extern "C-unwind" fn list_set_object_value(
        _this: *mut AnyObject,
        _cmd: Sel,
        table: *mut AnyObject,
        value: *mut AnyObject,
        _column: *mut AnyObject,
        row: isize,
    ) {
        if row < 0 {
            return;
        }
        let Some(value) = cocoa_text(value) else {
            return;
        };
        let tag: isize = unsafe { msg_send![table, tag] };
        let updated = if tag == 1 {
            EDITOR_LISTENERS
                .lock()
                .unwrap()
                .get_mut(row as usize)
                .map(|slot| *slot = value)
                .is_some()
        } else {
            EDITOR_PAC_FILES
                .lock()
                .unwrap()
                .get_mut(row as usize)
                .map(|slot| *slot = value)
                .is_some()
        };
        if updated && let Err(error) = commit_editor_preferences() {
            show_message("Could not apply this change", &format!("{error:#}"));
        }
    }
    fn append_listener_placeholder(values: &mut Vec<String>) -> usize {
        values.push(String::new());
        values.len() - 1
    }
    fn update_editor_list(
        values: &mut Vec<String>,
        operation: isize,
        selected: Option<usize>,
    ) -> Result<Option<usize>> {
        let mut new_selection = selected;
        match operation {
            3 => {
                if let Some(index) = selected {
                    anyhow::ensure!(values.len() > 1, "at least one item is required");
                    if index < values.len() {
                        values.remove(index);
                        new_selection = Some(index.min(values.len() - 1));
                    }
                }
            }
            4 => {
                if let Some(index) = selected.filter(|index| *index > 0 && *index < values.len()) {
                    values.swap(index, index - 1);
                    new_selection = Some(index - 1);
                }
            }
            5 => {
                if let Some(index) = selected
                    && index + 1 < values.len()
                {
                    values.swap(index, index + 1);
                    new_selection = Some(index + 1);
                }
            }
            _ => anyhow::bail!("unsupported editor operation {operation}"),
        }
        Ok(new_selection)
    }
    unsafe extern "C-unwind" fn list_editor_action(
        this: *mut AnyObject,
        _cmd: Sel,
        sender: *mut AnyObject,
    ) {
        let action: isize = unsafe { msg_send![sender, tag] };
        if action == 1000 || action == 1001 {
            let app: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
            let _: () = unsafe { msg_send![app, stopModalWithCode:action] };
            return;
        }
        if action == 1206 {
            if let Err(error) = open_selected_pac(this) {
                show_message("Could not open PAC source", &format!("{error:#}"));
            }
            return;
        }
        if action == 1207 {
            if let Err(error) = add_remote_pac_file() {
                show_message("Could not add PAC URL", &format!("{error:#}"));
            }
            return;
        }
        if (3001..=3003).contains(&action) {
            change_editor_checkbox(sender, action);
            return;
        }
        let (is_pac_files, operation, table) = match action {
            1102..=1105 => (
                false,
                action - 1100,
                *LISTENER_TABLE.lock().unwrap() as *mut AnyObject,
            ),
            1202..=1205 => (
                true,
                action - 1200,
                *PAC_FILE_TABLE.lock().unwrap() as *mut AnyObject,
            ),
            _ => return,
        };
        if table.is_null() {
            return;
        }

        let selected_row: isize = unsafe { msg_send![table, selectedRow] };
        let selected = (selected_row >= 0).then_some(selected_row as usize);
        let mut edit_new_row = false;
        let mut new_selection = selected;
        if operation == 2 {
            if is_pac_files {
                if let Some(path) = choose_pac_file() {
                    let mut values = EDITOR_PAC_FILES.lock().unwrap();
                    values.push(path);
                    new_selection = Some(values.len() - 1);
                }
            } else {
                edit_new_row = true;
                let mut values = EDITOR_LISTENERS.lock().unwrap();
                new_selection = Some(append_listener_placeholder(&mut values));
            }
        } else {
            let mut values = if is_pac_files {
                EDITOR_PAC_FILES.lock().unwrap()
            } else {
                EDITOR_LISTENERS.lock().unwrap()
            };
            match update_editor_list(&mut values, operation, selected) {
                Ok(selection) => new_selection = selection,
                Err(_) => {
                    drop(values);
                    show_message("Unproxy Settings", "At least one item is required.");
                    return;
                }
            }
        }
        let _: () = unsafe { msg_send![table, reloadData] };
        if let Some(index) = new_selection {
            let _: () = unsafe {
                msg_send![table, selectRowIndexes:index_set(index), byExtendingSelection:objc2::runtime::Bool::NO]
            };
            let _: () = unsafe { msg_send![table, scrollRowToVisible:index as isize] };
            if edit_new_row {
                let _: () = unsafe {
                    msg_send![table, editColumn:0isize, row:index as isize, withEvent:ptr::null_mut::<AnyObject>(), select:objc2::runtime::Bool::YES]
                };
            }
        }
        if !edit_new_row && let Err(error) = commit_editor_preferences() {
            show_message("Could not apply this change", &format!("{error:#}"));
        }
    }
    unsafe extern "C-unwind" fn list_editor_window_will_close(
        _this: *mut AnyObject,
        _cmd: Sel,
        _notification: *mut AnyObject,
    ) {
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: () = unsafe { msg_send![app, stopModalWithCode:1000isize] };
    }
    fn change_editor_checkbox(sender: *mut AnyObject, tag: isize) {
        change_editor_checkbox_with(sender, tag, commit_editor_preferences, |message| {
            show_message("Could not apply this change", message)
        });
    }
    fn change_editor_checkbox_with(
        sender: *mut AnyObject,
        tag: isize,
        commit: impl FnOnce() -> Result<()>,
        alert: impl FnOnce(&str),
    ) {
        let enabled: isize = unsafe { msg_send![sender, state] };
        let enabled = enabled != 0;
        {
            let mut current = EDITOR_PREFS.lock().unwrap();
            if let Some(prefs) = current.as_mut() {
                match tag {
                    3001 => prefs.proxytunnel = enabled,
                    3002 => prefs.direct_fallback = enabled,
                    3003 => prefs.negotiate = enabled,
                    _ => return,
                }
            }
        }
        if let Err(error) = commit() {
            let current = STATE
                .lock()
                .unwrap()
                .as_ref()
                .map(|state| state.lock().unwrap().prefs.clone());
            if let Some(current) = current {
                let applied = match tag {
                    3001 => current.proxytunnel,
                    3002 => current.direct_fallback,
                    3003 => current.negotiate,
                    _ => enabled,
                };
                if applied != enabled {
                    let mut draft = EDITOR_PREFS.lock().unwrap();
                    if let Some(prefs) = draft.as_mut() {
                        match tag {
                            3001 => prefs.proxytunnel = applied,
                            3002 => prefs.direct_fallback = applied,
                            3003 => prefs.negotiate = applied,
                            _ => {}
                        }
                    }
                    let _: () =
                        unsafe { msg_send![sender, setState:if applied {1isize}else{0isize}] };
                }
            }
            alert(&format!("{error:#}"));
        }
    }
    fn validated_editor_preferences() -> Result<Preferences> {
        let listeners = EDITOR_LISTENERS.lock().unwrap().clone();
        let parsed = listeners
            .iter()
            .map(|listener| parse_listener(listener))
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(!parsed.is_empty(), "at least one listener is required");
        let mut unique_listeners = std::collections::HashSet::new();
        anyhow::ensure!(
            parsed
                .iter()
                .all(|address| unique_listeners.insert(*address)),
            "listener addresses must be unique"
        );

        let pac_values = EDITOR_PAC_FILES.lock().unwrap().clone();
        anyhow::ensure!(!pac_values.is_empty(), "at least one PAC file is required");
        let mut pac_files = Vec::with_capacity(pac_values.len());
        let mut unique_pac_files = std::collections::HashSet::new();
        for value in pac_values {
            let path = if let Some(uri) = parse_remote_pac_uri(&value)? {
                PathBuf::from(uri.to_string())
            } else {
                let path = PathBuf::from(value.trim());
                anyhow::ensure!(
                    path.is_absolute(),
                    "PAC path must be absolute: {}",
                    path.display()
                );
                anyhow::ensure!(path.is_file(), "PAC file is missing: {}", path.display());
                std::fs::File::open(&path)
                    .with_context(|| format!("could not read PAC file {}", path.display()))?;
                path
            };
            anyhow::ensure!(
                unique_pac_files.insert(path.clone()),
                "PAC source is listed more than once: {}",
                path.display()
            );
            pac_files.push(path);
        }

        let mut updated = EDITOR_PREFS
            .lock()
            .unwrap()
            .clone()
            .context("settings editor is not active")?;
        updated.port = u32::from(parsed[0].port());
        updated.listeners = Some(parsed.iter().map(ToString::to_string).collect());
        updated.pac_file = pac_files[0].clone();
        updated.pac_files = Some(pac_files);
        Ok(updated)
    }
    fn commit_editor_preferences() -> Result<()> {
        let updated = validated_editor_preferences()?;
        let shared = STATE
            .lock()
            .unwrap()
            .as_ref()
            .cloned()
            .context("Unproxy state is unavailable")?;
        let mut state = shared.lock().unwrap();
        if state.prefs == updated {
            return Ok(());
        }
        let restart_required = updated.effective_listeners() != state.prefs.effective_listeners()
            || updated.effective_pac_files() != state.prefs.effective_pac_files()
            || updated.negotiate != state.prefs.negotiate
            || updated.proxytunnel != state.prefs.proxytunnel
            || updated.direct_fallback != state.prefs.direct_fallback;
        let running = state.child.is_running();
        save_native_preferences(
            &updated,
            &state.prefs_path,
            state.defaults as *mut AnyObject,
        )?;
        state.prefs = updated.clone();
        *EDITOR_PREFS.lock().unwrap() = Some(updated.clone());
        if running && restart_required {
            let exe = state.child_exe.clone();
            match state.child.restart(&exe, &updated) {
                Ok(()) => {
                    state.start_failed = false;
                    reset_runtime_status(&mut state);
                }
                Err(error) => {
                    state.start_failed = true;
                    state.last_running = false;
                    return Err(error);
                }
            }
        }
        state.last_running = state.child.is_running();
        Ok(())
    }
    fn settings_window(prefs: &Preferences) -> Result<()> {
        settings_window_with(prefs, |window, _target| {
            let app: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
            let _: () =
                unsafe { msg_send![window, makeKeyAndOrderFront:ptr::null_mut::<AnyObject>()] };
            let _: isize = unsafe { msg_send![app, runModalForWindow:window] };
            Ok(())
        })
    }

    fn settings_window_with(
        prefs: &Preferences,
        present: impl FnOnce(*mut AnyObject, *mut AnyObject) -> Result<()>,
    ) -> Result<()> {
        let (window, target) = build_settings_window(prefs)?;
        present(window, target)?;
        unsafe {
            let _: () = msg_send![window, orderOut:ptr::null_mut::<AnyObject>()];
        }
        *LISTENER_TABLE.lock().unwrap() = 0;
        *PAC_FILE_TABLE.lock().unwrap() = 0;
        Ok(())
    }

    fn build_settings_window(prefs: &Preferences) -> Result<(*mut AnyObject, *mut AnyObject)> {
        *EDITOR_LISTENERS.lock().unwrap() = prefs.effective_listeners();
        *EDITOR_PAC_FILES.lock().unwrap() = prefs
            .effective_pac_files()
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        *EDITOR_PREFS.lock().unwrap() = Some(prefs.clone());

        let allocated: *mut AnyObject = unsafe { msg_send![objc2::class!(NSWindow), alloc] };
        let window: *mut AnyObject = unsafe {
            msg_send![allocated, initWithContentRect:rect(0.0, 0.0, 960.0, 660.0), styleMask:3isize, backing:2isize, defer:objc2::runtime::Bool::NO]
        };
        anyhow::ensure!(!window.is_null(), "could not create the settings window");
        let _: () = unsafe { msg_send![window, setReleasedWhenClosed:objc2::runtime::Bool::NO] };
        let _: () = unsafe { msg_send![window, setTitle:cocoa_string("Unproxy Settings")] };
        let _: () = unsafe { msg_send![window, center] };
        let content: *mut AnyObject = unsafe { msg_send![window, contentView] };
        let target: *mut AnyObject = unsafe { msg_send![action_class(), new] };
        let _: () = unsafe { msg_send![window, setDelegate:target] };

        settings_label(
            content,
            "Changes are applied immediately as you edit.",
            24.0,
            612.0,
            912.0,
            24.0,
            false,
        );
        settings_label(content, "Listeners", 24.0, 570.0, 440.0, 24.0, true);
        settings_label(
            content,
            "Numeric IP and port; put IPv6 addresses in brackets.",
            24.0,
            542.0,
            440.0,
            22.0,
            false,
        );
        settings_label(content, "PAC files", 490.0, 570.0, 446.0, 24.0, true);
        settings_label(
            content,
            "Files or URLs; first non-DIRECT result wins, top to bottom.",
            490.0,
            542.0,
            446.0,
            22.0,
            false,
        );
        let listener_table = settings_list_table(content, target, 1, 24.0, 204.0, 440.0, 320.0);
        let pac_table = settings_list_table(content, target, 2, 490.0, 204.0, 446.0, 320.0);
        *LISTENER_TABLE.lock().unwrap() = listener_table as usize;
        *PAC_FILE_TABLE.lock().unwrap() = pac_table as usize;
        settings_toolbar(content, target, 1100, 24.0);
        settings_toolbar(content, target, 1200, 490.0);
        settings_button(
            content,
            target,
            "Add URL…",
            "Add a remote HTTP or HTTPS PAC URL",
            1207,
            rect(620.0, 168.0, 100.0, 26.0),
            None,
        );
        settings_button(
            content,
            target,
            "Open / View",
            "Open the selected local PAC file or view a remote PAC URL",
            1206,
            rect(728.0, 168.0, 128.0, 26.0),
            None,
        );

        settings_label(
            content,
            "Connection behavior",
            24.0,
            125.0,
            440.0,
            24.0,
            true,
        );
        settings_checkbox(
            content,
            target,
            "Always use CONNECT",
            prefs.proxytunnel,
            3001,
            24.0,
            250.0,
        );
        settings_checkbox(
            content,
            target,
            "DIRECT fallback",
            prefs.direct_fallback,
            3002,
            300.0,
            210.0,
        );
        #[cfg(feature = "negotiate")]
        settings_checkbox(
            content,
            target,
            "Negotiate",
            prefs.negotiate,
            3003,
            540.0,
            170.0,
        );
        settings_button(
            content,
            target,
            "Close",
            "Close settings",
            1000,
            rect(842.0, 22.0, 94.0, 30.0),
            Some("\r"),
        );
        Ok((window, target))
    }
    fn show_settings(shared: &Arc<Mutex<State>>) -> Result<()> {
        let prefs = shared.lock().unwrap().prefs.clone();
        settings_window(&prefs)
    }
    fn open_path(path: &Path) -> Result<()> {
        let status = Command::new("open")
            .arg(path)
            .status()
            .with_context(|| format!("launch the default app for {}", path.display()))?;
        anyhow::ensure!(status.success(), "open command exited with {status}");
        Ok(())
    }
    fn pac_editor_command(path: &Path) -> Command {
        let mut command = Command::new("/usr/bin/open");
        command.arg("-e").arg(path);
        command
    }
    fn open_pac_file(path: &Path) -> Result<()> {
        let output = pac_editor_command(path)
            .output()
            .with_context(|| format!("launch TextEdit for {}", path.display()))?;
        anyhow::ensure!(
            output.status.success(),
            "TextEdit could not open {} ({}): {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
    fn copy_to_clipboard(value: &str) -> Result<()> {
        let pasteboard: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSPasteboard), generalPasteboard] };
        let _: isize = unsafe { msg_send![pasteboard, clearContents] };
        let copied: objc2::runtime::Bool = unsafe {
            msg_send![pasteboard, setString:cocoa_string(value), forType:cocoa_string("public.utf8-plain-text")]
        };
        anyhow::ensure!(
            copied.as_bool(),
            "macOS pasteboard rejected the proxy address"
        );
        Ok(())
    }
    fn show_message(title: &str, message: &str) {
        let alert: *mut AnyObject = unsafe { msg_send![objc2::class!(NSAlert), new] };
        let _: () = unsafe { msg_send![alert, setMessageText:cocoa_string(title)] };
        let _: () = unsafe { msg_send![alert, setInformativeText:cocoa_string(message)] };
        let _: *mut AnyObject = unsafe { msg_send![alert, addButtonWithTitle:cocoa_string("OK")] };
        let _: isize = unsafe { msg_send![alert, runModal] };
    }
    fn set_login_item(enabled: bool) -> Result<()> {
        #[link(name = "ServiceManagement", kind = "framework")]
        unsafe extern "C" {
            fn SMLoginItemSetEnabled(identifier: *mut AnyObject, enabled: u8) -> u8;
        }
        set_login_item_with(enabled, |enabled| unsafe {
            SMLoginItemSetEnabled(cocoa_string(HELPER_BUNDLE_ID), u8::from(enabled)) != 0
        })
    }
    fn set_login_item_with(enabled: bool, update: impl FnOnce(bool) -> bool) -> Result<()> {
        anyhow::ensure!(
            update(enabled),
            "ServiceManagement rejected the login item change"
        );
        Ok(())
    }
    fn native_preferences(defaults_path: &Path) -> Result<(Preferences, *mut AnyObject)> {
        let defaults: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSUserDefaults), standardUserDefaults] };
        Ok((native_preferences_with(defaults, defaults_path)?, defaults))
    }

    fn native_preferences_with(
        defaults: *mut AnyObject,
        defaults_path: &Path,
    ) -> Result<Preferences> {
        let key = |s: &str| cocoa_string(s);
        let get = |name: &str| -> *mut AnyObject {
            unsafe { msg_send![defaults,objectForKey:key(name)] }
        };
        let mut p = Preferences::default();
        let port = get("port");
        if port.is_null() {
            let _: () =
                unsafe { msg_send![defaults,setInteger:p.port as isize,forKey:key("port")] };
        } else {
            let n: isize = unsafe { msg_send![port, integerValue] };
            p.port = n.clamp(0, u32::MAX as isize) as u32;
        }
        let listeners = get("listeners");
        if !listeners.is_null() {
            let count: usize = unsafe { msg_send![listeners, count] };
            let mut values = Vec::with_capacity(count);
            for index in 0..count {
                let item: *mut AnyObject = unsafe { msg_send![listeners, objectAtIndex:index] };
                let bytes: *const std::ffi::c_char = unsafe { msg_send![item, UTF8String] };
                if !bytes.is_null() {
                    values.push(
                        unsafe { std::ffi::CStr::from_ptr(bytes) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
            p.listeners = Some(values);
        }
        let pac = get("pacFile");
        if pac.is_null() {
            let _: () = unsafe {
                msg_send![defaults,setObject:cocoa_string(&p.pac_file.to_string_lossy()),forKey:key("pacFile")]
            };
        } else {
            let c: *const std::ffi::c_char = unsafe { msg_send![pac, UTF8String] };
            if !c.is_null() {
                p.pac_file = PathBuf::from(
                    unsafe { std::ffi::CStr::from_ptr(c) }
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        p.pac_file = resolve_pac_source(p.pac_file)?;
        let pac_files = get("pacFiles");
        if !pac_files.is_null() {
            let count: usize = unsafe { msg_send![pac_files, count] };
            let mut values = Vec::with_capacity(count);
            for index in 0..count {
                let item: *mut AnyObject = unsafe { msg_send![pac_files, objectAtIndex:index] };
                let bytes: *const std::ffi::c_char = unsafe { msg_send![item, UTF8String] };
                if !bytes.is_null() {
                    let path = PathBuf::from(
                        unsafe { std::ffi::CStr::from_ptr(bytes) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                    values.push(resolve_pac_source(path)?);
                }
            }
            if let Some(first) = values.first() {
                p.pac_file = first.clone();
            }
            p.pac_files = Some(values);
        }
        for (name, field) in [
            ("negotiate", 0u8),
            ("proxytunnel", 1),
            ("directFallback", 2),
            ("autostart", 3),
        ] {
            let obj = get(name);
            if obj.is_null() {
                let default = match field {
                    0 => p.negotiate,
                    1 => p.proxytunnel,
                    2 => p.direct_fallback,
                    _ => p.autostart,
                };
                let _: () = unsafe {
                    msg_send![defaults,setBool:objc2::runtime::Bool::new(default),forKey:key(name)]
                };
            } else {
                let b: objc2::runtime::Bool = unsafe { msg_send![obj, boolValue] };
                match field {
                    0 => p.negotiate = b.as_bool(),
                    1 => p.proxytunnel = b.as_bool(),
                    2 => p.direct_fallback = b.as_bool(),
                    _ => p.autostart = b.as_bool(),
                }
            }
        }
        p.save(defaults_path)?;
        Ok(p)
    }
    fn save_native_preferences(p: &Preferences, path: &Path, d: *mut AnyObject) -> Result<()> {
        p.save(path)?;
        let _: () = unsafe { msg_send![d,setInteger:p.port as isize,forKey:cocoa_string("port")] };
        if let Some(listeners) = &p.listeners {
            let array: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMutableArray), new] };
            for listener in listeners {
                let _: () = unsafe { msg_send![array, addObject:cocoa_string(listener)] };
            }
            let _: () = unsafe { msg_send![d,setObject:array,forKey:cocoa_string("listeners")] };
        } else {
            let _: () = unsafe { msg_send![d,removeObjectForKey:cocoa_string("listeners")] };
        }
        if let Some(pac_files) = &p.pac_files {
            let array: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMutableArray), new] };
            for pac_file in pac_files {
                let _: () = unsafe {
                    msg_send![array, addObject:cocoa_string(&pac_file.to_string_lossy())]
                };
            }
            let _: () = unsafe { msg_send![d,setObject:array,forKey:cocoa_string("pacFiles")] };
        } else {
            let _: () = unsafe { msg_send![d,removeObjectForKey:cocoa_string("pacFiles")] };
        }
        let _: () = unsafe {
            msg_send![d,setObject:cocoa_string(&p.pac_file.to_string_lossy()),forKey:cocoa_string("pacFile")]
        };
        let _: () = unsafe {
            msg_send![d,setBool:objc2::runtime::Bool::new(p.negotiate),forKey:cocoa_string("negotiate")]
        };
        let _: () = unsafe {
            msg_send![d,setBool:objc2::runtime::Bool::new(p.proxytunnel),forKey:cocoa_string("proxytunnel")]
        };
        let _: () = unsafe {
            msg_send![d,setBool:objc2::runtime::Bool::new(p.direct_fallback),forKey:cocoa_string("directFallback")]
        };
        let _: () = unsafe {
            msg_send![d,setBool:objc2::runtime::Bool::new(p.autostart),forKey:cocoa_string("autostart")]
        };
        let _: objc2::runtime::Bool = unsafe { msg_send![d, synchronize] };
        Ok(())
    }
    fn menu_item(
        menu: *mut AnyObject,
        title: &str,
        tag: i64,
        state: bool,
        enabled: bool,
        target: *mut AnyObject,
    ) {
        let ns = cocoa_string(title);
        let item: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenuItem), alloc] };
        let item: *mut AnyObject = unsafe {
            msg_send![item, initWithTitle:ns, action:sel!(clicked:), keyEquivalent:cocoa_string("")]
        };
        let _: () = unsafe { msg_send![item, setTarget:target] };
        let _: () = unsafe { msg_send![item, setTag:tag] };
        let _: () = unsafe { msg_send![item, setState:if state {1isize}else{0isize}] };
        let _: () = unsafe { msg_send![item, setEnabled:objc2::runtime::Bool::new(enabled)] };
        let _: () = unsafe { msg_send![menu, addItem:item] };
    }
    pub fn run() -> Result<()> {
        objc2::rc::autoreleasepool(|_| run_inner())
    }
    fn run_inner() -> Result<()> {
        let paths = BundlePaths::from_main_executable(&std::env::current_exe()?)?;
        run_startup(StartupOptions {
            support_dir: support_dir(),
            child_exe: paths.child,
            sample_pac: default_pac_path(),
            defaults: None,
            run_event_loop: true,
            helper_notification: HELPER_TERMINATE_NOTIFICATION.to_owned(),
            login_item: set_login_item,
        })
    }
    struct StartupOptions {
        support_dir: PathBuf,
        child_exe: PathBuf,
        sample_pac: PathBuf,
        defaults: Option<usize>,
        run_event_loop: bool,
        helper_notification: String,
        login_item: fn(bool) -> Result<()>,
    }
    fn run_startup(options: StartupOptions) -> Result<()> {
        let dir = options.support_dir;
        std::fs::create_dir_all(&dir)?;
        use std::os::fd::AsRawFd;
        let instance_lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("controller.lock"))?;
        if unsafe { libc::flock(instance_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Ok(());
        }
        let path = dir.join("preferences.json");
        let (prefs, defaults) = if let Some(defaults) = options.defaults {
            let defaults = defaults as *mut AnyObject;
            (native_preferences_with(defaults, &path)?, defaults)
        } else {
            native_preferences(&path)?
        };
        let exe = options.child_exe;
        let sample_pac = options.sample_pac;
        if !sample_pac.exists() {
            std::fs::write(
                &sample_pac,
                "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
            )?;
        }
        let auth_configured = auth_is_configured(&prefs);
        let state = Arc::new(Mutex::new(State {
            prefs,
            prefs_path: path,
            defaults: defaults as usize,
            child: ChildLifecycle::default(),
            child_exe: exe,
            network_available: None,
            _instance_lock: instance_lock,
            status_button: 0,
            last_running: false,
            start_failed: false,
            notice: None,
            tray_status: TrayStatus {
                authentication_configured: auth_configured,
                authentication_state: if auth_configured {
                    "configured".into()
                } else {
                    "disabled".into()
                },
                ..TrayStatus::default()
            },
            last_icon_key: String::new(),
        }));
        *STATE.lock().unwrap() = Some(state.clone());
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: objc2::runtime::Bool = unsafe { msg_send![app, setActivationPolicy:1isize] };
        {
            let mut s = state.lock().unwrap();
            let exe = s.child_exe.clone();
            let prefs = s.prefs.clone();
            match s.child.start(&exe, &prefs) {
                Ok(()) => {
                    s.start_failed = false;
                    reset_runtime_status(&mut s);
                }
                Err(e) => {
                    s.start_failed = true;
                    s.notice = Some(format!("Could not start Unproxy: {e:#}"));
                }
            }
            s.last_running = s.child.is_running();
            if !s.last_running
                && let Some(exit) = &s.child.last_exit
            {
                s.notice = Some(exit.clone());
            }
            let running = s.last_running;
            refresh_runtime_status(&mut s, running);
        }
        let bar: *mut AnyObject = unsafe { msg_send![objc2::class!(NSStatusBar), systemStatusBar] };
        let item: *mut AnyObject = unsafe { msg_send![bar, statusItemWithLength:-1.0f64] };
        let button: *mut AnyObject = unsafe { msg_send![item, button] };
        {
            let mut s = state.lock().unwrap();
            s.status_button = button as usize;
            let running = s.last_running;
            update_status_button(&mut s, running);
        }
        let cls = action_class();
        let target: *mut AnyObject = unsafe { msg_send![cls, new] };
        let _: () = unsafe { msg_send![app, setDelegate:target] };
        let _: *mut AnyObject = unsafe {
            msg_send![objc2::class!(NSTimer), scheduledTimerWithTimeInterval:1.0f64,target:target,selector:sel!(pollChild:),userInfo:ptr::null_mut::<AnyObject>(),repeats:objc2::runtime::Bool::YES]
        };
        let center: *mut AnyObject = unsafe {
            msg_send![
                objc2::class!(NSDistributedNotificationCenter),
                defaultCenter
            ]
        };
        let _: () = unsafe {
            msg_send![center,addObserver:target,selector:sel!(networkAvailable:),name:cocoa_string(INTERNAL_AVAILABLE_NOTIFICATION),object:ptr::null_mut::<AnyObject>()]
        };
        let _: () = unsafe {
            msg_send![center,addObserver:target,selector:sel!(networkUnavailable:),name:cocoa_string(INTERNAL_UNAVAILABLE_NOTIFICATION),object:ptr::null_mut::<AnyObject>()]
        };
        let _: () = unsafe {
            msg_send![center,postNotificationName:cocoa_string(&options.helper_notification),object:ptr::null_mut::<AnyObject>(),userInfo:ptr::null_mut::<AnyObject>(),deliverImmediately:objc2::runtime::Bool::YES]
        };
        let login_enabled = state.lock().unwrap().prefs.autostart;
        if let Err(e) = (options.login_item)(login_enabled) {
            state.lock().unwrap().notice =
                Some(format!("Could not update Unproxy login startup: {e:#}"));
        }
        let menu: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenu), new] };
        let _: () = unsafe { msg_send![menu, setDelegate:target] };
        let _: () = unsafe { msg_send![item, setMenu:menu] };
        if options.run_event_loop {
            let _: () = unsafe { msg_send![app, run] };
        }
        let _ = state.lock().unwrap().child.stop();
        *STATE.lock().unwrap() = None;
        Ok(())
    }

    pub fn run_helper() -> Result<()> {
        objc2::rc::autoreleasepool(|_| run_helper_inner())
    }
    fn run_helper_inner() -> Result<()> {
        if main_app_is_running() {
            return Ok(());
        }
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: objc2::runtime::Bool = unsafe { msg_send![app,setActivationPolicy:2isize] };
        let superclass = AnyClass::get(c"NSObject").unwrap();
        let mut cb = ClassBuilder::new(c"UnproxyLoginHelper", superclass).unwrap();
        unsafe {
            cb.add_method(
                sel!(terminateHelper:),
                helper_terminate as unsafe extern "C-unwind" fn(_, _, _),
            );
        }
        let cls = cb.register();
        let target: *mut AnyObject = unsafe { msg_send![cls, new] };
        let center: *mut AnyObject = unsafe {
            msg_send![
                objc2::class!(NSDistributedNotificationCenter),
                defaultCenter
            ]
        };
        let _: () = unsafe {
            msg_send![center,addObserver:target,selector:sel!(terminateHelper:),name:cocoa_string(HELPER_TERMINATE_NOTIFICATION),object:ptr::null_mut::<AnyObject>()]
        };
        let status = Command::new("open").args(["-b", APP_BUNDLE_ID]).status()?;
        if !status.success() {
            return Ok(());
        }
        let _: () = unsafe { msg_send![app, run] };
        Ok(())
    }

    pub fn run_main_thread_probe(
        support_dir: &Path,
        child_exe: &Path,
        pac_file: &Path,
    ) -> Result<()> {
        objc2::rc::autoreleasepool(|_| {
            std::fs::create_dir_all(support_dir)?;
            let invocation = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let suite = cocoa_string(&format!(
                "de.m42e.unproxy.test.{}.{}",
                std::process::id(),
                invocation
            ));
            let defaults_class = objc2::class!(NSUserDefaults);
            let allocated: *mut AnyObject = unsafe { msg_send![defaults_class, alloc] };
            let defaults: *mut AnyObject = unsafe { msg_send![allocated, initWithSuiteName:suite] };
            anyhow::ensure!(
                !defaults.is_null(),
                "could not create isolated preferences suite"
            );
            let preferences_path = support_dir.join("preferences.json");

            let initial = native_preferences_with(defaults, &preferences_path)?;
            anyhow::ensure!(initial.port == 3128 && initial.autostart);
            let initialized_port: *mut AnyObject =
                unsafe { msg_send![defaults, objectForKey:cocoa_string("port")] };
            anyhow::ensure!(
                !initialized_port.is_null(),
                "missing native port default was not initialized"
            );

            let relative = cocoa_string("relative.pac");
            let _: () =
                unsafe { msg_send![defaults, setInteger:-1isize, forKey:cocoa_string("port")] };
            let _: () =
                unsafe { msg_send![defaults, setObject:relative, forKey:cocoa_string("pacFile")] };
            let _: () = unsafe {
                msg_send![defaults, setBool:objc2::runtime::Bool::YES, forKey:cocoa_string("negotiate")]
            };
            let _: () = unsafe {
                msg_send![defaults, setBool:objc2::runtime::Bool::YES, forKey:cocoa_string("proxytunnel")]
            };
            let _: () = unsafe {
                msg_send![defaults, setBool:objc2::runtime::Bool::YES, forKey:cocoa_string("directFallback")]
            };
            let _: () = unsafe {
                msg_send![defaults, setBool:objc2::runtime::Bool::NO, forKey:cocoa_string("autostart")]
            };
            let native_listeners: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSMutableArray), new] };
            let _: () =
                unsafe { msg_send![native_listeners, addObject:cocoa_string("127.0.0.1:3128")] };
            let _: () = unsafe {
                msg_send![defaults, setObject:native_listeners, forKey:cocoa_string("listeners")]
            };
            let native_pac_files: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSMutableArray), new] };
            let _: () =
                unsafe { msg_send![native_pac_files, addObject:cocoa_string("relative.pac")] };
            let _: () = unsafe {
                msg_send![native_pac_files, addObject:cocoa_string(&pac_file.to_string_lossy())]
            };
            let _: () = unsafe {
                msg_send![defaults, setObject:native_pac_files, forKey:cocoa_string("pacFiles")]
            };
            let loaded = native_preferences_with(defaults, &preferences_path)?;
            anyhow::ensure!(loaded.port == 0 && loaded.effective_port() == 3128);
            anyhow::ensure!(loaded.pac_file == std::env::current_dir()?.join("relative.pac"));
            anyhow::ensure!(
                loaded.listeners.as_deref() == Some(&["127.0.0.1:3128".to_owned()][..])
            );
            anyhow::ensure!(loaded.effective_pac_files().len() == 2);
            anyhow::ensure!(loaded.effective_pac_files()[1] == pac_file);
            anyhow::ensure!(loaded.negotiate && loaded.proxytunnel && loaded.direct_fallback);
            anyhow::ensure!(!loaded.autostart);
            let bad_path = support_dir.join("not-a-directory");
            std::fs::write(&bad_path, "blocker")?;
            anyhow::ensure!(
                native_preferences_with(defaults, &bad_path.join("prefs.json")).is_err()
            );

            let mut prefs = Preferences {
                port: 65535,
                listeners: None,
                pac_file: pac_file.to_owned(),
                pac_files: None,
                negotiate: true,
                proxytunnel: false,
                direct_fallback: false,
                autostart: true,
            };
            save_native_preferences(&prefs, &preferences_path, defaults)?;
            let roundtrip = native_preferences_with(defaults, &preferences_path)?;
            anyhow::ensure!(roundtrip == prefs, "native preferences did not roundtrip");

            use std::os::unix::process::ExitStatusExt;
            let mut captured_script = None;
            let answer = prompt_with("Path \"one\"\\two", "old \"path\"", |script| {
                captured_script = Some(script.to_owned());
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: b"button returned: Save, text returned: /tmp/new.pac\n".to_vec(),
                    stderr: vec![],
                })
            });
            anyhow::ensure!(answer.as_deref() == Some("/tmp/new.pac"));
            let script = captured_script.unwrap();
            anyhow::ensure!(script.contains("Path \\\"one\\\"\\\\two"));
            anyhow::ensure!(script.contains("old \\\"path\\\""));
            let cancelled = prompt_with("Cancel", "value", |_| {
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(1),
                    stdout: b"".to_vec(),
                    stderr: vec![],
                })
            });
            anyhow::ensure!(cancelled.is_none());
            anyhow::ensure!(
                prompt_with("Malformed", "value", |_| {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(0),
                        stdout: b"no returned text".to_vec(),
                        stderr: vec![],
                    })
                })
                .is_none()
            );
            anyhow::ensure!(
                prompt_with("Unavailable", "value", |_| {
                    Err(std::io::Error::other("fixture command unavailable"))
                })
                .is_none()
            );
            set_login_item_with(true, |requested| requested)?;
            anyhow::ensure!(set_login_item_with(false, |requested| requested).is_err());

            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            prefs.port = u32::from(listener.local_addr()?.port());
            drop(listener);
            save_native_preferences(&prefs, &preferences_path, defaults)?;

            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(support_dir.join("controller.lock"))?;
            let app: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
            let _: objc2::runtime::Bool = unsafe { msg_send![app, setActivationPolicy:1isize] };
            let child = ChildLifecycle::with_support_dir(support_dir.to_owned());
            let state = Arc::new(Mutex::new(State {
                prefs: prefs.clone(),
                prefs_path: preferences_path,
                defaults: defaults as usize,
                child,
                child_exe: child_exe.to_owned(),
                network_available: None,
                _instance_lock: lock,
                status_button: 0,
                last_running: false,
                start_failed: false,
                notice: None,
                tray_status: TrayStatus::default(),
                last_icon_key: String::new(),
            }));
            *STATE.lock().unwrap() = Some(state.clone());
            exercise_runtime_status_probe()?;
            exercise_tray_status(&state)?;
            probe_settings_editor(&state, &prefs, support_dir, pac_file)?;
            let actions = action_class();
            let target: *mut AnyObject = unsafe { msg_send![actions, new] };
            let menu: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenu), new] };
            let _: () = unsafe { msg_send![menu, setDelegate:target] };

            unsafe { network_available(target, sel!(networkAvailable:), ptr::null_mut()) };
            unsafe { rebuild_menu(target, sel!(menuNeedsUpdate:), menu) };
            anyhow::ensure!(menu_has_tag(menu, 1), "stopped menu lacks Start");
            anyhow::ensure!(
                menu_has_tag(menu, 9)
                    && menu_has_tag(menu, 10)
                    && menu_has_tag(menu, 11)
                    && menu_has_tag(menu, 12),
                "menu is missing a requested action"
            );

            unsafe { send_action(3) };
            unsafe { send_action(4) };
            unsafe { send_action(5) };
            {
                let state = state.lock().unwrap();
                anyhow::ensure!(state.prefs.proxytunnel && state.prefs.direct_fallback);
                #[cfg(feature = "negotiate")]
                anyhow::ensure!(!state.prefs.negotiate);
                anyhow::ensure!(
                    Preferences::load(&state.prefs_path)? == state.prefs,
                    "action changes were not persisted"
                );
            }
            unsafe { network_unavailable(target, sel!(networkUnavailable:), ptr::null_mut()) };
            unsafe { rebuild_menu(target, sel!(menuNeedsUpdate:), menu) };

            unsafe { send_action(1) };
            anyhow::ensure!(
                state.lock().unwrap().child.is_running(),
                "Start action did not launch child"
            );
            unsafe { poll_child(target, sel!(pollChild:), ptr::null_mut()) };
            unsafe { rebuild_menu(target, sel!(menuNeedsUpdate:), menu) };
            anyhow::ensure!(menu_has_tag(menu, 2), "running menu lacks Stop");
            anyhow::ensure!(!menu_has_tag(menu, 1), "running menu still offers Start");
            anyhow::ensure!(menu_has_tag(menu, 12), "running menu lacks Settings");
            let shared = STATE.lock().unwrap().as_ref().unwrap().clone();
            let guard = shared.lock().unwrap();
            unsafe { poll_child(target, sel!(pollChild:), ptr::null_mut()) };
            drop(guard);

            let edit_values = std::cell::RefCell::new(std::collections::VecDeque::from([
                "0".to_owned(),
                "relative.pac".to_owned(),
                pac_file.to_string_lossy().into_owned(),
                state.lock().unwrap().prefs.port.to_string(),
            ]));
            let prompt_calls = std::cell::RefCell::new(Vec::new());
            let alert_calls = std::cell::RefCell::new(Vec::new());
            let reject_login = std::cell::Cell::new(true);
            let mut action_services = ActionServices {
                prompt: |message: &str, current: &str| {
                    prompt_calls
                        .borrow_mut()
                        .push((message.to_owned(), current.to_owned()));
                    edit_values.borrow_mut().pop_front()
                },
                alert: |message: &str| alert_calls.borrow_mut().push(message.to_owned()),
                save: |prefs: &Preferences, path: &Path, defaults: usize| {
                    save_native_preferences(prefs, path, defaults as *mut AnyObject)
                },
                login_item: |enabled| {
                    if reject_login.get() {
                        Err(anyhow::anyhow!("fixture refused {enabled}"))
                    } else {
                        Ok(())
                    }
                },
            };
            {
                let mut current = state.lock().unwrap();
                let previous_tunnel = current.prefs.proxytunnel;
                anyhow::ensure!(!handle_action(&mut current, 3, &mut action_services));
                anyhow::ensure!(current.prefs.proxytunnel != previous_tunnel);
                anyhow::ensure!(
                    current.child.is_running(),
                    "running toggle did not restart child"
                );
                let initial_port = current.prefs.port;
                anyhow::ensure!(!handle_action(&mut current, 7, &mut action_services));
                anyhow::ensure!(current.prefs.port == initial_port);
                anyhow::ensure!(!handle_action(&mut current, 8, &mut action_services));
                anyhow::ensure!(current.prefs.pac_file == pac_file);
                anyhow::ensure!(!handle_action(&mut current, 8, &mut action_services));
                anyhow::ensure!(!handle_action(&mut current, 7, &mut action_services));
                anyhow::ensure!(current.prefs.port == initial_port);
                anyhow::ensure!(
                    Preferences::load(&current.prefs_path)? == current.prefs,
                    "accepted edit values were not persisted"
                );
                let login_enabled = current.prefs.autostart;
                anyhow::ensure!(!handle_action(&mut current, 9, &mut action_services));
                anyhow::ensure!(current.prefs.autostart == login_enabled);
                anyhow::ensure!(
                    Preferences::load(&current.prefs_path)? == current.prefs,
                    "rejected login-item change was not rolled back"
                );
                current.prefs.autostart = false;
                reject_login.set(false);
                anyhow::ensure!(!handle_action(&mut current, 9, &mut action_services));
                anyhow::ensure!(current.prefs.autostart);
                anyhow::ensure!(handle_action(&mut current, 6, &mut action_services));
                anyhow::ensure!(!current.child.is_running());
                current.child_exe = support_dir.join("missing-child");
                anyhow::ensure!(!handle_action(&mut current, 1, &mut action_services));
                anyhow::ensure!(!current.last_running);
            }
            anyhow::ensure!(prompt_calls.borrow().len() == 4);
            anyhow::ensure!(
                alert_calls
                    .borrow()
                    .iter()
                    .any(|m| m.contains("Port must be"))
            );
            anyhow::ensure!(
                alert_calls
                    .borrow()
                    .iter()
                    .any(|m| m.contains("PAC path must"))
            );
            anyhow::ensure!(
                alert_calls
                    .borrow()
                    .iter()
                    .any(|m| m.contains("fixture refused"))
            );
            anyhow::ensure!(
                alert_calls
                    .borrow()
                    .iter()
                    .any(|m| m.contains("Could not start"))
            );
            unsafe { send_action(2) };
            anyhow::ensure!(!state.lock().unwrap().child.is_running());
            unsafe {
                application_will_terminate(target, sel!(applicationWillTerminate:), ptr::null_mut())
            };
            unsafe { send_action(999) };
            *STATE.lock().unwrap() = None;
            let suite_name = cocoa_string(&format!("de.m42e.unproxy.test.{}", std::process::id()));
            let _: () = unsafe { msg_send![defaults, removePersistentDomainForName:suite_name] };

            let startup_dir = support_dir.join("startup-probe");
            let available_port = std::net::TcpListener::bind(("127.0.0.1", 0))?
                .local_addr()?
                .port();
            let _: () = unsafe {
                msg_send![defaults, setInteger:available_port as isize, forKey:cocoa_string("port")]
            };
            let _: () = unsafe {
                msg_send![defaults, setObject:cocoa_string(&pac_file.to_string_lossy()), forKey:cocoa_string("pacFile")]
            };
            fn ignore_login_item(_: bool) -> Result<()> {
                Ok(())
            }
            let sample = startup_dir.join("proxy.pac");
            run_startup(StartupOptions {
                support_dir: startup_dir.clone(),
                child_exe: child_exe.to_owned(),
                sample_pac: sample.clone(),
                defaults: Some(defaults as usize),
                run_event_loop: false,
                helper_notification: format!(
                    "de.m42e.unproxy.test.{}.terminate",
                    std::process::id()
                ),
                login_item: ignore_login_item,
            })?;
            anyhow::ensure!(
                sample.is_file(),
                "startup did not create its sample PAC file"
            );
            anyhow::ensure!(startup_dir.join("preferences.json").is_file());
            anyhow::ensure!(startup_dir.join("controller.lock").is_file());
            anyhow::ensure!(STATE.lock().unwrap().is_none());

            fn reject_login_item(enabled: bool) -> Result<()> {
                anyhow::bail!("fixture rejected login item {enabled}")
            }
            let failed_startup_dir = support_dir.join("startup-failure-probe");
            let failed_sample = failed_startup_dir.join("proxy.pac");
            run_startup(StartupOptions {
                support_dir: failed_startup_dir.clone(),
                child_exe: support_dir.join("missing-startup-child"),
                sample_pac: failed_sample.clone(),
                defaults: Some(defaults as usize),
                run_event_loop: false,
                helper_notification: format!("de.m42e.unproxy.test.{}.failure", std::process::id()),
                login_item: reject_login_item,
            })?;
            anyhow::ensure!(failed_sample.is_file());
            anyhow::ensure!(STATE.lock().unwrap().is_none());

            use std::os::fd::AsRawFd;
            let held_lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(failed_startup_dir.join("controller.lock"))?;
            anyhow::ensure!(unsafe {
                libc::flock(held_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0
            });
            run_startup(StartupOptions {
                support_dir: failed_startup_dir,
                child_exe: child_exe.to_owned(),
                sample_pac: failed_sample,
                defaults: Some(defaults as usize),
                run_event_loop: false,
                helper_notification: format!(
                    "de.m42e.unproxy.test.{}.already-running",
                    std::process::id()
                ),
                login_item: ignore_login_item,
            })?;
            let _ = unsafe { libc::flock(held_lock.as_raw_fd(), libc::LOCK_UN) };
            Ok(())
        })
    }

    fn probe_settings_editor(
        state: &Arc<Mutex<State>>,
        prefs: &Preferences,
        support_dir: &Path,
        pac_file: &Path,
    ) -> Result<()> {
        settings_window_with(prefs, |window, target| {
            let listener_table = *LISTENER_TABLE.lock().unwrap() as *mut AnyObject;
            let pac_table = *PAC_FILE_TABLE.lock().unwrap() as *mut AnyObject;
            anyhow::ensure!(!listener_table.is_null() && !pac_table.is_null());
            let content: *mut AnyObject = unsafe { msg_send![window, contentView] };
            let subviews: *mut AnyObject = unsafe { msg_send![content, subviews] };
            let subview_count: usize = unsafe { msg_send![subviews, count] };
            let mut has_open_view = false;
            let mut has_add_url = false;
            for index in 0..subview_count {
                let subview: *mut AnyObject = unsafe { msg_send![subviews, objectAtIndex:index] };
                let tag: isize = unsafe { msg_send![subview, tag] };
                has_open_view |= tag == 1206;
                has_add_url |= tag == 1207;
            }
            anyhow::ensure!(
                has_open_view,
                "settings window has no Open / View PAC button"
            );
            anyhow::ensure!(has_add_url, "settings window has no Add URL button");
            let original_listeners = prefs.effective_listeners();

            let listener_rows: isize =
                unsafe { msg_send![target, numberOfRowsInTableView:listener_table] };
            anyhow::ensure!(
                listener_rows == original_listeners.len() as isize,
                "settings listener table has {listener_rows} rows; expected {}",
                original_listeners.len()
            );
            let first_listener: *mut AnyObject = unsafe {
                msg_send![target, tableView:listener_table, objectValueForTableColumn:ptr::null_mut::<AnyObject>(), row:0isize]
            };
            anyhow::ensure!(
                cocoa_text(first_listener).as_deref()
                    == prefs.effective_listeners().first().map(String::as_str),
                "settings listener table returned the wrong value"
            );
            let pac_rows: isize = unsafe { msg_send![target, numberOfRowsInTableView:pac_table] };
            anyhow::ensure!(pac_rows == 1, "settings PAC table has the wrong row count");
            let first_pac: *mut AnyObject = unsafe {
                msg_send![target, tableView:pac_table, objectValueForTableColumn:ptr::null_mut::<AnyObject>(), row:0isize]
            };
            anyhow::ensure!(cocoa_text(first_pac).is_some());
            anyhow::ensure!(
                unsafe {
                    list_object_value(
                        target,
                        sel!(tableView:objectValueForTableColumn:row:),
                        listener_table,
                        ptr::null_mut(),
                        -1,
                    )
                }
                .is_null()
            );
            unsafe {
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    listener_table,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    -1,
                );
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    listener_table,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                );
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    listener_table,
                    cocoa_string("127.0.0.2:3128"),
                    ptr::null_mut(),
                    10,
                );
            }
            let alternate_port = if prefs.port >= 65534 {
                prefs.port - 1
            } else {
                prefs.port + 1
            };
            let alternate_listener = format!("127.0.0.2:{alternate_port}");
            unsafe {
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    listener_table,
                    cocoa_string(&alternate_listener),
                    ptr::null_mut(),
                    0,
                );
            }
            anyhow::ensure!(
                state.lock().unwrap().prefs.listeners.as_ref().unwrap()[0] == alternate_listener,
                "editing a listener did not update preferences"
            );
            unsafe {
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    listener_table,
                    cocoa_string(&original_listeners[0]),
                    ptr::null_mut(),
                    0,
                );
            }
            anyhow::ensure!(
                state.lock().unwrap().prefs.effective_listeners() == original_listeners,
                "editing a listener back did not restore preferences"
            );

            unsafe {
                let _: () = msg_send![listener_table, selectRowIndexes:index_set(0), byExtendingSelection:objc2::runtime::Bool::NO];
                send_editor_action(1105, None);
            }
            anyhow::ensure!(
                *EDITOR_LISTENERS.lock().unwrap()
                    == vec![original_listeners[1].clone(), original_listeners[0].clone()],
                "moving a listener down did not reorder it"
            );
            unsafe { send_editor_action(1104, None) };
            anyhow::ensure!(*EDITOR_LISTENERS.lock().unwrap() == original_listeners);
            unsafe { send_editor_action(1103, None) };
            anyhow::ensure!(
                *EDITOR_LISTENERS.lock().unwrap() == vec![original_listeners[1].clone()],
                "removing a listener did not update the table"
            );
            *EDITOR_LISTENERS.lock().unwrap() = original_listeners.clone();
            commit_editor_preferences()?;
            anyhow::ensure!(
                state.lock().unwrap().prefs.effective_listeners() == original_listeners
            );

            use std::os::unix::fs::PermissionsExt;
            let fixture_child = support_dir.join("settings-probe-child");
            std::fs::write(&fixture_child, "#!/bin/sh\nexec /bin/sleep 60\n")?;
            let mut permissions = std::fs::metadata(&fixture_child)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&fixture_child, permissions)?;
            let original_child = state.lock().unwrap().child_exe.clone();
            {
                let mut current = state.lock().unwrap();
                current.child_exe = fixture_child.clone();
                let child_prefs = current.prefs.clone();
                current.child.start(&fixture_child, &child_prefs)?;
                anyhow::ensure!(current.child.is_running());
            }
            EDITOR_LISTENERS.lock().unwrap()[0] = alternate_listener.clone();
            commit_editor_preferences()?;
            anyhow::ensure!(state.lock().unwrap().child.is_running());
            EDITOR_LISTENERS.lock().unwrap()[0] = original_listeners[0].clone();
            commit_editor_preferences()?;
            anyhow::ensure!(state.lock().unwrap().child.is_running());

            {
                state.lock().unwrap().child_exe = support_dir.join("missing-restart-child");
            }
            EDITOR_LISTENERS.lock().unwrap()[0] = alternate_listener;
            anyhow::ensure!(
                commit_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("start")
            );
            {
                let mut current = state.lock().unwrap();
                anyhow::ensure!(current.start_failed && !current.child.is_running());
                current.child_exe = original_child;
                current.start_failed = false;
                current.last_running = false;
            }
            EDITOR_LISTENERS.lock().unwrap()[0] = original_listeners[0].clone();
            commit_editor_preferences()?;

            let alternate_pac = support_dir.join("alternate.pac");
            std::fs::write(
                &alternate_pac,
                "function FindProxyForURL(){return 'DIRECT';}\n",
            )?;
            unsafe {
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    pac_table,
                    cocoa_string(&alternate_pac.to_string_lossy()),
                    ptr::null_mut(),
                    0,
                );
            }
            anyhow::ensure!(
                state.lock().unwrap().prefs.pac_file == alternate_pac,
                "editing a PAC path was not applied"
            );
            unsafe {
                list_set_object_value(
                    target,
                    sel!(tableView:setObjectValue:forTableColumn:row:),
                    pac_table,
                    cocoa_string(&pac_file.to_string_lossy()),
                    ptr::null_mut(),
                    0,
                );
            }
            let checkbox: *mut AnyObject = unsafe { msg_send![objc2::class!(NSButton), new] };
            unsafe {
                let _: () = msg_send![checkbox, setState:1isize];
            }
            let rollback_alert = std::cell::RefCell::new(None::<String>);
            change_editor_checkbox_with(
                checkbox,
                3001,
                || Err(anyhow::anyhow!("fixture save rejected")),
                |message| *rollback_alert.borrow_mut() = Some(message.to_owned()),
            );
            let checkbox_state: isize = unsafe { msg_send![checkbox, state] };
            anyhow::ensure!(checkbox_state == 0);
            anyhow::ensure!(!state.lock().unwrap().prefs.proxytunnel);
            anyhow::ensure!(!EDITOR_PREFS.lock().unwrap().as_ref().unwrap().proxytunnel);
            anyhow::ensure!(
                rollback_alert
                    .borrow()
                    .as_deref()
                    .is_some_and(|message| message.contains("fixture save rejected"))
            );
            unsafe {
                let no_selection: *mut AnyObject = msg_send![objc2::class!(NSIndexSet), indexSet];
                let _: () = msg_send![listener_table, selectRowIndexes:no_selection, byExtendingSelection:objc2::runtime::Bool::NO];
                send_editor_action(1103, None);
                send_editor_action(1104, None);
                send_editor_action(1105, None);
                *LISTENER_TABLE.lock().unwrap() = 0;
                send_editor_action(1102, None);
                *LISTENER_TABLE.lock().unwrap() = listener_table as usize;
                send_editor_action(9999, None);
                send_editor_action(3001, Some(true));
                send_editor_action(3002, Some(true));
                #[cfg(feature = "negotiate")]
                send_editor_action(3003, Some(false));
                send_editor_action(3002, Some(false));
                send_editor_action(3001, Some(false));
                #[cfg(feature = "negotiate")]
                send_editor_action(3003, Some(true));
            }

            let valid_listener = prefs.effective_listeners()[0].clone();
            let valid_pac = pac_file.to_string_lossy().into_owned();
            *EDITOR_LISTENERS.lock().unwrap() = Vec::new();
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("at least one listener")
            );
            *EDITOR_LISTENERS.lock().unwrap() = vec!["invalid listener".into()];
            anyhow::ensure!(validated_editor_preferences().is_err());
            *EDITOR_LISTENERS.lock().unwrap() =
                vec![valid_listener.clone(), valid_listener.clone()];
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("unique")
            );
            *EDITOR_LISTENERS.lock().unwrap() = vec![valid_listener];
            *EDITOR_PAC_FILES.lock().unwrap() = Vec::new();
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("at least one PAC file")
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec!["relative.pac".into()];
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("must be absolute")
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec![
                support_dir
                    .join("missing.pac")
                    .to_string_lossy()
                    .into_owned(),
            ];
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("is missing")
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec![valid_pac.clone(), valid_pac.clone()];
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("more than once")
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec![valid_pac.clone()];
            anyhow::ensure!(validated_editor_preferences().is_ok());
            *EDITOR_PAC_FILES.lock().unwrap() =
                vec!["HTTPS://proxy.example.org/company.pac".into()];
            let remote_prefs = validated_editor_preferences()?;
            anyhow::ensure!(
                remote_prefs.effective_pac_files()[0]
                    == Path::new("https://proxy.example.org/company.pac"),
                "settings editor did not preserve the remote PAC URL"
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec![
                "https://proxy.example.org/company.pac".into(),
                "HTTPS://proxy.example.org/company.pac".into(),
            ];
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("more than once")
            );
            *EDITOR_PAC_FILES.lock().unwrap() = vec![valid_pac];
            *EDITOR_PREFS.lock().unwrap() = None;
            anyhow::ensure!(
                validated_editor_preferences()
                    .unwrap_err()
                    .to_string()
                    .contains("not active")
            );
            let mut current = state.lock().unwrap();
            let defaults = current.defaults as *mut AnyObject;
            save_native_preferences(prefs, &current.prefs_path, defaults)?;
            current.prefs = prefs.clone();
            current.last_running = current.child.is_running();
            drop(current);
            *EDITOR_LISTENERS.lock().unwrap() = prefs.effective_listeners();
            *EDITOR_PAC_FILES.lock().unwrap() = prefs
                .effective_pac_files()
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect();
            *EDITOR_PREFS.lock().unwrap() = Some(prefs.clone());
            Ok(())
        })
    }

    fn exercise_runtime_status_probe() -> Result<()> {
        let checked_at = chrono::Utc::now().timestamp();
        let body = serde_json::json!({
            "pac_loaded": true,
            "authentication_configured": true,
            "upstream_state": "ok",
            "authentication_state": "authenticated",
            "upstream_checked_at": checked_at,
        })
        .to_string();
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        let status = parse_runtime_status_response(response.as_bytes())
            .context("parse populated runtime status")?;
        anyhow::ensure!(status.pac_loaded == Some(true));
        anyhow::ensure!(status.authentication_configured);
        anyhow::ensure!(status.upstream_state == "ok");
        anyhow::ensure!(status.authentication_state == "authenticated");
        anyhow::ensure!(status.upstream_checked_at == Some(checked_at));

        let status = parse_runtime_status_response(b"HTTP/1.1 200 OK\r\n\r\n{}")
            .context("parse empty runtime status")?;
        anyhow::ensure!(status.pac_loaded.is_none());
        anyhow::ensure!(!status.authentication_configured);
        anyhow::ensure!(status.upstream_state == "unknown");
        anyhow::ensure!(status.authentication_state == "unknown");
        anyhow::ensure!(status.upstream_checked_at.is_none());
        anyhow::ensure!(parse_runtime_status_response(b"malformed").is_none());
        anyhow::ensure!(
            parse_runtime_status_response(b"HTTP/1.1 200 OK\r\n\r\nnot-json").is_none()
        );

        Ok(())
    }

    fn exercise_tray_status(state: &Arc<Mutex<State>>) -> Result<()> {
        let mut state = state.lock().unwrap();
        let original_status = state.tray_status.clone();
        let original_start_failed = state.start_failed;
        let result = (|| {
            state.tray_status = TrayStatus::default();
            state.start_failed = false;
            anyhow::ensure!(
                icon_statuses(&state, false) == ("stopped", "unloaded", "unknown", "disabled")
            );
            let labels = status_labels(&state, false);
            anyhow::ensure!(labels.0 == "Stopped" && labels.1 == "Not loaded");
            anyhow::ensure!(labels.2 == "No recent proxy request");
            anyhow::ensure!(labels.3 == "Not configured");

            state.start_failed = true;
            anyhow::ensure!(icon_statuses(&state, false).0 == "failed");
            anyhow::ensure!(status_labels(&state, false).0 == "Stopped unexpectedly");
            state.start_failed = false;

            state.tray_status = TrayStatus {
                pac_loaded: Some(true),
                authentication_configured: true,
                upstream_state: "ok".into(),
                authentication_state: "authenticated".into(),
                upstream_checked_at: Some(chrono::Utc::now().timestamp()),
            };
            anyhow::ensure!(
                icon_statuses(&state, true) == ("running", "loaded", "ok", "authenticated")
            );
            let labels = status_labels(&state, true);
            anyhow::ensure!(labels.0 == "Running" && labels.1 == "Loaded");
            anyhow::ensure!(labels.2 == "Last proxy request succeeded");
            anyhow::ensure!(labels.3 == "Accepted on last request");

            state.tray_status.upstream_state = "error".into();
            state.tray_status.authentication_state = "rejected".into();
            anyhow::ensure!(icon_statuses(&state, true).2 == "error");
            anyhow::ensure!(icon_statuses(&state, true).3 == "rejected");
            anyhow::ensure!(status_labels(&state, true).2 == "Last proxy request failed");
            anyhow::ensure!(status_labels(&state, true).3 == "Rejected by upstream (407)");

            state.tray_status.upstream_checked_at =
                Some(chrono::Utc::now().timestamp().saturating_sub(301));
            anyhow::ensure!(icon_statuses(&state, true).2 == "unknown");
            anyhow::ensure!(icon_statuses(&state, true).3 == "configured");
            anyhow::ensure!(status_labels(&state, true).2 == "No recent proxy request");
            anyhow::ensure!(status_labels(&state, true).3 == "Configured; not verified yet");

            state.tray_status.upstream_checked_at =
                Some(chrono::Utc::now().timestamp().saturating_add(1));
            anyhow::ensure!(!upstream_is_recent(&state.tray_status));
            Ok(())
        })();
        state.tray_status = original_status;
        state.start_failed = original_start_failed;
        result
    }

    unsafe fn send_editor_action(tag: isize, state: Option<bool>) {
        let sender: *mut AnyObject = unsafe { msg_send![objc2::class!(NSButton), new] };
        let _: () = unsafe { msg_send![sender, setTag:tag] };
        if let Some(state) = state {
            let _: () = unsafe { msg_send![sender, setState:if state {1isize}else{0isize}] };
        }
        unsafe { list_editor_action(ptr::null_mut(), sel!(listEditorAction:), sender) };
    }

    unsafe fn send_action(tag: i64) {
        let item: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenuItem), alloc] };
        let item: *mut AnyObject = unsafe {
            msg_send![item, initWithTitle:cocoa_string("probe"), action:sel!(clicked:), keyEquivalent:cocoa_string("")]
        };
        let _: () = unsafe { msg_send![item, setTag:tag] };
        unsafe { action(ptr::null_mut(), sel!(clicked:), item) };
    }

    fn menu_has_tag(menu: *mut AnyObject, wanted: i64) -> bool {
        let count: isize = unsafe { msg_send![menu, numberOfItems] };
        (0..count).any(|index| {
            let item: *mut AnyObject = unsafe { msg_send![menu, itemAtIndex:index] };
            let tag: i64 = unsafe { msg_send![item, tag] };
            tag == wanted
        })
    }

    #[cfg(test)]
    mod editor_list_tests {
        use super::*;

        #[test]
        fn pac_files_open_in_textedit_without_relying_on_file_associations() {
            let path = Path::new("/tmp/my proxy.pac");
            let command = pac_editor_command(path);
            assert_eq!(command.get_program(), "/usr/bin/open");
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                vec![std::ffi::OsStr::new("-e"), path.as_os_str()]
            );
        }

        #[test]
        fn editor_list_items_can_be_added_moved_and_removed() {
            let mut values = vec!["first".to_owned(), "second".to_owned()];
            assert_eq!(append_listener_placeholder(&mut values), 2);
            assert_eq!(values, ["first", "second", ""]);

            assert_eq!(
                update_editor_list(&mut values, 4, Some(2)).unwrap(),
                Some(1)
            );
            assert_eq!(values, ["first", "", "second"]);
            assert_eq!(
                update_editor_list(&mut values, 5, Some(1)).unwrap(),
                Some(2)
            );
            assert_eq!(values, ["first", "second", ""]);
            assert_eq!(
                update_editor_list(&mut values, 3, Some(2)).unwrap(),
                Some(1)
            );
            assert_eq!(values, ["first", "second"]);
        }

        #[test]
        fn editor_list_actions_handle_boundaries_and_reject_removing_last_item() {
            let mut values = vec!["first".to_owned(), "second".to_owned()];
            assert_eq!(
                update_editor_list(&mut values, 4, Some(0)).unwrap(),
                Some(0)
            );
            assert_eq!(
                update_editor_list(&mut values, 5, Some(1)).unwrap(),
                Some(1)
            );
            assert_eq!(update_editor_list(&mut values, 3, None).unwrap(), None);
            assert_eq!(values, ["first", "second"]);

            let mut only_item = vec!["only".to_owned()];
            assert!(
                update_editor_list(&mut only_item, 3, Some(0))
                    .unwrap_err()
                    .to_string()
                    .contains("at least one item")
            );
            assert_eq!(only_item, ["only"]);
        }
    }
}

pub fn launch_helper_main_app() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").args(["-b", APP_BUNDLE_ID]).status();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_pac_uris_are_validated_and_scheme_is_normalized() {
        let http = parse_remote_pac_uri("HTTP://proxy.example.org/company.pac")
            .unwrap()
            .unwrap();
        assert_eq!(http.to_string(), "http://proxy.example.org/company.pac");
        let uri = parse_remote_pac_uri("HTTPS://proxy.example.org/company.pac?team=a")
            .unwrap()
            .unwrap();
        assert_eq!(
            uri.to_string(),
            "https://proxy.example.org/company.pac?team=a"
        );
        assert!(
            parse_remote_pac_uri("https://user:password@proxy.example.org/policy.pac").is_err()
        );
        assert!(parse_remote_pac_uri("https:///policy.pac").is_err());
        assert!(
            parse_remote_pac_uri("ftp://proxy.example.org/policy.pac")
                .unwrap()
                .is_none()
        );
        assert!(parse_remote_pac_uri("/tmp/company.pac").unwrap().is_none());
        assert_eq!(
            resolve_pac_source(PathBuf::from("HTTPS://proxy.example.org/company.pac")).unwrap(),
            PathBuf::from("https://proxy.example.org/company.pac")
        );
        assert_eq!(
            resolve_pac_source(PathBuf::from("proxy.pac")).unwrap(),
            std::env::current_dir().unwrap().join("proxy.pac")
        );
        let absolute = std::env::current_exe().unwrap();
        assert_eq!(resolve_pac_source(absolute.clone()).unwrap(), absolute);
    }

    #[cfg(unix)]
    fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    fn effective_port_accepts_only_the_supported_inclusive_range() {
        for (saved, expected) in [
            (0, 3128),
            (1023, 3128),
            (1024, 1024),
            (65534, 65534),
            (65535, 3128),
            (u32::MAX, 3128),
        ] {
            assert_eq!(
                Preferences {
                    port: saved,
                    ..Preferences::default()
                }
                .effective_port(),
                expected
            );
        }
    }

    #[test]
    fn desktop_defaults_override_only_the_specified_preferences() {
        let mut preferences = Preferences::default();
        DesktopDefaults {
            port: Some(4321),
            pac_file: Some(PathBuf::from("custom/proxy.pac")),
            negotiate: Some(true),
            proxytunnel: Some(true),
            direct_fallback: Some(true),
            autostart: Some(false),
        }
        .apply(&mut preferences);

        assert_eq!(preferences.port, 4321);
        assert_eq!(preferences.pac_file, support_dir().join("custom/proxy.pac"));
        assert!(preferences.negotiate);
        assert!(preferences.proxytunnel);
        assert!(preferences.direct_fallback);
        assert!(!preferences.autostart);

        let original = preferences.clone();
        DesktopDefaults::default().apply(&mut preferences);
        assert_eq!(preferences, original);

        let absolute_pac = std::env::current_exe().unwrap();
        DesktopDefaults {
            pac_file: Some(absolute_pac.clone()),
            ..DesktopDefaults::default()
        }
        .apply(&mut preferences);
        assert_eq!(preferences.pac_file, absolute_pac);

        let mut embedded = Preferences::default();
        apply_desktop_defaults_json(&mut embedded, Some(r#"{"port":4321,"autostart":false}"#));
        assert_eq!(embedded.port, 4321);
        assert!(!embedded.autostart);
        let unchanged = embedded.clone();
        apply_desktop_defaults_json(&mut embedded, Some("invalid JSON"));
        assert_eq!(embedded, unchanged);
    }

    #[test]
    fn bundle_paths_require_a_macos_contents_executable_and_find_children() {
        let paths = BundlePaths::from_main_executable(Path::new(
            "/Applications/Unproxy.app/Contents/MacOS/unproxy-app",
        ))
        .unwrap();
        assert_eq!(
            paths.child,
            PathBuf::from("/Applications/Unproxy.app/Contents/MacOS/unproxy")
        );
        assert_eq!(
            paths.login_helper,
            PathBuf::from(
                "/Applications/Unproxy.app/Contents/Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper"
            )
        );
        assert!(BundlePaths::from_main_executable(Path::new("unproxy-app")).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn native_desktop_entry_points_report_their_platform_requirement() {
        assert!(run_app().unwrap_err().to_string().contains("only on macOS"));
        assert!(
            run_login_helper()
                .unwrap_err()
                .to_string()
                .contains("only on macOS")
        );
        assert!(
            validate_native_bindings()
                .unwrap_err()
                .to_string()
                .contains("only on macOS")
        );
    }

    #[cfg(windows)]
    #[test]
    fn tray_command_uses_hidden_sta_powershell_and_reports_failures() {
        use std::os::windows::process::ExitStatusExt;

        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("Unproxy Tray.exe");
        let script = temp.path().join("unproxy-tray.ps1");
        std::fs::write(&script, "fixture").unwrap();
        let mut called = false;
        run_tray_with(&exe, |program, args, flags| {
            called = true;
            assert_eq!(program, "powershell.exe");
            assert_eq!(
                args.iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
                [
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-STA",
                    "-WindowStyle",
                    "Hidden",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    script.to_string_lossy().as_ref(),
                ]
            );
            assert_eq!(flags, 0x08000000);
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .unwrap();
        assert!(called);

        let failure =
            run_tray_with(&exe, |_, _, _| Ok(std::process::ExitStatus::from_raw(1))).unwrap_err();
        assert!(failure.to_string().contains("tray controller exited"));

        std::fs::remove_file(script).unwrap();
        let missing =
            run_tray_with(&exe, |_, _, _| panic!("missing script must not launch")).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("tray controller script is missing")
        );
    }

    #[test]
    fn preferences_apply_serde_defaults_and_reject_wrong_field_types() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/preferences.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"port":65534,"direct_fallback":true}"#).unwrap();

        let prefs = Preferences::load(&path).unwrap();
        assert_eq!(prefs.port, 65534);
        assert!(prefs.direct_fallback);
        assert!(!prefs.negotiate);
        assert!(prefs.autostart);

        for port in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("3128"),
            serde_json::Value::Null,
            serde_json::json!(u64::MAX),
        ] {
            std::fs::write(&path, serde_json::json!({"port": port}).to_string()).unwrap();
            assert_eq!(Preferences::load(&path).unwrap().port, u32::MAX);
        }

        std::fs::write(&path, r#"{"autostart":"yes"}"#).unwrap();
        assert!(Preferences::load(&path).is_err());
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, "file").unwrap();
        assert!(
            Preferences::default()
                .save(&blocker.join("preferences.json"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_captures_child_arguments_streams_and_closed_stdin() {
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let args_file = dir.path().join("args.txt");
        let program = executable(
            dir.path(),
            "capture.sh",
            &format!(
                "printf '%s\\n' \"$*\" > '{}'\nprintf 'out\\n'\nprintf 'err\\n' >&2\nif IFS= read -r line; then echo stdin-open; else echo stdin-closed; fi",
                args_file.display()
            ),
        );
        let pac = dir.path().join("proxy.pac");
        std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
        let mut prefs = Preferences {
            port: 4321,
            proxytunnel: true,
            direct_fallback: true,
            ..Preferences::default()
        };
        prefs.pac_file = pac;
        let mut child =
            ChildLifecycle::for_test(dir.path().join("support"), Duration::from_secs(1));
        child.start(&program, &prefs).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while child.is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!child.is_running());
        let args = std::fs::read_to_string(args_file).unwrap();
        assert!(args.contains("--listen 127.0.0.1:4321"));
        assert!(args.contains("--proxytunnel"));
        assert!(args.contains("--direct-fallback"));
        #[cfg(feature = "negotiate")]
        assert!(!args.contains("--negotiate"));
        assert!(
            child
                .last_exit
                .as_deref()
                .unwrap()
                .contains("Proxy exited unexpectedly")
        );
        let log = std::fs::read_to_string(dir.path().join("support/unproxy.log")).unwrap();
        assert!(log.contains("out\n"));
        assert!(log.contains("err\n"));
        assert!(log.contains("stdin-closed"));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_is_idempotent_reaps_on_drop_and_escalates_after_deadline() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        std::fs::write(&pac, "DIRECT").unwrap();
        let prefs = Preferences {
            pac_file: pac,
            ..Preferences::default()
        };

        let launch_marker = dir.path().join("launches");
        let sleeper = executable(
            dir.path(),
            "sleep.sh",
            &format!(
                "echo launch >> '{}'\nexec sleep 30",
                launch_marker.display()
            ),
        );
        let support = dir.path().join("support");
        let mut child = ChildLifecycle::for_test(support.clone(), Duration::from_secs(1));
        child.start(&sleeper, &prefs).unwrap();
        child.start(&sleeper, &prefs).unwrap();
        assert!(child.is_running());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !launch_marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read_to_string(&launch_marker)
                .unwrap()
                .lines()
                .count(),
            1
        );
        child.stop().unwrap();
        child.stop().unwrap();
        assert!(!child.is_running());

        let ready = dir.path().join("stubborn-ready");
        let stubborn = executable(
            dir.path(),
            "stubborn.sh",
            &format!(
                "trap '' TERM\necho ready > '{}'\nwhile :; do :; done",
                ready.display()
            ),
        );
        let mut child = ChildLifecycle::for_test(support.clone(), Duration::from_millis(100));
        child.start(&stubborn, &prefs).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "TERM-ignoring fixture did not start");
        child.stop().unwrap();
        assert!(
            std::fs::read_to_string(support.join("unproxy.log"))
                .unwrap()
                .contains("forcing termination")
        );

        let mut child = ChildLifecycle::for_test(support, Duration::from_secs(1));
        child.start(&sleeper, &prefs).unwrap();
        let pid = child.child.as_ref().unwrap().id() as i32;
        drop(child);
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_reports_spawn_and_log_setup_failures() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let pac = dir.path().join("proxy.pac");
        std::fs::write(&pac, "DIRECT").unwrap();
        let prefs = Preferences {
            pac_file: pac,
            ..Preferences::default()
        };
        let mut child =
            ChildLifecycle::for_test(dir.path().join("support"), Duration::from_secs(1));
        let missing = child
            .start(&dir.path().join("missing"), &prefs)
            .unwrap_err();
        assert!(format!("{missing:#}").contains("start "));

        let blocker = dir.path().join("support-is-file");
        std::fs::write(&blocker, "file").unwrap();
        let program = executable(dir.path(), "ready.sh", "sleep 30");
        let mut child = ChildLifecycle::for_test(blocker, Duration::from_secs(1));
        assert!(child.start(&program, &prefs).is_err());
        assert!(!child.is_running());
    }
}
