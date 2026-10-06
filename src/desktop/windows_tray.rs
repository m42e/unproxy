use super::{
    CREATE_NO_WINDOW, ChildLifecycle, Preferences, default_pac_path, log_path, support_dir,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateEventW, CreateMutexW, SetEvent, WaitForSingleObject},
    UI::WindowsAndMessaging::{
        DispatchMessageW, MB_ICONERROR, MB_OK, MSG, MessageBoxW, PM_REMOVE, PeekMessageW,
        TranslateMessage, WM_QUIT,
    },
};

const MENU_PROXY: &str = "proxy";
const MENU_OPEN_LOG: &str = "open-log";
const MENU_COPY_ADDRESS: &str = "copy-address";
const MENU_SETTINGS: &str = "settings";
const MENU_QUIT: &str = "quit";
struct KernelHandle(HANDLE);

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Default, Deserialize)]
struct RuntimeStatus {
    pac_loaded: Option<bool>,
    authentication_configured: Option<bool>,
    upstream_state: Option<String>,
    authentication_state: Option<String>,
    upstream_checked_at: Option<i64>,
}

struct Controller {
    preferences: Preferences,
    preferences_path: PathBuf,
    child_executable: PathBuf,
    child: ChildLifecycle,
    tray: TrayIcon,
    proxy_item: MenuItem,
    settings_item: MenuItem,
    last_icon_key: String,
    last_error: Option<String>,
    settings_process: Option<Child>,
    icon_directory: PathBuf,
}

pub(super) fn run() -> Result<()> {
    let activation_event = create_event("Local\\UnproxyTrayActivate")?;
    let exit_event = create_event("Local\\UnproxyTrayExit")?;
    let Some(_instance_mutex) = acquire_instance_mutex(&activation_event)? else {
        return Ok(());
    };

    let executable = std::env::current_exe()?;
    let icon_directory = tray_icon_directory(&executable)?;
    let child_executable = executable
        .parent()
        .context("tray executable has no parent directory")?
        .join("unproxy.exe");
    ensure!(
        child_executable.is_file(),
        "proxy executable is missing: {}",
        child_executable.display()
    );

    let preferences_path = support_dir().join("preferences.json");
    let first_run = !preferences_path.exists();
    let preferences = Preferences::load(&preferences_path)?;
    create_default_pac_if_needed(first_run, &preferences)?;

    let mut child = ChildLifecycle::default();
    let mut last_error = None;
    if preferences.autostart
        && let Err(error) = child.start(&child_executable, &preferences)
    {
        last_error = Some(format!("{error:#}"));
        show_error("Could not start Unproxy", &format!("{error:#}"));
    }

    let (menu, proxy_item, open_log_item, copy_address_item, settings_item, quit_item) =
        build_menu()?;
    let initial_running = child.is_running();
    let initial_status = read_runtime_status(&preferences);
    let initial_icon_key = icon_key(
        initial_running,
        child.last_exit.is_some() || last_error.is_some(),
        initial_status.as_ref(),
        &preferences,
    );
    let tray = TrayIconBuilder::new()
        .with_icon(load_icon(&icon_directory, &initial_icon_key)?)
        .with_tooltip(tooltip_for(&initial_icon_key))
        .with_menu(Box::new(menu))
        .build()
        .context("create Unproxy notification-area icon")?;

    let mut controller = Controller {
        preferences,
        preferences_path,
        child_executable,
        child,
        tray,
        proxy_item,
        settings_item,
        last_icon_key: initial_icon_key,
        last_error,
        settings_process: None,
        icon_directory,
    };
    let mut last_refresh = Instant::now();

    loop {
        if !pump_messages() {
            break;
        }
        match unsafe { WaitForSingleObject(exit_event.0, 25) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => {}
            result => anyhow::bail!("wait for tray exit signal failed ({result})"),
        }

        let _ = unsafe { WaitForSingleObject(activation_event.0, 0) };

        let mut quit_requested = false;
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let event_id = event.id();
            if event_id == quit_item.id() {
                quit_requested = true;
                break;
            }
            let result = if event_id == controller.proxy_item.id() {
                controller.toggle_proxy()
            } else if event_id == open_log_item.id() {
                open_log()
            } else if event_id == copy_address_item.id() {
                copy_proxy_address(&controller.preferences.primary_listener())
            } else if event_id == controller.settings_item.id() {
                controller.open_settings()
            } else {
                Ok(())
            };
            if let Err(error) = result {
                controller.last_error = Some(format!("{error:#}"));
                show_error("Unproxy", &format!("{error:#}"));
            }
        }
        if quit_requested {
            break;
        }

        if let Err(error) = controller.finish_settings_if_ready() {
            controller.last_error = Some(format!("{error:#}"));
            show_error("Unproxy Settings", &format!("{error:#}"));
        }

        if last_refresh.elapsed() >= Duration::from_secs(1) {
            if let Err(error) = controller.refresh_status() {
                let message = format!("{error:#}");
                if controller.last_error.as_deref() != Some(&message) {
                    log_status_error(&message);
                    controller.last_error = Some(message);
                }
            }
            last_refresh = Instant::now();
        }
    }

    controller.child.stop()?;
    Ok(())
}

fn pump_messages() -> bool {
    let mut message: MSG = unsafe { std::mem::zeroed() };
    while unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
        if message.message == WM_QUIT {
            return false;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    true
}

impl Controller {
    fn toggle_proxy(&mut self) -> Result<()> {
        if self.child.is_running() {
            self.child.stop()?;
            self.child.last_exit = None;
            self.last_error = None;
        } else {
            self.child
                .start(&self.child_executable, &self.preferences)?;
            self.last_error = None;
        }
        self.refresh_status()
    }

    fn open_settings(&mut self) -> Result<()> {
        if self.settings_process.is_some() {
            return Ok(());
        }
        let script = settings_script_path(&std::env::current_exe()?)?;
        let mut command = Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-STA",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .arg("-SettingsOnly")
            .creation_flags(CREATE_NO_WINDOW);
        self.settings_process = Some(command.spawn().context("open Unproxy settings")?);
        self.settings_item.set_enabled(false);
        Ok(())
    }

    fn finish_settings_if_ready(&mut self) -> Result<()> {
        let Some(process) = self.settings_process.as_mut() else {
            return Ok(());
        };
        let Some(status) = process.try_wait()? else {
            return Ok(());
        };
        self.settings_process = None;
        self.settings_item.set_enabled(true);

        if !status.success() {
            anyhow::bail!("settings helper exited with {status}");
        }

        let updated = Preferences::load(&self.preferences_path)?;
        if updated != self.preferences {
            if self.child.is_running() && child_restart_required(&self.preferences, &updated) {
                self.child.restart(&self.child_executable, &updated)?;
            }
            self.preferences = updated;
            self.last_error = None;
            self.last_icon_key.clear();
        }
        Ok(())
    }

    fn refresh_status(&mut self) -> Result<()> {
        let running = self.child.is_running();
        let failed = self.child.last_exit.is_some() || self.last_error.is_some();
        let status = running
            .then(|| read_runtime_status(&self.preferences))
            .flatten();
        let key = icon_key(running, failed, status.as_ref(), &self.preferences);
        if key != self.last_icon_key {
            self.tray
                .set_icon(Some(load_icon(&self.icon_directory, &key)?))?;
            self.tray.set_tooltip(Some(tooltip_for(&key)))?;
            self.last_icon_key = key.clone();
        }
        self.proxy_item.set_text(proxy_menu_text(running, failed));
        Ok(())
    }
}

fn build_menu() -> Result<(Menu, MenuItem, MenuItem, MenuItem, MenuItem, MenuItem)> {
    let menu = Menu::new();
    let proxy = MenuItem::with_id(MENU_PROXY, "Proxy: Starting...", true, None);
    let open_log = MenuItem::with_id(MENU_OPEN_LOG, "Open Log", true, None);
    let copy_address = MenuItem::with_id(MENU_COPY_ADDRESS, "Copy Proxy Address", true, None);
    let settings = MenuItem::with_id(MENU_SETTINGS, "Settings...", true, None);
    let quit = MenuItem::with_id(MENU_QUIT, "Quit Unproxy", true, None);
    let separator = PredefinedMenuItem::separator();

    menu.append(&proxy).context("add proxy menu item")?;
    menu.append(&open_log).context("add log menu item")?;
    menu.append(&copy_address)
        .context("add copy-address menu item")?;
    menu.append(&separator).context("add menu separator")?;
    menu.append(&settings).context("add settings menu item")?;
    menu.append(&separator).context("add menu separator")?;
    menu.append(&quit).context("add quit menu item")?;
    Ok((menu, proxy, open_log, copy_address, settings, quit))
}

fn child_restart_required(current: &Preferences, updated: &Preferences) -> bool {
    current.effective_listeners() != updated.effective_listeners()
        || current.effective_pac_files() != updated.effective_pac_files()
        || current.effective_filter_lists() != updated.effective_filter_lists()
        || current.proxytunnel != updated.proxytunnel
        || current.direct_fallback != updated.direct_fallback
        || (cfg!(feature = "negotiate") && current.negotiate != updated.negotiate)
}

fn create_event(name: &str) -> Result<KernelHandle> {
    let name = wide(name);
    let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
    ensure!(!handle.is_null(), "create tray event failed");
    Ok(KernelHandle(handle))
}

fn acquire_instance_mutex(activation_event: &KernelHandle) -> Result<Option<KernelHandle>> {
    let name = wide("Local\\UnproxyTray");
    let handle = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
    ensure!(!handle.is_null(), "create tray instance mutex failed");
    let handle = KernelHandle(handle);
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED_0 => Ok(Some(handle)),
        WAIT_TIMEOUT => {
            unsafe { SetEvent(activation_event.0) };
            Ok(None)
        }
        result => anyhow::bail!("acquire tray instance mutex failed ({result})"),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn tray_icon_directory(executable: &Path) -> Result<PathBuf> {
    let installed = executable
        .parent()
        .context("tray executable has no parent directory")?
        .join("tray-icons");
    if installed.is_dir() {
        return Ok(installed);
    }
    let development = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/tray-icons");
    ensure!(development.is_dir(), "tray icon assets are missing");
    Ok(development)
}

fn settings_script_path(executable: &Path) -> Result<PathBuf> {
    let installed = executable
        .parent()
        .context("tray executable has no parent directory")?
        .join("unproxy-tray.ps1");
    let script = if installed.is_file() {
        installed
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/unproxy-tray.ps1")
    };
    ensure!(
        script.is_file(),
        "settings helper is missing: {}",
        script.display()
    );
    Ok(script)
}

fn create_default_pac_if_needed(first_run: bool, preferences: &Preferences) -> Result<()> {
    if !first_run || preferences.pac_file != default_pac_path() || preferences.pac_file.exists() {
        return Ok(());
    }
    if let Some(parent) = preferences.pac_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &preferences.pac_file,
        "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
    )?;
    Ok(())
}

fn load_icon(directory: &Path, key: &str) -> Result<Icon> {
    let path = directory.join(format!("{key}.png"));
    let rgba = image::open(&path)
        .with_context(|| format!("load tray icon {}", path.display()))?
        .to_rgba8();
    let (width, height) = rgba.dimensions();
    Icon::from_rgba(rgba.into_raw(), width, height).context("decode tray icon")
}

fn read_runtime_status(preferences: &Preferences) -> Option<RuntimeStatus> {
    preferences
        .effective_listeners()
        .iter()
        .filter_map(|listener| listener.parse::<SocketAddr>().ok())
        .find_map(read_runtime_status_at)
}

fn read_runtime_status_at(address: SocketAddr) -> Option<RuntimeStatus> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    write!(
        stream,
        "GET /status.json HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;

    let mut response = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if response.len() + count > 16 * 1024 {
                    return None;
                }
                response.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(_) => return None,
        }
    }
    let response = String::from_utf8_lossy(&response);
    let (headers, body) = response.split_once("\r\n\r\n")?;
    if !headers.starts_with("HTTP/1.1 200") {
        return None;
    }
    serde_json::from_str(body).ok()
}

fn icon_key(
    running: bool,
    failed: bool,
    status: Option<&RuntimeStatus>,
    preferences: &Preferences,
) -> String {
    let service = if running {
        "running"
    } else if failed {
        "failed"
    } else {
        "stopped"
    };
    let pac = if !running {
        "unloaded"
    } else {
        match status.and_then(|status| status.pac_loaded) {
            Some(true) => "loaded",
            Some(false) => "unloaded",
            None => "unknown",
        }
    };
    let recent = status
        .and_then(|status| status.upstream_checked_at)
        .is_some_and(|checked| {
            let age = chrono::Utc::now().timestamp() - checked;
            (0..=300).contains(&age)
        });
    let upstream = if !recent {
        "unknown"
    } else if status.and_then(|status| status.upstream_state.as_deref()) == Some("ok") {
        "ok"
    } else {
        "error"
    };
    let auth_configured = status
        .and_then(|status| status.authentication_configured)
        .unwrap_or_else(|| {
            (preferences.negotiate && cfg!(feature = "negotiate"))
                || dirs::home_dir().is_some_and(|home| home.join(".netrc").is_file())
        });
    let authentication = if !auth_configured {
        "disabled"
    } else if recent
        && status.and_then(|status| status.authentication_state.as_deref()) == Some("authenticated")
    {
        "authenticated"
    } else if recent
        && status.and_then(|status| status.authentication_state.as_deref()) == Some("rejected")
    {
        "rejected"
    } else {
        "configured"
    };
    format!("{service}-{pac}-{upstream}-{authentication}")
}

fn tooltip_for(key: &str) -> String {
    let mut states = key.split('-');
    let service = match states.next() {
        Some("running") => "On",
        Some("failed") => "Error",
        _ => "Off",
    };
    let pac = match states.next() {
        Some("loaded") => "Ready",
        Some("unloaded") => "No",
        _ => "?",
    };
    let upstream = match states.next() {
        Some("ok") => "OK",
        Some("error") => "Fail",
        _ => "?",
    };
    let authentication = match states.next() {
        Some("authenticated") => "OK",
        Some("rejected") => "407",
        Some("configured") => "Set",
        _ => "Off",
    };
    format!("Unproxy {service} | PAC {pac} | Up {upstream} | Auth {authentication}")
}

fn proxy_menu_text(running: bool, failed: bool) -> &'static str {
    if running {
        "Proxy: Running (click to stop)"
    } else if failed {
        "Proxy: Error (click to restart)"
    } else {
        "Proxy: Stopped (click to start)"
    }
}

fn open_log() -> Result<()> {
    Command::new("notepad.exe")
        .arg(log_path())
        .spawn()
        .context("open Unproxy log")?;
    Ok(())
}

fn log_status_error(message: &str) {
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(
            file,
            "{} tray status update failed: {message}",
            chrono::Local::now().to_rfc3339()
        );
    }
}

fn copy_proxy_address(address: &str) -> Result<()> {
    let mut process = Command::new("clip.exe")
        .stdin(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("open Windows clipboard")?;
    process
        .stdin
        .take()
        .context("open clipboard input")?
        .write_all(address.as_bytes())?;
    ensure!(
        process.wait()?.success(),
        "Windows clipboard rejected the address"
    );
    Ok(())
}

fn show_error(title: &str, message: &str) {
    let title = wide(title);
    let message = wide(message);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub(super) fn show_startup_error(message: &str) {
    show_error("Unproxy", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_status_uses_configured_listeners() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_address = unused.local_addr().unwrap();
        drop(unused);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept status request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            request.read_line(&mut request_line).unwrap();
            assert!(request_line.starts_with("GET /status.json "));
            loop {
                let mut header = String::new();
                request.read_line(&mut header).unwrap();
                if header == "\r\n" || header.is_empty() {
                    break;
                }
            }
            let body = r#"{"pac_loaded":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });
        let preferences = Preferences {
            listeners: Some(vec![unavailable_address.to_string(), address.to_string()]),
            ..Preferences::default()
        };

        let status = read_runtime_status(&preferences).expect("configured listener status");
        server.join().unwrap();
        assert_eq!(status.pac_loaded, Some(true));
    }

    #[test]
    fn icon_key_reflects_proxy_and_runtime_status() {
        let preferences = Preferences::default();
        assert_eq!(
            icon_key(false, false, None, &preferences),
            "stopped-unloaded-unknown-disabled"
        );
        assert_eq!(
            icon_key(false, true, None, &preferences),
            "failed-unloaded-unknown-disabled"
        );
        assert_eq!(
            proxy_menu_text(true, false),
            "Proxy: Running (click to stop)"
        );
    }

    #[test]
    fn changing_login_startup_does_not_restart_the_proxy() {
        let current = Preferences::default();
        let updated = Preferences {
            autostart: !current.autostart,
            ..current.clone()
        };
        assert!(!child_restart_required(&current, &updated));

        let updated = Preferences {
            direct_fallback: !current.direct_fallback,
            ..current.clone()
        };
        assert!(child_restart_required(&current, &updated));
    }

    #[test]
    fn changing_filter_lists_restarts_the_windows_proxy_child() {
        let current = Preferences::default();
        let updated = Preferences {
            filter_lists: Some(vec![PathBuf::from("C:\\lists\\hosts.txt")]),
            ..current.clone()
        };
        assert!(child_restart_required(&current, &updated));
        assert!(!child_restart_required(&updated, &updated));
    }
}
