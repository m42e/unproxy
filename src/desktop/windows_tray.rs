use super::{
    CREATE_NO_WINDOW, ChildLifecycle, Preferences, default_pac_path, log_path, support_dir,
};
mod settings;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
        DispatchMessageW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MSG, MessageBoxW, PM_REMOVE,
        PeekMessageW, TranslateMessage, WM_QUIT,
    },
};

const MENU_PROXY: &str = "proxy";
const MENU_OPEN_STATUS: &str = "open-status";
const MENU_OPEN_LOG: &str = "open-log";
const MENU_COPY_ADDRESS: &str = "copy-address";
const MENU_CHECK_UPDATES: &str = "check-updates";
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
    check_updates_item: MenuItem,
    last_icon_key: String,
    last_error: Option<String>,
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
    // Autostart controls login registration only. Running the tray manually
    // always starts the proxy child.
    if let Err(error) = start_proxy_for_tray_launch(&preferences, |preferences| {
        child.start(&child_executable, preferences)
    }) {
        last_error = Some(format!("{error:#}"));
        show_error("Could not start Unproxy", &format!("{error:#}"));
    }

    let TrayMenuItems {
        menu,
        proxy: proxy_item,
        open_status: open_status_item,
        open_log: open_log_item,
        copy_address: copy_address_item,
        check_updates: check_updates_item,
        settings: settings_item,
        quit: quit_item,
    } = build_menu()?;
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
        check_updates_item,
        last_icon_key: initial_icon_key,
        last_error,
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
            } else if event_id == open_status_item.id() {
                open_status_page(&controller.preferences)
            } else if event_id == open_log_item.id() {
                open_log()
            } else if event_id == copy_address_item.id() {
                copy_proxy_address(&controller.preferences.primary_listener())
            } else if event_id == controller.check_updates_item.id() {
                controller.check_for_upgrade()
            } else if event_id == controller.settings_item.id() {
                controller.open_settings()
            } else {
                Ok(())
            };
            if let Err(error) = result {
                controller.last_error = Some(format!("{error:#}"));
                let title = if event_id == controller.settings_item.id() {
                    "Unproxy Settings"
                } else if event_id == controller.check_updates_item.id() {
                    "Check for Updates"
                } else {
                    "Unproxy"
                };
                show_error(title, &format!("{error:#}"));
            }
        }
        if quit_requested {
            break;
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
    fn check_for_upgrade(&self) -> Result<()> {
        match crate::upgrade::check_for_upgrade_blocking(
            self.preferences.release_info_url.as_deref(),
        )? {
            crate::upgrade::UpgradeStatus::UpToDate { current_version } => {
                show_information(
                    "Unproxy is Up to Date",
                    &format!("You are using the latest version ({current_version})."),
                );
            }
            crate::upgrade::UpgradeStatus::UpgradeAvailable(release) => {
                show_information(
                    "Unproxy Update Available",
                    &format!(
                        "Version {} is available. Opening the release page.",
                        release.version
                    ),
                );
                open_external_url(&release.url)?;
            }
        }
        Ok(())
    }

    fn toggle_proxy(&mut self) -> Result<()> {
        if self.child.is_running() {
            self.child.stop()?;
            self.child.last_exit = None;
            self.last_error = None;
        } else {
            if reload_preferences(&self.preferences_path, &mut self.preferences)? {
                self.last_icon_key.clear();
            }
            self.child
                .start(&self.child_executable, &self.preferences)?;
            self.last_error = None;
        }
        self.refresh_status()
    }

    fn open_settings(&mut self) -> Result<()> {
        let Some(updated) =
            settings::show_dialog(&self.preferences).context("open Unproxy settings")?
        else {
            return Ok(());
        };
        if updated == self.preferences {
            return Ok(());
        }

        let executable = std::env::current_exe().context("find Unproxy tray executable")?;
        let preferences_path = self.preferences_path.clone();
        let previous = self.preferences.clone();
        self.child.apply_preferences(
            &self.child_executable,
            &previous,
            &updated,
            |preferences| {
                preferences
                    .save(&preferences_path)
                    .context("save Unproxy settings")?;
                if previous.effective_listeners() != updated.effective_listeners() {
                    update_managed_proxy_environment(preferences)?;
                }
                if updated.autostart != previous.autostart {
                    settings::set_login_startup(preferences.autostart, &executable)?;
                }
                Ok(())
            },
        )?;
        if previous.effective_listeners() != updated.effective_listeners() {
            show_information(
                "Unproxy Settings",
                "The proxy listener changed. Reopen applications that use the installed proxy environment to pick up the updated address. Update any manually configured proxy addresses as well.",
            );
        }
        self.preferences = updated;
        self.last_error = None;
        self.last_icon_key.clear();
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

/// Update the installer's per-user proxy values only while they still match
/// the values it installed. This preserves any later user or administrator edit.
fn update_managed_proxy_environment(preferences: &Preferences) -> Result<()> {
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, RegCloseKey, RegOpenKeyExW,
    };

    let state_path = support_dir().join("environment-before-install.json");
    if !state_path.is_file() {
        return Ok(());
    }
    let bytes = std::fs::read(&state_path).context("read installed environment tracking")?;
    let mut state = parse_tracking_json(&bytes).context("parse installed environment tracking")?;
    let installed = state
        .get("installed")
        .and_then(serde_json::Value::as_object)
        .context("installed environment tracking has no installed values")?
        .clone();
    let proxy_url = proxy_environment_url(preferences)?;
    let key_path = wide("Environment");
    let mut key = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut key,
        )
    };
    if status != 0 {
        anyhow::bail!("open per-user environment registry key failed ({status})");
    }
    let result = sync_managed_proxy_values(
        installed,
        &proxy_url,
        |name| read_registry_string(key, name),
        |name, value| write_registry_string(key, name, value),
        |installed| {
            state["installed"] = serde_json::Value::Object(installed.clone());
            write_json_atomically(&state_path, &state)
                .context("update installed environment tracking")
        },
    );
    unsafe { RegCloseKey(key) };
    result?;
    notify_environment_changed();
    Ok(())
}

fn parse_tracking_json(bytes: &[u8]) -> serde_json::Result<serde_json::Value> {
    serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
}

fn start_proxy_for_tray_launch(
    preferences: &Preferences,
    start: impl FnOnce(&Preferences) -> Result<()>,
) -> Result<()> {
    // Autostart controls login registration, never a manual tray launch.
    start(preferences)
}

fn sync_managed_proxy_values(
    mut installed: serde_json::Map<String, serde_json::Value>,
    proxy_url: &str,
    mut read: impl FnMut(&str) -> Result<Option<String>>,
    mut write: impl FnMut(&str, &str) -> Result<()>,
    mut persist: impl FnMut(&serde_json::Map<String, serde_json::Value>) -> Result<()>,
) -> Result<()> {
    let original_installed = installed.clone();
    let mut changed = Vec::<(String, String)>::new();
    let update = (|| {
        for name in ["http_proxy", "https_proxy"] {
            let Some(current) = read(name)? else {
                continue;
            };
            if installed.get(name).and_then(serde_json::Value::as_str) != Some(&current) {
                continue;
            }
            write(name, proxy_url)?;
            changed.push((name.to_owned(), current));
            installed.insert(
                name.to_owned(),
                serde_json::Value::String(proxy_url.to_owned()),
            );
        }
        persist(&installed)
    })();
    if let Err(error) = update {
        let mut rollback_errors = Vec::new();
        for (name, old_value) in changed.iter().rev() {
            if let Err(rollback) = write(name, old_value) {
                rollback_errors.push(format!("restore {name}: {rollback:#}"));
            }
        }
        if let Err(rollback) = persist(&original_installed) {
            rollback_errors.push(format!("restore tracking: {rollback:#}"));
        }
        if rollback_errors.is_empty() {
            return Err(error);
        }
        anyhow::bail!("{error:#}; rollback failed: {}", rollback_errors.join("; "));
    }
    Ok(())
}

fn read_registry_string(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Result<Option<String>> {
    use windows_sys::Win32::System::Registry::{REG_SZ, RegQueryValueExW};
    let name = wide(name);
    let mut kind = 0;
    let mut bytes = 0u32;
    let query = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if query != 0 || kind != REG_SZ || bytes < 2 {
        return Ok(None);
    }
    let mut data = vec![0u16; (bytes as usize).div_ceil(2)];
    let query = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if query != 0 {
        return Ok(None);
    }
    let end = data
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(data.len());
    Ok(Some(String::from_utf16_lossy(&data[..end])))
}

fn write_registry_string(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value: &str,
) -> Result<()> {
    use windows_sys::Win32::System::Registry::{REG_SZ, RegSetValueExW};
    let name_wide = wide(name);
    let value_wide = wide(value);
    let status = unsafe {
        RegSetValueExW(
            key,
            name_wide.as_ptr(),
            0,
            REG_SZ,
            value_wide.as_ptr().cast(),
            (value_wide.len() * 2) as u32,
        )
    };
    if status != 0 {
        anyhow::bail!("write per-user {name} failed ({status})");
    }
    Ok(())
}

fn write_json_atomically(path: &Path, value: &serde_json::Value) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    let source = wide(&temporary.to_string_lossy());
    let destination = wide(&path.to_string_lossy());
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let _ = std::fs::remove_file(&temporary);
        anyhow::bail!("replace installed environment tracking failed");
    }
    Ok(())
}

fn proxy_environment_url(preferences: &Preferences) -> Result<String> {
    let listener = preferences
        .primary_listener()
        .parse::<SocketAddr>()
        .context("parse primary proxy listener")?;
    let ip = match listener.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".parse().unwrap(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => "::1".parse().unwrap(),
        ip => ip,
    };
    let host = match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Ok(format!("http://{host}:{}", listener.port()))
}

fn notify_environment_changed() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    let setting = wide("Environment");
    let mut ignored = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            setting.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            &mut ignored,
        );
    }
}

struct TrayMenuItems {
    menu: Menu,
    proxy: MenuItem,
    open_status: MenuItem,
    open_log: MenuItem,
    copy_address: MenuItem,
    check_updates: MenuItem,
    settings: MenuItem,
    quit: MenuItem,
}

fn build_menu() -> Result<TrayMenuItems> {
    let menu = Menu::new();
    let proxy = MenuItem::with_id(MENU_PROXY, "Proxy: Starting...", true, None);
    let open_status = MenuItem::with_id(MENU_OPEN_STATUS, "Open Status Page", true, None);
    let open_log = MenuItem::with_id(MENU_OPEN_LOG, "Open Log", true, None);
    let copy_address = MenuItem::with_id(MENU_COPY_ADDRESS, "Copy Proxy Address", true, None);
    let check_updates = MenuItem::with_id(MENU_CHECK_UPDATES, "Check for Updates", true, None);
    let settings = MenuItem::with_id(MENU_SETTINGS, "Settings...", true, None);
    let quit = MenuItem::with_id(MENU_QUIT, "Quit Unproxy", true, None);
    let separator = PredefinedMenuItem::separator();

    menu.append(&proxy).context("add proxy menu item")?;
    menu.append(&open_status)
        .context("add status-page menu item")?;
    menu.append(&open_log).context("add log menu item")?;
    menu.append(&copy_address)
        .context("add copy-address menu item")?;
    menu.append(&check_updates)
        .context("add check-updates menu item")?;
    menu.append(&separator).context("add menu separator")?;
    menu.append(&settings).context("add settings menu item")?;
    menu.append(&separator).context("add menu separator")?;
    menu.append(&quit).context("add quit menu item")?;
    Ok(TrayMenuItems {
        menu,
        proxy,
        open_status,
        open_log,
        copy_address,
        check_updates,
        settings,
        quit,
    })
}

#[cfg(test)]
fn child_restart_required(current: &Preferences, updated: &Preferences) -> bool {
    current.effective_listeners() != updated.effective_listeners()
        || current.effective_pac_files() != updated.effective_pac_files()
        || current.effective_filter_lists() != updated.effective_filter_lists()
        || current.proxytunnel != updated.proxytunnel
        || current.direct_fallback != updated.direct_fallback
        || (cfg!(feature = "negotiate") && current.negotiate != updated.negotiate)
}

fn reload_preferences(path: &Path, current: &mut Preferences) -> Result<bool> {
    let updated = Preferences::load(path)?;
    let changed = updated != *current;
    *current = updated;
    Ok(changed)
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
    read_runtime_status_with(preferences, read_runtime_status_at)
}

fn read_runtime_status_with(
    preferences: &Preferences,
    read_at: impl FnMut(SocketAddr) -> Option<RuntimeStatus>,
) -> Option<RuntimeStatus> {
    preferences
        .effective_listeners()
        .iter()
        .filter_map(|listener| listener.parse::<SocketAddr>().ok())
        .find_map(read_at)
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

fn open_status_page(preferences: &Preferences) -> Result<()> {
    open_external_url(&preferences.status_url()?)
}

fn open_external_url(url: &str) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide_url = std::ffi::OsStr::new(url)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // ShellExecute opens the URL through the user's default browser association.
    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            std::ptr::null(),
            wide_url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    ensure!(
        result as isize > 32,
        "could not open the URL (ShellExecute error {})",
        result as isize
    );
    Ok(())
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

fn show_information(title: &str, message: &str) {
    let title = wide(title);
    let message = wide(message);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
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
    fn menu_exposes_the_status_page_action() {
        let menu = build_menu().unwrap();
        assert_eq!(menu.open_status.id().0, MENU_OPEN_STATUS);
        assert_eq!(menu.open_status.text(), "Open Status Page");
        assert_eq!(menu.check_updates.id().0, MENU_CHECK_UPDATES);
        assert_eq!(menu.check_updates.text(), "Check for Updates");
    }

    #[test]
    fn runtime_status_uses_configured_listeners() {
        let unavailable_address = "127.0.0.1:3128".parse::<SocketAddr>().unwrap();
        let address = "[::1]:3128".parse::<SocketAddr>().unwrap();
        let preferences = Preferences {
            listeners: Some(vec![unavailable_address.to_string(), address.to_string()]),
            ..Preferences::default()
        };
        let mut attempted = Vec::new();

        let status = read_runtime_status_with(&preferences, |candidate| {
            attempted.push(candidate);
            (candidate == address).then(|| RuntimeStatus {
                pac_loaded: Some(true),
                ..RuntimeStatus::default()
            })
        })
        .expect("configured listener status");

        assert_eq!(attempted, vec![unavailable_address, address]);
        assert_eq!(status.pac_loaded, Some(true));
    }

    #[test]
    fn tray_status_probe_uses_public_sanitized_endpoint_without_owner_secret() {
        use std::io::{BufRead, BufReader};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            request.read_line(&mut line).unwrap();
            assert!(line.starts_with("GET /status.json "));
            loop {
                line.clear();
                request.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
            }
            let body = r#"{"pac_loaded":true,"pac_files":["remote PAC file"],"upstream_route":"HTTP proxy","authentication_configured":false,"upstream_state":"ok","authentication_state":"disabled"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let status = read_runtime_status_at(address).expect("sanitized status remains available");
        server.join().unwrap();
        assert_eq!(status.pac_loaded, Some(true));
        assert_eq!(status.upstream_state, "ok");
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
    fn listener_settings_produce_a_local_proxy_environment_url() {
        let preferences = Preferences {
            listeners: Some(vec!["0.0.0.0:4321".to_owned()]),
            ..Preferences::default()
        };
        assert_eq!(
            proxy_environment_url(&preferences).unwrap(),
            "http://127.0.0.1:4321"
        );

        let preferences = Preferences {
            listeners: Some(vec!["[::]:8765".to_owned()]),
            ..Preferences::default()
        };
        assert_eq!(
            proxy_environment_url(&preferences).unwrap(),
            "http://[::1]:8765"
        );
    }

    #[test]
    fn tracking_json_accepts_the_windows_powershell_utf8_bom() {
        let bytes = b"\xef\xbb\xbf{\"original\":{\"http_proxy\":null},\"installed\":{}}";
        let state = parse_tracking_json(bytes).unwrap();
        assert!(state["original"]["http_proxy"].is_null());
    }

    #[test]
    fn manual_tray_launch_starts_proxy_when_login_autostart_is_disabled() {
        let preferences = Preferences {
            autostart: false,
            ..Preferences::default()
        };
        let mut started = false;
        start_proxy_for_tray_launch(&preferences, |_| {
            started = true;
            Ok(())
        })
        .unwrap();
        assert!(started);
    }

    #[test]
    fn environment_sync_preserves_overrides_missing_values_and_uninstall_originals() {
        let mut installed = serde_json::Map::new();
        installed.insert("http_proxy".into(), "http://127.0.0.1:3128".into());
        installed.insert("https_proxy".into(), "http://127.0.0.1:3128".into());
        installed.insert("no_proxy".into(), "localhost".into());
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            (
                "http_proxy".to_owned(),
                "http://proxy.example:8080".to_owned(),
            ),
            ("https_proxy".to_owned(), "http://127.0.0.1:3128".to_owned()),
        ]));
        let mut state = serde_json::json!({
            "original": {"http_proxy": "original-user-value"},
            "installed": installed,
        });
        sync_managed_proxy_values(
            state["installed"].as_object().unwrap().clone(),
            "http://127.0.0.1:4444",
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                current
                    .borrow_mut()
                    .insert(name.to_owned(), value.to_owned());
                Ok(())
            },
            |installed| {
                state["installed"] = serde_json::Value::Object(installed.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(current.borrow()["http_proxy"], "http://proxy.example:8080");
        assert_eq!(current.borrow()["https_proxy"], "http://127.0.0.1:4444");
        assert_eq!(state["original"]["http_proxy"], "original-user-value");
        assert_eq!(state["installed"]["https_proxy"], "http://127.0.0.1:4444");
        assert_eq!(state["installed"]["http_proxy"], "http://127.0.0.1:3128");
        assert_eq!(state["installed"]["no_proxy"], "localhost");
    }

    #[test]
    fn environment_sync_does_not_create_a_missing_user_value() {
        let old = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), old.into()),
            ("https_proxy".into(), old.into()),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([(
            "http_proxy".to_owned(),
            old.to_owned(),
        )]));
        let mut persisted = None;
        sync_managed_proxy_values(
            installed,
            "http://127.0.0.1:4444",
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                current
                    .borrow_mut()
                    .insert(name.to_owned(), value.to_owned());
                Ok(())
            },
            |installed| {
                persisted = Some(installed.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(current.borrow().get("https_proxy"), None);
        assert_eq!(persisted.unwrap()["https_proxy"], old);
    }

    #[test]
    fn environment_sync_rolls_back_prior_writes_after_a_partial_write_failure() {
        let old = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), old.into()),
            ("https_proxy".into(), old.into()),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".to_owned(), old.to_owned()),
            ("https_proxy".to_owned(), old.to_owned()),
        ]));
        let mut fail_https_once = true;
        let result = sync_managed_proxy_values(
            installed,
            "http://127.0.0.1:4444",
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                if name == "https_proxy" && fail_https_once {
                    fail_https_once = false;
                    anyhow::bail!("injected registry write failure");
                }
                current
                    .borrow_mut()
                    .insert(name.to_owned(), value.to_owned());
                Ok(())
            },
            |_| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(current.borrow()["http_proxy"], old);
        assert_eq!(current.borrow()["https_proxy"], old);
    }

    #[test]
    fn environment_sync_rolls_back_registry_when_tracking_persistence_fails() {
        let old = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), old.into()),
            ("https_proxy".into(), old.into()),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".to_owned(), old.to_owned()),
            ("https_proxy".to_owned(), old.to_owned()),
        ]));
        let mut persistence_calls = 0;
        let result = sync_managed_proxy_values(
            installed,
            "http://127.0.0.1:4444",
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                current
                    .borrow_mut()
                    .insert(name.to_owned(), value.to_owned());
                Ok(())
            },
            |_| {
                persistence_calls += 1;
                if persistence_calls == 1 {
                    anyhow::bail!("injected tracking write failure");
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(current.borrow()["http_proxy"], old);
        assert_eq!(current.borrow()["https_proxy"], old);
        assert_eq!(persistence_calls, 2);
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

    #[test]
    fn restarting_proxy_reloads_preferences_from_disk() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preferences.json");
        let original = Preferences {
            filter_lists: Some(vec![PathBuf::from("C:\\lists\\hosts.txt")]),
            ..Preferences::default()
        };
        original.save(&path).unwrap();

        let updated = Preferences {
            filter_lists: None,
            ..original.clone()
        };
        updated.save(&path).unwrap();
        let mut current = original;

        assert!(reload_preferences(&path, &mut current).unwrap());
        assert!(current.effective_filter_lists().is_empty());
        assert!(!reload_preferences(&path, &mut current).unwrap());
    }
}
