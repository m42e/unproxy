use super::{
    CREATE_NO_WINDOW, ChildLifecycle, Preferences, default_pac_path, log_path, support_dir,
};
mod settings;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    io::Write,
    net::SocketAddr,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateEventW, CreateMutexW, ResetEvent, SetEvent, WaitForSingleObject},
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

#[derive(Clone, Default, Deserialize)]
struct RuntimeStatus {
    pac_loaded: Option<bool>,
    authentication_configured: Option<bool>,
    upstream_state: Option<String>,
    authentication_state: Option<String>,
    upstream_checked_at: Option<i64>,
}

struct RuntimeStatusPoller {
    sender: Sender<(u64, Preferences, Option<RuntimeStatus>)>,
    receiver: Receiver<(u64, Preferences, Option<RuntimeStatus>)>,
    in_flight: bool,
    cached: Option<(Preferences, Option<RuntimeStatus>)>,
    next_poll: Instant,
    generation: u64,
    was_running: bool,
    tracked_preferences: Option<Preferences>,
}

impl Default for RuntimeStatusPoller {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver,
            in_flight: false,
            cached: None,
            next_poll: Instant::now(),
            generation: 0,
            was_running: false,
            tracked_preferences: None,
        }
    }
}

impl RuntimeStatusPoller {
    fn status(
        &mut self,
        running: bool,
        preferences: &Preferences,
        read: impl FnOnce(&Preferences) -> Option<RuntimeStatus> + Send + 'static,
    ) -> Result<Option<RuntimeStatus>> {
        if let Ok((generation, polled_preferences, status)) = self.receiver.try_recv() {
            self.in_flight = false;
            if running && generation == self.generation && polled_preferences == *preferences {
                self.cached = Some((polled_preferences, status));
            }
        }

        if self.was_running != running || self.tracked_preferences.as_ref() != Some(preferences) {
            self.generation = self.generation.wrapping_add(1);
            self.cached = None;
            self.was_running = running;
            self.tracked_preferences = Some(preferences.clone());
        }

        if !running {
            self.cached = None;
            return Ok(None);
        }

        if self
            .cached
            .as_ref()
            .is_some_and(|(polled_preferences, _)| polled_preferences != preferences)
        {
            self.cached = None;
        }

        if Instant::now() >= self.next_poll {
            self.next_poll = Instant::now() + Duration::from_secs(1);
            if !self.in_flight {
                let preferences = preferences.clone();
                let sender = self.sender.clone();
                let generation = self.generation;
                thread::Builder::new()
                    .name("unproxy-runtime-status".into())
                    .spawn(move || {
                        let status = read(&preferences);
                        let _ = sender.send((generation, preferences, status));
                    })
                    .context("start runtime status poll")?;
                self.in_flight = true;
            }
        }

        Ok(self.cached.as_ref().and_then(|(_, status)| status.clone()))
    }
}

struct Controller {
    preferences: Preferences,
    preferences_path: PathBuf,
    child_executable: PathBuf,
    child: ChildLifecycle,
    environment_active: bool,
    status_poller: RuntimeStatusPoller,
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

    // Retract values left by older tray versions before any later startup
    // check can fail. Inactive reconciliation does not use the preferences.
    set_managed_proxy_environment(false, &Preferences::default())?;

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
        child.start_confirmed(&child_executable, preferences, false)
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
        environment_active: false,
        status_poller: RuntimeStatusPoller::default(),
        tray,
        proxy_item,
        settings_item,
        check_updates_item,
        last_icon_key: initial_icon_key,
        last_error,
        icon_directory,
    };
    if controller.child.is_running() {
        if let Err(error) = controller.set_environment_active(true) {
            controller.last_error = Some(format!("{error:#}"));
            show_error_async("Unproxy", &format!("{error:#}"));
        }
    }
    let mut last_refresh = Instant::now();

    loop {
        let mut shutdown_requested = !pump_messages();
        match unsafe { WaitForSingleObject(exit_event.0, 25) } {
            WAIT_OBJECT_0 => shutdown_requested = true,
            WAIT_TIMEOUT => {}
            result => anyhow::bail!("wait for tray exit signal failed ({result})"),
        }
        if shutdown_requested {
            if let Err(error) =
                stop_child_after_withdrawal(controller.set_environment_active(false), || {
                    controller.child.stop()
                })
            {
                if !controller.environment_active {
                    return Err(error);
                }
                // A failed withdrawal leaves the named event signaled. Reset
                // it so the tray can keep serving the endpoint and retry only
                // after the user requests shutdown again.
                ensure!(
                    unsafe { ResetEvent(exit_event.0) } != 0,
                    "reset tray exit signal after failed withdrawal"
                );
                let message =
                    format!("could not withdraw proxy settings before shutdown: {error:#}");
                log_status_error(&message);
                show_error_async("Could Not Stop Unproxy", &message);
                continue;
            }
            return Ok(());
        }

        let _ = unsafe { WaitForSingleObject(activation_event.0, 0) };

        // Observe unexpected child exits on every tray-loop iteration so a
        // stale user proxy setting is withdrawn promptly.
        if let Err(error) = controller.reconcile_environment() {
            let message = format!("{error:#}");
            if controller.last_error.as_deref() != Some(&message) {
                log_status_error(&message);
                controller.last_error = Some(message);
            }
        }

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
                open_status_page_async(&controller.preferences)
            } else if event_id == open_log_item.id() {
                open_log()
            } else if event_id == copy_address_item.id() {
                copy_proxy_address_async(controller.preferences.primary_listener())
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
                show_error_async(title, &format!("{error:#}"));
            }
        }
        if quit_requested {
            if let Err(error) =
                stop_child_after_withdrawal(controller.set_environment_active(false), || {
                    controller.child.stop()
                })
            {
                if !controller.environment_active {
                    return Err(error);
                }
                ensure!(
                    unsafe { ResetEvent(exit_event.0) } != 0,
                    "reset tray exit signal after failed withdrawal"
                );
                let message =
                    format!("could not withdraw proxy settings before shutdown: {error:#}");
                log_status_error(&message);
                show_error_async("Could Not Stop Unproxy", &message);
                continue;
            }
            return Ok(());
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
        let release_info_url = self.preferences.release_info_url.clone();
        spawn_background_task("unproxy-update-check", move || {
            match crate::upgrade::check_for_upgrade_blocking(release_info_url.as_deref()) {
                Ok(crate::upgrade::UpgradeStatus::UpToDate { current_version }) => {
                    show_information(
                        "Unproxy is Up to Date",
                        &format!("You are using the latest version ({current_version})."),
                    );
                }
                Ok(crate::upgrade::UpgradeStatus::UpgradeAvailable(release)) => {
                    show_information(
                        "Unproxy Update Available",
                        &format!(
                            "Version {} is available. Opening the release page.",
                            release.version
                        ),
                    );
                    if let Err(error) = open_external_url(&release.url) {
                        show_error("Check for Updates", &format!("{error:#}"));
                    }
                }
                Err(error) => show_error("Check for Updates", &format!("{error:#}")),
            }
        })
    }

    fn toggle_proxy(&mut self) -> Result<()> {
        if self.child.is_running() {
            stop_child_after_withdrawal(self.set_environment_active(false), || self.child.stop())?;
            self.child.last_exit = None;
            self.last_error = None;
        } else {
            let withdrawal = if self.environment_active {
                self.set_environment_active(false)
            } else {
                Ok(())
            };
            start_child_after_withdrawal(withdrawal, || {
                if reload_preferences(&self.preferences_path, &mut self.preferences)? {
                    self.last_icon_key.clear();
                }
                self.child
                    .start_confirmed(&self.child_executable, &self.preferences, false)?;
                self.set_environment_active(true)
            })?;
            self.last_error = None;
        }
        self.refresh_status()
    }

    fn open_settings(&mut self) -> Result<()> {
        let was_advertised = self.environment_active;
        if was_advertised {
            self.set_environment_active(false)?;
        }
        let dialog_result =
            settings::show_dialog(&self.preferences).context("open Unproxy settings");
        let child_running = self.child.is_running();
        let Some(updated) =
            finish_settings_dialog(dialog_result, was_advertised, child_running, || {
                self.set_environment_active(true)
            })?
        else {
            return Ok(());
        };
        if updated == self.preferences {
            finish_settings_dialog::<Preferences>(Ok(None), was_advertised, child_running, || {
                self.set_environment_active(true)
            })?;
            return Ok(());
        }

        let executable = std::env::current_exe().context("find Unproxy tray executable")?;
        let preferences_path = self.preferences_path.clone();
        let previous = self.preferences.clone();
        let apply_result = self.child.apply_preferences(
            &self.child_executable,
            &previous,
            &updated,
            |preferences| {
                preferences
                    .save(&preferences_path)
                    .context("save Unproxy settings")?;
                if updated.autostart != previous.autostart {
                    settings::set_login_startup(preferences.autostart, &executable)?;
                }
                Ok(())
            },
        );
        let running_after_apply = self.child.is_running();
        if apply_result.is_ok() {
            self.preferences = updated;
        }
        finish_settings_apply(apply_result, was_advertised, running_after_apply, || {
            self.set_environment_active(true)
        })?;
        let listener_changed =
            previous.effective_listeners() != self.preferences.effective_listeners();
        if listener_changed {
            show_information_async(
                "Unproxy Settings",
                "The proxy listener changed. Reopen applications that use the installed proxy environment to pick up the updated address. Update any manually configured proxy addresses as well.",
            );
        }
        self.last_error = None;
        self.last_icon_key.clear();
        Ok(())
    }

    fn refresh_status(&mut self) -> Result<()> {
        self.reconcile_environment()?;
        let running = self.child.is_running();
        let failed = self.child.last_exit.is_some() || self.last_error.is_some();
        let status = self
            .status_poller
            .status(running, &self.preferences, |preferences| {
                read_runtime_status(preferences)
            })?;
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

    fn set_environment_active(&mut self, active: bool) -> Result<()> {
        if self.environment_active == active {
            return Ok(());
        }
        if let Err(error) = set_managed_proxy_environment(active, &self.preferences) {
            if active {
                match set_managed_proxy_environment(false, &self.preferences) {
                    Ok(()) => self.environment_active = false,
                    Err(withdrawal_error) => {
                        self.environment_active = true;
                        return Err(error.context(format!(
                            "activation cleanup also failed: {withdrawal_error:#}"
                        )));
                    }
                }
            } else {
                // A failed or partial withdrawal may leave either variable
                // pointing here. Keep ownership until withdrawal succeeds.
                self.environment_active = true;
            }
            return Err(error);
        }
        self.environment_active = active;
        Ok(())
    }

    fn reconcile_environment(&mut self) -> Result<()> {
        let running = self.child.is_running();
        if !running && self.environment_active {
            self.set_environment_active(false)?;
        } else if running && !self.environment_active {
            self.set_environment_active(true)?;
        }
        Ok(())
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if self.environment_active
            && self.set_environment_active(false).is_err()
            && self.child.is_running()
        {
            log_status_error(
                "proxy settings could not be withdrawn; leaving the proxy child running to keep the endpoint owned",
            );
            self.child.leave_running();
        }
    }
}

/// Advertise the HTTP proxy only while the tray owns a ready child endpoint.
/// Values that no longer match Unproxy's tracking or the saved original are
/// treated as user overrides and left alone.
fn set_managed_proxy_environment(advertised: bool, preferences: &Preferences) -> Result<()> {
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
    let original = state
        .get("original")
        .and_then(serde_json::Value::as_object)
        .context("installed environment tracking has no original values")?
        .clone();
    let desired = advertised
        .then(|| proxy_environment_url(preferences))
        .transpose()?;
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
        &original,
        desired.as_deref(),
        |name| read_registry_string(key, name),
        |name, value| write_registry_string(key, name, value),
        |installed| {
            state["installed"] = serde_json::Value::Object(installed.clone());
            write_json_atomically(&state_path, &state)
                .context("update installed environment tracking")
        },
    );
    unsafe { RegCloseKey(key) };
    notify_environment_changed();
    result
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

fn finish_settings_dialog<T>(
    result: Result<Option<T>>,
    was_advertised: bool,
    child_running: bool,
    restore: impl FnOnce() -> Result<()>,
) -> Result<Option<T>> {
    if !was_advertised || !child_running || matches!(&result, Ok(Some(_))) {
        return result;
    }
    if let Err(restore_error) = restore() {
        return match result {
            Err(dialog_error) => Err(dialog_error.context(format!(
                "settings dialog failed and proxy environment restoration failed: {restore_error:#}"
            ))),
            Ok(None) => {
                Err(restore_error.context("restore proxy environment after settings dialog"))
            }
            Ok(Some(_)) => unreachable!("successful settings result does not require restoration"),
        };
    }
    result
}

fn finish_settings_apply(
    result: Result<()>,
    was_advertised: bool,
    child_running_after_apply: bool,
    activate: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !was_advertised || !child_running_after_apply {
        return result;
    }
    match result {
        Ok(()) => activate().context("settings applied, but proxy environment activation failed"),
        Err(error) => match activate() {
            Ok(()) => Err(error),
            Err(activation_error) => Err(error.context(format!(
                "settings failed and proxy environment restoration failed: {activation_error:#}"
            ))),
        },
    }
}

fn sync_managed_proxy_values(
    mut installed: serde_json::Map<String, serde_json::Value>,
    original: &serde_json::Map<String, serde_json::Value>,
    desired: Option<&str>,
    mut read: impl FnMut(&str) -> Result<Option<String>>,
    mut write: impl FnMut(&str, Option<&str>) -> Result<()>,
    mut persist: impl FnMut(&serde_json::Map<String, serde_json::Value>) -> Result<()>,
) -> Result<()> {
    if desired.is_none() {
        // Withdrawal is monotonic: attempt both variables, never restore a
        // value already withdrawn, and leave tracking untouched. The caller
        // must keep the child alive if either managed value could remain.
        let mut errors = Vec::new();
        for name in ["http_proxy", "https_proxy"] {
            let current = match read(name) {
                Ok(current) => current,
                Err(error) => {
                    errors.push(format!("read {name}: {error:#}"));
                    continue;
                }
            };
            let installed_value = installed.get(name).and_then(serde_json::Value::as_str);
            let pending_value = installed
                .get(&format!("{name}_pending"))
                .and_then(serde_json::Value::as_str);
            if installed_value.is_none() && pending_value.is_none() {
                continue;
            }
            if current.as_deref() != installed_value && current.as_deref() != pending_value {
                continue;
            }
            let original_value = original.get(name).and_then(serde_json::Value::as_str);
            if current.as_deref() == original_value {
                if current.as_deref() == installed_value {
                    errors.push(format!(
                        "{name} original value is the attempted managed endpoint and cannot be withdrawn safely"
                    ));
                }
                continue;
            }
            if let Err(error) = write(name, original_value) {
                errors.push(format!("withdraw {name}: {error:#}"));
            }
        }
        if errors.is_empty() {
            return Ok(());
        }
        anyhow::bail!("managed proxy withdrawal failed: {}", errors.join("; "));
    }

    let proxy_url = desired.expect("checked Some above");
    let mut attempted = Vec::<(String, Option<String>)>::new();
    for name in ["http_proxy", "https_proxy"] {
        let current = read(name)?;
        let installed_value = installed.get(name).and_then(serde_json::Value::as_str);
        let pending_key = format!("{name}_pending");
        let pending_value = installed
            .get(&pending_key)
            .and_then(serde_json::Value::as_str);
        let original_value = original.get(name).and_then(serde_json::Value::as_str);
        if current.as_deref() != installed_value
            && current.as_deref() != pending_value
            && current.as_deref() != original_value
        {
            continue;
        }
        installed.insert(
            name.to_owned(),
            serde_json::Value::String(proxy_url.to_owned()),
        );
        if current.as_deref() == Some(proxy_url) {
            installed.remove(&pending_key);
        } else if let Some(current_value) = current.as_ref() {
            installed.insert(
                pending_key,
                serde_json::Value::String(current_value.clone()),
            );
        } else {
            installed.remove(&pending_key);
        }
        if current.as_deref() != Some(proxy_url) {
            attempted.push((name.to_owned(), current));
        }
    }

    // Record every value that may be written before touching the registry.
    // If a write or rollback fails, the next withdrawal can identify both the
    // old and attempted URLs without ever losing ownership information.
    persist(&installed)?;
    let mut attempted_writes = Vec::new();
    for (name, old_value) in &attempted {
        attempted_writes.push((name.clone(), old_value.clone()));
        if let Err(error) = write(name, Some(proxy_url)) {
            let mut rollback_errors = Vec::new();
            for (changed_name, changed_value) in attempted_writes.iter().rev() {
                if let Err(rollback) = write(changed_name, changed_value.as_deref()) {
                    rollback_errors.push(format!("restore {changed_name}: {rollback:#}"));
                }
            }
            if rollback_errors.is_empty() {
                return Err(error);
            }
            anyhow::bail!("{error:#}; rollback failed: {}", rollback_errors.join("; "));
        }
    }

    for name in ["http_proxy", "https_proxy"] {
        installed.remove(&format!("{name}_pending"));
    }
    if let Err(error) = persist(&installed) {
        let mut rollback_errors = Vec::new();
        for (name, old_value) in attempted.iter().rev() {
            if let Err(rollback) = write(name, old_value.as_deref()) {
                rollback_errors.push(format!("restore {name}: {rollback:#}"));
            }
        }
        if rollback_errors.is_empty() {
            return Err(error);
        }
        anyhow::bail!("{error:#}; rollback failed: {}", rollback_errors.join("; "));
    }
    Ok(())
}

fn stop_child_after_withdrawal(
    withdrawal: Result<()>,
    stop: impl FnOnce() -> Result<()>,
) -> Result<()> {
    withdrawal.context("withdraw proxy settings before stopping child")?;
    stop()
}

fn start_child_after_withdrawal(
    withdrawal: Result<()>,
    start: impl FnOnce() -> Result<()>,
) -> Result<()> {
    withdrawal.context("withdraw proxy settings before starting child")?;
    start()
}

fn read_registry_string(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Result<Option<String>> {
    use windows_sys::Win32::System::Registry::{REG_SZ, RegQueryValueExW};
    let name_wide = wide(name);
    let mut kind = 0;
    let mut bytes = 0u32;
    let query = unsafe {
        RegQueryValueExW(
            key,
            name_wide.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if !registry_query_status_has_value(query, name)? {
        return Ok(None);
    }
    ensure!(
        kind == REG_SZ,
        "per-user {name} registry value is not a string"
    );
    ensure!(
        bytes >= 2,
        "per-user {name} registry value is empty or malformed"
    );
    let mut data = vec![0u16; (bytes as usize).div_ceil(2)];
    let query = unsafe {
        RegQueryValueExW(
            key,
            name_wide.as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if !registry_query_status_has_value(query, name)? {
        return Ok(None);
    }
    let end = data
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(data.len());
    Ok(Some(String::from_utf16_lossy(&data[..end])))
}

fn registry_query_status_has_value(status: u32, name: &str) -> Result<bool> {
    match status {
        0 => Ok(true),
        2 => Ok(false), // ERROR_FILE_NOT_FOUND
        status => anyhow::bail!("query per-user {name} registry value failed ({status})"),
    }
}

fn write_registry_string(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value: Option<&str>,
) -> Result<()> {
    use windows_sys::Win32::System::Registry::{REG_SZ, RegDeleteValueW, RegSetValueExW};
    let name_wide = wide(name);
    let Some(value) = value else {
        let status = unsafe { RegDeleteValueW(key, name_wide.as_ptr()) };
        if status != 0 && status != 2 {
            anyhow::bail!("delete per-user {name} failed ({status})");
        }
        return Ok(());
    };
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
    if let Err(error) = spawn_background_task("unproxy-environment-notification", || {
        notify_environment_changed_blocking();
    }) {
        log_status_error(&format!(
            "could not broadcast environment change: {error:#}"
        ));
    }
}

fn notify_environment_changed_blocking() {
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
    let deadline = Instant::now() + super::STATUS_PROBE_DEADLINE;
    read_runtime_status_with(preferences, |address| {
        read_runtime_status_until(address, deadline)
    })
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

#[cfg(test)]
fn read_runtime_status_at(address: SocketAddr) -> Option<RuntimeStatus> {
    read_runtime_status_until(address, Instant::now() + super::STATUS_PROBE_DEADLINE)
}

fn read_runtime_status_until(address: SocketAddr, deadline: Instant) -> Option<RuntimeStatus> {
    let response = super::read_status_response(address, deadline)?;
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

fn open_status_page_async(preferences: &Preferences) -> Result<()> {
    let url = preferences.status_url()?;
    spawn_background_task("unproxy-open-status-page", move || {
        if let Err(error) = open_external_url(&url) {
            show_error_async("Open Status Page", &format!("{error:#}"));
        }
    })
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

fn copy_proxy_address_async(address: String) -> Result<()> {
    spawn_background_task("unproxy-copy-proxy-address", move || {
        if let Err(error) = copy_proxy_address(&address) {
            show_error_async("Copy Proxy Address", &format!("{error:#}"));
        }
    })
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

fn show_error_async(title: &str, message: &str) {
    let title = title.to_owned();
    let message = message.to_owned();
    if let Err(error) =
        spawn_background_task("unproxy-error-dialog", move || show_error(&title, &message))
    {
        log_status_error(&format!("could not open error dialog: {error:#}"));
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

fn show_information_async(title: &str, message: &str) {
    let title = title.to_owned();
    let message = message.to_owned();
    if let Err(error) = spawn_background_task("unproxy-info-dialog", move || {
        show_information(&title, &message)
    }) {
        log_status_error(&format!("could not open information dialog: {error:#}"));
    }
}

fn spawn_background_task(name: &str, task: impl FnOnce() + Send + 'static) -> Result<()> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(task)
        .map(|_| ())
        .with_context(|| format!("start background task {name}"))
}

pub(super) fn show_startup_error(message: &str) {
    show_error("Unproxy", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_query_only_treats_missing_values_as_absent() {
        assert!(registry_query_status_has_value(0, "http_proxy").unwrap());
        assert!(!registry_query_status_has_value(2, "http_proxy").unwrap());
        assert!(registry_query_status_has_value(5, "http_proxy").is_err());
        assert!(registry_query_status_has_value(234, "http_proxy").is_err());
    }

    #[test]
    fn menu_exposes_the_status_page_action() {
        let menu = build_menu().unwrap();
        assert_eq!(menu.open_status.id().0, MENU_OPEN_STATUS);
        assert_eq!(menu.open_status.text(), "Open Status Page");
        assert_eq!(menu.check_updates.id().0, MENU_CHECK_UPDATES);
        assert_eq!(menu.check_updates.text(), "Check for Updates");
    }

    #[test]
    fn blocking_ui_work_runs_without_blocking_the_tray_caller() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        spawn_background_task("test-blocking-ui", move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        })
        .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker starts while caller remains available");
        release_tx.send(()).unwrap();
    }

    #[test]
    fn blocked_runtime_status_poll_does_not_block_tray_work() {
        let preferences = Preferences::default();
        let mut poller = RuntimeStatusPoller::default();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let read_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_count = read_count.clone();

        let started_at = Instant::now();
        poller
            .status(true, &preferences, move |_| {
                worker_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                None
            })
            .unwrap();
        let poll_call_elapsed = started_at.elapsed();
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("status poll runs in the background");

        poller.next_poll = Instant::now();
        let duplicate_count = read_count.clone();
        poller
            .status(true, &preferences, move |_| {
                duplicate_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            })
            .unwrap();
        let mut child_stopped = false;
        stop_child_after_withdrawal(Ok(()), || {
            child_stopped = true;
            Ok(())
        })
        .unwrap();

        assert!(poll_call_elapsed < Duration::from_secs(1));
        assert!(child_stopped);
        assert_eq!(read_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
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
        assert_eq!(status.upstream_state.as_deref(), Some("ok"));
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
    fn cancelling_settings_restores_environment_only_while_child_runs() {
        let mut restored = false;
        let result = finish_settings_dialog::<Preferences>(Ok(None), true, true, || {
            restored = true;
            Ok(())
        })
        .unwrap();
        assert!(result.is_none());
        assert!(restored);

        restored = false;
        finish_settings_dialog::<Preferences>(Ok(None), true, false, || {
            restored = true;
            Ok(())
        })
        .unwrap();
        assert!(!restored);
    }

    #[test]
    fn settings_dialog_error_restores_environment_and_preserves_the_error() {
        let mut restored = false;
        let result = finish_settings_dialog::<Preferences>(
            Err(anyhow::anyhow!("injected dialog error")),
            true,
            true,
            || {
                restored = true;
                Ok(())
            },
        );
        assert!(restored);
        assert!(format!("{:#}", result.unwrap_err()).contains("injected dialog error"));
    }

    #[test]
    fn changed_settings_remain_unadvertised_until_apply_completes() {
        let result = finish_settings_dialog(Ok(Some(Preferences::default())), true, true, || {
            anyhow::bail!("must not advertise before apply")
        })
        .unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn settings_apply_activates_only_after_completion_and_only_with_a_running_child() {
        let apply_completed = true;
        let mut activated = false;
        finish_settings_apply(Ok(()), true, true, || {
            assert!(apply_completed);
            activated = true;
            Ok(())
        })
        .unwrap();
        assert!(activated);

        activated = false;
        let result = finish_settings_apply(
            Err(anyhow::anyhow!("injected settings failure")),
            true,
            false,
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(!activated);
        assert!(format!("{:#}", result.unwrap_err()).contains("injected settings failure"));

        activated = false;
        let result = finish_settings_apply(
            Err(anyhow::anyhow!("injected settings failure")),
            true,
            true,
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(activated);
        assert!(format!("{:#}", result.unwrap_err()).contains("injected settings failure"));
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
            "original": {"http_proxy": "http://original-user-value", "https_proxy": null},
            "installed": installed,
        });
        let original = state["original"].as_object().unwrap().clone();
        sync_managed_proxy_values(
            state["installed"].as_object().unwrap().clone(),
            &original,
            Some("http://127.0.0.1:4444"),
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
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
        assert_eq!(
            state["original"]["http_proxy"],
            "http://original-user-value"
        );
        assert_eq!(state["installed"]["https_proxy"], "http://127.0.0.1:4444");
        assert_eq!(state["installed"]["http_proxy"], "http://127.0.0.1:3128");
        assert_eq!(state["installed"]["no_proxy"], "localhost");
    }

    #[test]
    fn environment_sync_advertises_when_the_original_value_was_missing() {
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
            &serde_json::Map::new(),
            Some("http://127.0.0.1:4444"),
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |installed| {
                persisted = Some(installed.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(current.borrow()["https_proxy"], "http://127.0.0.1:4444");
        assert_eq!(persisted.unwrap()["https_proxy"], "http://127.0.0.1:4444");
    }

    #[test]
    fn environment_sync_withdraws_managed_values_and_preserves_user_overrides() {
        let installed_url = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), installed_url.into()),
        ]);
        let original = serde_json::Map::from_iter([
            (
                "http_proxy".into(),
                serde_json::Value::String("http://original:80".into()),
            ),
            ("https_proxy".into(), serde_json::Value::Null),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), "http://user-override:8080".into()),
        ]));
        let mut persist_calls = 0;
        sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| {
                persist_calls += 1;
                anyhow::bail!("withdrawal must not persist unchanged tracking")
            },
        )
        .unwrap();
        assert_eq!(current.borrow()["http_proxy"], "http://original:80");
        assert_eq!(current.borrow()["https_proxy"], "http://user-override:8080");
        assert_eq!(persist_calls, 0);
    }

    #[test]
    fn environment_sync_does_not_restore_over_a_user_cleared_value() {
        let installed = serde_json::Map::new();
        let original = serde_json::Map::from_iter([(
            "http_proxy".into(),
            serde_json::Value::String("http://original:80".into()),
        )]);
        let current = std::cell::RefCell::new(std::collections::HashMap::<String, String>::new());
        let mut writes = Vec::new();
        sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                writes.push((name.to_owned(), value.map(str::to_owned)));
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(writes.is_empty());
        assert!(current.borrow().is_empty());
    }

    #[test]
    fn environment_sync_removes_managed_value_when_original_was_unset() {
        let installed_url = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([("http_proxy".into(), installed_url.into())]);
        let original = serde_json::Map::from_iter([("http_proxy".into(), serde_json::Value::Null)]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([(
            "http_proxy".to_owned(),
            installed_url.into(),
        )]));
        sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(current.borrow().is_empty());
    }

    #[test]
    fn failed_second_withdrawal_does_not_restore_the_first_proxy_value() {
        let installed_url = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), installed_url.into()),
        ]);
        let original = serde_json::Map::from_iter([
            (
                "http_proxy".into(),
                serde_json::Value::String("http://original-http:80".into()),
            ),
            ("https_proxy".into(), serde_json::Value::Null),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), installed_url.into()),
        ]));
        let mut write_attempts = Vec::new();
        let mut persist_calls = 0;
        let result = sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                write_attempts.push(name.to_owned());
                if name == "https_proxy" {
                    anyhow::bail!("injected second-key write failure");
                }
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| {
                persist_calls += 1;
                anyhow::bail!("injected tracking persistence failure")
            },
        );
        assert!(result.is_err());
        assert_eq!(persist_calls, 0);
        assert_eq!(write_attempts, ["http_proxy", "https_proxy"]);
        assert_eq!(current.borrow()["http_proxy"], "http://original-http:80");
        assert_eq!(current.borrow()["https_proxy"], installed_url);
    }

    #[test]
    fn withdrawal_fails_closed_when_the_original_value_is_the_managed_endpoint() {
        let installed_url = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([("http_proxy".into(), installed_url.into())]);
        let original = serde_json::Map::from_iter([("http_proxy".into(), installed_url.into())]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([(
            "http_proxy".to_owned(),
            installed_url.into(),
        )]));
        let mut writes = 0;
        let result = sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_| anyhow::bail!("withdrawal must not persist unchanged tracking"),
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("attempted managed endpoint"));
        assert_eq!(writes, 0);
        assert_eq!(current.borrow()["http_proxy"], installed_url);
    }

    #[test]
    fn withdrawn_pending_value_equal_to_original_does_not_block_shutdown() {
        let old_url = "http://127.0.0.1:3128";
        let attempted_url = "http://127.0.0.1:4444";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), attempted_url.into()),
            ("http_proxy_pending".into(), old_url.into()),
        ]);
        let original = serde_json::Map::from_iter([("http_proxy".into(), old_url.into())]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([(
            "http_proxy".to_owned(),
            old_url.to_owned(),
        )]));
        let mut writes = 0;
        sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_| anyhow::bail!("withdrawal must not persist unchanged tracking"),
        )
        .unwrap();
        assert_eq!(writes, 0);
        assert_eq!(current.borrow()["http_proxy"], old_url);
    }

    #[test]
    fn activation_rollback_failure_keeps_both_possible_urls_tracked_for_withdrawal() {
        let old_url = "http://127.0.0.1:3128";
        let attempted_url = "http://127.0.0.1:4444";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), old_url.into()),
            ("https_proxy".into(), old_url.into()),
        ]);
        let original = serde_json::Map::from_iter([
            ("http_proxy".into(), serde_json::Value::Null),
            ("https_proxy".into(), serde_json::Value::Null),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".to_owned(), old_url.to_owned()),
            ("https_proxy".to_owned(), old_url.to_owned()),
        ]));
        let tracking = std::cell::RefCell::new(installed);
        let mut fail_https_activation = true;
        let mut fail_http_rollback = true;
        let result = sync_managed_proxy_values(
            tracking.borrow().clone(),
            &original,
            Some(attempted_url),
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                if name == "https_proxy" && value == Some(attempted_url) && fail_https_activation {
                    fail_https_activation = false;
                    anyhow::bail!("injected https activation failure");
                }
                if name == "http_proxy" && value == Some(old_url) && fail_http_rollback {
                    fail_http_rollback = false;
                    anyhow::bail!("injected http rollback failure");
                }
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |installed| {
                *tracking.borrow_mut() = installed.clone();
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(current.borrow()["http_proxy"], attempted_url);
        assert_eq!(current.borrow()["https_proxy"], old_url);
        assert_eq!(tracking.borrow()["http_proxy"], attempted_url);
        assert_eq!(tracking.borrow()["http_proxy_pending"], old_url);
        assert_eq!(tracking.borrow()["https_proxy"], attempted_url);
        assert_eq!(tracking.borrow()["https_proxy_pending"], old_url);

        let mut fail_https_withdrawal = true;
        let withdrawal = sync_managed_proxy_values(
            tracking.borrow().clone(),
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                if name == "https_proxy" && fail_https_withdrawal {
                    fail_https_withdrawal = false;
                    anyhow::bail!("injected cleanup withdrawal failure");
                }
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| anyhow::bail!("withdrawal must not persist unchanged tracking"),
        );
        assert!(withdrawal.is_err());
        assert!(current.borrow().get("http_proxy").is_none());
        assert_eq!(current.borrow()["https_proxy"], old_url);
        let mut stopped = false;
        assert!(
            stop_child_after_withdrawal(withdrawal, || {
                stopped = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!stopped);

        sync_managed_proxy_values(
            tracking.borrow().clone(),
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| anyhow::bail!("withdrawal must not persist unchanged tracking"),
        )
        .unwrap();
        assert!(current.borrow().is_empty());
    }

    #[test]
    fn withdrawal_succeeds_when_tracking_persistence_would_fail() {
        let installed_url = "http://127.0.0.1:3128";
        let installed = serde_json::Map::from_iter([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), installed_url.into()),
        ]);
        let original = serde_json::Map::from_iter([
            ("http_proxy".into(), serde_json::Value::Null),
            ("https_proxy".into(), serde_json::Value::Null),
        ]);
        let current = std::cell::RefCell::new(std::collections::HashMap::from([
            ("http_proxy".into(), installed_url.into()),
            ("https_proxy".into(), installed_url.into()),
        ]));
        let mut persist_calls = 0;
        sync_managed_proxy_values(
            installed,
            &original,
            None,
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                let mut current = current.borrow_mut();
                if let Some(value) = value {
                    current.insert(name.to_owned(), value.to_owned());
                } else {
                    current.remove(name);
                }
                Ok(())
            },
            |_| {
                persist_calls += 1;
                anyhow::bail!("injected tracking persistence failure")
            },
        )
        .unwrap();
        assert_eq!(persist_calls, 0);
        assert!(current.borrow().is_empty());
    }

    #[test]
    fn child_stop_is_not_attempted_when_environment_withdrawal_fails() {
        let mut stopped = false;
        let result = stop_child_after_withdrawal(
            Err(anyhow::anyhow!("injected withdrawal failure")),
            || {
                stopped = true;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!stopped);
    }

    #[test]
    fn child_start_is_not_attempted_when_stale_environment_withdrawal_fails() {
        let mut started = false;
        let result = start_child_after_withdrawal(
            Err(anyhow::anyhow!("injected withdrawal failure")),
            || {
                started = true;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!started);
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
        let original = serde_json::Map::new();
        let result = sync_managed_proxy_values(
            installed,
            &original,
            Some("http://127.0.0.1:4444"),
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                if name == "https_proxy" && fail_https_once {
                    fail_https_once = false;
                    anyhow::bail!("injected registry write failure");
                }
                if let Some(value) = value {
                    current
                        .borrow_mut()
                        .insert(name.to_owned(), value.to_owned());
                } else {
                    current.borrow_mut().remove(name);
                }
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
        let original = serde_json::Map::new();
        let result = sync_managed_proxy_values(
            installed,
            &original,
            Some("http://127.0.0.1:4444"),
            |name| Ok(current.borrow().get(name).cloned()),
            |name, value| {
                if let Some(value) = value {
                    current
                        .borrow_mut()
                        .insert(name.to_owned(), value.to_owned());
                } else {
                    current.borrow_mut().remove(name);
                }
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
        assert_eq!(persistence_calls, 1);
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
