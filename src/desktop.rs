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
    pub pac_file: PathBuf,
    pub negotiate: bool,
    pub proxytunnel: bool,
    pub direct_fallback: bool,
    pub autostart: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            port: 3128,
            pac_file: default_pac_path(),
            negotiate: false,
            proxytunnel: false,
            direct_fallback: false,
            autostart: true,
        }
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
    pub fn effective_port(&self) -> u16 {
        if (1024..=65534).contains(&self.port) {
            self.port as u16
        } else {
            3128
        }
    }
    pub fn child_args(&self) -> Vec<String> {
        let mut a = vec![
            "--listen".into(),
            format!("127.0.0.1:{}", self.effective_port()),
            "--graceful-shutdown-timeout".into(),
            "0".into(),
            "--pac-file".into(),
            self.pac_file.to_string_lossy().into_owned(),
        ];
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

#[derive(Default)]
pub struct ChildLifecycle {
    child: Option<Child>,
    pub last_exit: Option<String>,
}
impl ChildLifecycle {
    pub fn is_running(&mut self) -> bool {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let message = format!("Proxy exited unexpectedly ({status})");
                    self.last_exit = Some(message.clone());
                    if let Ok(mut log) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log_path())
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
        anyhow::ensure!(prefs.pac_file.is_absolute(), "PAC path must be absolute");
        anyhow::ensure!(
            prefs.pac_file.is_file(),
            "PAC file is missing: {}",
            prefs.pac_file.display()
        );
        std::fs::File::open(&prefs.pac_file)
            .with_context(|| format!("read PAC file {}", prefs.pac_file.display()))?;
        if let Some(parent) = log_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path())?;
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
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
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
                        .open(log_path())
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
    let script = exe
        .parent()
        .context("tray executable has no parent directory")?
        .join("unproxy-tray.ps1");
    anyhow::ensure!(
        script.is_file(),
        "tray controller script is missing: {}",
        script.display()
    );
    let status = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script)
        .creation_flags(0x08000000)
        .status()?;
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
    struct State {
        prefs: Preferences,
        prefs_path: PathBuf,
        child: ChildLifecycle,
        child_exe: PathBuf,
        network_available: Option<bool>,
        _instance_lock: std::fs::File,
        status_button: usize,
        last_running: bool,
    }
    unsafe extern "C-unwind" fn action(_this: *mut AnyObject, _cmd: Sel, sender: *mut AnyObject) {
        let tag: i64 = unsafe { msg_send![sender, tag] };
        let mut terminate = false;
        if let Some(shared) = STATE.lock().unwrap().as_ref() {
            let mut s = shared.lock().unwrap();
            match tag {
                1 => {
                    let exe = s.child_exe.clone();
                    let prefs = s.prefs.clone();
                    if let Err(error) = s.child.start(&exe, &prefs) {
                        show_alert(&format!("Could not start Unproxy: {error:#}"));
                    }
                    s.last_running = s.child.is_running();
                    if !s.last_running {
                        if let Some(exit) = &s.child.last_exit {
                            show_alert(exit);
                        }
                    }
                }
                2 => {
                    let _ = s.child.stop();
                    s.last_running = false;
                }
                3..=5 => {
                    let running = s.child.is_running();
                    match tag {
                        3 => s.prefs.proxytunnel = !s.prefs.proxytunnel,
                        4 => s.prefs.direct_fallback = !s.prefs.direct_fallback,
                        _ => s.prefs.negotiate = !s.prefs.negotiate,
                    }
                    let _ = save_native_preferences(&s.prefs, &s.prefs_path);
                    let exe = s.child_exe.clone();
                    let prefs = s.prefs.clone();
                    if running {
                        if let Err(e) = s.child.restart(&exe, &prefs) {
                            show_alert(&format!("Could not restart Unproxy: {e:#}"));
                        }
                    }
                    s.last_running = s.child.is_running();
                }
                7 | 8 => {
                    let running = s.child.is_running();
                    let current = if tag == 7 {
                        s.prefs.port.to_string()
                    } else {
                        s.prefs.pac_file.to_string_lossy().into_owned()
                    };
                    if let Some(value) = prompt(
                        if tag == 7 {
                            "Listener port (1024–65534)"
                        } else {
                            "Absolute PAC file path"
                        },
                        &current,
                    ) {
                        if tag == 7 {
                            match value.parse::<u32>() {
                                Ok(port) if (1024..=65534).contains(&port) => s.prefs.port = port,
                                _ => show_alert("Port must be an integer from 1024 through 65534."),
                            }
                        } else {
                            let path = PathBuf::from(value);
                            if !path.is_absolute() {
                                show_alert("PAC path must be absolute.");
                            } else {
                                s.prefs.pac_file = path;
                            }
                        }
                        let _ = save_native_preferences(&s.prefs, &s.prefs_path);
                        if running {
                            let exe = s.child_exe.clone();
                            let prefs = s.prefs.clone();
                            if let Err(e) = s.child.restart(&exe, &prefs) {
                                show_alert(&format!("Could not restart Unproxy: {e:#}"));
                            }
                        }
                        s.last_running = s.child.is_running();
                    }
                }
                9 => {
                    s.prefs.autostart = !s.prefs.autostart;
                    let enabled = s.prefs.autostart;
                    let _ = save_native_preferences(&s.prefs, &s.prefs_path);
                    let result = set_login_item(enabled);
                    if let Err(e) = result {
                        s.prefs.autostart = !enabled;
                        let _ = save_native_preferences(&s.prefs, &s.prefs_path);
                        show_alert(&format!("Could not update login startup: {e:#}"));
                    }
                }
                6 => {
                    let _ = s.child.stop();
                    terminate = true;
                }
                _ => {}
            }
        }
        if terminate {
            let app: *mut AnyObject =
                unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
            let _: () = unsafe { msg_send![app, terminate:ptr::null_mut::<AnyObject>()] };
        }
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
                let detail = s.child.last_exit.as_deref().unwrap_or("Proxy stopped");
                show_alert(detail);
            }
            s.last_running = running;
            let title = if running { "Unproxy •" } else { "Unproxy" };
            let button = s.status_button as *mut AnyObject;
            if !button.is_null() {
                let _: () = unsafe { msg_send![button, setTitle:cocoa_string(title)] };
            }
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
            let target: *mut AnyObject = unsafe { msg_send![menu, delegate] };
            if running {
                menu_item(menu, "Stop", 2, false, true, target);
                menu_item(
                    menu,
                    &format!("Port {}", s.prefs.effective_port()),
                    0,
                    false,
                    false,
                    target,
                );
                menu_item(
                    menu,
                    &format!("PAC {}", s.prefs.pac_file.display()),
                    0,
                    false,
                    false,
                    target,
                );
            } else {
                menu_item(menu, "Start", 1, false, true, target);
                if let Some(exit) = &s.child.last_exit {
                    menu_item(menu, exit, 0, false, false, target);
                }
            }
            menu_item(
                menu,
                if (1024..=65534).contains(&s.prefs.port) {
                    "Edit Listener Port…"
                } else {
                    "Edit Listener Port… (invalid saved value)"
                },
                7,
                false,
                true,
                target,
            );
            menu_item(menu, "Edit PAC File…", 8, false, true, target);
            menu_item(
                menu,
                "Always use CONNECT",
                3,
                s.prefs.proxytunnel,
                true,
                target,
            );
            menu_item(
                menu,
                "DIRECT fallback",
                4,
                s.prefs.direct_fallback,
                true,
                target,
            );
            #[cfg(feature = "negotiate")]
            {
                menu_item(menu, "Negotiate", 5, s.prefs.negotiate, true, target);
                if s.prefs.negotiate {
                    menu_item(
                        menu,
                        &format!(
                            "Internal network: {}",
                            match s.network_available {
                                Some(true) => "available",
                                Some(false) => "unavailable",
                                None => "unknown",
                            }
                        ),
                        0,
                        false,
                        false,
                        target,
                    );
                }
            }
            menu_item(menu, "Start at Login", 9, s.prefs.autostart, true, target);
            menu_item(
                menu,
                &format!("Log: {}", log_path().display()),
                0,
                false,
                false,
                target,
            );
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
        let defaults = AnyClass::get(c"NSUserDefaults").context("NSUserDefaults class missing")?;
        for sel in [
            sel!(standardUserDefaults),
            sel!(objectForKey:),
            sel!(setObject:forKey:),
            sel!(setBool:forKey:),
            sel!(setInteger:forKey:),
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
    fn prompt(message: &str, default: &str) -> Option<String> {
        let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "display dialog \"{}\" default answer \"{}\" buttons {{\"Cancel\", \"Save\"}} default button \"Save\"",
            escape(message),
            escape(default)
        );
        let out = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Some(text.split_once("text returned:")?.1.trim().to_owned())
    }
    fn set_login_item(enabled: bool) -> Result<()> {
        #[link(name = "ServiceManagement", kind = "framework")]
        unsafe extern "C" {
            fn SMLoginItemSetEnabled(identifier: *mut AnyObject, enabled: u8) -> u8;
        }
        let ok =
            unsafe { SMLoginItemSetEnabled(cocoa_string(HELPER_BUNDLE_ID), u8::from(enabled)) };
        anyhow::ensure!(ok != 0, "ServiceManagement rejected the login item change");
        Ok(())
    }
    fn native_preferences(defaults_path: &Path) -> Result<Preferences> {
        let defaults: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSUserDefaults), standardUserDefaults] };
        let key = |s: &str| cocoa_string(s);
        let get = |name: &str| -> *mut AnyObject {
            unsafe { msg_send![defaults,objectForKey:key(name)] }
        };
        let mut p = Preferences::default();
        let port = get("port");
        if port.is_null() {
            let _: () = unsafe { msg_send![defaults,setInteger:3128isize,forKey:key("port")] };
        } else {
            let n: isize = unsafe { msg_send![port, integerValue] };
            p.port = n.clamp(0, u32::MAX as isize) as u32;
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
        if !p.pac_file.is_absolute() {
            p.pac_file = std::env::current_dir()?.join(&p.pac_file);
        }
        for (name, field) in [
            ("negotiate", 0u8),
            ("proxytunnel", 1),
            ("directFallback", 2),
            ("autostart", 3),
        ] {
            let obj = get(name);
            if obj.is_null() {
                let _: () = unsafe {
                    msg_send![defaults,setBool:objc2::runtime::Bool::new(field == 3),forKey:key(name)]
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
    fn save_native_preferences(p: &Preferences, path: &Path) -> Result<()> {
        p.save(path)?;
        let d: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSUserDefaults), standardUserDefaults] };
        let _: () = unsafe { msg_send![d,setInteger:p.port as isize,forKey:cocoa_string("port")] };
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
        let dir = support_dir();
        std::fs::create_dir_all(&dir)?;
        use std::os::fd::AsRawFd;
        let instance_lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(dir.join("controller.lock"))?;
        if unsafe { libc::flock(instance_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Ok(());
        }
        let path = dir.join("preferences.json");
        let prefs = native_preferences(&path)?;
        let paths = BundlePaths::from_main_executable(&std::env::current_exe()?)?;
        let exe = paths.child;
        let sample_pac = default_pac_path();
        if !sample_pac.exists() {
            std::fs::write(
                &sample_pac,
                "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
            )?;
        }
        let state = Arc::new(Mutex::new(State {
            prefs,
            prefs_path: path,
            child: ChildLifecycle::default(),
            child_exe: exe,
            network_available: None,
            _instance_lock: instance_lock,
            status_button: 0,
            last_running: false,
        }));
        *STATE.lock().unwrap() = Some(state.clone());
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: objc2::runtime::Bool = unsafe { msg_send![app, setActivationPolicy:1isize] };
        {
            let mut s = state.lock().unwrap();
            let exe = s.child_exe.clone();
            let prefs = s.prefs.clone();
            if let Err(e) = s.child.start(&exe, &prefs) {
                show_alert(&format!("Could not start Unproxy: {e:#}"));
            }
            s.last_running = s.child.is_running();
            if !s.last_running {
                if let Some(exit) = &s.child.last_exit {
                    show_alert(exit);
                }
            }
        }
        let bar: *mut AnyObject = unsafe { msg_send![objc2::class!(NSStatusBar), systemStatusBar] };
        let item: *mut AnyObject = unsafe { msg_send![bar, statusItemWithLength:-1.0f64] };
        let button: *mut AnyObject = unsafe { msg_send![item, button] };
        let _: () = unsafe { msg_send![button, setTitle:cocoa_string("Unproxy")] };
        state.lock().unwrap().status_button = button as usize;
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
            msg_send![center,postNotificationName:cocoa_string(HELPER_TERMINATE_NOTIFICATION),object:ptr::null_mut::<AnyObject>(),userInfo:ptr::null_mut::<AnyObject>(),deliverImmediately:objc2::runtime::Bool::YES]
        };
        let login_enabled = state.lock().unwrap().prefs.autostart;
        if let Err(e) = set_login_item(login_enabled) {
            show_alert(&format!("Could not update Unproxy login startup: {e:#}"));
        }
        let menu: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenu), new] };
        let _: () = unsafe { msg_send![menu, setDelegate:target] };
        let _: () = unsafe { msg_send![item, setMenu:menu] };
        let _: () = unsafe { msg_send![app, run] };
        let _ = state.lock().unwrap().child.stop();
        Ok(())
    }

    fn show_alert(message: &str) {
        let alert: *mut AnyObject = unsafe { msg_send![objc2::class!(NSAlert), new] };
        let _: () = unsafe { msg_send![alert, setMessageText:cocoa_string("Unproxy")] };
        let _: () = unsafe { msg_send![alert, setInformativeText:cocoa_string(message)] };
        let _: isize = unsafe { msg_send![alert, runModal] };
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
}

pub fn launch_helper_main_app() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").args(["-b", APP_BUNDLE_ID]).status();
    }
    Ok(())
}
