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
    pub port: u16,
    pub pac_file: PathBuf,
    pub negotiate: bool,
    pub proxytunnel: bool,
    pub direct_fallback: bool,
    pub autostart: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            port: 8080,
            pac_file: default_pac_path(),
            negotiate: false,
            proxytunnel: false,
            direct_fallback: false,
            autostart: false,
        }
    }
}
pub fn support_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/Application Support/Unproxy")
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
        Ok(Self{child:contents.join("Resources/unproxy"),login_helper:contents.join("Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper")})
    }
}
impl Preferences {
    pub fn effective_port(&self) -> u16 {
        if (1024..=65534).contains(&self.port) {
            self.port
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
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
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
}
impl ChildLifecycle {
    pub fn is_running(&mut self) -> bool {
        if self
            .child
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some())
        {
            self.child = None;
        }
        self.child.is_some()
    }
    pub fn start(&mut self, exe: &Path, prefs: &Preferences) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        let mut c = Command::new(exe);
        c.args(prefs.child_args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        self.child = Some(
            c.spawn()
                .with_context(|| format!("start {}", exe.display()))?,
        );
        Ok(())
    }
    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        Ok(())
    }
    pub fn restart(&mut self, exe: &Path, prefs: &Preferences) -> Result<()> {
        self.stop()?;
        self.start(exe, prefs)
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
        network_available: bool,
    }
    unsafe extern "C-unwind" fn action(_this: *mut AnyObject, _cmd: Sel, sender: *mut AnyObject) {
        let tag: i64 = unsafe { msg_send![sender, tag] };
        if let Some(shared) = STATE.lock().unwrap().as_ref() {
            let mut s = shared.lock().unwrap();
            match tag {
                1 => {
                    let exe = s.child_exe.clone();
                    let prefs = s.prefs.clone();
                    let _ = s.child.start(&exe, &prefs);
                }
                2 => {
                    let _ = s.child.stop();
                }
                3..=5 => {
                    match tag {
                        3 => s.prefs.proxytunnel = !s.prefs.proxytunnel,
                        4 => s.prefs.direct_fallback = !s.prefs.direct_fallback,
                        _ => s.prefs.negotiate = !s.prefs.negotiate,
                    }
                    let _ = save_native_preferences(&s.prefs, &s.prefs_path);
                    let exe = s.child_exe.clone();
                    let prefs = s.prefs.clone();
                    let _ = s.child.restart(&exe, &prefs);
                }
                6 => {
                    let _ = s.child.stop();
                    let app: *mut AnyObject =
                        unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
                    let _: () = unsafe { msg_send![app, terminate:ptr::null_mut::<AnyObject>()] };
                }
                _ => {}
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
            }
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
                        "Internal network available",
                        0,
                        s.network_available,
                        false,
                        target,
                    );
                }
            }
            menu_item(menu, "Quit", 6, false, true, target);
        }
    }
    unsafe extern "C-unwind" fn network_available(
        _this: *mut AnyObject,
        _cmd: Sel,
        _note: *mut AnyObject,
    ) {
        if let Some(s) = STATE.lock().unwrap().as_ref() {
            s.lock().unwrap().network_available = true;
        }
    }
    unsafe extern "C-unwind" fn network_unavailable(
        _this: *mut AnyObject,
        _cmd: Sel,
        _note: *mut AnyObject,
    ) {
        if let Some(s) = STATE.lock().unwrap().as_ref() {
            s.lock().unwrap().network_available = false;
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
        }
        cb.register()
    }
    pub fn validate_bindings() -> Result<()> {
        let cls = action_class();
        for selector in [
            sel!(clicked:),
            sel!(menuNeedsUpdate:),
            sel!(networkAvailable:),
            sel!(networkUnavailable:),
            sel!(terminateHelper:),
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
            let _: () = unsafe { msg_send![defaults,setInteger:8080isize,forKey:key("port")] };
        } else {
            let n: isize = unsafe { msg_send![port, integerValue] };
            p.port = n.clamp(0, 65535) as u16;
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
        for (name, field) in [
            ("negotiate", 0u8),
            ("proxytunnel", 1),
            ("directFallback", 2),
            ("autostart", 3),
        ] {
            let obj = get(name);
            if obj.is_null() {
                let _: () = unsafe {
                    msg_send![defaults,setBool:objc2::runtime::Bool::NO,forKey:key(name)]
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
        let path = dir.join("preferences.json");
        let prefs = native_preferences(&path)?;
        let paths = BundlePaths::from_main_executable(&std::env::current_exe()?)?;
        let exe = paths.child;
        let state = Arc::new(Mutex::new(State {
            prefs,
            prefs_path: path,
            child: ChildLifecycle::default(),
            child_exe: exe,
            network_available: true,
        }));
        *STATE.lock().unwrap() = Some(state.clone());
        {
            let mut s = state.lock().unwrap();
            let exe = s.child_exe.clone();
            let prefs = s.prefs.clone();
            s.child.start(&exe, &prefs)?;
        }
        let app: *mut AnyObject =
            unsafe { msg_send![objc2::class!(NSApplication), sharedApplication] };
        let _: objc2::runtime::Bool = unsafe { msg_send![app, setActivationPolicy:1isize] };
        let bar: *mut AnyObject = unsafe { msg_send![objc2::class!(NSStatusBar), systemStatusBar] };
        let item: *mut AnyObject = unsafe { msg_send![bar, statusItemWithLength:-1.0f64] };
        let button: *mut AnyObject = unsafe { msg_send![item, button] };
        let _: () = unsafe { msg_send![button, setTitle:cocoa_string("Proxy")] };
        let cls = action_class();
        let target: *mut AnyObject = unsafe { msg_send![cls, new] };
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
        #[link(name = "ServiceManagement", kind = "framework")]
        unsafe extern "C" {
            fn SMLoginItemSetEnabled(identifier: *mut AnyObject, enabled: u8) -> u8;
        }
        let _: u8 = unsafe { SMLoginItemSetEnabled(cocoa_string(HELPER_BUNDLE_ID), 1) };
        let menu: *mut AnyObject = unsafe { msg_send![objc2::class!(NSMenu), new] };
        let _: () = unsafe { msg_send![menu, setDelegate:target] };
        let _: () = unsafe { msg_send![item, setMenu:menu] };
        let _: () = unsafe { msg_send![app, run] };
        let _ = state.lock().unwrap().child.stop();
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
        let _ = Command::new("open").args(["-b", APP_BUNDLE_ID]).status();
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
