//! Native listener ownership, process controls and macOS network preferences.
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::TcpListener;

/// Query the routing table without transmitting application data.
pub fn default_interface_ipv4() -> IpAddr {
    let discover = || -> std::io::Result<IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("192.0.2.1:9")?;
        Ok(socket.local_addr()?.ip())
    };
    discover().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

pub fn attach_console() -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let error = std::io::Error::last_os_error();
            // ERROR_ACCESS_DENIED means we already have a console.
            if error.raw_os_error() != Some(5) {
                return Err(error).context("attaching to parent console");
            }
        }
    }
    Ok(())
}

pub fn activated_listeners(name: &str) -> Result<Vec<TcpListener>> {
    #[cfg(windows)]
    { let _ = name; bail!("socket activation is unsupported on Windows"); }
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let descriptors: Vec<i32>;
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn launch_activate_socket(name: *const libc::c_char, fds: *mut *mut libc::c_int, count: *mut libc::size_t) -> libc::c_int;
            }
            let name = std::ffi::CString::new(name)?;
            let mut fds = std::ptr::null_mut();
            let mut count = 0;
            let code = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
            if code != 0 { bail!("launchd socket activation: {}", std::io::Error::from_raw_os_error(code)); }
            descriptors = if count == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(fds, count) }.to_vec() };
            unsafe { libc::free(fds.cast()) };
        }
        #[cfg(not(target_os = "macos"))]
        {
            let count: usize = std::env::var("LISTEN_FDS").context("missing LISTEN_FDS")?.parse().context("invalid LISTEN_FDS")?;
            anyhow::ensure!(count <= (i32::MAX - 3) as usize, "LISTEN_FDS is too large");
            let names = std::env::var("LISTEN_FDNAMES").context("missing LISTEN_FDNAMES")?;
            let names: Vec<_> = if names.is_empty() { Vec::new() } else { names.split(':').collect() };
            anyhow::ensure!(names.len() == count, "LISTEN_FDNAMES count does not match LISTEN_FDS");
            if let Ok(pid) = std::env::var("LISTEN_PID") && let Ok(pid) = pid.parse::<u32>() {
                anyhow::ensure!(pid == std::process::id(), "LISTEN_PID belongs to another process");
            }
            descriptors = names.iter().enumerate().filter(|(_, n)| **n == name).map(|(i, _)| 3 + i as i32).collect();
        }
        anyhow::ensure!(!descriptors.is_empty(), "no activated sockets match {name:?}");
        let mut listeners = Vec::new();
        for fd in descriptors {
            anyhow::ensure!(fd >= 0, "invalid activated descriptor");
            // The activation protocol transfers ownership of these descriptors.
            let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            listener.local_addr().context("activated descriptor is not a TCP listener")?;
            listener.set_nonblocking(true)?;
            listeners.push(TcpListener::from_std(listener)?);
        }
        Ok(listeners)
    }
    #[cfg(not(any(unix, windows)))]
    { let _ = name; bail!("socket activation is unsupported on this platform"); }
}

/// Run the launchd service command in the current user's GUI domain.
pub fn service_control(command: &str, registration: bool) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    { let _ = (command, registration); bail!("launchd service controls require macOS"); }
    #[cfg(target_os = "macos")]
    {
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let target = format!("{domain}/de.m42e.unproxy");
        let plist = "/Library/LaunchAgents/de.m42e.unproxy.plist";
        let run = |args: &[&str]| -> Result<()> {
            let status = std::process::Command::new("/bin/launchctl").args(args).status().context("executing launchctl")?;
            anyhow::ensure!(status.success(), "launchctl {} failed: {status}", args.join(" "));
            Ok(())
        };
        match (registration, command) {
            (_, "status") => {
                run(&["print", &target])?;
                let output = std::process::Command::new("/bin/launchctl").args(["print", &target]).output()?;
                if let Some(pid) = String::from_utf8_lossy(&output.stdout).lines().find_map(|line| line.trim().strip_prefix("pid = ")) {
                    let status = std::process::Command::new("/bin/ps").args(["-p", pid.trim(), "-o", "pid,etime,command"]).status()?;
                    anyhow::ensure!(status.success(), "ps failed: {status}");
                }
                Ok(())
            }
            (false, "start") => run(&["kickstart", &target]),
            (false, "restart") => run(&["kickstart", "-k", &target]),
            (false, "stop") => run(&["kill", "TERM", &target]),
            (false, "enable") => run(&["bootstrap", &domain, plist]),
            (false, "disable") => run(&["bootout", &target]),
            (true, "install") => {
                run(&["enable", &target])?;
                run(&["bootstrap", &domain, plist])?;
                run(&["print", &target])?;
                run(&["kickstart", &target])
            }
            (true, "uninstall") => {
                let _ = run(&["kill", "TERM", &target]);
                run(&["disable", &target])?;
                run(&["bootout", &target])
            }
            _ => bail!("unknown command {command:?}; expected {}", if registration {"install, uninstall, status"} else {"status, start, restart, stop, enable, disable"}),
        }
    }
}

pub fn set_system_proxy(port: u16) -> Result<usize> {
    #[cfg(target_os = "macos")]
    { macos_preferences::set_proxy(port) }
    #[cfg(not(target_os = "macos"))]
    { let _ = port; bail!("system proxy preferences require macOS"); }
}

#[cfg(target_os = "macos")]
mod macos_preferences {
    use super::*;
    use std::ffi::{c_char, c_void};
    type Ref = *const c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: Ref);
        fn CFEqual(a: Ref, b: Ref) -> u8;
        fn CFStringCreateWithBytes(allocator: Ref, bytes: *const u8, len: isize, encoding: u32, external: u8) -> Ref;
        fn CFNumberCreate(allocator: Ref, kind: isize, value: *const c_void) -> Ref;
        fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
        fn CFArrayGetCount(array: Ref) -> isize;
        fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
        fn CFDictionaryCreateMutable(allocator: Ref, capacity: isize, keys: Ref, values: Ref) -> *mut c_void;
        fn CFDictionarySetValue(dictionary: *mut c_void, key: Ref, value: Ref);
        static kCFTypeArrayCallBacks: u8;
        static kCFTypeDictionaryKeyCallBacks: u8;
        static kCFTypeDictionaryValueCallBacks: u8;
    }
    #[repr(C)]
    struct AuthorizationItem {name: *const c_char, value_len: usize, value: *mut c_void, flags: u32}
    #[repr(C)]
    struct AuthorizationRights {count: u32, items: *mut AuthorizationItem}
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn AuthorizationCreate(rights: *const AuthorizationRights, environment: *const AuthorizationRights, flags: u32, authorization: *mut *mut c_void) -> i32;
        fn AuthorizationFree(authorization: *mut c_void, flags: u32) -> i32;
    }
    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCPreferencesCreateWithAuthorization(allocator: Ref, name: Ref, prefs_id: Ref, auth: *mut c_void) -> Ref;
        fn SCPreferencesCommitChanges(prefs: Ref) -> u8;
        fn SCPreferencesApplyChanges(prefs: Ref) -> u8;
        fn SCPreferencesSynchronize(prefs: Ref);
        fn SCNetworkServiceCopyAll(prefs: Ref) -> Ref;
        fn SCNetworkServiceGetInterface(service: Ref) -> Ref;
        fn SCNetworkInterfaceGetInterfaceType(interface: Ref) -> Ref;
        fn SCNetworkServiceCopyProtocol(service: Ref, kind: Ref) -> Ref;
        fn SCNetworkProtocolGetConfiguration(protocol: Ref) -> Ref;
        fn SCNetworkProtocolSetConfiguration(protocol: Ref, config: Ref) -> u8;
        fn SCError() -> i32;
    }
    struct Owned(Ref);
    impl Drop for Owned { fn drop(&mut self) { if !self.0.is_null() { unsafe { CFRelease(self.0) }; } } }
    fn string(value: &str) -> Owned {
        Owned(unsafe { CFStringCreateWithBytes(std::ptr::null(), value.as_ptr(), value.len() as isize, 0x08000100, 0) })
    }
    fn number(value: i32) -> Owned { Owned(unsafe { CFNumberCreate(std::ptr::null(), 3, (&value as *const i32).cast()) }) }
    struct Authorization(*mut c_void);
    impl Drop for Authorization { fn drop(&mut self) { unsafe { AuthorizationFree(self.0, 0) }; } }
    pub fn set_proxy(port: u16) -> Result<usize> {
        // Every CF object returned by a Create/Copy function is owned locally.
        unsafe {
            let mut item = AuthorizationItem {name: c"system.preferences".as_ptr(), value_len: 0, value: std::ptr::null_mut(), flags: 0};
            let rights = AuthorizationRights { count: 1, items: &mut item };
            let mut auth = std::ptr::null_mut();
            let status = AuthorizationCreate(&rights, std::ptr::null(), 1 | 2 | 8, &mut auth);
            anyhow::ensure!(status == 0, "authorization failed: {status}");
            let auth = Authorization(auth);
            let name = string("Unproxy");
            let prefs = Owned(SCPreferencesCreateWithAuthorization(std::ptr::null(), name.0, std::ptr::null(), auth.0));
            anyhow::ensure!(!prefs.0.is_null(), "creating network preferences failed: {}", SCError());
            let services = Owned(SCNetworkServiceCopyAll(prefs.0));
            anyhow::ensure!(!services.0.is_null(), "enumerating network services failed: {}", SCError());
            let config = Owned(CFDictionaryCreateMutable(std::ptr::null(), 0, (&raw const kCFTypeDictionaryKeyCallBacks).cast(), (&raw const kCFTypeDictionaryValueCallBacks).cast()));
            for (key, value) in [("HTTPEnable", i32::from(port != 0)), ("HTTPSEnable", i32::from(port != 0)), ("ProxyAutoDiscoveryEnable", 0), ("ProxyAutoConfigEnable", 0), ("SOCKSEnable", 0), ("GopherEnable", 0)] {
                CFDictionarySetValue(config.0.cast_mut(), string(key).0, number(value).0);
            }
            if port != 0 {
                for key in ["HTTPProxy", "HTTPSProxy"] { CFDictionarySetValue(config.0.cast_mut(), string(key).0, string("127.0.0.1").0); }
                for key in ["HTTPPort", "HTTPSPort"] { CFDictionarySetValue(config.0.cast_mut(), string(key).0, number(i32::from(port)).0); }
            }
            let exceptions: Vec<_> = ["::1", "127.0.0.1", "localhost", "*.local"].iter().map(|s| string(s)).collect();
            let refs: Vec<_> = exceptions.iter().map(|s| s.0).collect();
            let array = Owned(CFArrayCreate(std::ptr::null(), refs.as_ptr(), refs.len() as isize, (&raw const kCFTypeArrayCallBacks).cast()));
            CFDictionarySetValue(config.0.cast_mut(), string("ExceptionsList").0, array.0);
            let ethernet = string("Ethernet"); let wifi = string("IEEE80211"); let proxies = string("Proxies");
            let mut changed = 0;
            for i in 0..CFArrayGetCount(services.0) {
                let service = CFArrayGetValueAtIndex(services.0, i);
                let interface = SCNetworkServiceGetInterface(service);
                if interface.is_null() { continue; }
                let kind = SCNetworkInterfaceGetInterfaceType(interface);
                if kind.is_null() || (CFEqual(kind, ethernet.0) == 0 && CFEqual(kind, wifi.0) == 0) { continue; }
                let protocol = Owned(SCNetworkServiceCopyProtocol(service, proxies.0));
                anyhow::ensure!(!protocol.0.is_null(), "reading proxy protocol failed: {}", SCError());
                let old = SCNetworkProtocolGetConfiguration(protocol.0);
                if !old.is_null() && CFEqual(old, config.0) != 0 { continue; }
                anyhow::ensure!(SCNetworkProtocolSetConfiguration(protocol.0, config.0) != 0, "setting proxy preferences failed: {}", SCError());
                changed += 1;
            }
            if changed != 0 {
                anyhow::ensure!(SCPreferencesCommitChanges(prefs.0) != 0, "committing network preferences failed: {}", SCError());
                anyhow::ensure!(SCPreferencesApplyChanges(prefs.0) != 0, "applying network preferences failed: {}", SCError());
                SCPreferencesSynchronize(prefs.0);
            }
            Ok(changed)
        }
    }
}
