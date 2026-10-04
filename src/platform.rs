//! Native listener ownership, process controls and macOS network preferences.
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::TcpListener;

#[cfg(windows)]
#[path = "platform/windows_service.rs"]
mod windows_service;

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
    {
        let _ = name;
        bail!("socket activation is unsupported on Windows");
    }
    #[cfg(unix)]
    {
        let descriptors: Vec<i32>;
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn launch_activate_socket(
                    name: *const libc::c_char,
                    fds: *mut *mut libc::c_int,
                    count: *mut libc::size_t,
                ) -> libc::c_int;
            }
            let name = std::ffi::CString::new(name)?;
            let mut fds = std::ptr::null_mut();
            let mut count = 0;
            let code = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
            if code != 0 {
                bail!(
                    "launchd socket activation: {}",
                    std::io::Error::from_raw_os_error(code)
                );
            }
            descriptors = if count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(fds, count) }.to_vec()
            };
            unsafe { libc::free(fds.cast()) };
        }
        #[cfg(not(target_os = "macos"))]
        {
            let count = std::env::var("LISTEN_FDS").context("missing LISTEN_FDS")?;
            let names = std::env::var("LISTEN_FDNAMES").context("missing LISTEN_FDNAMES")?;
            let pid = std::env::var_os("LISTEN_PID")
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("invalid LISTEN_PID encoding"))
                })
                .transpose()?;
            descriptors = activation_descriptors(name, &count, &names, pid.as_deref())?;
        }
        activated_listeners_from_fds(name, descriptors)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = name;
        bail!("socket activation is unsupported on this platform");
    }
}

#[cfg(unix)]
fn activated_listeners_from_fds(name: &str, descriptors: Vec<i32>) -> Result<Vec<TcpListener>> {
    use std::os::fd::FromRawFd;
    anyhow::ensure!(
        !descriptors.is_empty(),
        "no activated sockets match {name:?}"
    );
    let mut listeners = Vec::new();
    for fd in descriptors {
        anyhow::ensure!(fd >= 0, "invalid activated descriptor");
        // The activation protocol transfers ownership of these descriptors.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        listener
            .local_addr()
            .context("activated descriptor is not a TCP listener")?;
        listener.set_nonblocking(true)?;
        listeners.push(TcpListener::from_std(listener)?);
    }
    Ok(listeners)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn activation_descriptors(
    name: &str,
    count: &str,
    names: &str,
    pid: Option<&str>,
) -> Result<Vec<i32>> {
    let count: usize = count.parse().context("invalid LISTEN_FDS")?;
    anyhow::ensure!(count <= (i32::MAX - 3) as usize, "LISTEN_FDS is too large");
    let names: Vec<_> = if names.is_empty() {
        Vec::new()
    } else {
        names.split(':').collect()
    };
    anyhow::ensure!(
        names.len() == count,
        "LISTEN_FDNAMES count does not match LISTEN_FDS"
    );
    if let Some(pid) = pid {
        let pid = pid.parse::<u32>().context("invalid LISTEN_PID")?;
        anyhow::ensure!(
            pid == std::process::id(),
            "LISTEN_PID belongs to another process"
        );
    }
    Ok(names
        .iter()
        .enumerate()
        .filter(|(_, n)| **n == name)
        .map(|(i, _)| 3 + i as i32)
        .collect())
}

/// Run the current platform's service control command.
pub fn service_control(command: &str, registration: bool) -> Result<()> {
    let commands = if registration {
        ["install", "uninstall", "status"].as_slice()
    } else {
        ["status", "start", "restart", "stop", "enable", "disable"].as_slice()
    };
    anyhow::ensure!(
        commands.contains(&command),
        "unknown command {command:?}; expected {}",
        commands.join(", ")
    );

    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        let _ = (command, registration);
        bail!("service controls are unsupported on this platform");
    }
    #[cfg(target_os = "macos")]
    {
        service_control_with(
            command,
            registration,
            |program, args| {
                invoke_service_status(program, args, |executable, args| {
                    std::process::Command::new(executable).args(args).status()
                })
            },
            |program, args| {
                invoke_service_output(program, args, |executable, args| {
                    std::process::Command::new(executable).args(args).output()
                })
            },
        )
    }
    #[cfg(windows)]
    {
        windows_service::service_control(command, registration)
    }
}

#[cfg(windows)]
pub fn dispatch_service() -> Result<bool> {
    windows_service::dispatch_service()
}

#[cfg(target_os = "macos")]
fn invoke_service_status(
    program: &str,
    args: &[&str],
    execute: impl FnOnce(&str, &[&str]) -> std::io::Result<std::process::ExitStatus>,
) -> Result<()> {
    let executable = match program {
        "launchctl" => "/bin/launchctl",
        "ps" => "/bin/ps",
        _ => bail!("unknown service command executable {program}"),
    };
    let status = execute(executable, args).with_context(|| format!("executing {program}"))?;
    anyhow::ensure!(
        status.success(),
        "{program} {} failed: {status}",
        args.join(" ")
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn invoke_service_output(
    program: &str,
    args: &[&str],
    capture: impl FnOnce(&str, &[&str]) -> std::io::Result<std::process::Output>,
) -> Result<String> {
    let executable = match program {
        "launchctl" => "/bin/launchctl",
        _ => bail!("unknown service command executable {program}"),
    };
    let output = capture(executable, args).with_context(|| format!("executing {program}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn service_control_with(
    command: &str,
    registration: bool,
    mut invoke: impl FnMut(&str, &[&str]) -> Result<()>,
    mut capture: impl FnMut(&str, &[&str]) -> Result<String>,
) -> Result<()> {
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    let target = format!("{domain}/de.m42e.unproxy");
    let plist = "/Library/LaunchAgents/de.m42e.unproxy.plist";
    match (registration, command) {
        (_, "status") => {
            invoke("launchctl", &["print", &target])?;
            let output = capture("launchctl", &["print", &target])?;
            if let Some(pid) = output
                .lines()
                .find_map(|line| line.trim().strip_prefix("pid = "))
            {
                invoke("ps", &["-p", pid.trim(), "-o", "pid,etime,command"])?;
            }
            Ok(())
        }
        (false, "start") => invoke("launchctl", &["kickstart", &target]),
        (false, "restart") => invoke("launchctl", &["kickstart", "-k", &target]),
        (false, "stop") => invoke("launchctl", &["kill", "TERM", &target]),
        (false, "enable") => invoke("launchctl", &["bootstrap", &domain, plist]),
        (false, "disable") => invoke("launchctl", &["bootout", &target]),
        (true, "install") => {
            invoke("launchctl", &["enable", &target])?;
            invoke("launchctl", &["bootstrap", &domain, plist])?;
            invoke("launchctl", &["print", &target])?;
            invoke("launchctl", &["kickstart", &target])
        }
        (true, "uninstall") => {
            let _ = invoke("launchctl", &["kill", "TERM", &target]);
            invoke("launchctl", &["disable", &target])?;
            invoke("launchctl", &["bootout", &target])
        }
        _ => bail!(
            "unknown command {command:?}; expected {}",
            if registration {
                "install, uninstall, status"
            } else {
                "status, start, restart, stop, enable, disable"
            }
        ),
    }
}

pub fn set_system_proxy(port: u16) -> Result<usize> {
    #[cfg(target_os = "macos")]
    {
        macos_preferences::set_proxy(port)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = port;
        bail!("system proxy preferences require macOS");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn socket_activation_selects_matching_names_and_validates_metadata() {
        assert_eq!(
            activation_descriptors(
                "web",
                "3",
                "metrics:web:web",
                Some(&std::process::id().to_string())
            )
            .unwrap(),
            [4, 5]
        );
        let other_pid = std::process::id().wrapping_add(1).to_string();
        assert!(activation_descriptors("web", "3", "metrics:web:web", Some(&other_pid)).is_err());
        assert!(activation_descriptors("web", "3", "web:metrics", None).is_err());
        assert_eq!(
            activation_descriptors("web", "2", "web:metrics", None).unwrap(),
            [3]
        );
        assert_eq!(
            activation_descriptors("missing", "2", "web:metrics", None).unwrap(),
            Vec::<i32>::new()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_control_rejects_unknown_commands_before_invoking_launchctl() {
        let error = service_control("invalid-test-command", false).unwrap_err();
        assert!(error.to_string().contains("unknown command"));
        assert!(
            error
                .to_string()
                .contains("status, start, restart, stop, enable, disable")
        );

        // Exercise the native status adapter. The result depends on whether
        // this test runner has a launchd registration, so only its dispatch is
        // relevant here.
        let _ = service_control("status", false);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_command_adapters_map_executables_and_preserve_status_errors() {
        use std::os::unix::process::ExitStatusExt;

        invoke_service_status("launchctl", &["print", "gui/501/service"], |path, args| {
            assert_eq!(path, "/bin/launchctl");
            assert_eq!(args, ["print", "gui/501/service"]);
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .unwrap();
        invoke_service_status("ps", &["-p", "42"], |path, args| {
            assert_eq!(path, "/bin/ps");
            assert_eq!(args, ["-p", "42"]);
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .unwrap();

        let failure = invoke_service_status("launchctl", &["kickstart"], |_, _| {
            Ok(std::process::ExitStatus::from_raw(1))
        })
        .unwrap_err();
        assert!(format!("{failure:#}").contains("launchctl kickstart failed"));
        let spawn_error = invoke_service_status("ps", &["-p", "42"], |_, _| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "fixture"))
        })
        .unwrap_err();
        assert!(format!("{spawn_error:#}").contains("executing ps"));
        assert!(invoke_service_status("unknown", &[], |_, _| unreachable!()).is_err());

        let output = invoke_service_output("launchctl", &["print"], |path, args| {
            assert_eq!(path, "/bin/launchctl");
            assert_eq!(args, ["print"]);
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: b"pid = 42\n".to_vec(),
                stderr: vec![],
            })
        })
        .unwrap();
        assert_eq!(output, "pid = 42\n");
        assert!(invoke_service_output("ps", &[], |_, _| unreachable!()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_control_dispatches_commands_and_ignores_uninstall_termination_failure() {
        use std::{cell::RefCell, string::ToString};

        let calls = RefCell::new(Vec::<(String, Vec<String>)>::new());
        let refuse_kill = RefCell::new(false);
        let captured_output = RefCell::new("service state\n  pid = 1234\n".to_owned());
        let target = format!("gui/{}/de.m42e.unproxy", unsafe { libc::getuid() });
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let mut invoke = |program: &str, args: &[&str]| {
            calls.borrow_mut().push((
                program.to_owned(),
                args.iter().map(ToString::to_string).collect(),
            ));
            if args.first() == Some(&"kill") && *refuse_kill.borrow() {
                bail!("fixture refuses stop")
            }
            Ok(())
        };
        let mut capture = |program: &str, args: &[&str]| {
            calls.borrow_mut().push((
                format!("{program} output"),
                args.iter().map(ToString::to_string).collect(),
            ));
            Ok(captured_output.borrow().clone())
        };

        for (command, args) in [
            ("start", vec!["kickstart", target.as_str()]),
            ("restart", vec!["kickstart", "-k", target.as_str()]),
            ("stop", vec!["kill", "TERM", target.as_str()]),
            (
                "enable",
                vec![
                    "bootstrap",
                    domain.as_str(),
                    "/Library/LaunchAgents/de.m42e.unproxy.plist",
                ],
            ),
            ("disable", vec!["bootout", target.as_str()]),
        ] {
            service_control_with(command, false, &mut invoke, &mut capture).unwrap();
            assert_eq!(calls.borrow().last().unwrap().1, args);
        }

        calls.borrow_mut().clear();
        service_control_with("install", true, &mut invoke, &mut capture).unwrap();
        assert_eq!(calls.borrow().len(), 4);
        assert_eq!(calls.borrow()[0].1, ["enable", target.as_str()]);
        assert_eq!(
            calls.borrow()[1].1,
            [
                "bootstrap",
                domain.as_str(),
                "/Library/LaunchAgents/de.m42e.unproxy.plist"
            ]
        );
        assert_eq!(calls.borrow()[3].1, ["kickstart", target.as_str()]);

        calls.borrow_mut().clear();
        *refuse_kill.borrow_mut() = true;
        service_control_with("uninstall", true, &mut invoke, &mut capture).unwrap();
        assert_eq!(calls.borrow().len(), 3);
        assert_eq!(calls.borrow()[0].1, ["kill", "TERM", target.as_str()]);
        assert_eq!(calls.borrow()[1].1, ["disable", target.as_str()]);
        assert_eq!(calls.borrow()[2].1, ["bootout", target.as_str()]);

        calls.borrow_mut().clear();
        service_control_with("status", false, &mut invoke, &mut capture).unwrap();
        assert_eq!(calls.borrow().len(), 3);
        assert_eq!(calls.borrow()[0].1, ["print", target.as_str()]);
        assert_eq!(calls.borrow()[1].0, "launchctl output");
        assert_eq!(calls.borrow()[2].0, "ps");
        assert_eq!(
            calls.borrow()[2].1,
            ["-p", "1234", "-o", "pid,etime,command"]
        );

        calls.borrow_mut().clear();
        *captured_output.borrow_mut() = "service has no process".to_owned();
        service_control_with("status", false, &mut invoke, &mut capture).unwrap();
        assert_eq!(calls.borrow().len(), 2);
        assert!(service_control_with("bad", true, &mut invoke, &mut capture).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_control_stops_after_install_and_status_command_errors() {
        use std::{cell::Cell, cell::RefCell, string::ToString};

        let calls = RefCell::new(Vec::<(String, Vec<String>)>::new());
        let fail_command = Cell::new("bootstrap");
        let mut invoke = |program: &str, args: &[&str]| {
            let args = args.iter().map(ToString::to_string).collect::<Vec<_>>();
            calls.borrow_mut().push((program.to_owned(), args.clone()));
            if args.first().is_some_and(|arg| arg == fail_command.get()) {
                bail!("fixture {program} failure");
            }
            Ok(())
        };
        let mut capture = |program: &str, args: &[&str]| {
            calls.borrow_mut().push((
                format!("{program} output"),
                args.iter().map(ToString::to_string).collect(),
            ));
            Ok("pid = 10\n".to_owned())
        };
        let target = format!("gui/{}/de.m42e.unproxy", unsafe { libc::getuid() });
        let domain = format!("gui/{}", unsafe { libc::getuid() });

        let error = service_control_with("install", true, &mut invoke, &mut capture).unwrap_err();
        assert!(error.to_string().contains("fixture launchctl failure"));
        assert_eq!(
            calls.borrow().as_slice(),
            [
                (
                    "launchctl".to_owned(),
                    vec!["enable".to_owned(), target.clone()]
                ),
                (
                    "launchctl".to_owned(),
                    vec![
                        "bootstrap".to_owned(),
                        domain,
                        "/Library/LaunchAgents/de.m42e.unproxy.plist".to_owned(),
                    ],
                ),
            ]
        );

        calls.borrow_mut().clear();
        fail_command.set("print");
        let error = service_control_with("status", false, &mut invoke, &mut capture).unwrap_err();
        assert!(error.to_string().contains("fixture launchctl failure"));
        assert_eq!(
            calls.borrow().as_slice(),
            [("launchctl".to_owned(), vec!["print".to_owned(), target])]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_platform_entry_points_fail_or_succeed_without_mutating_preferences() {
        assert!(attach_console().is_ok());
        assert!(!default_interface_ipv4().is_unspecified());
        let error = activated_listeners("unproxy-test-listener-that-does-not-exist").unwrap_err();
        assert!(
            error.to_string().contains("launchd socket activation")
                || error.to_string().contains("no activated sockets")
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn activated_descriptor_conversion_validates_and_takes_ownership() {
        use std::os::fd::AsRawFd;

        assert!(
            activated_listeners_from_fds("fixture", vec![])
                .unwrap_err()
                .to_string()
                .contains("no activated sockets")
        );
        assert!(
            activated_listeners_from_fds("fixture", vec![-1])
                .unwrap_err()
                .to_string()
                .contains("invalid activated descriptor")
        );

        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let duplicate = unsafe { libc::dup(tcp.as_raw_fd()) };
        assert!(duplicate >= 0);
        let listeners = activated_listeners_from_fds("fixture", vec![duplicate]).unwrap();
        assert_eq!(listeners[0].local_addr().unwrap(), address);
        drop(listeners);

        let file = std::fs::File::open("/dev/null").unwrap();
        let duplicate = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(duplicate >= 0);
        let error = activated_listeners_from_fds("fixture", vec![duplicate]).unwrap_err();
        assert!(error.to_string().contains("not a TCP listener"));
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
    }

    #[cfg(all(not(target_os = "macos"), not(windows)))]
    #[test]
    fn service_control_reports_unsupported_platform() {
        let invalid = service_control("bogus", false).unwrap_err();
        assert!(invalid.to_string().contains("unknown command"));

        let error = service_control("status", false).unwrap_err();
        assert!(error.to_string().contains("unsupported on this platform"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn system_proxy_reports_preferences_are_unavailable() {
        let error = set_system_proxy(3128).unwrap_err();
        assert!(error.to_string().contains("require macOS"));
    }
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
        fn CFStringCreateWithBytes(
            allocator: Ref,
            bytes: *const u8,
            len: isize,
            encoding: u32,
            external: u8,
        ) -> Ref;
        fn CFNumberCreate(allocator: Ref, kind: isize, value: *const c_void) -> Ref;
        fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
        fn CFArrayGetCount(array: Ref) -> isize;
        fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
        #[cfg(test)]
        fn CFNumberGetValue(number: Ref, kind: isize, value: *mut c_void) -> u8;
        fn CFDictionaryCreateMutable(
            allocator: Ref,
            capacity: isize,
            keys: Ref,
            values: Ref,
        ) -> *mut c_void;
        fn CFDictionarySetValue(dictionary: *mut c_void, key: Ref, value: Ref);
        #[cfg(test)]
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        static kCFTypeArrayCallBacks: u8;
        static kCFTypeDictionaryKeyCallBacks: u8;
        static kCFTypeDictionaryValueCallBacks: u8;
    }
    #[repr(C)]
    struct AuthorizationItem {
        name: *const c_char,
        value_len: usize,
        value: *mut c_void,
        flags: u32,
    }
    #[repr(C)]
    struct AuthorizationRights {
        count: u32,
        items: *mut AuthorizationItem,
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn AuthorizationCreate(
            rights: *const AuthorizationRights,
            environment: *const AuthorizationRights,
            flags: u32,
            authorization: *mut *mut c_void,
        ) -> i32;
        fn AuthorizationFree(authorization: *mut c_void, flags: u32) -> i32;
    }
    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCPreferencesCreateWithAuthorization(
            allocator: Ref,
            name: Ref,
            prefs_id: Ref,
            auth: *mut c_void,
        ) -> Ref;
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
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }
    fn string(value: &str) -> Owned {
        Owned(unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                value.as_ptr(),
                value.len() as isize,
                0x08000100,
                0,
            )
        })
    }
    fn number(value: i32) -> Owned {
        Owned(unsafe { CFNumberCreate(std::ptr::null(), 3, (&value as *const i32).cast()) })
    }
    struct Authorization(*mut c_void);
    impl Drop for Authorization {
        fn drop(&mut self) {
            unsafe { AuthorizationFree(self.0, 0) };
        }
    }
    fn proxy_config(port: u16) -> Owned {
        unsafe {
            let config = Owned(CFDictionaryCreateMutable(
                std::ptr::null(),
                0,
                (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
                (&raw const kCFTypeDictionaryValueCallBacks).cast(),
            ));
            for (key, value) in [
                ("HTTPEnable", i32::from(port != 0)),
                ("HTTPSEnable", i32::from(port != 0)),
                ("ProxyAutoDiscoveryEnable", 0),
                ("ProxyAutoConfigEnable", 0),
                ("SOCKSEnable", 0),
                ("GopherEnable", 0),
            ] {
                CFDictionarySetValue(config.0.cast_mut(), string(key).0, number(value).0);
            }
            if port != 0 {
                for key in ["HTTPProxy", "HTTPSProxy"] {
                    CFDictionarySetValue(config.0.cast_mut(), string(key).0, string("127.0.0.1").0);
                }
                for key in ["HTTPPort", "HTTPSPort"] {
                    CFDictionarySetValue(
                        config.0.cast_mut(),
                        string(key).0,
                        number(i32::from(port)).0,
                    );
                }
            }
            let exceptions: Vec<_> = ["::1", "127.0.0.1", "localhost", "*.local"]
                .iter()
                .map(|s| string(s))
                .collect();
            let refs: Vec<_> = exceptions.iter().map(|s| s.0).collect();
            let array = Owned(CFArrayCreate(
                std::ptr::null(),
                refs.as_ptr(),
                refs.len() as isize,
                (&raw const kCFTypeArrayCallBacks).cast(),
            ));
            CFDictionarySetValue(config.0.cast_mut(), string("ExceptionsList").0, array.0);
            config
        }
    }
    fn finish_changes(
        changed: usize,
        mut commit: impl FnMut() -> Result<()>,
        mut apply: impl FnMut() -> Result<()>,
        mut synchronize: impl FnMut(),
    ) -> Result<usize> {
        if changed == 0 {
            return Ok(0);
        }
        commit()?;
        apply()?;
        synchronize();
        Ok(changed)
    }

    pub fn set_proxy(port: u16) -> Result<usize> {
        // Every CF object returned by a Create/Copy function is owned locally.
        unsafe {
            let mut item = AuthorizationItem {
                name: c"system.preferences".as_ptr(),
                value_len: 0,
                value: std::ptr::null_mut(),
                flags: 0,
            };
            let rights = AuthorizationRights {
                count: 1,
                items: &mut item,
            };
            let mut auth = std::ptr::null_mut();
            let status = AuthorizationCreate(&rights, std::ptr::null(), 1 | 2 | 16, &mut auth);
            anyhow::ensure!(status == 0, "authorization failed: {status}");
            let auth = Authorization(auth);
            let name = string("Unproxy");
            let prefs = Owned(SCPreferencesCreateWithAuthorization(
                std::ptr::null(),
                name.0,
                std::ptr::null(),
                auth.0,
            ));
            anyhow::ensure!(
                !prefs.0.is_null(),
                "creating network preferences failed: {}",
                SCError()
            );
            let services = Owned(SCNetworkServiceCopyAll(prefs.0));
            anyhow::ensure!(
                !services.0.is_null(),
                "enumerating network services failed: {}",
                SCError()
            );
            let config = proxy_config(port);
            let ethernet = string("Ethernet");
            let wifi = string("IEEE80211");
            let proxies = string("Proxies");
            let mut changed = 0;
            for i in 0..CFArrayGetCount(services.0) {
                let service = CFArrayGetValueAtIndex(services.0, i);
                let interface = SCNetworkServiceGetInterface(service);
                if interface.is_null() {
                    continue;
                }
                let kind = SCNetworkInterfaceGetInterfaceType(interface);
                if kind.is_null() || (CFEqual(kind, ethernet.0) == 0 && CFEqual(kind, wifi.0) == 0)
                {
                    continue;
                }
                let protocol = Owned(SCNetworkServiceCopyProtocol(service, proxies.0));
                anyhow::ensure!(
                    !protocol.0.is_null(),
                    "reading proxy protocol failed: {}",
                    SCError()
                );
                let old = SCNetworkProtocolGetConfiguration(protocol.0);
                if !old.is_null() && CFEqual(old, config.0) != 0 {
                    continue;
                }
                anyhow::ensure!(
                    SCNetworkProtocolSetConfiguration(protocol.0, config.0) != 0,
                    "setting proxy preferences failed: {}",
                    SCError()
                );
                changed += 1;
            }
            finish_changes(
                changed,
                || {
                    anyhow::ensure!(
                        SCPreferencesCommitChanges(prefs.0) != 0,
                        "committing network preferences failed: {}",
                        SCError()
                    );
                    Ok(())
                },
                || {
                    anyhow::ensure!(
                        SCPreferencesApplyChanges(prefs.0) != 0,
                        "applying network preferences failed: {}",
                        SCError()
                    );
                    Ok(())
                },
                || SCPreferencesSynchronize(prefs.0),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        unsafe fn number_at(config: &Owned, key: &str) -> i32 {
            let key = string(key);
            let value = unsafe { CFDictionaryGetValue(config.0, key.0) };
            assert!(!value.is_null());
            let mut number = 0i32;
            assert_ne!(
                unsafe { CFNumberGetValue(value, 3, (&mut number as *mut i32).cast()) },
                0
            );
            number
        }

        #[test]
        fn proxy_dictionary_encodes_enabled_and_disabled_loopback_settings() {
            let enabled = proxy_config(8123);
            unsafe {
                for key in ["HTTPEnable", "HTTPSEnable"] {
                    assert_eq!(number_at(&enabled, key), 1);
                }
                for key in [
                    "ProxyAutoDiscoveryEnable",
                    "ProxyAutoConfigEnable",
                    "SOCKSEnable",
                    "GopherEnable",
                ] {
                    assert_eq!(number_at(&enabled, key), 0);
                }
                for (key, expected) in [("HTTPProxy", "127.0.0.1"), ("HTTPSProxy", "127.0.0.1")] {
                    let key = string(key);
                    let value = CFDictionaryGetValue(enabled.0, key.0);
                    let expected = string(expected);
                    assert_ne!(CFEqual(value, expected.0), 0);
                }
                for key in ["HTTPPort", "HTTPSPort"] {
                    assert_eq!(number_at(&enabled, key), 8123);
                }
                let key = string("ExceptionsList");
                let exceptions = CFDictionaryGetValue(enabled.0, key.0);
                assert_eq!(CFArrayGetCount(exceptions), 4);
                for (index, expected) in ["::1", "127.0.0.1", "localhost", "*.local"]
                    .iter()
                    .enumerate()
                {
                    let actual = CFArrayGetValueAtIndex(exceptions, index as isize);
                    let expected = string(expected);
                    assert_ne!(CFEqual(actual, expected.0), 0);
                }
            }

            let disabled = proxy_config(0);
            unsafe {
                assert_eq!(number_at(&disabled, "HTTPEnable"), 0);
                assert_eq!(number_at(&disabled, "HTTPSEnable"), 0);
                for key in ["HTTPProxy", "HTTPSProxy", "HTTPPort", "HTTPSPort"] {
                    let key = string(key);
                    assert!(CFDictionaryGetValue(disabled.0, key.0).is_null());
                }
                let key = string("ExceptionsList");
                assert_eq!(CFArrayGetCount(CFDictionaryGetValue(disabled.0, key.0)), 4);
            }
        }

        #[test]
        fn preference_transaction_stops_after_commit_or_apply_failure() {
            use std::cell::RefCell;

            let calls = RefCell::new(Vec::new());
            let changed = finish_changes(
                0,
                || {
                    calls.borrow_mut().push("commit");
                    Ok(())
                },
                || {
                    calls.borrow_mut().push("apply");
                    Ok(())
                },
                || calls.borrow_mut().push("synchronize"),
            )
            .unwrap();
            assert_eq!(changed, 0);
            assert!(calls.borrow().is_empty());

            let calls = RefCell::new(Vec::new());
            let error = finish_changes(
                2,
                || {
                    calls.borrow_mut().push("commit");
                    bail!("commit fixture failure")
                },
                || {
                    calls.borrow_mut().push("apply");
                    Ok(())
                },
                || calls.borrow_mut().push("synchronize"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("commit fixture failure"));
            assert_eq!(calls.borrow().as_slice(), ["commit"]);

            let calls = RefCell::new(Vec::new());
            let error = finish_changes(
                2,
                || {
                    calls.borrow_mut().push("commit");
                    Ok(())
                },
                || {
                    calls.borrow_mut().push("apply");
                    bail!("apply fixture failure")
                },
                || calls.borrow_mut().push("synchronize"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("apply fixture failure"));
            assert_eq!(calls.borrow().as_slice(), ["commit", "apply"]);

            let calls = RefCell::new(Vec::new());
            let changed = finish_changes(
                3,
                || {
                    calls.borrow_mut().push("commit");
                    Ok(())
                },
                || {
                    calls.borrow_mut().push("apply");
                    Ok(())
                },
                || calls.borrow_mut().push("synchronize"),
            )
            .unwrap();
            assert_eq!(changed, 3);
            assert_eq!(
                calls.borrow().as_slice(),
                ["commit", "apply", "synchronize"]
            );
        }
    }
}
