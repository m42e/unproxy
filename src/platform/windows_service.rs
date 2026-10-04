//! Windows Service Control Manager support for the Unproxy proxy process.
use anyhow::{Context, Result, anyhow, bail};
use std::{
    ffi::c_void,
    path::PathBuf,
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicPtr, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, GetLastError,
    },
    System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
        CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
        RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
        SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_AUTO_START,
        SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW,
        SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
    },
};

const SERVICE_NAME: &str = "Unproxy";
const DISPLAY_NAME: &str = "Unproxy Local Proxy";
const SERVICE_DESCRIPTION: &str = "Local PAC-aware HTTP proxy";
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const SERVICE_DELETE_ACCESS: u32 = 0x0001_0000;

static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static STOP_SIGNAL: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();

struct ScHandle(SC_HANDLE);

impl ScHandle {
    fn new(handle: SC_HANDLE, context: &str) -> Result<Self> {
        if handle.is_null() {
            Err(last_error(context))
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn last_error(context: &str) -> anyhow::Error {
    let code = unsafe { GetLastError() };
    error_code(context, code)
}

fn error_code(context: &str, code: u32) -> anyhow::Error {
    anyhow!(
        "{context}: {} (Windows error {code})",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

fn check_bool(value: i32, context: &str) -> Result<()> {
    if value == 0 {
        Err(last_error(context))
    } else {
        Ok(())
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn service_name() -> Vec<u16> {
    wide(SERVICE_NAME)
}

fn manager(access: u32) -> Result<ScHandle> {
    ScHandle::new(
        unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) },
        "opening the Windows Service Control Manager",
    )
}

fn open_service_optional(access: u32) -> Result<Option<ScHandle>> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let name = service_name();
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if service.is_null() {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        Err(error_code("opening the Unproxy service", code))
    } else {
        Ok(Some(ScHandle(service)))
    }
}

fn open_service(access: u32) -> Result<ScHandle> {
    open_service_optional(access)?.ok_or_else(|| anyhow!("Unproxy service is not installed"))
}

fn query_status(service: SC_HANDLE) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut required = 0;
    check_bool(
        unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut required,
            )
        },
        "querying Unproxy service status",
    )?;
    Ok(status)
}

fn state_name(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "Starting",
        SERVICE_RUNNING => "Running",
        SERVICE_STOP_PENDING => "Stopping",
        _ => "Pending",
    }
}

fn wait_for_state(service: SC_HANDLE, expected: u32) -> Result<SERVICE_STATUS_PROCESS> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let status = query_status(service)?;
        if status.dwCurrentState == expected {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for Unproxy to become {}; current state is {}",
                state_name(expected),
                state_name(status.dwCurrentState)
            );
        }
        if expected == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED {
            bail!(
                "Unproxy stopped before reaching Running; inspect ProgramData\\Unproxy\\service-error.log"
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn start_service(service: SC_HANDLE) -> Result<()> {
    let started = unsafe { StartServiceW(service, 0, ptr::null()) };
    if started == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(error_code("starting the Unproxy service", code));
        }
    }
    wait_for_state(service, SERVICE_RUNNING)?;
    Ok(())
}

fn stop_service(service: SC_HANDLE) -> Result<()> {
    let mut status = SERVICE_STATUS::default();
    let stopped = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };
    if stopped == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_SERVICE_NOT_ACTIVE {
            return Err(error_code("stopping the Unproxy service", code));
        }
    }
    wait_for_state(service, SERVICE_STOPPED)?;
    Ok(())
}

fn binary_path() -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let helper = std::env::current_exe().context("locating the service registration executable")?;
    let directory = helper
        .parent()
        .ok_or_else(|| anyhow!("service registration executable has no parent directory"))?;
    let executable = directory.join("unproxy.exe");
    anyhow::ensure!(
        executable.is_file(),
        "the Unproxy service executable was not found at {}",
        executable.display()
    );
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("ProgramFiles is not set"))?
        .canonicalize()
        .context("resolving Program Files")?;
    let protected_executable = executable
        .canonicalize()
        .context("resolving the Unproxy service executable")?;
    let protected_prefix = format!(
        "{}\\",
        program_files
            .to_string_lossy()
            .trim_end_matches('\\')
            .to_lowercase()
    );
    anyhow::ensure!(
        protected_executable
            .to_string_lossy()
            .to_lowercase()
            .starts_with(&protected_prefix),
        "Windows services must run from a protected Program Files directory; run install.ps1 -AsService"
    );
    let mut quoted = vec![b'"' as u16];
    quoted.extend(protected_executable.as_os_str().encode_wide());
    quoted.push(b'"' as u16);
    quoted.push(0);
    Ok(quoted)
}

fn install_service() -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = service_name();
    let display = wide(DISPLAY_NAME);
    let account = wide("NT AUTHORITY\\NetworkService");
    let binary = binary_path()?;
    let access = SERVICE_QUERY_STATUS
        | SERVICE_START
        | SERVICE_STOP
        | SERVICE_CHANGE_CONFIG
        | SERVICE_DELETE_ACCESS;
    let mut service = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            access,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            account.as_ptr(),
            ptr::null(),
        )
    };
    if service.is_null() {
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_EXISTS {
            service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
            if service.is_null() {
                return Err(last_error("opening the existing Unproxy service"));
            }
            check_bool(
                unsafe {
                    ChangeServiceConfigW(
                        service,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_NO_CHANGE,
                        binary.as_ptr(),
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        display.as_ptr(),
                    )
                },
                "updating the Unproxy service configuration",
            )?;
        } else {
            return Err(error_code("creating the Unproxy service", code));
        }
    }
    let service = ScHandle(service);
    let description = wide(SERVICE_DESCRIPTION);
    let mut description = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_ptr().cast_mut(),
    };
    check_bool(
        unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DESCRIPTION,
                (&mut description as *mut SERVICE_DESCRIPTIONW).cast(),
            )
        },
        "setting the Unproxy service description",
    )?;
    start_service(service.0)?;
    println!("Unproxy service installed and started.");
    Ok(())
}

fn remove_service() -> Result<()> {
    let Some(service) =
        open_service_optional(SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_DELETE_ACCESS)?
    else {
        println!("Unproxy service is not installed.");
        return Ok(());
    };
    stop_service(service.0)?;
    check_bool(
        unsafe { DeleteService(service.0) },
        "removing the Unproxy service registration",
    )?;
    println!("Unproxy service removed.");
    Ok(())
}

fn set_startup(start_type: u32) -> Result<()> {
    let service = open_service(SERVICE_CHANGE_CONFIG)?;
    check_bool(
        unsafe {
            ChangeServiceConfigW(
                service.0,
                SERVICE_NO_CHANGE,
                start_type,
                SERVICE_NO_CHANGE,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        },
        "changing Unproxy service startup",
    )
}

pub fn service_control(command: &str, registration: bool) -> Result<()> {
    match (registration, command) {
        (true, "install") => install_service(),
        (true, "uninstall") => remove_service(),
        (true, "status") => {
            let Some(service) = open_service_optional(SERVICE_QUERY_STATUS)? else {
                println!("Unproxy service is not installed.");
                return Ok(());
            };
            let status = query_status(service.0)?;
            println!(
                "Unproxy service: {}{}",
                state_name(status.dwCurrentState),
                if status.dwProcessId == 0 {
                    String::new()
                } else {
                    format!(" (PID {})", status.dwProcessId)
                }
            );
            Ok(())
        }
        (false, "status") => service_control(command, true),
        (false, "start") => start_service(open_service(SERVICE_QUERY_STATUS | SERVICE_START)?.0),
        (false, "restart") => {
            let service = open_service(SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP)?;
            stop_service(service.0)?;
            start_service(service.0)
        }
        (false, "stop") => stop_service(open_service(SERVICE_QUERY_STATUS | SERVICE_STOP)?.0),
        (false, "enable") => set_startup(SERVICE_AUTO_START),
        (false, "disable") => set_startup(SERVICE_DEMAND_START),
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

fn report_status(state: u32, exit_code: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

unsafe extern "system" fn service_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report_status(SERVICE_STOP_PENDING, 0);
            if let Some(stop) = STOP_SIGNAL.get() {
                let _ = stop.send(true);
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120,
    }
}

pub fn dispatch_service() -> Result<bool> {
    let mut name = service_name();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            return Ok(false);
        }
        return Err(error_code(
            "connecting to the Windows service controller",
            code,
        ));
    }
    Ok(true)
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let result = std::panic::catch_unwind(service_main_impl);
    let exit_code = match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            write_service_error(&format!("{error:#}"));
            1
        }
        Err(_) => {
            write_service_error("Unproxy service panicked.");
            1
        }
    };
    report_status(SERVICE_STOPPED, exit_code);
}

fn service_main_impl() -> Result<()> {
    let (stop, receiver) = tokio::sync::watch::channel(false);
    STOP_SIGNAL
        .set(stop)
        .map_err(|_| anyhow!("Windows service stop signal was already initialized"))?;
    let name = service_name();
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(service_handler), ptr::null()) };
    if handle.is_null() {
        return Err(last_error(
            "registering the Unproxy service control handler",
        ));
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    report_status(SERVICE_START_PENDING, 0);

    let config_path = service_config_path();
    let settings = crate::config::token_file(&config_path);
    let mut args = std::env::args_os().collect::<Vec<_>>();
    args.splice(1..1, settings.into_iter().map(Into::into));
    let args = crate::config::parse_main_from(args, false)
        .with_context(|| format!("parsing {}", config_path.display()))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the Unproxy service runtime")?;
    let (ready, started) = tokio::sync::oneshot::channel();
    let mut server = runtime.spawn(crate::runtime::run_windows_service(args, receiver, ready));
    runtime.block_on(async {
        tokio::select! {
            result = &mut server => result.context("joining the Unproxy service runtime")?,
            started = started => {
                if started.is_ok() {
                    report_status(SERVICE_RUNNING, 0);
                }
                server.await.context("joining the Unproxy service runtime")?
            }
        }
    })
}

fn service_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Unproxy")
        .join("unproxyrc")
}

fn write_service_error(message: &str) {
    let path = service_config_path()
        .parent()
        .unwrap_or_else(|| std::path::Path::new(r"C:\ProgramData"))
        .join("service-error.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{message}");
    }
}
