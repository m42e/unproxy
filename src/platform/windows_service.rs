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

trait ServiceApi {
    fn last_error(&self) -> u32;
    fn close_service_handle(&self, handle: SC_HANDLE);
    fn open_manager(&self, access: u32) -> SC_HANDLE;
    fn open_service(&self, manager: SC_HANDLE, name: *const u16, access: u32) -> SC_HANDLE;
    fn query_service_status(
        &self,
        service: SC_HANDLE,
        status: &mut SERVICE_STATUS_PROCESS,
        required: &mut u32,
    ) -> i32;
    fn start_service(&self, service: SC_HANDLE) -> i32;
    fn control_service(&self, service: SC_HANDLE, control: u32, status: &mut SERVICE_STATUS)
    -> i32;
    fn create_service(
        &self,
        manager: SC_HANDLE,
        name: *const u16,
        display: *const u16,
        access: u32,
        binary: *const u16,
        account: *const u16,
    ) -> SC_HANDLE;
    fn update_service_config(
        &self,
        service: SC_HANDLE,
        binary: *const u16,
        display: *const u16,
    ) -> i32;
    fn set_description(&self, service: SC_HANDLE, description: *mut SERVICE_DESCRIPTIONW) -> i32;
    fn change_startup(&self, service: SC_HANDLE, start_type: u32) -> i32;
    fn delete_service(&self, service: SC_HANDLE) -> i32;
}

struct WindowsServiceApi;

impl ServiceApi for WindowsServiceApi {
    fn last_error(&self) -> u32 {
        unsafe { GetLastError() }
    }

    fn close_service_handle(&self, handle: SC_HANDLE) {
        unsafe {
            CloseServiceHandle(handle);
        }
    }

    fn open_manager(&self, access: u32) -> SC_HANDLE {
        unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) }
    }

    fn open_service(&self, manager: SC_HANDLE, name: *const u16, access: u32) -> SC_HANDLE {
        unsafe { OpenServiceW(manager, name, access) }
    }

    fn query_service_status(
        &self,
        service: SC_HANDLE,
        status: &mut SERVICE_STATUS_PROCESS,
        required: &mut u32,
    ) -> i32 {
        unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                required,
            )
        }
    }

    fn start_service(&self, service: SC_HANDLE) -> i32 {
        unsafe { StartServiceW(service, 0, ptr::null()) }
    }

    fn control_service(
        &self,
        service: SC_HANDLE,
        control: u32,
        status: &mut SERVICE_STATUS,
    ) -> i32 {
        unsafe { ControlService(service, control, status) }
    }

    fn create_service(
        &self,
        manager: SC_HANDLE,
        name: *const u16,
        display: *const u16,
        access: u32,
        binary: *const u16,
        account: *const u16,
    ) -> SC_HANDLE {
        unsafe {
            CreateServiceW(
                manager,
                name,
                display,
                access,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                binary,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                account,
                ptr::null(),
            )
        }
    }

    fn update_service_config(
        &self,
        service: SC_HANDLE,
        binary: *const u16,
        display: *const u16,
    ) -> i32 {
        unsafe {
            ChangeServiceConfigW(
                service,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_NO_CHANGE,
                binary,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                display,
            )
        }
    }

    fn set_description(&self, service: SC_HANDLE, description: *mut SERVICE_DESCRIPTIONW) -> i32 {
        unsafe { ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, description.cast()) }
    }

    fn change_startup(&self, service: SC_HANDLE, start_type: u32) -> i32 {
        unsafe {
            ChangeServiceConfigW(
                service,
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
        }
    }

    fn delete_service(&self, service: SC_HANDLE) -> i32 {
        unsafe { DeleteService(service) }
    }
}

static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static STOP_SIGNAL: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();

struct ScHandle<'api>(SC_HANDLE, &'api dyn ServiceApi);

impl<'api> ScHandle<'api> {
    fn new(api: &'api dyn ServiceApi, handle: SC_HANDLE, context: &str) -> Result<Self> {
        if handle.is_null() {
            Err(last_error(api, context))
        } else {
            Ok(Self(handle, api))
        }
    }
}

impl Drop for ScHandle<'_> {
    fn drop(&mut self) {
        self.1.close_service_handle(self.0);
    }
}

fn last_error(api: &dyn ServiceApi, context: &str) -> anyhow::Error {
    let code = api.last_error();
    error_code(context, code)
}

fn error_code(context: &str, code: u32) -> anyhow::Error {
    anyhow!(
        "{context}: {} (Windows error {code})",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

fn check_bool(api: &dyn ServiceApi, value: i32, context: &str) -> Result<()> {
    if value == 0 {
        Err(last_error(api, context))
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

fn manager(api: &dyn ServiceApi, access: u32) -> Result<ScHandle<'_>> {
    ScHandle::new(
        api,
        api.open_manager(access),
        "opening the Windows Service Control Manager",
    )
}

fn open_service_optional(api: &dyn ServiceApi, access: u32) -> Result<Option<ScHandle<'_>>> {
    let manager = manager(api, SC_MANAGER_CONNECT)?;
    let name = service_name();
    let service = api.open_service(manager.0, name.as_ptr(), access);
    if service.is_null() {
        let code = api.last_error();
        if code == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        Err(error_code("opening the Unproxy service", code))
    } else {
        Ok(Some(ScHandle(service, api)))
    }
}

fn open_service(api: &dyn ServiceApi, access: u32) -> Result<ScHandle<'_>> {
    open_service_optional(api, access)?.ok_or_else(|| anyhow!("Unproxy service is not installed"))
}

fn query_status(api: &dyn ServiceApi, service: SC_HANDLE) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut required = 0;
    check_bool(
        api,
        api.query_service_status(service, &mut status, &mut required),
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

fn wait_for_state(
    api: &dyn ServiceApi,
    service: SC_HANDLE,
    expected: u32,
) -> Result<SERVICE_STATUS_PROCESS> {
    wait_for_state_with_timeout(api, service, expected, WAIT_TIMEOUT)
}

fn wait_for_state_with_timeout(
    api: &dyn ServiceApi,
    service: SC_HANDLE,
    expected: u32,
    timeout: Duration,
) -> Result<SERVICE_STATUS_PROCESS> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = query_status(api, service)?;
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

fn start_service(api: &dyn ServiceApi, service: SC_HANDLE) -> Result<()> {
    let started = api.start_service(service);
    if started == 0 {
        let code = api.last_error();
        if code != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(error_code("starting the Unproxy service", code));
        }
    }
    wait_for_state(api, service, SERVICE_RUNNING)?;
    Ok(())
}

fn stop_service(api: &dyn ServiceApi, service: SC_HANDLE) -> Result<()> {
    let mut status = SERVICE_STATUS::default();
    let stopped = api.control_service(service, SERVICE_CONTROL_STOP, &mut status);
    if stopped == 0 {
        let code = api.last_error();
        if code != ERROR_SERVICE_NOT_ACTIVE {
            return Err(error_code("stopping the Unproxy service", code));
        }
    }
    wait_for_state(api, service, SERVICE_STOPPED)?;
    Ok(())
}

fn binary_path() -> Result<Vec<u16>> {
    let helper = std::env::current_exe().context("locating the service registration executable")?;
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("ProgramFiles is not set"))?;
    binary_path_for(&helper, &program_files)
}

fn binary_path_for(helper: &std::path::Path, program_files: &std::path::Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let directory = helper
        .parent()
        .ok_or_else(|| anyhow!("service registration executable has no parent directory"))?;
    let executable = directory.join("unproxy.exe");
    anyhow::ensure!(
        executable.is_file(),
        "the Unproxy service executable was not found at {}",
        executable.display()
    );
    let program_files = program_files
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

fn install_service_with_binary(api: &dyn ServiceApi, binary: &[u16]) -> Result<()> {
    let manager = manager(api, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = service_name();
    let display = wide(DISPLAY_NAME);
    let account = wide("NT AUTHORITY\\NetworkService");
    let access = SERVICE_QUERY_STATUS
        | SERVICE_START
        | SERVICE_STOP
        | SERVICE_CHANGE_CONFIG
        | SERVICE_DELETE_ACCESS;
    let mut service = api.create_service(
        manager.0,
        name.as_ptr(),
        display.as_ptr(),
        access,
        binary.as_ptr(),
        account.as_ptr(),
    );
    if service.is_null() {
        let code = api.last_error();
        if code == ERROR_SERVICE_EXISTS {
            service = api.open_service(manager.0, name.as_ptr(), access);
            if service.is_null() {
                return Err(last_error(api, "opening the existing Unproxy service"));
            }
            check_bool(
                api,
                api.update_service_config(service, binary.as_ptr(), display.as_ptr()),
                "updating the Unproxy service configuration",
            )?;
        } else {
            return Err(error_code("creating the Unproxy service", code));
        }
    }
    let service = ScHandle(service, api);
    let description = wide(SERVICE_DESCRIPTION);
    let mut description = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_ptr().cast_mut(),
    };
    check_bool(
        api,
        api.set_description(service.0, &mut description),
        "setting the Unproxy service description",
    )?;
    start_service(api, service.0)?;
    println!("Unproxy service installed and started.");
    Ok(())
}

fn remove_service_with_api(api: &dyn ServiceApi, access: u32) -> Result<()> {
    let Some(service) = open_service_optional(api, access)? else {
        println!("Unproxy service is not installed.");
        return Ok(());
    };
    stop_service(api, service.0)?;
    check_bool(
        api,
        api.delete_service(service.0),
        "removing the Unproxy service registration",
    )?;
    println!("Unproxy service removed.");
    Ok(())
}

fn set_startup(api: &dyn ServiceApi, start_type: u32) -> Result<()> {
    let service = open_service(api, SERVICE_CHANGE_CONFIG)?;
    check_bool(
        api,
        api.change_startup(service.0, start_type),
        "changing Unproxy service startup",
    )
}

pub fn service_control(command: &str, registration: bool) -> Result<()> {
    let api = WindowsServiceApi;
    service_control_with(&api, command, registration, || {
        let binary = binary_path()?;
        install_service_with_binary(&api, &binary)
    })
}

fn service_control_with(
    api: &dyn ServiceApi,
    command: &str,
    registration: bool,
    install: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match (registration, command) {
        (true, "install") => install(),
        (true, "uninstall") => remove_service_with_api(
            api,
            SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_DELETE_ACCESS,
        ),
        (_, "status") => {
            let Some(service) = open_service_optional(api, SERVICE_QUERY_STATUS)? else {
                println!("Unproxy service is not installed.");
                return Ok(());
            };
            let status = query_status(api, service.0)?;
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
        (false, "start") => start_service(
            api,
            open_service(api, SERVICE_QUERY_STATUS | SERVICE_START)?.0,
        ),
        (false, "restart") => {
            let service = open_service(api, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP)?;
            stop_service(api, service.0)?;
            start_service(api, service.0)
        }
        (false, "stop") => stop_service(
            api,
            open_service(api, SERVICE_QUERY_STATUS | SERVICE_STOP)?.0,
        ),
        (false, "enable") => set_startup(api, SERVICE_AUTO_START),
        (false, "disable") => set_startup(api, SERVICE_DEMAND_START),
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
            &WindowsServiceApi,
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
    service_config_path_from(std::env::var_os("ProgramData").map(PathBuf::from))
}

fn service_config_path_from(program_data: Option<PathBuf>) -> PathBuf {
    program_data
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Unproxy")
        .join("unproxyrc")
}

fn write_service_error(message: &str) {
    let path = service_config_path()
        .parent()
        .unwrap_or_else(|| std::path::Path::new(r"C:\ProgramData"))
        .join("service-error.log");
    write_service_error_to(&path, message);
}

fn write_service_error_to(path: &std::path::Path, message: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        ptr::NonNull,
    };

    struct FakeServiceApi {
        manager_error: Cell<Option<u32>>,
        service_exists: Cell<bool>,
        current_state: Cell<u32>,
        process_id: Cell<u32>,
        status_error: Cell<Option<u32>>,
        start_error: Cell<Option<u32>>,
        stop_error: Cell<Option<u32>>,
        create_error: Cell<Option<u32>>,
        update_error: Cell<Option<u32>>,
        description_error: Cell<Option<u32>>,
        startup_error: Cell<Option<u32>>,
        delete_error: Cell<Option<u32>>,
        last_error: Cell<u32>,
        startup_type: Cell<Option<u32>>,
        calls: RefCell<Vec<String>>,
        closed_handles: Cell<usize>,
    }

    impl Default for FakeServiceApi {
        fn default() -> Self {
            Self {
                manager_error: Cell::new(None),
                service_exists: Cell::new(true),
                current_state: Cell::new(SERVICE_STOPPED),
                process_id: Cell::new(0),
                status_error: Cell::new(None),
                start_error: Cell::new(None),
                stop_error: Cell::new(None),
                create_error: Cell::new(None),
                update_error: Cell::new(None),
                description_error: Cell::new(None),
                startup_error: Cell::new(None),
                delete_error: Cell::new(None),
                last_error: Cell::new(0),
                startup_type: Cell::new(None),
                calls: RefCell::new(Vec::new()),
                closed_handles: Cell::new(0),
            }
        }
    }

    impl FakeServiceApi {
        fn handle(&self) -> SC_HANDLE {
            NonNull::<u8>::dangling().as_ptr().cast()
        }

        fn record(&self, call: &str) {
            self.calls.borrow_mut().push(call.to_owned());
        }
    }

    impl ServiceApi for FakeServiceApi {
        fn last_error(&self) -> u32 {
            self.last_error.get()
        }

        fn close_service_handle(&self, _handle: SC_HANDLE) {
            self.closed_handles.set(self.closed_handles.get() + 1);
        }

        fn open_manager(&self, _access: u32) -> SC_HANDLE {
            self.record("open_manager");
            if let Some(code) = self.manager_error.get() {
                self.last_error.set(code);
                ptr::null_mut()
            } else {
                self.handle()
            }
        }

        fn open_service(&self, _manager: SC_HANDLE, _name: *const u16, _access: u32) -> SC_HANDLE {
            self.record("open_service");
            if self.service_exists.get() {
                self.handle()
            } else {
                self.last_error.set(ERROR_SERVICE_DOES_NOT_EXIST);
                ptr::null_mut()
            }
        }

        fn query_service_status(
            &self,
            _service: SC_HANDLE,
            status: &mut SERVICE_STATUS_PROCESS,
            required: &mut u32,
        ) -> i32 {
            self.record("query_status");
            if let Some(code) = self.status_error.get() {
                self.last_error.set(code);
                return 0;
            }
            status.dwCurrentState = self.current_state.get();
            status.dwProcessId = self.process_id.get();
            *required = std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32;
            1
        }

        fn start_service(&self, _service: SC_HANDLE) -> i32 {
            self.record("start");
            if let Some(code) = self.start_error.get() {
                self.last_error.set(code);
                0
            } else {
                self.current_state.set(SERVICE_RUNNING);
                1
            }
        }

        fn control_service(
            &self,
            _service: SC_HANDLE,
            control: u32,
            _status: &mut SERVICE_STATUS,
        ) -> i32 {
            self.record("control");
            if control == SERVICE_CONTROL_STOP {
                if let Some(code) = self.stop_error.get() {
                    self.last_error.set(code);
                    if code == ERROR_SERVICE_NOT_ACTIVE {
                        self.current_state.set(SERVICE_STOPPED);
                    }
                    return 0;
                }
                self.current_state.set(SERVICE_STOPPED);
            }
            1
        }

        fn create_service(
            &self,
            _manager: SC_HANDLE,
            _name: *const u16,
            _display: *const u16,
            _access: u32,
            _binary: *const u16,
            _account: *const u16,
        ) -> SC_HANDLE {
            self.record("create_service");
            if let Some(code) = self.create_error.get() {
                self.last_error.set(code);
                ptr::null_mut()
            } else {
                self.service_exists.set(true);
                self.current_state.set(SERVICE_STOPPED);
                self.handle()
            }
        }

        fn update_service_config(
            &self,
            _service: SC_HANDLE,
            _binary: *const u16,
            _display: *const u16,
        ) -> i32 {
            self.record("update_config");
            if let Some(code) = self.update_error.get() {
                self.last_error.set(code);
                0
            } else {
                1
            }
        }

        fn set_description(
            &self,
            _service: SC_HANDLE,
            _description: *mut SERVICE_DESCRIPTIONW,
        ) -> i32 {
            self.record("set_description");
            if let Some(code) = self.description_error.get() {
                self.last_error.set(code);
                0
            } else {
                1
            }
        }

        fn change_startup(&self, _service: SC_HANDLE, start_type: u32) -> i32 {
            self.record("change_startup");
            if let Some(code) = self.startup_error.get() {
                self.last_error.set(code);
                0
            } else {
                self.startup_type.set(Some(start_type));
                1
            }
        }

        fn delete_service(&self, _service: SC_HANDLE) -> i32 {
            self.record("delete_service");
            if let Some(code) = self.delete_error.get() {
                self.last_error.set(code);
                0
            } else {
                self.service_exists.set(false);
                1
            }
        }
    }

    fn run_control(api: &FakeServiceApi, command: &str, registration: bool) -> Result<()> {
        let binary = wide(r"C:\Program Files\Unproxy\unproxy.exe");
        service_control_with(api, command, registration, || {
            install_service_with_binary(api, &binary)
        })
    }

    #[test]
    fn command_dispatch_covers_status_start_restart_stop_and_startup_modes() {
        let api = FakeServiceApi::default();
        api.current_state.set(SERVICE_RUNNING);
        api.process_id.set(42);
        run_control(&api, "status", false).unwrap();
        assert!(api.calls.borrow().contains(&"query_status".to_owned()));

        run_control(&api, "restart", false).unwrap();
        assert_eq!(api.current_state.get(), SERVICE_RUNNING);
        run_control(&api, "stop", false).unwrap();
        assert_eq!(api.current_state.get(), SERVICE_STOPPED);
        run_control(&api, "start", false).unwrap();
        assert_eq!(api.current_state.get(), SERVICE_RUNNING);

        run_control(&api, "enable", false).unwrap();
        assert_eq!(api.startup_type.get(), Some(SERVICE_AUTO_START));
        run_control(&api, "disable", false).unwrap();
        assert_eq!(api.startup_type.get(), Some(SERVICE_DEMAND_START));
        assert!(api.closed_handles.get() >= 8);
    }

    #[test]
    fn missing_service_and_invalid_commands_return_expected_results() {
        let api = FakeServiceApi::default();
        api.service_exists.set(false);
        run_control(&api, "status", true).unwrap();
        run_control(&api, "uninstall", true).unwrap();
        let error = run_control(&api, "start", false).unwrap_err();
        assert!(error.to_string().contains("not installed"));

        let error = run_control(&api, "invalid", false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("status, start, restart, stop, enable, disable")
        );
        let error = run_control(&api, "start", true).unwrap_err();
        assert!(error.to_string().contains("install, uninstall, status"));
        assert_eq!(state_name(0xffff), "Pending");
    }

    #[test]
    fn install_and_uninstall_cover_new_and_existing_service_paths() {
        let binary = wide(r"C:\Program Files\Unproxy\unproxy.exe");
        let api = FakeServiceApi::default();
        install_service_with_binary(&api, &binary).unwrap();
        assert_eq!(api.current_state.get(), SERVICE_RUNNING);
        assert!(api.calls.borrow().contains(&"create_service".to_owned()));

        let existing = FakeServiceApi::default();
        existing.create_error.set(Some(ERROR_SERVICE_EXISTS));
        install_service_with_binary(&existing, &binary).unwrap();
        assert!(
            existing
                .calls
                .borrow()
                .contains(&"update_config".to_owned())
        );

        existing.current_state.set(SERVICE_RUNNING);
        run_control(&existing, "uninstall", true).unwrap();
        assert!(!existing.service_exists.get());
        assert!(
            existing
                .calls
                .borrow()
                .contains(&"delete_service".to_owned())
        );
    }

    #[test]
    fn service_failures_preserve_the_operation_context() {
        let binary = wide(r"C:\Program Files\Unproxy\unproxy.exe");
        let manager = FakeServiceApi::default();
        manager.manager_error.set(Some(5));
        assert!(
            install_service_with_binary(&manager, &binary)
                .unwrap_err()
                .to_string()
                .contains("Service Control Manager")
        );

        let create = FakeServiceApi::default();
        create.create_error.set(Some(5));
        assert!(
            install_service_with_binary(&create, &binary)
                .unwrap_err()
                .to_string()
                .contains("creating the Unproxy service")
        );

        let update = FakeServiceApi::default();
        update.create_error.set(Some(ERROR_SERVICE_EXISTS));
        update.update_error.set(Some(5));
        assert!(
            install_service_with_binary(&update, &binary)
                .unwrap_err()
                .to_string()
                .contains("updating the Unproxy service configuration")
        );

        let description = FakeServiceApi::default();
        description.description_error.set(Some(5));
        assert!(
            install_service_with_binary(&description, &binary)
                .unwrap_err()
                .to_string()
                .contains("setting the Unproxy service description")
        );

        let start = FakeServiceApi::default();
        start.start_error.set(Some(5));
        assert!(
            install_service_with_binary(&start, &binary)
                .unwrap_err()
                .to_string()
                .contains("starting the Unproxy service")
        );

        let query = FakeServiceApi::default();
        query.status_error.set(Some(5));
        assert!(
            run_control(&query, "status", true)
                .unwrap_err()
                .to_string()
                .contains("querying Unproxy service status")
        );

        let stop = FakeServiceApi::default();
        stop.stop_error.set(Some(5));
        assert!(
            run_control(&stop, "stop", false)
                .unwrap_err()
                .to_string()
                .contains("stopping the Unproxy service")
        );

        let delete = FakeServiceApi::default();
        delete.delete_error.set(Some(5));
        assert!(
            run_control(&delete, "uninstall", true)
                .unwrap_err()
                .to_string()
                .contains("removing the Unproxy service registration")
        );

        let startup = FakeServiceApi::default();
        startup.startup_error.set(Some(5));
        assert!(
            run_control(&startup, "disable", false)
                .unwrap_err()
                .to_string()
                .contains("changing Unproxy service startup")
        );
    }

    #[test]
    fn state_wait_handles_timeouts_and_early_service_exit() {
        let api = FakeServiceApi::default();
        let timeout =
            wait_for_state_with_timeout(&api, api.handle(), SERVICE_START_PENDING, Duration::ZERO)
                .err()
                .expect("state wait should time out");
        assert!(timeout.to_string().contains("timed out"));

        let stopped = wait_for_state_with_timeout(
            &api,
            api.handle(),
            SERVICE_RUNNING,
            Duration::from_secs(1),
        )
        .err()
        .expect("stopped service should fail before reaching Running");
        assert!(
            stopped
                .to_string()
                .contains("stopped before reaching Running")
        );

        let already_running = FakeServiceApi::default();
        already_running.current_state.set(SERVICE_RUNNING);
        already_running
            .start_error
            .set(Some(ERROR_SERVICE_ALREADY_RUNNING));
        start_service(&already_running, already_running.handle()).unwrap();

        let inactive = FakeServiceApi::default();
        inactive.stop_error.set(Some(ERROR_SERVICE_NOT_ACTIVE));
        stop_service(&inactive, inactive.handle()).unwrap();
    }

    #[test]
    fn service_binary_must_live_under_program_files() {
        use std::path::Path;

        let root = tempfile::tempdir().unwrap();
        let program_files = root.path().join("Program Files");
        let service_dir = program_files.join("Unproxy");
        std::fs::create_dir_all(&service_dir).unwrap();
        let executable = service_dir.join("unproxy.exe");
        std::fs::write(&executable, b"fixture").unwrap();
        let helper = service_dir.join("unproxy-register.exe");
        let binary = binary_path_for(&helper, &program_files).unwrap();
        let quoted = String::from_utf16(&binary[..binary.len() - 1]).unwrap();
        assert_eq!(
            quoted,
            format!("\"{}\"", executable.canonicalize().unwrap().display())
        );

        let outside = root.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("unproxy.exe"), b"fixture").unwrap();
        assert!(
            binary_path_for(&outside.join("unproxy-register.exe"), &program_files)
                .unwrap_err()
                .to_string()
                .contains("protected Program Files")
        );
        assert!(binary_path_for(Path::new("unproxy-register.exe"), &program_files).is_err());
    }

    #[test]
    fn service_error_files_append_and_config_paths_have_a_safe_fallback() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("service-error.log");
        write_service_error_to(&path, "first failure");
        write_service_error_to(&path, "second failure");
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "first failure\nsecond failure\n"
        );
        assert_eq!(
            service_config_path_from(Some(PathBuf::from(r"D:\ProgramData"))),
            PathBuf::from(r"D:\ProgramData\Unproxy\unproxyrc")
        );
        assert_eq!(
            service_config_path_from(None),
            PathBuf::from(r"C:\ProgramData\Unproxy\unproxyrc")
        );
    }

    #[test]
    fn native_service_entry_points_handle_console_processes_without_mutation() {
        assert!(!dispatch_service().unwrap());
        report_status(SERVICE_RUNNING, 0);
        assert_eq!(
            unsafe {
                service_handler(
                    SERVICE_CONTROL_INTERROGATE,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { service_handler(SERVICE_CONTROL_STOP, 0, ptr::null_mut(), ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { service_handler(0xffff, 0, ptr::null_mut(), ptr::null_mut()) },
            120
        );
        let error = service_main_impl().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registering the Unproxy service control handler")
        );

        // Status is read-only and exercises the real SCM adapter from a normal console process.
        let _ = service_control("status", false);
    }
}
