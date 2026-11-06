use super::super::{Preferences, parse_listener, parse_remote_pac_uri};
use anyhow::{Context, Result, anyhow, ensure};
use std::{
    collections::HashSet,
    ffi::OsString,
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_CLASS_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GetLastError, HINSTANCE,
        HWND, LPARAM, LRESULT, RECT, WPARAM,
    },
    Graphics::Gdi::{COLOR_WINDOW, HBRUSH, UpdateWindow},
    System::{
        LibraryLoader::GetModuleHandleW,
        Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
            RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
        },
    },
    UI::{
        Controls::{
            BST_CHECKED,
            Dialogs::{
                CommDlgExtendedError, GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
                OFN_PATHMUSTEXIST, OPENFILENAMEW,
            },
        },
        Input::KeyboardAndMouse::EnableWindow,
        WindowsAndMessaging::{
            AdjustWindowRectEx, BM_GETCHECK, BM_SETCHECK, BN_CLICKED, BS_AUTOCHECKBOX,
            BS_DEFPUSHBUTTON, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
            DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_WANTRETURN,
            GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW,
            IDC_ARROW, IsDialogMessageW, LoadCursorW, MB_ICONERROR, MB_OK, MSG, MessageBoxW,
            PostQuitMessage, RegisterClassW, SW_SHOW, SendMessageW, SetForegroundWindow,
            SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, WM_CLOSE, WM_COMMAND,
            WM_CREATE, WM_DESTROY, WM_NCCREATE, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD,
            WS_EX_DLGMODALFRAME, WS_HSCROLL, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP,
            WS_VISIBLE, WS_VSCROLL,
        },
    },
};

const WINDOW_CLASS: &str = "UnproxySettingsWindow";
const CLIENT_WIDTH: i32 = 760;
const CLIENT_HEIGHT: i32 = 680;

const ID_LISTENERS: u16 = 1001;
const ID_PAC_FILES: u16 = 1002;
const ID_PAC_BROWSE: u16 = 1003;
const ID_FILTER_LISTS: u16 = 1004;
const ID_FILTER_BROWSE: u16 = 1005;
const ID_NEGOTIATE: u16 = 1006;
const ID_TUNNEL: u16 = 1007;
const ID_DIRECT_FALLBACK: u16 = 1008;
const ID_AUTOSTART: u16 = 1009;
const ID_SAVE: u16 = 1010;
const ID_CANCEL: u16 = 1011;

struct Controls {
    listeners: HWND,
    pac_files: HWND,
    filter_lists: HWND,
    negotiate: HWND,
    tunnel: HWND,
    direct_fallback: HWND,
    autostart: HWND,
}

#[derive(Clone, Copy)]
struct ControlBounds {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

struct SettingsDialog {
    current: Preferences,
    controls: Controls,
    result: Option<Preferences>,
    initialization_error: Option<String>,
}

struct SettingsFields {
    listeners: String,
    pac_files: String,
    filter_lists: String,
    negotiate: bool,
    tunnel: bool,
    direct_fallback: bool,
    autostart: bool,
}

impl SettingsDialog {
    fn new(current: &Preferences) -> Self {
        Self {
            current: current.clone(),
            controls: Controls {
                listeners: null_mut(),
                pac_files: null_mut(),
                filter_lists: null_mut(),
                negotiate: null_mut(),
                tunnel: null_mut(),
                direct_fallback: null_mut(),
                autostart: null_mut(),
            },
            result: None,
            initialization_error: None,
        }
    }

    fn preferences_from_controls(&self) -> Result<Preferences> {
        build_preferences(
            &self.current,
            SettingsFields {
                listeners: control_text(self.controls.listeners),
                pac_files: control_text(self.controls.pac_files),
                filter_lists: control_text(self.controls.filter_lists),
                negotiate: control_checked(self.controls.negotiate),
                tunnel: control_checked(self.controls.tunnel),
                direct_fallback: control_checked(self.controls.direct_fallback),
                autostart: control_checked(self.controls.autostart),
            },
        )
    }
}

pub(super) fn show_dialog(current: &Preferences) -> Result<Option<Preferences>> {
    let instance = unsafe { GetModuleHandleW(null()) };
    ensure!(
        !instance.is_null(),
        "get Unproxy module handle: {}",
        std::io::Error::last_os_error()
    );
    register_window_class(instance)?;

    let mut state = Box::new(SettingsDialog::new(current));
    let class_name = wide(WINDOW_CLASS);
    let title = wide("Unproxy Settings");
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    let extended_style = WS_EX_DLGMODALFRAME;
    let mut rectangle = RECT {
        left: 0,
        top: 0,
        right: CLIENT_WIDTH,
        bottom: CLIENT_HEIGHT,
    };
    ensure!(
        unsafe { AdjustWindowRectEx(&mut rectangle, style, 0, extended_style) } != 0,
        "calculate Unproxy settings window size: {}",
        std::io::Error::last_os_error()
    );

    let window = unsafe {
        CreateWindowExW(
            extended_style,
            class_name.as_ptr(),
            title.as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rectangle.right - rectangle.left,
            rectangle.bottom - rectangle.top,
            null_mut(),
            null_mut(),
            instance,
            (&mut *state as *mut SettingsDialog).cast(),
        )
    };
    if window.is_null() {
        let detail = state
            .initialization_error
            .take()
            .unwrap_or_else(|| std::io::Error::last_os_error().to_string());
        return Err(anyhow!("create Unproxy settings window: {detail}"));
    }

    unsafe {
        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
        SetForegroundWindow(window);
    }
    let mut message: MSG = unsafe { std::mem::zeroed() };
    loop {
        let status = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if status == -1 {
            return Err(std::io::Error::last_os_error())
                .context("read Unproxy settings window messages");
        }
        if status == 0 {
            break;
        }
        if unsafe { IsDialogMessageW(window, &message) } == 0 {
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    Ok(state.result.take())
}

pub(super) fn set_login_startup(enabled: bool, executable: &Path) -> Result<()> {
    let key_name = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let value_name = wide("Unproxy");
    let mut key = null_mut();
    let status = unsafe {
        if enabled {
            let mut disposition = 0;
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                null(),
                &mut key,
                &mut disposition,
            )
        } else {
            RegOpenKeyExW(HKEY_CURRENT_USER, key_name.as_ptr(), 0, KEY_WRITE, &mut key)
        }
    };
    if !enabled && status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    ensure!(
        status == ERROR_SUCCESS,
        "open Unproxy login startup registry key: {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
    let key = RegistryKey(key);

    let status = if enabled {
        let mut value = Vec::with_capacity(executable.as_os_str().len() + 3);
        value.push(b'"' as u16);
        value.extend(executable.as_os_str().encode_wide());
        value.extend([b'"' as u16, 0]);
        let byte_count = u32::try_from(value.len() * size_of::<u16>())
            .context("Unproxy startup command is too long")?;
        unsafe {
            RegSetValueExW(
                key.0,
                value_name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                byte_count,
            )
        }
    } else {
        unsafe { RegDeleteValueW(key.0, value_name.as_ptr()) }
    };
    if !enabled && status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    ensure!(
        status == ERROR_SUCCESS,
        "update Unproxy login startup: {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
    Ok(())
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn build_preferences(current: &Preferences, fields: SettingsFields) -> Result<Preferences> {
    let listeners = parse_listener_lines(&fields.listeners)?;
    let pac_files = parse_source_lines(&fields.pac_files, "PAC", true)?;
    let filter_lists = parse_source_lines(&fields.filter_lists, "filter-list", false)?;
    let first_listener = *listeners
        .first()
        .context("at least one listener is required")?;
    let first_pac_file = pac_files
        .first()
        .context("at least one PAC source is required")?
        .clone();

    let mut updated = current.clone();
    updated.port = u32::from(first_listener.port());
    updated.listeners = Some(
        listeners
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
    );
    updated.pac_file = first_pac_file;
    updated.pac_files = Some(pac_files);
    updated.filter_lists = Some(filter_lists);
    if cfg!(feature = "negotiate") {
        updated.negotiate = fields.negotiate;
    }
    updated.proxytunnel = fields.tunnel;
    updated.direct_fallback = fields.direct_fallback;
    updated.autostart = fields.autostart;
    Ok(updated)
}

fn parse_listener_lines(text: &str) -> Result<Vec<std::net::SocketAddr>> {
    let mut listeners = Vec::new();
    let mut unique = HashSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let address = parse_listener(line).with_context(|| format!("invalid listener {line:?}"))?;
        ensure!(
            unique.insert(address),
            "listener addresses must be unique: {address}"
        );
        listeners.push(address);
    }
    ensure!(!listeners.is_empty(), "at least one listener is required");
    Ok(listeners)
}

fn parse_source_lines(text: &str, description: &str, required: bool) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    let mut unique = HashSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let source = if let Some(uri) = parse_remote_pac_uri(line)
            .with_context(|| format!("invalid {description} URL {line:?}"))?
        {
            ensure!(
                !line.contains('#'),
                "{description} URLs must not include fragments: {line}"
            );
            PathBuf::from(uri.to_string())
        } else {
            let path = Path::new(line);
            ensure!(
                path.is_absolute(),
                "{description} paths must be absolute: {line}"
            );
            ensure!(path.is_file(), "{description} file not found: {line}");
            path.to_path_buf()
        };
        let key = source.to_string_lossy().to_lowercase();
        ensure!(
            unique.insert(key),
            "{description} sources must be unique: {line}"
        );
        sources.push(source);
    }
    ensure!(
        !required || !sources.is_empty(),
        "at least one {description} source is required"
    );
    Ok(sources)
}

fn register_window_class(instance: HINSTANCE) -> Result<()> {
    let class_name = wide(WINDOW_CLASS);
    let window_class = WNDCLASSW {
        hInstance: instance,
        lpfnWndProc: Some(settings_window_proc),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: ((COLOR_WINDOW + 1) as usize) as HBRUSH,
        lpszClassName: class_name.as_ptr(),
        ..Default::default()
    };
    let atom = unsafe { RegisterClassW(&window_class) };
    if atom == 0 {
        let error = unsafe { GetLastError() };
        ensure!(
            error == ERROR_CLASS_ALREADY_EXISTS,
            "register Unproxy settings window class: {}",
            std::io::Error::from_raw_os_error(error as i32)
        );
    }
    Ok(())
}

unsafe extern "system" fn settings_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = unsafe {
            &*(lparam as *const windows_sys::Win32::UI::WindowsAndMessaging::CREATESTRUCTW)
        };
        unsafe {
            SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize);
        }
        return 1;
    }

    let state_ptr = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) as *mut SettingsDialog };
    if state_ptr.is_null() {
        return unsafe { DefWindowProcW(window, message, wparam, lparam) };
    }
    let state = unsafe { &mut *state_ptr };

    match message {
        WM_CREATE => {
            let instance = unsafe { GetModuleHandleW(null()) };
            if let Err(error) = create_controls(window, instance, state) {
                state.initialization_error = Some(format!("{error:#}"));
                -1
            } else {
                0
            }
        }
        WM_COMMAND => {
            let control_id = (wparam & 0xffff) as u16;
            let notification = ((wparam >> 16) & 0xffff) as u16;
            if notification == BN_CLICKED as u16 {
                handle_button(window, state, control_id);
            }
            0
        }
        WM_CLOSE => {
            unsafe { DestroyWindow(window) };
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

fn create_controls(window: HWND, instance: HINSTANCE, state: &mut SettingsDialog) -> Result<()> {
    create_control(
        window,
        instance,
        "STATIC",
        "Listeners (numeric IP address and port; IPv6 in brackets, one per line)",
        WS_CHILD | WS_VISIBLE,
        ControlBounds {
            x: 18,
            y: 14,
            width: 720,
            height: 20,
        },
        0,
    )?;
    state.controls.listeners = create_multiline_edit(
        window,
        instance,
        ID_LISTENERS,
        &state
            .current
            .effective_listeners()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\r\n"),
        ControlBounds {
            x: 18,
            y: 36,
            width: 724,
            height: 72,
        },
    )?;

    create_control(
        window,
        instance,
        "STATIC",
        "PAC files or HTTP(S) URLs (one per line; order matters)",
        WS_CHILD | WS_VISIBLE,
        ControlBounds {
            x: 18,
            y: 120,
            width: 720,
            height: 20,
        },
        0,
    )?;
    let pac_files = state
        .current
        .effective_pac_files()
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\r\n");
    state.controls.pac_files = create_multiline_edit(
        window,
        instance,
        ID_PAC_FILES,
        &pac_files,
        ControlBounds {
            x: 18,
            y: 142,
            width: 724,
            height: 124,
        },
    )?;
    create_control(
        window,
        instance,
        "BUTTON",
        "Browse PAC file...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        ControlBounds {
            x: 18,
            y: 274,
            width: 150,
            height: 28,
        },
        ID_PAC_BROWSE,
    )?;

    create_control(
        window,
        instance,
        "STATIC",
        "Optional filter-list files or HTTP(S) URLs (hosts format; one per line)",
        WS_CHILD | WS_VISIBLE,
        ControlBounds {
            x: 18,
            y: 314,
            width: 720,
            height: 20,
        },
        0,
    )?;
    let filter_lists = state
        .current
        .effective_filter_lists()
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\r\n");
    state.controls.filter_lists = create_multiline_edit(
        window,
        instance,
        ID_FILTER_LISTS,
        &filter_lists,
        ControlBounds {
            x: 18,
            y: 336,
            width: 724,
            height: 96,
        },
    )?;
    create_control(
        window,
        instance,
        "BUTTON",
        "Browse filter list...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        ControlBounds {
            x: 18,
            y: 430,
            width: 170,
            height: 28,
        },
        ID_FILTER_BROWSE,
    )?;

    state.controls.tunnel = create_checkbox(
        window,
        instance,
        "Always use CONNECT",
        state.current.proxytunnel,
        ControlBounds {
            x: 18,
            y: 478,
            width: 360,
            height: 24,
        },
        ID_TUNNEL,
    )?;
    state.controls.direct_fallback = create_checkbox(
        window,
        instance,
        "DIRECT fallback",
        state.current.direct_fallback,
        ControlBounds {
            x: 18,
            y: 506,
            width: 360,
            height: 24,
        },
        ID_DIRECT_FALLBACK,
    )?;
    state.controls.negotiate = create_checkbox(
        window,
        instance,
        "Negotiate",
        state.current.negotiate,
        ControlBounds {
            x: 18,
            y: 534,
            width: 360,
            height: 24,
        },
        ID_NEGOTIATE,
    )?;
    if !cfg!(feature = "negotiate") {
        unsafe { EnableWindow(state.controls.negotiate, 0) };
    }
    state.controls.autostart = create_checkbox(
        window,
        instance,
        "Start Unproxy when I sign in",
        state.current.autostart,
        ControlBounds {
            x: 18,
            y: 562,
            width: 360,
            height: 24,
        },
        ID_AUTOSTART,
    )?;

    create_control(
        window,
        instance,
        "BUTTON",
        "Save",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
        ControlBounds {
            x: 572,
            y: 628,
            width: 80,
            height: 30,
        },
        ID_SAVE,
    )?;
    create_control(
        window,
        instance,
        "BUTTON",
        "Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        ControlBounds {
            x: 662,
            y: 628,
            width: 80,
            height: 30,
        },
        ID_CANCEL,
    )?;
    Ok(())
}

fn create_multiline_edit(
    parent: HWND,
    instance: HINSTANCE,
    id: u16,
    text: &str,
    bounds: ControlBounds,
) -> Result<HWND> {
    create_control(
        parent,
        instance,
        "EDIT",
        text,
        WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_TABSTOP
            | WS_VSCROLL
            | WS_HSCROLL
            | ES_MULTILINE as u32
            | ES_AUTOVSCROLL as u32
            | ES_AUTOHSCROLL as u32
            | ES_WANTRETURN as u32,
        bounds,
        id,
    )
}

fn create_checkbox(
    parent: HWND,
    instance: HINSTANCE,
    text: &str,
    checked: bool,
    bounds: ControlBounds,
    id: u16,
) -> Result<HWND> {
    let control = create_control(
        parent,
        instance,
        "BUTTON",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
        bounds,
        id,
    )?;
    unsafe {
        SendMessageW(
            control,
            BM_SETCHECK,
            if checked { BST_CHECKED as usize } else { 0 },
            0,
        );
    }
    Ok(control)
}

fn create_control(
    parent: HWND,
    instance: HINSTANCE,
    class: &str,
    text: &str,
    style: u32,
    bounds: ControlBounds,
    id: u16,
) -> Result<HWND> {
    let class = wide(class);
    let text = wide(text);
    let control = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            text.as_ptr(),
            style,
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            parent,
            id as usize as _,
            instance,
            null(),
        )
    };
    ensure!(
        !control.is_null(),
        "create Unproxy settings control {id}: {}",
        std::io::Error::last_os_error()
    );
    Ok(control)
}

fn handle_button(window: HWND, state: &mut SettingsDialog, control_id: u16) {
    let result = match control_id {
        ID_PAC_BROWSE => browse_into(window, state.controls.pac_files, true),
        ID_FILTER_BROWSE => browse_into(window, state.controls.filter_lists, false),
        ID_SAVE => match state.preferences_from_controls() {
            Ok(updated) => {
                state.result = Some(updated);
                unsafe { DestroyWindow(window) };
                return;
            }
            Err(error) => Err(error),
        },
        ID_CANCEL => {
            unsafe { DestroyWindow(window) };
            return;
        }
        _ => return,
    };
    if let Err(error) = result {
        show_error(window, &format!("{error:#}"));
    }
}

fn browse_into(window: HWND, edit: HWND, pac_file: bool) -> Result<()> {
    let (title, filter) = if pac_file {
        (
            "Choose a PAC file",
            &[("PAC files (*.pac)", "*.pac"), ("All files (*.*)", "*.*")][..],
        )
    } else {
        (
            "Choose a filter list",
            &[
                ("Text and hosts files", "*.txt;*.hosts"),
                ("All files (*.*)", "*.*"),
            ][..],
        )
    };
    if let Some(path) = open_file_dialog(window, title, filter)? {
        let mut lines = control_text(edit)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        lines.push(path.to_string_lossy().into_owned());
        set_control_text(edit, &lines.join("\r\n"))?;
    }
    Ok(())
}

fn open_file_dialog(owner: HWND, title: &str, filter: &[(&str, &str)]) -> Result<Option<PathBuf>> {
    let mut filter_wide = Vec::new();
    for (description, pattern) in filter {
        filter_wide.extend(description.encode_utf16());
        filter_wide.push(0);
        filter_wide.extend(pattern.encode_utf16());
        filter_wide.push(0);
    }
    filter_wide.push(0);
    let title = wide(title);
    let mut filename = vec![0u16; 32_768];
    let mut dialog = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: filter_wide.as_ptr(),
        lpstrFile: filename.as_mut_ptr(),
        nMaxFile: filename.len() as u32,
        lpstrTitle: title.as_ptr(),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        let error = unsafe { CommDlgExtendedError() };
        if error == 0 {
            return Ok(None);
        }
        return Err(anyhow!(
            "Windows file picker failed with error 0x{error:08X}"
        ));
    }
    let length = filename
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(filename.len());
    Ok(Some(PathBuf::from(OsString::from_wide(
        &filename[..length],
    ))))
}

fn control_text(control: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(control) };
    if length <= 0 {
        return String::new();
    }
    let mut buffer = vec![0u16; length as usize + 1];
    let copied = unsafe { GetWindowTextW(control, buffer.as_mut_ptr(), buffer.len() as i32) };
    String::from_utf16_lossy(&buffer[..copied.max(0) as usize])
}

fn control_checked(control: HWND) -> bool {
    unsafe { SendMessageW(control, BM_GETCHECK, 0, 0) as u32 == BST_CHECKED }
}

fn set_control_text(control: HWND, text: &str) -> Result<()> {
    let text = wide(text);
    ensure!(
        unsafe { SetWindowTextW(control, text.as_ptr()) } != 0,
        "update Unproxy settings field: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn show_error(owner: HWND, message: &str) {
    let title = wide("Unproxy Settings");
    let message = wide(message);
    unsafe {
        MessageBoxW(
            owner,
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_preserve_pac_order_and_update_all_preferences() {
        let directory = tempfile::tempdir().unwrap();
        let pac = directory.path().join("proxy.pac");
        std::fs::write(&pac, "DIRECT").unwrap();
        let filter_file = directory.path().join("hosts.txt");
        std::fs::write(&filter_file, "0.0.0.0 example.test").unwrap();
        let current = Preferences::default();
        let updated = build_preferences(
            &current,
            SettingsFields {
                listeners: "127.0.0.1:8080\n[::1]:8080".into(),
                pac_files: format!("https://pac.example.test/first.pac\n{}", pac.display()),
                filter_lists: format!(
                    "{}\nhttps://filters.example.test/hosts.txt",
                    filter_file.display()
                ),
                negotiate: true,
                tunnel: true,
                direct_fallback: true,
                autostart: false,
            },
        )
        .unwrap();

        assert_eq!(
            updated.listeners.as_deref().unwrap(),
            &["127.0.0.1:8080".to_owned(), "[::1]:8080".to_owned()]
        );
        assert_eq!(updated.port, 8080);
        assert_eq!(
            updated
                .effective_pac_files()
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![
                "https://pac.example.test/first.pac".to_owned(),
                pac.to_string_lossy().into_owned()
            ]
        );
        assert_eq!(
            updated
                .effective_filter_lists()
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![
                filter_file.to_string_lossy().into_owned(),
                "https://filters.example.test/hosts.txt".to_owned()
            ]
        );
        assert_eq!(updated.negotiate, cfg!(feature = "negotiate"));
        assert!(updated.proxytunnel);
        assert!(updated.direct_fallback);
        assert!(!updated.autostart);
    }

    #[test]
    fn settings_reject_invalid_or_duplicate_listeners_and_sources() {
        assert!(parse_listener_lines("0.0.0.0:3128").is_err());
        assert!(parse_listener_lines("127.0.0.1:3128\n127.0.0.1:3128").is_err());

        let directory = tempfile::tempdir().unwrap();
        let list = directory.path().join("hosts.txt");
        std::fs::write(&list, "0.0.0.0 example.test").unwrap();
        assert!(
            parse_source_lines(
                &format!("{}\n{}", list.display(), list.display()),
                "filter-list",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn remote_sources_reject_credentials_and_fragments() {
        assert!(parse_source_lines("https://user@pac.example.test/file.pac", "PAC", true).is_err());
        assert!(
            parse_source_lines("https://pac.example.test/file.pac#fragment", "PAC", true).is_err()
        );
    }
}
