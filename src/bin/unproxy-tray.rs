#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    if let Err(error) = unproxy::desktop::run_tray() {
        #[cfg(not(windows))]
        eprintln!("UnproxyTray: {error:#}");
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &format!("Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('{}','Unproxy')", error.to_string().replace('\'', "''"))]).status();
        }
        std::process::exit(1)
    }
}
