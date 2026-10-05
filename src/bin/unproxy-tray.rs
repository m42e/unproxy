#![cfg_attr(windows, windows_subsystem = "windows")]

use clap::Parser;

#[derive(Parser)]
#[command(
    about = "Launch the Unproxy Windows tray controller",
    long_about = "Start the per-user Windows tray controller for the Unproxy proxy. This executable is normally launched from the installed Unproxy directory."
)]
struct Args {}

fn main() {
    let _ = Args::parse();
    if let Err(error) = unproxy::desktop::run_tray() {
        #[cfg(not(windows))]
        eprintln!("UnproxyTray: {error:#}");
        #[cfg(windows)]
        {
            unproxy::desktop::show_tray_error(&format!("{error:#}"));
        }
        std::process::exit(1)
    }
}
