#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::Result;
#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(windows)]
    if std::env::args_os().any(|x| x == "--attach-console") {
        unproxy::platform::attach_console()?;
    }
    let args = unproxy::config::parse_main()?;
    unproxy::runtime::run(args).await
}
