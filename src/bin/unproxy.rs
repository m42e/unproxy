#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::Result;
#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<()> {
    let args = unproxy::config::parse_main()?;
    unproxy::runtime::run(args).await
}

#[cfg(windows)]
fn main() -> Result<()> {
    if unproxy::platform::dispatch_service()? {
        return Ok(());
    }
    #[cfg(windows)]
    if std::env::args_os().any(|x| x == "--attach-console") {
        unproxy::platform::attach_console()?;
    }
    let args = unproxy::config::parse_main()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(unproxy::runtime::run(args))
}
