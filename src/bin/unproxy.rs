#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::Result;
use std::ffi::OsString;

fn shell_setup_args() -> Option<Vec<OsString>> {
    let mut args = std::env::args_os();
    let program = args.next()?;
    let rest = args.collect::<Vec<_>>();
    (rest.first().is_some_and(|arg| arg == "shell-setup"))
        .then(|| std::iter::once(program).chain(rest).collect())
}

fn run_shell_setup(args: Vec<OsString>) -> Result<()> {
    unproxy::shell_setup::run(args)
}

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<()> {
    if let Some(args) = shell_setup_args() {
        return run_shell_setup(args);
    }
    let args = unproxy::config::parse_main()?;
    unproxy::runtime::run(args).await
}

#[cfg(windows)]
fn main() -> Result<()> {
    if let Some(args) = shell_setup_args() {
        return run_shell_setup(args);
    }
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
