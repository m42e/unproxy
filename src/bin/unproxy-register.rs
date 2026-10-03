fn main() -> anyhow::Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    if raw_args.iter().any(|s| s == "--help" || s == "-h") {
        println!(
            "Usage: unproxy-register [install|uninstall|status]\n\
Manage Unproxy's operating-system service registration.\n\
\nCommands:\n\
  install    Register the service and configure it to start\n\
  uninstall  Remove the service registration\n\
  status     Show whether the service is registered (default)"
        );
        return Ok(());
    }
    let mut args = raw_args.into_iter();
    let command = args.next().unwrap_or_else(|| "status".into());
    anyhow::ensure!(args.next().is_none(), "expected one registration command");
    unproxy::platform::service_control(&command, true)
}
