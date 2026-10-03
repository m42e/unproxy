fn main() -> anyhow::Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    if raw_args.iter().any(|s| s == "--help" || s == "-h") {
        println!(
            "Usage: unproxyctl [status|start|restart|stop|enable|disable]\n\
Control the installed Unproxy system service.\n\
\nCommands:\n\
  status   Show service status (default)\n\
  start    Start the service\n\
  restart  Restart the service\n\
  stop     Stop the service\n\
  enable   Enable the service at login or boot\n\
  disable  Disable automatic service start"
        );
        return Ok(());
    }
    let mut args = raw_args.into_iter();
    let command = args.next().unwrap_or_else(|| "status".into());
    anyhow::ensure!(args.next().is_none(), "expected one service command");
    unproxy::platform::service_control(&command, false)
}
