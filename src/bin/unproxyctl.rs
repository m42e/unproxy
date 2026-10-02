fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "status".into());
    if command == "--help" || command == "-h" {
        println!("unproxyctl [status|start|restart|stop|enable|disable]");
        return Ok(());
    }
    anyhow::ensure!(args.next().is_none(), "expected one service command");
    unproxy::platform::service_control(&command, false)
}
