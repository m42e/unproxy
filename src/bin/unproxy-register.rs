fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "status".into());
    if command == "--help" || command == "-h" {
        println!("unproxy-register [install|uninstall|status]");
        return Ok(());
    }
    anyhow::ensure!(args.next().is_none(), "expected one registration command");
    unproxy::platform::service_control(&command, true)
}
