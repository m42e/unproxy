fn main() {
    let result = (|| -> anyhow::Result<()> {
        let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
        if raw_args.iter().any(|s| s == "--help" || s == "-h") {
            println!(
                "Usage: unproxy-system-proxy PORT\n\
Set the operating system's HTTP and HTTPS proxy for network services.\n\
\nPORT is an unsigned 16-bit number. Use 0 to disable the system proxy, or\n\
1..65535 to set it to 127.0.0.1:PORT. This does not start or stop Unproxy."
            );
            return Ok(());
        }
        let mut args = raw_args.into_iter();
        let text = args.next().ok_or_else(|| {
            anyhow::anyhow!("Usage: unproxy-system-proxy PORT (0 disables proxies)")
        })?;
        anyhow::ensure!(args.next().is_none(), "expected one unsigned 16-bit port");
        let port = text
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid unsigned 16-bit port: {text}"))?;
        println!(
            "Updated {} network services",
            unproxy::platform::set_system_proxy(port)?
        );
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("Unproxy: {error:#}");
        std::process::exit(1);
    }
}
