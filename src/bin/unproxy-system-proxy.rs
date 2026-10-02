fn main() {
    let result = (|| -> anyhow::Result<()> {
        let mut args = std::env::args().skip(1);
        let text = args.next().ok_or_else(|| {
            anyhow::anyhow!("Usage: unproxy-system-proxy PORT (0 disables proxies)")
        })?;
        if text == "--help" || text == "-h" {
            println!(
                "unproxy-system-proxy PORT\n0 disables HTTP/HTTPS proxies; 1..65535 enables 127.0.0.1:PORT."
            );
            return Ok(());
        }
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
