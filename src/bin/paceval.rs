use anyhow::{Context, Result};
use std::{env, fs};
use unproxy::pac::Pac;

fn run() -> Result<()> {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.iter().any(|s| s == "-h" || s == "--help") {
        println!(
            "Usage: paceval <local-pac-file> [url ...]\n\
Evaluate one or more URLs using a local PAC script and print the selected routes.\n\
The PAC file is read from disk and is not fetched from a URL. Each input URL must\n\
include a host. With no URLs, the PAC file is still checked for load errors.\n\
\nExample:\n\
  paceval proxy.pac https://example.com/ http://intranet/"
        );
        return Ok(());
    }
    let mut args = raw_args.into_iter();
    let file = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: paceval <local-pac-file> [url ...]"))?;
    let source = fs::read_to_string(&file).with_context(|| format!("read PAC file {file}"))?;
    let mut pac = Pac::new(Some(&source)).context("load PAC script")?;
    for raw in args {
        let uri: http::Uri = raw.parse().with_context(|| format!("invalid URI {raw}"))?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("URI has no host: {raw}"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        // PAC evaluation accepts any parseable URI form with a host, including
        // authority-only inputs whose scheme is inferred by the proxy layer.
        let routes = pac
            .evaluate(&raw, host)
            .with_context(|| format!("evaluate {raw}"))?;
        println!("{raw}: {routes}");
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("paceval: {e:#}");
        std::process::exit(1)
    }
}
