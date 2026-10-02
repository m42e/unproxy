use anyhow::{Context, Result, bail};
use unproxy::{pac::Pac, route::Destination};
use std::{env, fs};

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
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
        // Validate destination components for absolute URIs. Authority-form inputs
        // remain useful to PAC scripts and use their authority as the host.
        if uri.scheme().is_some() {
            let _ = Destination::from_uri(&uri)
                .with_context(|| format!("invalid destination URI {raw}"))?;
        }
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
