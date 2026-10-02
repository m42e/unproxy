use anyhow::{Result, anyhow};
use clap::Parser;
use std::{env, fs, net::SocketAddr, path::PathBuf};
#[derive(Parser, Debug)]
#[command(name="dnsdetox",version=unproxy::DNS_VERSION)]
struct Args {
    #[arg(long, default_value_t = 5353)]
    port: u16,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    primary: Option<String>,
    #[arg(long, default_value = "https://8.8.8.8/dns-query")]
    secondary: String,
}
fn config() -> Option<PathBuf> {
    let mut p = vec![];
    if let Some(d) = dirs::config_dir() {
        p.push(d.join("dnsdetox/dnsdetoxrc"))
    }
    #[cfg(unix)]
    {
        p.push("/etc/dnsdetox/dnsdetoxrc".into());
        p.push("/usr/local/etc/dnsdetox/dnsdetoxrc".into());
    }
    #[cfg(windows)]
    {
        p.push("dnsdetoxrc".into());
        p.push("dnsdetoxrc.txt".into());
    }
    p.into_iter().find(|x| fs::read(x).is_ok())
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut argv = vec![env::args_os().next().unwrap_or_default()];
    if let Some(p) = config() {
        if let Ok(s) = fs::read_to_string(p) {
            for l in s
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                argv.extend(l.split_ascii_whitespace().map(Into::into));
            }
        }
    }
    argv.extend(env::args_os().skip(1));
    let a = Args::parse_from(argv);
    let primary: SocketAddr = a
        .primary
        .ok_or_else(|| anyhow!("--primary is required (IP:PORT)"))?
        .parse()?;
    let proxy = a
        .proxy
        .or_else(|| env::var("http_proxy").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3128".into());
    let secondary: http::Uri = a.secondary.parse()?;
    let p: http::Uri = proxy.parse()?;
    let pe = p
        .authority()
        .ok_or_else(|| anyhow!("proxy URL requires host and port"))?;
    let endpoint = unproxy::route::Endpoint {
        host: pe.host().to_string(),
        port: pe
            .port_u16()
            .or_else(|| {
                if p.scheme_str() == Some("https") {
                    Some(443)
                } else if p.scheme_str() == Some("http") {
                    Some(80)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("proxy URL must use HTTP or HTTPS"))?,
    };
    let route = match p.scheme_str() {
        Some("http") => unproxy::route::Route::Http(endpoint),
        Some("https") => unproxy::route::Route::Https(endpoint),
        _ => return Err(anyhow!("proxy URL must use HTTP or HTTPS")),
    };
    let options = unproxy::net::ConnectionOptions::default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    unproxy::dns::serve(a.port, primary, secondary, route, options).await?;
    Ok(())
}
