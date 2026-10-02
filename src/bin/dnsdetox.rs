use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::{env, fs, net::SocketAddr, path::PathBuf};
#[derive(Parser, Debug)]
#[command(name="dnsdetox",version=unproxy::DNS_VERSION,args_override_self=true)]
struct Args {
    #[arg(long, default_value_t = 5353)]
    port: u16,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, required = true)]
    primary: Option<SocketAddr>,
    #[arg(long, default_value = "https://8.8.8.8/dns-query")]
    secondary: http::Uri,
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
    if let Ok(e) = env::current_exe() {
        if let Some(d) = e.parent() {
            p.push(d.join("dnsdetoxrc"));
            p.push(d.join("dnsdetoxrc.txt"));
        }
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
    let primary = a.primary.ok_or_else(|| anyhow!("--primary is required"))?;
    let proxy = a
        .proxy
        .or_else(|| env::var("http_proxy").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3128".into());
    let secondary = a.secondary;
    unproxy::dns::validate_secondary_uri(&secondary).context("invalid secondary DNS URI")?;
    let p: http::Uri = proxy.parse()?;
    let authority = p
        .authority()
        .ok_or_else(|| anyhow!("proxy URL requires a host"))?;
    if authority.as_str().contains('@') {
        return Err(anyhow!("proxy URL user information is not supported"));
    }
    let scheme = p
        .scheme_str()
        .ok_or_else(|| anyhow!("proxy URL requires an HTTP or HTTPS scheme"))?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return Err(anyhow!("proxy URL must use HTTP or HTTPS")),
    };
    let port = if unproxy::dns::authority_has_explicit_port(authority.as_str()) {
        authority
            .port_u16()
            .ok_or_else(|| anyhow!("invalid proxy port"))?
    } else {
        default_port
    };
    if port == 0 {
        return Err(anyhow!("proxy port must be nonzero"));
    }
    let endpoint = unproxy::route::Endpoint {
        host: authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    };
    if endpoint.host.is_empty() {
        return Err(anyhow!("proxy URL requires a host"));
    }
    let route = if scheme == "http" {
        unproxy::route::Route::Http(endpoint)
    } else {
        unproxy::route::Route::Https(endpoint)
    };
    let options = unproxy::net::ConnectionOptions::default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    unproxy::dns::serve(a.port, primary, secondary, route, options).await?;
    Ok(())
}
