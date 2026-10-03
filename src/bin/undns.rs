use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::{env, ffi::OsString, fs, net::SocketAddr, path::PathBuf};
#[derive(Parser, Debug)]
#[command(
    name = "undns",
    version = unproxy::DNS_VERSION,
    about = "Run a local DNS-over-HTTPS forwarding service",
    long_about = "Listen for DNS queries on a local UDP port, forward them to a primary DNS server through Unproxy, and use a secondary DNS-over-HTTPS endpoint as fallback. Options may also be read from the undnsrc configuration file; command-line values take precedence.",
    args_override_self = true
)]
struct Args {
    /// Local UDP port to listen on.
    #[arg(long, default_value_t = 5353)]
    port: u16,
    /// HTTP or HTTPS URL of the proxy used to reach the primary DNS server.
    #[arg(long)]
    proxy: Option<String>,
    /// Address of the primary DNS server.
    #[arg(long, required = true)]
    primary: Option<SocketAddr>,
    /// DNS-over-HTTPS fallback URL.
    #[arg(long, default_value = "https://8.8.8.8/dns-query")]
    secondary: http::Uri,
}
fn config() -> Option<PathBuf> {
    let mut p = vec![];
    if let Some(d) = dirs::config_dir() {
        p.push(d.join("undns/undnsrc"))
    }
    #[cfg(unix)]
    {
        p.push("/etc/undns/undnsrc".into());
        p.push("/usr/local/etc/undns/undnsrc".into());
    }
    #[cfg(windows)]
    if let Ok(e) = env::current_exe()
        && let Some(d) = e.parent()
    {
        p.push(d.join("undnsrc"));
        p.push(d.join("undnsrc.txt"));
    }
    p.into_iter().find(|x| fs::read(x).is_ok())
}
fn merge_args(
    program: OsString,
    settings: Option<&str>,
    cli: impl IntoIterator<Item = OsString>,
) -> Vec<OsString> {
    let mut argv = vec![program];
    if let Some(settings) = settings {
        for line in settings
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            argv.extend(line.split_ascii_whitespace().map(Into::into));
        }
    }
    argv.extend(cli);
    argv
}

fn proxy_route(proxy: &str) -> Result<unproxy::route::Route> {
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
    Ok(if scheme == "http" {
        unproxy::route::Route::Http(endpoint)
    } else {
        unproxy::route::Route::Https(endpoint)
    })
}
#[tokio::main]
async fn main() -> Result<()> {
    let settings = config().and_then(|path| fs::read_to_string(path).ok());
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let argv = merge_args(program, settings.as_deref(), args);
    let a = Args::parse_from(argv);
    let primary = a.primary.ok_or_else(|| anyhow!("--primary is required"))?;
    let proxy = a
        .proxy
        .or_else(|| env::var("http_proxy").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3128".into());
    let secondary = a.secondary;
    unproxy::dns::validate_secondary_uri(&secondary).context("invalid secondary DNS URI")?;
    let route = proxy_route(&proxy)?;
    let options = unproxy::net::ConnectionOptions::default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    unproxy::dns::serve(a.port, primary, secondary, route, options).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_tokens_ignore_comments_and_precede_cli_overrides() {
        let args = merge_args(
            "undns".into(),
            Some(" # defaults\n --port 5300\n\n--primary 192.0.2.1:53\n"),
            ["--port".into(), "5353".into()],
        );
        let parsed = Args::try_parse_from(args).unwrap();
        assert_eq!(parsed.port, 5353);
        assert_eq!(parsed.primary.unwrap().to_string(), "192.0.2.1:53");
    }

    #[test]
    fn proxy_urls_resolve_scheme_defaults_explicit_ports_and_ipv6() {
        assert_eq!(
            proxy_route("http://proxy.example.test")
                .unwrap()
                .to_string(),
            "HTTP proxy.example.test:80"
        );
        assert_eq!(
            proxy_route("https://[2001:db8::1]:8443")
                .unwrap()
                .to_string(),
            "HTTPS [2001:db8::1]:8443"
        );
    }

    #[test]
    fn proxy_url_validation_rejects_unsafe_or_unusable_values() {
        for proxy in [
            "proxy.example.test:8080",
            "ftp://proxy.example.test",
            "http://user@proxy.example.test",
            "http://proxy.example.test:bad",
            "http://proxy.example.test:0",
            "http:///missing-host",
        ] {
            assert!(proxy_route(proxy).is_err(), "accepted {proxy}");
        }
    }
}
