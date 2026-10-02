//! Command-line options and settings-file discovery.
use anyhow::{Result, anyhow};
use clap::Parser;
use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

pub fn user_config_dir() -> Option<PathBuf> {
    dirs::config_dir()
}
pub fn token_file(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .flat_map(|l| {
                    l.split_ascii_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect()
        })
        .unwrap_or_default()
}
pub fn first_readable(paths: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|p| fs::read(p).is_ok())
}
pub fn settings_path() -> Option<PathBuf> {
    let mut p = vec![];
    if let Some(d) = user_config_dir() {
        p.push(d.join("unproxy/unproxyrc"))
    }
    #[cfg(unix)]
    {
        p.push("/etc/unproxy/unproxyrc".into());
        p.push("/usr/local/etc/unproxy/unproxyrc".into());
    }
    #[cfg(target_os = "macos")]
    p.push("/opt/unproxy/etc/unproxyrc".into());
    #[cfg(windows)]
    if let Ok(e) = env::current_exe()
        && let Some(d) = e.parent()
    {
        p.push(d.join("unproxyrc"));
        p.push(d.join("unproxyrc.txt"));
    }
    first_readable(p)
}
pub fn pac_path() -> Option<PathBuf> {
    let mut p = vec![];
    if let Some(d) = user_config_dir() {
        p.push(d.join("unproxy/proxy.pac"))
    }
    #[cfg(unix)]
    {
        p.push("/etc/unproxy/proxy.pac".into());
        p.push("/usr/local/etc/unproxy/proxy.pac".into());
    }
    #[cfg(target_os = "macos")]
    p.push("/opt/unproxy/etc/proxy.pac".into());
    #[cfg(windows)]
    if let Ok(e) = env::current_exe()
        && let Some(d) = e.parent()
    {
        p.push(d.join("proxy.pac"))
    }
    p.into_iter().find(|p| p.is_file())
}
pub fn netrc_default() -> Option<PathBuf> {
    dirs::home_dir().map(|p| p.join(".netrc"))
}
#[derive(Parser, Debug, Clone)]
#[command(name = "unproxy", version = crate::VERSION, args_override_self = true)]
pub struct MainArgs {
    #[arg(short='v',long="verbose",action=clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(short='q',long="quiet",action=clap::ArgAction::Count)]
    pub quiet: u8,
    #[arg(long)]
    pub logfile: Option<PathBuf>,
    #[arg(short='L',long="listen",value_delimiter=None)]
    pub listen: Vec<String>,
    #[arg(long = "activate-socket")]
    pub activate_socket: Option<String>,
    #[arg(short = 'p', long = "pac-file", action = clap::ArgAction::Append)]
    pub pac_file: Vec<String>,
    #[arg(long = "my-ip-address")]
    pub my_ip_address: Option<IpAddr>,
    #[arg(long = "netrc-file")]
    #[cfg_attr(feature = "negotiate", arg(conflicts_with = "negotiate"))]
    pub netrc_file: Option<PathBuf>,
    #[cfg(feature = "negotiate")]
    #[arg(short='n',long="negotiate",num_args=0..=1,default_missing_value="",action=clap::ArgAction::Append)]
    pub negotiate: Vec<String>,
    #[arg(long = "proxytunnel")]
    pub proxytunnel: bool,
    #[arg(long = "direct-fallback")]
    pub direct_fallback: bool,
    #[arg(short='c',long="connect-timeout",value_parser=parse_duration,default_value="10")]
    pub connect_timeout: Duration,
    #[arg(long)]
    pub race_connect: bool,
    #[arg(long = "parallel-connect", default_value = "1")]
    pub parallel_connect: usize,
    #[arg(long="client-tcp-keepalive-time",value_parser=parse_duration)]
    pub client_tcp_keepalive_time: Option<Duration>,
    #[arg(long="client-tcp-keepalive-interval",value_parser=parse_duration)]
    pub client_tcp_keepalive_interval: Option<Duration>,
    #[arg(long = "client-tcp-keepalive-retries")]
    pub client_tcp_keepalive_retries: Option<u32>,
    #[arg(long="server-tcp-keepalive-time",value_parser=parse_duration)]
    pub server_tcp_keepalive_time: Option<Duration>,
    #[arg(long="server-tcp-keepalive-interval",value_parser=parse_duration)]
    pub server_tcp_keepalive_interval: Option<Duration>,
    #[arg(long = "server-tcp-keepalive-retries")]
    pub server_tcp_keepalive_retries: Option<u32>,
    #[arg(long = "graceful-shutdown-timeout", default_value = "30")]
    pub graceful_shutdown_timeout: u64,
    #[cfg(windows)]
    #[arg(long)]
    pub attach_console: bool,
}
fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let f: f64 = s
        .parse()
        .map_err(|_| "expected nonnegative seconds".to_string())?;
    if !f.is_finite() || f < 0.0 {
        return Err("expected finite nonnegative seconds".into());
    }
    Duration::try_from_secs_f64(f).map_err(|_| "duration out of range".into())
}
impl MainArgs {
    pub fn timeout(&self) -> Duration {
        self.connect_timeout
    }
    pub fn listen_addrs(&self) -> Result<Vec<SocketAddr>> {
        let xs = if self.listen.is_empty() {
            vec!["127.0.0.1:3128".to_owned()]
        } else {
            self.listen.clone()
        };
        xs.into_iter()
            .map(|s| {
                let a: SocketAddr = s
                    .parse()
                    .map_err(|_| anyhow!("invalid numeric listen address {s}"))?;
                if a.ip().is_unspecified() {
                    return Err(anyhow!("listen address must not be unspecified: {a}"));
                }
                Ok(a)
            })
            .collect()
    }
}
fn merged_args(args: Vec<std::ffi::OsString>, read_settings: bool) -> Vec<std::ffi::OsString> {
    let program = args.first().cloned().unwrap_or_else(|| "unproxy".into());
    let mut all = vec![program];
    if read_settings && let Some(p) = settings_path() {
        all.extend(token_file(&p).into_iter().map(Into::into));
    }
    all.extend(args.into_iter().skip(1));
    all
}
/// Parse current process arguments and honor UNPROXY_NORC.
pub fn parse_main() -> Result<MainArgs> {
    let args = env::args_os().collect::<Vec<_>>();
    let read = env::var_os("UNPROXY_NORC").is_none_or(|v| v.is_empty());
    Ok(MainArgs::parse_from(merged_args(args, read)))
}
/// Parse supplied arguments, optionally adding settings tokens. Intended for embedders.
pub fn try_parse_main_from(
    args: Vec<std::ffi::OsString>,
    read_settings: bool,
) -> std::result::Result<MainArgs, clap::Error> {
    MainArgs::try_parse_from(merged_args(args, read_settings))
}
pub fn parse_main_from(args: Vec<std::ffi::OsString>, read_settings: bool) -> Result<MainArgs> {
    try_parse_main_from(args, read_settings).map_err(|e| anyhow!(e.to_string()))
}
pub fn verbosity_level(v: u8, q: u8) -> Option<&'static str> {
    match v as i16 - q as i16 {
        i16::MIN..=-2 => None,
        -1 => Some("warn"),
        0 => Some("info"),
        1 => Some("debug"),
        _ => Some("trace"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_listeners() {
        let a = MainArgs::try_parse_from(["x"]).unwrap();
        assert_eq!(a.listen_addrs().unwrap()[0].to_string(), "127.0.0.1:3128");
        assert!(
            MainArgs::try_parse_from(["x", "-L", "0.0.0.0:80"])
                .unwrap()
                .listen_addrs()
                .is_err()
        )
    }
    #[test]
    fn scalar_command_line_values_override_rc_values_and_verbosity_can_disable_logs() {
        let a =
            MainArgs::try_parse_from(["x", "--connect-timeout", "4", "--connect-timeout", "0.25"])
                .unwrap();
        assert_eq!(a.connect_timeout, Duration::from_millis(250));
        assert_eq!(verbosity_level(0, 2), None);
        assert_eq!(verbosity_level(0, 1), Some("warn"));
        assert_eq!(verbosity_level(2, 0), Some("trace"));
    }
    #[test]
    fn rejects_unusable_durations() {
        assert!(MainArgs::try_parse_from(["x", "--connect-timeout", "NaN"]).is_err());
        assert!(MainArgs::try_parse_from(["x", "--connect-timeout", "-1"]).is_err());
    }
    #[test]
    fn token_lines() {
        let p = std::env::temp_dir().join("pd-config-test");
        fs::write(&p, "# hi\n--listen 127.0.0.1:5\n").unwrap();
        assert_eq!(token_file(&p), ["--listen", "127.0.0.1:5"]);
        let _ = fs::remove_file(p);
    }
}
