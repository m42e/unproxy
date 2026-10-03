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
#[command(
    name = "unproxy",
    version = crate::VERSION,
    about = "Local HTTP proxy with PAC based routing and corporate authentication",
    long_about = "Run a local HTTP proxy that routes requests through upstream proxies according to PAC scripts. By default it listens on 127.0.0.1:3128 and [::1]:3128. Options from the unproxy settings file are loaded first; command-line options take precedence. Set UNPROXY_NORC=1 to ignore the settings file. Use paceval to inspect PAC routing and unproxyctl to control the system service.",
    args_override_self = true
)]
pub struct MainArgs {
    /// Increase log verbosity; repeat to enable DEBUG and TRACE output.
    #[arg(short='v',long="verbose",action=clap::ArgAction::Count)]
    pub verbose: u8,
    /// Decrease log verbosity; repeat to disable logging.
    #[arg(short='q',long="quiet",action=clap::ArgAction::Count)]
    pub quiet: u8,
    /// Write diagnostic logs to this file, truncating it at startup.
    #[arg(long)]
    pub logfile: Option<PathBuf>,
    /// Listen on this numeric IP address and port; may be repeated.
    /// Defaults to 127.0.0.1:3128 and [::1]:3128.
    #[arg(short='L',long="listen",value_delimiter=None)]
    pub listen: Vec<String>,
    /// Accept connections from a named socket-activation listener.
    #[arg(long = "activate-socket")]
    pub activate_socket: Option<String>,
    /// Load a PAC script from a local path or HTTP(S) URL; may be repeated.
    #[arg(short = 'p', long = "pac-file", action = clap::ArgAction::Append)]
    pub pac_file: Vec<String>,
    /// Override the IP address returned by PAC's myIpAddress() function.
    #[arg(long = "my-ip-address")]
    pub my_ip_address: Option<IpAddr>,
    /// Read upstream proxy credentials from this netrc file (default: ~/.netrc).
    #[arg(long = "netrc-file")]
    #[cfg_attr(feature = "negotiate", arg(conflicts_with = "negotiate"))]
    pub netrc_file: Option<PathBuf>,
    #[cfg(feature = "negotiate")]
    /// Use Negotiate authentication; optionally restrict it to a host, repeatable.
    #[arg(short='n',long="negotiate",num_args=0..=1,default_missing_value="",action=clap::ArgAction::Append)]
    pub negotiate: Vec<String>,
    /// Use an upstream HTTP CONNECT tunnel for every request.
    #[arg(long = "proxytunnel")]
    pub proxytunnel: bool,
    /// Try a direct connection after all selected proxy routes fail.
    #[arg(long = "direct-fallback")]
    pub direct_fallback: bool,
    /// Fail closed until a routing script loads and on PAC evaluation errors.
    #[arg(long = "strict-policy")]
    pub strict_policy: bool,
    /// Maximum time in seconds to receive request headers.
    #[arg(long = "header-timeout", value_parser=parse_duration, default_value="15")]
    pub header_timeout: Duration,
    /// Maximum idle time in seconds for frontend and upstream HTTP connections.
    #[arg(long = "idle-timeout", value_parser=parse_duration, default_value="60")]
    pub idle_timeout: Duration,
    /// Maximum time in seconds for an upstream HTTP exchange.
    #[arg(long = "exchange-timeout", value_parser=parse_duration, default_value="30")]
    pub exchange_timeout: Duration,
    /// Maximum number of simultaneous client sessions, including CONNECT tunnels.
    #[arg(long = "max-sessions", default_value = "256")]
    pub max_sessions: usize,
    /// Timeout in seconds for each upstream connection attempt.
    #[arg(short='c',long="connect-timeout",value_parser=parse_duration,default_value="10")]
    pub connect_timeout: Duration,
    /// Race concurrent upstream connection attempts and use the first success.
    #[arg(long)]
    pub race_connect: bool,
    /// Maximum number of upstream connection attempts to run concurrently.
    #[arg(long = "parallel-connect", default_value = "1")]
    pub parallel_connect: usize,
    /// Set the client-side TCP keepalive idle time in seconds.
    #[arg(long="client-tcp-keepalive-time",value_parser=parse_duration)]
    pub client_tcp_keepalive_time: Option<Duration>,
    /// Set the client-side TCP keepalive probe interval in seconds.
    #[arg(long="client-tcp-keepalive-interval",value_parser=parse_duration)]
    pub client_tcp_keepalive_interval: Option<Duration>,
    /// Set the number of unacknowledged client-side TCP keepalive probes.
    #[arg(long = "client-tcp-keepalive-retries")]
    pub client_tcp_keepalive_retries: Option<u32>,
    /// Set the server-side TCP keepalive idle time in seconds.
    #[arg(long="server-tcp-keepalive-time",value_parser=parse_duration)]
    pub server_tcp_keepalive_time: Option<Duration>,
    /// Set the server-side TCP keepalive probe interval in seconds.
    #[arg(long="server-tcp-keepalive-interval",value_parser=parse_duration)]
    pub server_tcp_keepalive_interval: Option<Duration>,
    /// Set the number of unacknowledged server-side TCP keepalive probes.
    #[arg(long = "server-tcp-keepalive-retries")]
    pub server_tcp_keepalive_retries: Option<u32>,
    /// Wait this many seconds for active sessions to finish during shutdown.
    #[arg(long = "graceful-shutdown-timeout", default_value = "30")]
    pub graceful_shutdown_timeout: u64,
    #[cfg(windows)]
    /// Attach the process to the parent console before printing help or errors.
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
            vec!["127.0.0.1:3128".to_owned(), "[::1]:3128".to_owned()]
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
    fn config_file_discovery_helpers_return_only_real_files() {
        if let Some(path) = settings_path() {
            assert!(path.is_file(), "settings path must be readable: {path:?}");
        }
        if let Some(path) = pac_path() {
            assert!(path.is_file(), "PAC path must exist: {path:?}");
        }
        assert_eq!(
            netrc_default(),
            dirs::home_dir().map(|home| home.join(".netrc"))
        );
    }

    #[test]
    fn parse_main_from_preserves_clap_error_context() {
        let error =
            parse_main_from(vec!["unproxy".into(), "--unknown-option".into()], false).unwrap_err();
        assert!(error.to_string().contains("unexpected argument"));
    }

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
    fn routing_options_default_off_and_can_be_enabled_together() {
        let defaults = MainArgs::try_parse_from(["x"]).unwrap();
        assert!(!defaults.direct_fallback);
        assert!(!defaults.proxytunnel);

        let enabled =
            MainArgs::try_parse_from(["x", "--direct-fallback", "--proxytunnel"]).unwrap();
        assert!(enabled.direct_fallback);
        assert!(enabled.proxytunnel);
    }
    #[test]
    fn repeated_listeners_keep_input_order() {
        let args =
            MainArgs::try_parse_from(["x", "--listen", "127.0.0.1:3128", "--listen", "[::1]:8080"])
                .unwrap();
        assert_eq!(
            args.listen_addrs().unwrap(),
            [
                "127.0.0.1:3128".parse().unwrap(),
                "[::1]:8080".parse().unwrap()
            ]
        );
    }
    #[cfg(feature = "negotiate")]
    #[test]
    fn negotiate_accepts_global_and_ordered_host_restrictions() {
        let global = MainArgs::try_parse_from(["x", "--negotiate"]).unwrap();
        assert_eq!(global.negotiate, [""]);
        let hosts = MainArgs::try_parse_from([
            "x",
            "--negotiate",
            "proxy-one.example",
            "--negotiate",
            "proxy-two.example",
        ])
        .unwrap();
        assert_eq!(hosts.negotiate, ["proxy-one.example", "proxy-two.example"]);
    }
    #[test]
    fn client_and_server_keepalive_values_parse_from_cli() {
        let args = MainArgs::try_parse_from([
            "x",
            "--client-tcp-keepalive-time",
            "10",
            "--client-tcp-keepalive-interval",
            "20",
            "--client-tcp-keepalive-retries",
            "5",
            "--server-tcp-keepalive-time",
            "100",
            "--server-tcp-keepalive-interval",
            "200",
            "--server-tcp-keepalive-retries",
            "50",
        ])
        .unwrap();
        assert_eq!(
            args.client_tcp_keepalive_time,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            args.client_tcp_keepalive_interval,
            Some(Duration::from_secs(20))
        );
        assert_eq!(args.client_tcp_keepalive_retries, Some(5));
        assert_eq!(
            args.server_tcp_keepalive_time,
            Some(Duration::from_secs(100))
        );
        assert_eq!(
            args.server_tcp_keepalive_interval,
            Some(Duration::from_secs(200))
        );
        assert_eq!(args.server_tcp_keepalive_retries, Some(50));
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
    fn duration_arguments_cover_zero_fraction_and_invalid_boundaries() {
        for (value, expected) in [("0", Duration::ZERO), ("0.125", Duration::from_millis(125))] {
            let args = MainArgs::try_parse_from(["x", "--exchange-timeout", value]).unwrap();
            assert_eq!(args.exchange_timeout, expected, "value {value}");
        }

        for value in ["-0.1", "NaN", "inf", "-inf", "invalid", "1e100"] {
            let result = MainArgs::try_parse_from(["x", "--exchange-timeout", value]);
            assert!(result.is_err(), "value {value} should be rejected");
        }
    }

    #[test]
    fn listener_arguments_require_numeric_concrete_addresses() {
        for valid in ["127.0.0.1:0", "[::1]:3128"] {
            let args = MainArgs::try_parse_from(["x", "--listen", valid]).unwrap();
            assert_eq!(args.listen_addrs().unwrap().len(), 1, "address {valid}");
        }

        for invalid in [
            "localhost:3128",
            "0.0.0.0:3128",
            "[::]:3128",
            "127.0.0.1",
            "127.0.0.1:nope",
        ] {
            if let Ok(args) = MainArgs::try_parse_from(["x", "--listen", invalid]) {
                assert!(
                    args.listen_addrs().is_err(),
                    "address {invalid} should be rejected"
                );
            }
        }
    }

    #[test]
    fn numeric_limits_parse_zero_and_one_without_overflow() {
        for (name, field) in [("--max-sessions", 0usize), ("--parallel-connect", 0usize)] {
            let args = MainArgs::try_parse_from(["x", name, "0"]).unwrap();
            let actual = if name == "--max-sessions" {
                args.max_sessions
            } else {
                args.parallel_connect
            };
            assert_eq!(actual, field);
            let args = MainArgs::try_parse_from(["x", name, "1"]).unwrap();
            let actual = if name == "--max-sessions" {
                args.max_sessions
            } else {
                args.parallel_connect
            };
            assert_eq!(actual, 1);
            assert!(MainArgs::try_parse_from(["x", name, "184467440737095516160"]).is_err());
        }
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn explicit_netrc_conflicts_with_negotiate_before_startup() {
        assert!(
            MainArgs::try_parse_from(["x", "--netrc-file", "credentials.netrc", "--negotiate",])
                .is_err()
        );
    }
    #[test]
    fn token_lines() {
        let p = std::env::temp_dir().join("pd-config-test");
        fs::write(&p, "# hi\n--listen 127.0.0.1:5\n").unwrap();
        assert_eq!(token_file(&p), ["--listen", "127.0.0.1:5"]);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn file_discovery_skips_missing_and_directory_candidates_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let directory = dir.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        fs::write(&first, "first").unwrap();
        fs::write(&second, "second").unwrap();

        assert_eq!(
            first_readable([missing, directory, second.clone(), first]),
            Some(second)
        );
        assert_eq!(first_readable(std::iter::empty()), None);
        assert_eq!(token_file(&dir.path().join("absent")), Vec::<String>::new());
        let invalid = dir.path().join("invalid-utf8");
        fs::write(&invalid, [0xff, 0xfe]).unwrap();
        assert!(token_file(&invalid).is_empty());
    }

    #[test]
    fn timeout_accessor_returns_configured_duration() {
        let args = MainArgs::try_parse_from(["x", "--connect-timeout", "2.5"]).unwrap();
        assert_eq!(args.timeout(), Duration::from_millis(2500));
        assert_eq!(verbosity_level(1, 0), Some("debug"));
        assert_eq!(verbosity_level(0, u8::MAX), None);
    }
}
