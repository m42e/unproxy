# Configuration reference

Use desktop Settings for the tray or menu bar app. Use command-line flags or an `unproxyrc` file for a terminal process or service.

## CLI settings file

An `unproxyrc` file contains CLI options, with one or more options per line. Blank lines and lines beginning with `#` are ignored. Double quotes keep paths containing spaces together.

```text
# Local listeners
--listen 127.0.0.1:3128
--listen [::1]:3128

# Organization policy
--pac-file "https://proxy.example.org/company.pac"
--reload-pac-on-network-change
```

Restart the CLI process or service after changing its options. PAC reload updates policy contents, not CLI options.

The first readable settings file is used. User configuration is checked before system locations:

| Platform | Locations, in search order |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/unproxy/unproxyrc` (normally `~/.config/unproxy/unproxyrc`), `/etc/unproxy/unproxyrc`, `/usr/local/etc/unproxy/unproxyrc` |
| macOS CLI | `~/Library/Application Support/unproxy/unproxyrc`, `/etc/unproxy/unproxyrc`, `/usr/local/etc/unproxy/unproxyrc`, `/opt/unproxy/etc/unproxyrc` |
| Windows CLI | `%APPDATA%\unproxy\unproxyrc`, then `unproxyrc` or `unproxyrc.txt` beside the executable |
| Windows service installation | The installer creates `C:\ProgramData\Unproxy\unproxyrc` for the service. |

Options in the settings file load before command-line arguments. Later scalar values override earlier ones; repeatable source options such as `--pac-file` append. Set `UNPROXY_NORC=1` to ignore the settings file.

Default PAC discovery checks `proxy.pac` under the same user and Unix system directories. macOS also checks `/opt/unproxy/etc/proxy.pac`; Windows checks beside the executable. Explicit `--pac-file` options replace default PAC discovery.

## Desktop files

| Item | Windows | macOS |
| --- | --- | --- |
| Preferences | `%LOCALAPPDATA%\Unproxy\preferences.json` | Native application preferences for `de.m42e.unproxy.app` |
| Data and default PAC | `%LOCALAPPDATA%\Unproxy` | `~/Library/Application Support/Unproxy` |
| Diagnostic log | `unproxy.log` in the data folder | `unproxy.log` in the data folder |

Desktop apps use their own preferences and launch their proxy with explicit settings. Make desktop changes through **Settings…**. CLI `shell-setup` reads `unproxyrc`, so use explicit environment variables if your desktop listener differs.

## Routing and credentials

| Option | Purpose | Default |
| --- | --- | --- |
| `--listen IP:PORT` / `-L` | Numeric listener; repeat for multiple addresses. Unspecified IPs are rejected. | IPv4 and IPv6 loopback, port 3128 |
| `--pac-file PATH_OR_URL` / `-p` | Ordered PAC source; repeat to compose sources. | Discover a local default PAC |
| `--filter-list PATH_OR_URL` | Optional domain blocking source; repeat for multiple lists. | None |
| `--reload-pac-on-network-change` | Reload PAC after default-route local address changes. | Off |
| `--my-ip-address IP` | Override the address returned by PAC `myIpAddress()`. | Automatic |
| `--strict-policy` | Reject traffic until policy loads and on PAC evaluation errors. | Off |
| `--direct-fallback` | Try direct after selected proxy routes fail. | Off |
| `--proxytunnel` | Use upstream CONNECT for every proxied request. | Off |
| `--netrc-file PATH` | Read upstream password credentials from this file. | `~/.netrc` |
| `--negotiate [HOST]` / `-n` | Integrated authentication; optionally restrict hosts, repeatable. | Off; requires Negotiate build |

See [PAC & routing](routing.md) and [Authentication](authentication.md) before changing policy or sign-in behavior.

## Timeouts and capacity

Durations are in seconds. The connection, header, idle, exchange, and keepalive duration options accept nonnegative fractional seconds.

| Option | Purpose | Default |
| --- | --- | --- |
| `--connect-timeout` / `-c` | Each upstream connection attempt. | 10 |
| `--header-timeout` | Receiving request headers. | 15 |
| `--idle-timeout` | Idle frontend and upstream HTTP connections. | 60 |
| `--exchange-timeout` | An upstream HTTP exchange. | 30 |
| `--graceful-shutdown-timeout` | Wait for active sessions during CLI shutdown. | 30 |
| `--max-sessions` | Maximum simultaneous client sessions, including CONNECT tunnels. | 256 |
| `--parallel-connect` | Maximum concurrent upstream connection attempts. | 1 |
| `--race-connect` | Use the first successful concurrent connection attempt. | Off |

The desktop app stops its managed proxy without the CLI’s graceful shutdown wait. Changes that restart it can interrupt sessions.

For TCP keepalive tuning, use `--client-tcp-keepalive-time`, `--client-tcp-keepalive-interval`, `--client-tcp-keepalive-retries`, and the corresponding `--server-tcp-keepalive-*` options. Check your operating system’s behavior before tuning these.

Unproxy does not enforce a process memory limit. Memory use depends on traffic, PAC scripts, and filter data.

## Diagnostics and utilities

| Command / option | Purpose |
| --- | --- |
| `unproxy --help` | Full options supported by the installed build. |
| `unproxy doctor [--url URL] [--json]` | Check CLI settings, PAC routes, TCP reachability, credential readiness, and available runtime status. See [Troubleshooting](troubleshooting.md). |
| `unproxy --version` | Installed version. |
| `-v`, `-vv` | Debug and trace verbosity. |
| `-q`, `-qq` | Reduce or disable logging. |
| `--logfile PATH` | Append diagnostic logs; rotate at 10 MiB and keep three backups. |
| `unproxy shell-setup SHELL` | Print proxy variables and completion setup. |
| `paceval PAC_SOURCE URL` | Inspect a PAC decision for a destination. |
| `unproxyctl --help` | Service control commands for your platform. |
| `undns --help` | DNS utility options, including upstream proxy support. |

## Listener access and privacy

Listeners do not require client authentication. Anyone who can reach one can use the proxy and read its status, access log, and diagnostic endpoints. Keep loopback listeners for personal use. For intentional sharing, bind a specific trusted interface and restrict access with a firewall.

Logs can reveal destinations, network details, and errors. Review and redact them before sharing a support report.
