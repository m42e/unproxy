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

# Optional custom release metadata for `unproxy check-upgrade`
--release-info-url "https://updates.example.org/unproxy.json"
```

Restart the CLI process or service after changing its options. PAC reload updates policy contents, not CLI options.

The first readable settings file is used. User configuration is checked before system locations:

| Platform | Locations, in search order |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/unproxy/unproxyrc` (normally `~/.config/unproxy/unproxyrc`), `/etc/unproxy/unproxyrc`, `/usr/local/etc/unproxy/unproxyrc` |
| macOS CLI | `~/Library/Application Support/unproxy/unproxyrc`, `/etc/unproxy/unproxyrc`, `/usr/local/etc/unproxy/unproxyrc`, `/opt/unproxy/etc/unproxyrc` |
| Windows CLI | `%APPDATA%\unproxy\unproxyrc`, then `unproxyrc` or `unproxyrc.txt` beside the executable |
| Windows service installation | `C:\Program Files\Unproxy\data\unproxyrc` |

Options in the settings file load before command-line arguments. Later scalar values override earlier ones; repeatable source options such as `--pac-file` append. Set `UNPROXY_NORC=1` to ignore the settings file.

Default PAC discovery checks `proxy.pac` under the same user and Unix system directories. macOS also checks `/opt/unproxy/etc/proxy.pac`; Windows checks beside the executable. Explicit `--pac-file` options replace default PAC discovery.

## Desktop files

| Item | Windows | macOS |
| --- | --- | --- |
| Preferences | `%LOCALAPPDATA%\Unproxy\preferences.json` | `~/Library/Application Support/Unproxy/preferences.json` (other settings are also mirrored to native application preferences) |
| Data and default PAC | `%LOCALAPPDATA%\Unproxy` | `~/Library/Application Support/Unproxy` |
| Diagnostic log | `unproxy.log` in the data folder | `unproxy.log` in the data folder |

Desktop apps use their own preferences and launch their proxy with explicit settings. Make ordinary desktop changes through **Settings…**. The expert-only `releaseInfoUrl` update endpoint is configured in `preferences.json`; see [Check for upgrades](#check-for-upgrades). CLI `shell-setup` reads `unproxyrc`, so use explicit environment variables if your desktop listener differs.

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
| `--allow-insecure-proxy-auth ENDPOINT` | Allow netrc credentials on the exact plaintext `http://HOST:PORT` or `socks5://HOST:PORT` endpoint; repeatable. | None |
| `--negotiate [HOST]` / `-n` | Integrated authentication; optionally restrict hosts, repeatable. | Off; requires Negotiate build |
| `--release-info-url URL` | Custom JSON release metadata endpoint for `check-upgrade`. | GitHub Releases |

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
| `unproxy check-upgrade` | Check GitHub Releases for a newer version. |
| `unproxy --version` | Installed version. |
| `-v`, `-vv` | Debug and trace verbosity. |
| `-q`, `-qq` | Reduce or disable logging. |
| `--logfile PATH` | Append diagnostic logs; rotate at 10 MiB and keep three backups. |
| `unproxy shell-setup SHELL` | Print proxy variables and completion setup. |
| `paceval PAC_SOURCE URL` | Inspect a PAC decision for a destination. |
| `unproxyctl --help` | Service control commands for your platform. |
| `undns --help` | DNS utility options, including upstream proxy support. |

## Check for upgrades

Run `unproxy check-upgrade` to compare the installed version with the latest
GitHub release. On Windows and macOS, choose **Check for Updates** from the tray
or menu-bar menu. If an update is available, the desktop app opens its release
page.

To use a custom release metadata endpoint, set `--release-info-url` in the CLI
settings file or pass it before the command:

```sh
unproxy --release-info-url https://updates.example.org/unproxy.json check-upgrade
```

Desktop apps read the expert-only `releaseInfoUrl` setting from
`preferences.json` (Windows: `%LOCALAPPDATA%\Unproxy\preferences.json`; macOS:
`~/Library/Application Support/Unproxy/preferences.json`). Set it to a URL to
use custom metadata, or remove it or set it to `null` to use GitHub Releases.
Restart Unproxy after editing the file. For example:

```json
{
  "releaseInfoUrl": "https://updates.example.org/unproxy.json"
}
```

The endpoint must return JSON in this shape:

```json
{
  "version": "0.5.0",
  "url": "https://downloads.example.org/unproxy/0.5.0",
  "notes": "Optional release summary"
}
```

`version` is a semantic version and may start with `v`. `url` is the page the
desktop app opens when a newer version is found. `notes` is optional. The CLI
prints the available version and URL without opening a browser.

## Listener access and privacy

Proxy requests and the sanitized status page do not require client authentication. The public status response reports PAC source type and route protocol without source paths, PAC hosts, or upstream proxy addresses. The access log page and stream, application log page and stream, and PAC route resolver require the owner capability. A missing or incorrect token denies them even for a loopback client with a trusted `Host` header.

For a foreground runtime and its tray app, create a 32-byte random token in the owner’s process environment before starting them. On macOS or Linux:

```sh
export UNPROXY_MANAGEMENT_TOKEN="$(openssl rand -hex 32)"
```

In PowerShell:

```powershell
$bytes = New-Object byte[] 32
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$env:UNPROXY_MANAGEMENT_TOKEN = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
```

The tray’s **Open Status Page** opens the sanitized page. Opening a log viewer prompts the browser for Basic authentication: use username `unproxy` and the token as the password. Programmatic clients can send it as a Bearer token. The browser keeps HTTP Basic credentials in its origin-scoped auth cache; Unproxy never puts the token in a URL, cookie, process argument, or log.

Windows service setup creates a random token file readable only by NetworkService, SYSTEM, Administrators, and the installing user; the service config refers to it with `--management-token-file`. The tray gets an owner-only copy in that user’s support directory. Repair preserves the token only when the installing-user SID matches the recorded owner; changing the owner rotates it. For a manually managed service, provide a protected token file and grant access only to the service account and intended owner. Without a token, the tray continues to show sanitized status while detailed management endpoints remain closed.

Logs can reveal destinations, network details, and errors. Review and redact them before sharing a support report.
