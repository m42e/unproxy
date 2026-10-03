# Installation and client setup

Build with cargo build --release --locked --bins, or install the primary proxy
using cargo install --path . --bin unproxy --locked. Optional binaries are
paceval, dnsdetox, native controls and development utilities.

On Debian, install the generated .deb using apt install ./unproxy-VERSION-TARGET.deb.
The package installs the primary proxy and a user systemd service. On macOS,
the .pkg installs /opt/unproxy/bin, a launch agent and /etc/paths.d integration.
The separately generated app ZIP and native app installer both contain
Unproxy.app, its `unproxy` child, and the login helper. The menu extra opens port and PAC editors, saves the
CONNECT, DIRECT fallback, Negotiate, and login-start choices, and writes child
output to `~/Library/Application Support/Unproxy/unproxy.log`.

Windows ZIPs contain `unproxy.exe`, `UnproxyTray.exe`, its tray controller,
`install.ps1`, and `uninstall.ps1`. Run `install.ps1` to install under
`%LOCALAPPDATA%\Unproxy\bin`; login startup is per-user and enabled by default.
Use `install.ps1 -DisableLoginStartup` to install without it. Run
`uninstall.ps1` to stop the tray and child and remove binaries/shortcuts while
preserving preferences and logs; add `-RemoveUserData` to delete those too.
Windows settings and rotating logs are under `%LOCALAPPDATA%\Unproxy`. Neither
desktop controller changes operating-system proxy settings or installs a
Windows service.

Generic portable ZIPs contain unproxy, paceval and dnsdetox. Platform-native
installers intentionally contain the proxy and platform integrations only.

```sh
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export no_proxy=127.0.0.1,localhost,::1
```

These variables configure clients, not the main proxy's upstream policy.
Configure a browser's HTTP and HTTPS proxy at 127.0.0.1:3128 or use the generated
local PAC at http://127.0.0.1:3128/proxy.pac. The generated PAC only points to the
local listener; it does not disclose the upstream policy.
