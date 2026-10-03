# Installation and client setup

Build with cargo build --release --locked --bins, or install the primary proxy
using cargo install --path . --bin unproxy --locked. Optional binaries are
paceval, undns, native controls and development utilities.

On Debian, install the generated .deb using apt install ./unproxy-VERSION-TARGET.deb.
The package installs the primary proxy and a user systemd service. On macOS,
the .pkg installs /opt/unproxy/bin, a launch agent and /etc/paths.d integration.
The separately generated app ZIP contains Unproxy.app and its child/login helper.
Windows ZIPs contain unproxy.exe and install.ps1; running that script installs
under LOCALAPPDATA and sets the current user's Run entry named Unproxy.
It does not configure Windows proxy preferences or install a Windows service.

Generic portable ZIPs contain unproxy, paceval and undns. Platform-native
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
