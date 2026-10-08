# Use Unproxy

## Start it

Install Unproxy for your operating system by following [Installation](installation.md).
The Windows tray app and macOS menu bar app start the proxy for you. On Debian or
Ubuntu, start the service with:

```sh
systemctl --user enable --now unproxy
```

The tray icon's four lights show the local proxy, loaded PAC policy, latest
upstream result, and authentication state. Upstream and authentication stay
unknown or unverified until a request uses an upstream proxy; those results are
treated as stale after five minutes. Hover the icon or open its menu for labels.

To run the command directly instead, open a terminal and run:

```sh
unproxy
```

By default, Unproxy listens on `127.0.0.1:3128` and `[::1]:3128`. Keep this
terminal open while you use the proxy. Press Ctrl+C to stop it.

## Connect an application

In the application's proxy settings, choose manual proxy and enter:

| Setting | Value |
| --- | --- |
| HTTP proxy | `127.0.0.1` |
| HTTPS proxy | `127.0.0.1` |
| Port | `3128` |

If the application has one proxy address and one port, use `127.0.0.1:3128`.
Applications that support IPv6 loopback can use `[::1]:3128` instead.
Leave local addresses out of the proxy with the application's bypass list. For
terminal programs, generate the proxy variables and shell completion for the
current shell:

```sh
# bash
source <(unproxy shell-setup bash)

# zsh
source <(unproxy shell-setup zsh)

# fish
unproxy shell-setup fish | source
```

In PowerShell, use:

```powershell
Invoke-Expression (unproxy shell-setup powershell | Out-String)
```

The generated proxy address uses the first listener in Unproxy's settings file,
or `127.0.0.1:3128` when no listener is configured. For Windows Command
Prompt, run `for /f "delims=" %i in ('unproxy shell-setup cmd') do @%i` to set
proxy variables in the current window. Command Prompt has no native argument
completion support.

The Windows per-user installer also persists these variables for the installing
account. Reopen existing terminals so they inherit the updated environment. On
uninstall, Unproxy restores the previous values unless you changed them after
installation.

To undo these settings in that terminal, run:

```sh
unset http_proxy https_proxy no_proxy
```

## Use your organization's proxy rules

Ask your network administrator for the PAC file or PAC URL. Start Unproxy with
it, for example:

```sh
unproxy --pac-file /path/to/company.pac
```

or:

```sh
unproxy --pac-file https://proxy.example.org/company.pac
```

To reload configured PAC sources when Unproxy detects a change to the local
address selected by the default route, add `--reload-pac-on-network-change`.
This option is off by default and works on Windows, macOS, and Linux. Changes
are coalesced for one second; failed downloads leave the current policy active.
Remote PAC URLs that provide an ETag are revalidated on reload, so an unchanged
script can return `304 Not Modified` without sending its body again. The
detector watches the selected local address, so route changes that keep that
address may not be detected.

To combine PAC files, repeat `--pac-file`; the files are evaluated from first
to last. A PAC result containing a proxy route is used, while an all-`DIRECT`
result lets evaluation continue to the next file.

On Windows, choose **Settings…** in the tray menu. Use **Add PAC File…** for a
local file or **Add PAC URL…** for an HTTP(S) PAC URL. Each source row has an
**Open** button for local files, which launches the default app, or a **View**
button for remote URLs, which displays the downloaded text. Use each row's
**Remove** and **Up**/**Down** buttons to edit the ordered list. On macOS,
choose **Settings…** from the Unproxy menu bar menu to see listeners and PAC
sources together. Select a PAC row and click **Open / View**: local files open
in their default app, and remote URLs display their downloaded text. PAC file
**+** opens a local file chooser; **Add URL…** adds a remote HTTP(S) source.
Listener **+** adds a row you can edit in place. Double-click an existing row
to change its value. In **Ad blocking lists**, choose **Add Local List…** or
**Add Remote URL…**. Remove a row to disable that source; leaving the list empty
turns ad blocking off. Save to apply the changes. On macOS, choose **Settings…**
from the Unproxy menu bar menu to see listeners, PAC sources, and ad blocking
lists together. Use **+** under Ad blocking lists to choose a local file,
**Add URL…** to add a remote HTTP(S) list, and **−** to remove a source.
Valid macOS changes, including connection behavior checkboxes, are saved and
applied immediately. Add a listener for each numeric IP address
and port; write IPv6 addresses in brackets, such as
`[::1]:3128`. Both desktop apps start with IPv4 and IPv6 loopback listeners on
port 3128.

## Block domains with filter lists

Filter lists are optional. Repeat `--filter-list` with a local hosts-format
file or an HTTP(S) URL; the format accepts Pi-hole lists with `0.0.0.0` or
`127.0.0.1` mappings, as well as plain domain-per-line lists:

```sh
unproxy --filter-list /path/to/hosts.txt --filter-list https://example.org/hosts.txt
```

Blocked domains and their subdomains receive an HTTP 403 response before any
upstream connection is opened. Lists are loaded once at startup and stored in
a hash set, so each request checks only the hostname and its parent domains.
Lists larger than 64 MiB total are rejected. Add the same `--filter-list`
options to `~/.config/unproxy/unproxyrc` to use them with the desktop app.

**Copy Proxy Address** copies the first listener. On Linux, create
`~/.config/unproxy/unproxyrc` and put this in it:

```text
--pac-file /path/to/company.pac
```

Restart Unproxy after changing settings. To check a PAC file before using it,
run:

```sh
paceval /path/to/company.pac https://example.com/
```

Use the path to your `paceval` program if it is not on your PATH. If your
administrator supplied an HTTPS PAC URL, pass that URL to `paceval` too.

## Use a SOCKS upstream proxy

PAC scripts can return `SOCKS5 proxy.example.org:1080` or
`SOCKS proxy.example.org:1080` (`SOCKS4` and `SOCKS4A` are aliases for `SOCKS`).
For example:

```javascript
function FindProxyForURL(url, host) {
    return "SOCKS5 proxy.example.org:1080; DIRECT";
}
```

SOCKS routes support HTTP requests and HTTPS CONNECT tunnels. Hostnames are
resolved by the upstream proxy; SOCKS4 uses the SOCKS4a hostname extension.
SOCKS5 also supports IPv6 destinations. SOCKS5 username/password authentication
uses the proxy host's netrc entry described below. SOCKS4 uses an empty user ID.
To use SOCKS5 GSSAPI with your system credentials, enable **Negotiate** in the
desktop app or start Unproxy with `--negotiate`; the option can take a proxy host
to limit where credentials are offered. GSSAPI requests integrity and
confidentiality protection for the SOCKS connection. Applications continue to
use Unproxy's HTTP/HTTPS proxy listener.

`undns --proxy socks5://proxy.example.org:1080` also supports SOCKS upstreams;
`socks://`, `socks4://`, and `socks4a://` select SOCKS4a. The default SOCKS port is
1080. These routes provide TCP CONNECT; UDP ASSOCIATE and BIND are unsupported.

## Sign in to an upstream proxy

If your organization gave you a username and password for its proxy, add an
entry for the proxy host to `~/.netrc`:

```text
machine proxy.example.org login YOUR_USERNAME password YOUR_PASSWORD
```

Replace the example host and credentials with the ones your administrator gave
you. On macOS or Linux, protect the file by running `chmod 600 ~/.netrc`. If you
use your computer's Kerberos or Windows domain sign-in instead, enable
**Negotiate** in the Windows tray app or macOS menu, or start the command with:

```sh
unproxy --negotiate
```

## Check that it works

With Unproxy running and your application configured, open a website. If it
doesn't load, check these in order:

1. Confirm Unproxy is running.
2. Confirm the application's proxy is `127.0.0.1:3128`.
3. If your organization requires a PAC file, confirm Unproxy is using it.
4. If the upstream proxy requires a sign-in, check your `.netrc` entry or
   enable Negotiate.

On the same computer, open `http://127.0.0.1:3128/access.html` to see recent
requests. To stop Unproxy, click its status row in the Windows tray or macOS
menu, stop the Linux service with `systemctl --user stop unproxy`, or press
Ctrl+C if you started it in a terminal.
