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
terminal programs, set these variables in the same terminal before launching the
program:

```sh
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export no_proxy=localhost,127.0.0.1,::1
```

In Windows PowerShell, use:

```powershell
$env:http_proxy = 'http://127.0.0.1:3128'
$env:https_proxy = 'http://127.0.0.1:3128'
$env:no_proxy = 'localhost,127.0.0.1,::1'
```

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

On Windows, put the PAC file at `%LOCALAPPDATA%\Unproxy\proxy.pac` and use the
tray app's PAC setting. On macOS, choose **Edit PAC File…** from the Unproxy
menu bar menu. On Linux, create `~/.config/unproxy/unproxyrc` and put this in it:

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
requests. To stop Unproxy, use **Stop** in the Windows tray or macOS menu, stop
the Linux service with `systemctl --user stop unproxy`, or press Ctrl+C if you
started it in a terminal.
