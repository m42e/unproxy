# Your apps. Your network. Connected.

Unproxy runs on your computer and gives your applications one local proxy address. It applies your organization’s PAC rules and authenticates to upstream proxies for you.

> **The address to remember:** `127.0.0.1:3128`. Use it for both HTTP and HTTPS proxy settings. Unproxy also listens on IPv6 loopback at `[::1]:3128` by default.

## 1. Install and start Unproxy

Download a package from [GitHub Releases](https://github.com/m42e/unproxy/releases), then follow the [installation guide](installation.md) for your platform.

| Platform | Start here |
| --- | --- |
| Windows | Extract the ZIP and run `install.ps1` in PowerShell. The tray app starts near the clock. |
| macOS | Open the `*-app.pkg` installer, then open **Unproxy** from Applications. Look for its menu bar icon. |
| Debian / Ubuntu | Install the `.deb`, then run `systemctl --user enable --now unproxy`. |
| Terminal | Run `unproxy` and keep the terminal open. Press Ctrl+C to stop. |

## 2. Add your organization’s PAC file

A PAC file is a small script that decides which proxy to use for each destination, or whether to connect directly. Your network administrator can give you its path or URL.

On Windows or macOS, open **Settings…** from the Unproxy icon and add the PAC file or URL. Windows applies changes when you choose **Save**; macOS applies valid changes immediately. See [Desktop app](desktop.md) for the controls.

From a terminal:

```sh
unproxy --pac-file https://proxy.example.org/company.pac
```

Replace the example URL with your organization’s URL. If no PAC policy is configured or discovered, Unproxy connects directly. To require a loaded policy, see [strict policy](routing.md#require-a-loaded-policy).

## 3. Connect an application

Open your application’s proxy settings and choose a manual **HTTP proxy**:

| Setting | Value |
| --- | --- |
| HTTP proxy host | `127.0.0.1` |
| HTTPS proxy host | `127.0.0.1` |
| Port | `3128` |
| Proxy username / password | Leave empty; upstream credentials are configured in Unproxy. |

For an application that takes a URL, use `http://127.0.0.1:3128`. The scheme stays `http://` for HTTPS destinations too: the application uses an HTTP CONNECT tunnel for HTTPS.

Unproxy does not automatically configure every application. See [Connect applications](applications.md) for terminal setup and proxy bypass rules.

## 4. Check the connection

While Unproxy is running, choose **Open Status Page** from its tray or menu bar menu. This opens the first configured listener in your default browser, including a custom address or port. The page shows the listener, PAC policy, upstream, and authentication state. Then open a website through your configured application.

For a CLI or service instance, open the configured listener’s HTTP address; the default is `http://127.0.0.1:3128/`.

You can also test from a terminal:

```sh
curl --noproxy "" --proxy http://127.0.0.1:3128 https://example.com/
```

On Windows PowerShell, use `curl.exe` in place of `curl`. A successful request confirms that this destination works; use a company destination to check a route that needs your organization’s proxy.

If your proxy asks for credentials, follow [Authentication](authentication.md). If a request fails, start with [Troubleshooting](troubleshooting.md).

## Run a health check

If `unproxy` is on your PATH, run the built-in health check:

```sh
unproxy doctor
unproxy doctor --url https://intranet.example.org/
unproxy doctor --json
```

Doctor loads the CLI settings, evaluates PAC routes, checks TCP reachability,
and reads status from a running instance when available. Repeat `--url` to
check several destinations; `--json` produces a machine-readable report.

It checks whether local credentials can generate an authorization token without
printing or sending that token. It does not perform a new authenticated proxy
exchange; use normal application traffic to confirm that authentication works.

Doctor does not read desktop preferences automatically. See the
[OS-specific troubleshooting commands](troubleshooting.md) for installed binary
paths and examples that pass your listener and PAC settings explicitly.

## Find your next step

| I want to… | Read |
| --- | --- |
| Change listeners, PAC sources, or startup behavior | [Desktop app](desktop.md) |
| Configure a shell, browser, or developer tool | [Connect applications](applications.md) |
| Combine PAC files, use SOCKS, or block domains | [PAC & routing](routing.md) |
| Use a password or Windows / Kerberos sign-in | [Authentication](authentication.md) |
| Save CLI settings or tune timeouts | [Configuration reference](configuration.md) |
| Diagnose a failed request or find logs | [Troubleshooting](troubleshooting.md) |
