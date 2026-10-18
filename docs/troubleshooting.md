# Troubleshooting

Start with the local listener, then check the PAC decision and the selected upstream. This makes it easier to tell application setup problems from network or authentication failures.

## Check these first

1. Confirm Unproxy is running in the tray, menu bar, terminal, or service manager.
2. Choose **Open Status Page** from the tray or menu bar menu. For a CLI or service, open your listener’s HTTP address (default `http://127.0.0.1:3128/`).
3. Confirm your application uses `127.0.0.1:3128` as an **HTTP** proxy for both HTTP and HTTPS destinations.
4. Make an explicit test request from a terminal:

   ```sh
   curl --noproxy "" --proxy http://127.0.0.1:3128 https://example.com/
   ```

5. Repeat with the destination that fails. Use `curl.exe` in Windows PowerShell.

If the explicit test works but your app fails, inspect the app’s proxy settings, bypass rules, and inherited environment variables.

## Find status and logs

Choose **Open Status Page** from the tray or menu bar menu to open the current listener in your default browser. Use the links on that page to reach the live access log, diagnostic log, and status JSON.

For a CLI or service, use the following paths at your configured listener’s HTTP address. For example, with the default listener, `/access.html` becomes `http://127.0.0.1:3128/access.html`.

| Path | Use it for |
| --- | --- |
| `/` | Policy, upstream, and authentication summary. |
| `/access.html` | Recent requests and their results. |
| `/log.html` | Runtime messages. |
| `/status.json` | Machine-readable runtime state. |

Desktop users can also choose **Open Log**. File locations are listed in [Configuration reference](configuration.md#desktop-files). On Linux:

```sh
systemctl --user status unproxy
journalctl --user -u unproxy -n 100 --no-pager
```

For a CLI diagnostic run, stop the existing instance first, then start with extra verbosity:

```sh
unproxy -v --pac-file /path/to/company.pac
```

## The local status page does not open

Check that Unproxy is started and that the browser is using the configured listener address. If you changed the port, update the URL and the application proxy settings.

An “address already in use” message usually means another Unproxy instance or another process owns that listener. Stop the conflicting instance or choose another port. A Windows service, tray app, and terminal process cannot all bind the same address and port.

## Public sites work but company sites fail

Confirm you are connected to the required company network or VPN. Check that the configured PAC file or URL is correct and that the status page reports a loaded policy.

Inspect a routing decision:

```sh
paceval /path/to/company.pac https://intranet.example.org/
```

Check whether the selected upstream hostname is reachable on your current network. If a remote PAC download fails, inspect the diagnostic log. After fixing connectivity, restart Unproxy or reload the Linux user service.

## Authentication is rejected or unverified

An unverified light is expected until a request uses an upstream that performs authentication. Results become stale after five minutes.

For password authentication, confirm `.netrc` names the **proxy host**, and that the username and password are current. Restart after editing credentials. For Negotiate, check that the feature is available, the option is enabled, and system sign-in or Kerberos credentials are valid.

A Windows service normally uses NetworkService and the computer’s domain identity. The tray app uses your signed-in account. See [Authentication](authentication.md).

## A request returns an error

| Symptom | What to check |
| --- | --- |
| HTTP 403 for a domain | Check whether a filter list blocks that domain or a parent. An upstream can also return 403; inspect logs to locate the source. |
| HTTP 503, policy has not loaded | Strict policy is waiting for a successful PAC load. Fix the PAC source or download failure. |
| HTTP 502 or connection failure | Inspect the access and diagnostic logs for PAC evaluation, upstream connection, DNS, TLS, or authentication errors. |
| Slow or timed-out request | Check VPN and upstream reachability before adjusting [timeouts](configuration.md#timeouts-and-capacity). |

Avoid enabling DIRECT fallback as a general fix: it can allow traffic to bypass the corporate proxy. Use it only when permitted by your network policy.

## Changes do not take effect

Windows desktop settings apply after **Save**. macOS saves valid changes immediately. A running proxy restarts when connection settings change.

For CLI or service options, edit the [correct settings file](configuration.md#cli-settings-file), then restart. PAC and filter contents are loaded into memory; editing a file alone does not guarantee the active data changes. Restart to refresh both, or use PAC reload for policy changes.

Terminal proxy variables are inherited when a process starts. Open a new terminal after the Windows installer sets variables. `shell-setup` uses CLI settings rather than desktop preferences.

## Stop using or remove Unproxy

Clear the application’s proxy settings or [remove shell variables](applications.md#stop-using-proxy-variables) before stopping the proxy. Otherwise, applications can keep sending traffic to a listener that is no longer running.

Stop through the desktop status row, Ctrl+C in the terminal, or:

```sh
systemctl --user stop unproxy
```

For removal instructions, see [Uninstall](installation.md#remove-unproxy).

## Prepare a useful support report

Include your operating system, Unproxy version, desktop/CLI/service mode, the failing destination, expected PAC route, and the relevant error message. State whether the explicit curl test succeeds and whether the problem changes on or off the VPN.

Review logs and configuration before sharing. Remove passwords, tokens, sensitive URLs, and internal hostnames where necessary. Never include your `.netrc` password file.
