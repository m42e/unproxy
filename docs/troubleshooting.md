# Troubleshooting

Start with the local listener, then check the PAC decision and the selected upstream. This makes it easier to tell application setup problems from network or authentication failures.

## Check these first

1. Confirm Unproxy is running in the tray, menu bar, terminal, or service manager.
2. Choose **Open Status Page** from the tray or menu bar menu. For a CLI or service, open your listener’s HTTP address (default `http://127.0.0.1:3128/`).
3. Confirm your application uses `127.0.0.1:3128` as an **HTTP** proxy for both HTTP and HTTPS destinations.
4. Follow the commands for your operating system below. In the HTML guide, the tabs select your OS automatically; choose another tab to switch.
5. Repeat the request with the destination that fails. If the explicit test works but your app fails, inspect the app’s proxy settings, bypass rules, and inherited environment variables.

The examples use the default listener. Replace `http://127.0.0.1:3128` with your configured proxy address, and replace PAC paths with the file or URL you actually use. Stop the existing proxy before starting a CLI diagnostic instance on the same listener.

The built-in **doctor** health check can run while Unproxy is running. It loads CLI settings, evaluates PAC routes, probes TCP reachability, checks local credential readiness without printing or sending authorization tokens, and reads runtime status when available. It does not perform a new authenticated upstream exchange.

Doctor does not automatically read desktop preferences. For desktop diagnostics, pass the same listener, ordered PAC sources, and authentication options you use in Settings. The desktop examples below assume the default local PAC file and IPv4 listener. Place server options such as `--listen` and `--pac-file` **before** `doctor`; put doctor options such as `--url` and `--json` after it. Repeat `--url` to check several destinations. Reports use PASS, WARN, and FAIL; a failed check makes the command exit with status 1, while warnings alone do not.

## Windows

Use **PowerShell** for these commands. Choose **Open Status Page** or **Open Log** from the tray menu to inspect the running desktop instance.

### Run the health check in PowerShell

For the standard per-user tray installation, using its default listener and PAC path:

```powershell
& "$env:LOCALAPPDATA\Unproxy\bin\unproxy.exe" --listen 127.0.0.1:3128 --pac-file "$env:LOCALAPPDATA\Unproxy\proxy.pac" doctor --url https://intranet.example.org/
```

Add `--json` after `doctor` for a machine-readable report. Adjust the listener, PAC sources, and authentication options to match your desktop settings.

### Test a request in PowerShell

Use `curl.exe` explicitly so Windows PowerShell does not interpret `curl` as its `Invoke-WebRequest` alias. This command overrides inherited bypass rules for non-local destinations:

```powershell
curl.exe --noproxy localhost --proxy http://127.0.0.1:3128 https://example.com/
```

### Read the desktop log

```powershell
Get-Content "$env:LOCALAPPDATA\Unproxy\unproxy.log" -Tail 100
```

### Run desktop diagnostics from the terminal

Stop the proxy through its tray status row first. For the standard per-user installation:

```powershell
& "$env:LOCALAPPDATA\Unproxy\bin\unproxy.exe" -v --pac-file "$env:LOCALAPPDATA\Unproxy\proxy.pac"
```

Press Ctrl+C to end the diagnostic run, then start the proxy again from the tray menu.

### Check an optional Windows service

These commands apply to a service installed with `install.ps1 -AsService`, which runs without the tray app:

```powershell
& "$env:ProgramFiles\Unproxy\unproxyctl.exe" status
Get-Content "$env:ProgramData\Unproxy\unproxy.log" -Tail 100
```

To check a service using the default listener and ProgramData PAC file:

```powershell
& "$env:ProgramFiles\Unproxy\unproxy.exe" --listen 127.0.0.1:3128 --pac-file "$env:ProgramData\Unproxy\proxy.pac" doctor --url https://intranet.example.org/
```

Pass any additional routing and authentication options from the service's ProgramData `unproxyrc` explicitly. Doctor runs with your current user's credentials, so its credential readiness check can differ from the service's NetworkService identity; the report also shows the running instance's last recorded authentication result.

To restart or stop that service, open PowerShell as administrator and run the appropriate command:

```powershell
& "$env:ProgramFiles\Unproxy\unproxyctl.exe" restart
```

```powershell
& "$env:ProgramFiles\Unproxy\unproxyctl.exe" stop
```

## macOS

Use **Terminal** with Zsh or Bash for these commands. Choose **Open Status Page** or **Open Log** from the Unproxy menu bar menu to inspect the running desktop instance.

### Run the health check in Terminal

For the menu bar app installed in Applications, using its default listener and PAC path:

```sh
/Applications/Unproxy.app/Contents/MacOS/unproxy --listen 127.0.0.1:3128 --pac-file "$HOME/Library/Application Support/Unproxy/proxy.pac" doctor --url https://intranet.example.org/
```

Add `--json` after `doctor` for a machine-readable report. Adjust the listener, PAC sources, and authentication options to match your desktop settings.

### Test a request in Terminal

```sh
curl --noproxy "" --proxy http://127.0.0.1:3128 https://example.com/
```

### Read the menu bar app log

```sh
tail -n 100 "$HOME/Library/Application Support/Unproxy/unproxy.log"
```

### Run menu bar app diagnostics from the terminal

Stop the proxy through its menu bar status row first. For the app installed in Applications:

```sh
/Applications/Unproxy.app/Contents/MacOS/unproxy -v --pac-file "$HOME/Library/Application Support/Unproxy/proxy.pac"
```

Press Ctrl+C to end the diagnostic run, then start the proxy again from the menu bar menu. To stop the desktop proxy during everyday use, click its status row; to exit the app, choose **Quit Unproxy**.

## Debian or Ubuntu

Use a terminal for these commands. The Debian package installs a systemd **user** service; run `systemctl --user` as your normal user.

### Run the health check

Doctor reads the same CLI settings file as the installed user service:

```sh
unproxy doctor
unproxy doctor --url https://intranet.example.org/
unproxy doctor --json
```

Pass any options used only on a manually started CLI instance before `doctor` so it checks the same configuration.

### Test a request from the terminal

```sh
curl --noproxy "" --proxy http://127.0.0.1:3128 https://example.com/
```

### Check the service and its log

```sh
systemctl --user status unproxy
journalctl --user -u unproxy -n 100 --no-pager
```

### Run CLI diagnostics

Stop the user service first, then start a diagnostic instance with your PAC source:

```sh
systemctl --user stop unproxy
unproxy -v --pac-file /path/to/company.pac
```

Press Ctrl+C to finish, then restore the user service:

```sh
systemctl --user start unproxy
```

If you installed the standalone CLI instead, stop that instance with Ctrl+C before starting diagnostics.

### Inspect a PAC decision

```sh
paceval /path/to/company.pac https://intranet.example.org/
```

This checks the routing decision, not upstream connectivity or authentication.

### Reload, restart, or stop the service

Reload PAC contents without changing CLI options:

```sh
systemctl --user reload unproxy
```

After changing CLI options in `unproxyrc`, restart:

```sh
systemctl --user restart unproxy
```

To stop the user service:

```sh
systemctl --user stop unproxy
```

## Find status and logs

On Windows or macOS, choose **Open Status Page** from the tray or menu bar menu to open the current listener in your default browser. Use the links on that page to reach the live access log, diagnostic log, and status JSON.

For a CLI or service, use the following paths at your configured listener’s HTTP address. For example, with the default listener, `/access.html` becomes `http://127.0.0.1:3128/access.html`.

| Path | Use it for |
| --- | --- |
| `/` | Policy, upstream, and authentication summary. |
| `/access.html` | Recent requests and their results. |
| `/log.html` | Runtime messages. |
| `/status.json` | Machine-readable runtime state. |

File locations are listed in [Configuration reference](configuration.md#desktop-files). The OS instructions above show how to read the relevant log from a terminal.

## The local status page does not open

Check that Unproxy is started and that the browser is using the configured listener address. If you changed the port, update the URL and the application proxy settings.

An “address already in use” message usually means another Unproxy instance or another process owns that listener. Stop the conflicting instance or choose another port. A Windows service, tray app, and terminal process cannot all bind the same address and port.

## Public sites work but company sites fail

Confirm you are connected to the required company network or VPN. Check that the configured PAC file or URL is correct and that the status page reports a loaded policy.

Inspect the selected route in the access and diagnostic logs. If you have the `paceval` utility installed, you can also [check a PAC decision](routing.md#check-a-routing-decision).

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

Stop through the desktop status row or Ctrl+C in the terminal. For a service, use the stop command in your selected OS instructions above.

For removal instructions, see [Uninstall](installation.md#remove-unproxy).

## Prepare a useful support report

Include your operating system, Unproxy version, desktop/CLI/service mode, the failing destination, expected PAC route, and the relevant error message. State whether the explicit curl test succeeds and whether the problem changes on or off the VPN.

Review logs and configuration before sharing. Remove passwords, tokens, sensitive URLs, and internal hostnames where necessary. Never include your `.netrc` password file.
