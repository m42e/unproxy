# Desktop app

Manage the proxy from the Windows tray or macOS menu bar. The desktop app starts and supervises the local proxy, keeps your preferences, and shows connection status.

## Everyday controls

Click the Unproxy icon to open its menu.

| Control | What it does |
| --- | --- |
| Proxy status row | Starts or stops the local proxy. |
| Open Status Page | Opens the status page in your default browser using the first configured listener’s current address and port. |
| Settings… | Opens listeners, PAC sources, ad blocking lists, and connection preferences. |
| Copy Proxy Address | Copies the first configured listener. |
| Open Log | Opens the diagnostic log. |
| Start with Login (macOS) | Controls whether Unproxy opens when you sign in. |
| Quit | Exits the desktop app and stops its proxy. |

Start only one instance for a given listener address and port. A separately started CLI or Windows service can conflict with the desktop proxy.

## Read the four status lights

The icon summarizes four separate states. Hover over it or open the menu for text labels; color alone is not required to interpret the status.

| Light | What it tells you |
| --- | --- |
| Local proxy | Whether the proxy is running, stopped, or failed. |
| PAC policy | Whether a routing policy has loaded. |
| Upstream | The outcome of the latest upstream proxy attempt. |
| Authentication | Whether authentication is configured, verified, or rejected. |

Upstream and authentication can stay unknown or unverified until a request actually uses an upstream proxy. A direct request does not verify corporate authentication. Results become stale after five minutes. Choose **Open Status Page** from the icon’s menu for more detail.

## Configure listeners

A listener is the local IP address and port your applications connect to. Defaults are `127.0.0.1:3128` and `[::1]:3128`.

Add one numeric address and port per row. Enclose IPv6 addresses in brackets. To use port 8080, for example, use `127.0.0.1:8080` and `[::1]:8080`, then update your applications to match.

On macOS, use **+** under Listeners to add a row and double-click a row to edit it. On Windows, edit the listener rows in Settings.

> **Keep listeners local unless you need network access.** There is no client authentication. Anyone who can reach a listener can use the proxy and read its status and logs. Unspecified addresses such as `0.0.0.0` and `[::]` are rejected. Use a specific interface address and firewall restrictions when sharing intentionally.

## Manage PAC sources

PAC sources are evaluated in their displayed order. A result containing a proxy route is selected; an all-`DIRECT` result continues to the next source. See [PAC & routing](routing.md).

### Windows

Use **Add PAC File…** for a local file or **Add PAC URL…** for an HTTP(S) URL. Each row has **Open** for a local file or **View** to display a remote script. Use **Up**, **Down**, and **Remove** to arrange the list. Choose **Save** to apply.

### macOS

Use **+** under PAC files for a local file or **Add URL…** for an HTTP(S) URL. Select a row and use **Open / View** to open a local file in TextEdit or display a remote script. Double-click a row to edit it; use the ordering controls to change priority. Valid changes apply immediately.

## Add ad blocking lists

In **Ad blocking lists**, add local files or remote HTTP(S) URLs. Windows uses **Add Local List…** and **Add Remote URL…**; macOS uses **+** and **Add URL…**. Remove a source to disable it. An empty list turns blocking off.

Lists support hosts-format mappings and plain domain names. A blocked domain and its subdomains receive HTTP 403. See [filter list behavior](routing.md#block-domains-with-filter-lists) for format and loading details.

## Choose connection behavior

| Preference | Effect | Normal default |
| --- | --- | --- |
| Negotiate | Uses integrated Windows or Kerberos credentials for upstream proxy authentication. Available in builds with Negotiate support. | Off |
| Always use CONNECT | Uses an upstream HTTP CONNECT tunnel for proxied HTTP requests as well as HTTPS. | Off |
| DIRECT fallback | Tries a direct connection after selected proxy routes fail. This can bypass the upstream proxy. | Off |
| Start when signing in / Start with Login | Opens Unproxy at login. | On |

Company packages can supply different first-run defaults. Existing saved preferences take precedence when updating the app.

Enable DIRECT fallback only if your network policy permits direct access. For integrated authentication requirements, see [Authentication](authentication.md).

## Save and apply changes

On **Windows**, choose **Save**. On **macOS**, valid edits and checkbox changes save and apply immediately. Changes affecting a running proxy restart it, which can interrupt active requests or tunnels. If the proxy is stopped, the new preferences are used the next time you start it.

Desktop preferences persist across app launches. Windows stores them in `%LOCALAPPDATA%\Unproxy\preferences.json`; macOS uses native application preferences. Both apps keep PAC data and `unproxy.log` in their [support folders](configuration.md#desktop-files).

Use the desktop settings window to configure the desktop app. The CLI’s `unproxyrc` file and `shell-setup` command do not read desktop preferences.
