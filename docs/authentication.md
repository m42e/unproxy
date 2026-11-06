# Authentication

Unproxy supplies credentials to the upstream proxy. Your applications connect to the local listener without a proxy username or password.

## Choose your sign-in method

| Your organization uses… | Configure |
| --- | --- |
| A proxy username and password | A `.netrc` entry for the upstream proxy host. |
| Windows domain or Kerberos sign-in | Negotiate in desktop Settings or `--negotiate` on the CLI. |
| No proxy authentication | No credentials are needed. |

Ask your administrator which method and proxy hostname to use. Your website account and upstream proxy account may be different.

## Username and password

Create `.netrc` in your home directory (`~/.netrc` on macOS/Linux; `%USERPROFILE%\.netrc` on Windows):

```text
machine proxy.example.org login YOUR_USERNAME password YOUR_PASSWORD
```

Replace the hostname with the **upstream proxy host**, without a scheme or port. Replace the placeholders with your credentials. Protect the file because it contains a plaintext password. On macOS or Linux:

```sh
chmod 600 ~/.netrc
```

Restart Unproxy after changing credentials. To use a different file with the CLI:

```sh
unproxy --netrc-file /path/to/credentials.netrc --pac-file /path/to/company.pac
```

Netrc supplies Basic authentication for HTTP upstream proxies and username/password authentication for SOCKS5.

## Integrated sign-in with Negotiate

Enable **Negotiate** in desktop Settings, or run:

```sh
unproxy --negotiate --pac-file /path/to/company.pac
```

Negotiate must be included in your build. On Windows it uses the process’s Windows credentials; on macOS and Linux it needs working system Kerberos/GSSAPI credentials. If your organization requires a ticket, obtain it using your organization’s sign-in process before testing.

For the CLI, restrict where integrated credentials are offered by specifying proxy hosts. Repeat the option for multiple hosts:

```sh
unproxy --negotiate proxy.example.org --negotiate backup.example.org --pac-file /path/to/company.pac
```

An explicit `--netrc-file` cannot be combined with `--negotiate`. SOCKS5 GSSAPI is also supported when Negotiate is enabled; see [SOCKS upstreams](routing.md#use-a-socks-upstream).

## Windows service identity

The standard Windows tray app runs as the signed-in user. The optional Windows service runs as **NetworkService**, so domain Negotiate uses the computer account. A successful desktop sign-in does not prove that the service’s account can authenticate.

If a different service identity is required, configure it in Windows Services and grant that account Modify access to `C:\ProgramData\Unproxy`. See [Windows service installation](installation.md#windows-service).

## Confirm authentication

Make a request to a destination whose PAC route uses an authenticated upstream proxy. Choose **Open Status Page** from the tray or menu bar menu, then follow **Live access log** on the status page. For a CLI or service, open your listener’s HTTP address (default `http://127.0.0.1:3128/`).

An unknown or unverified authentication light can simply mean no upstream authentication has occurred yet. If authentication is rejected, check the proxy hostname, credentials, Kerberos ticket, and the account running Unproxy. See [Troubleshooting](troubleshooting.md).
