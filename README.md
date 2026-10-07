# Unproxy

Unproxy lets your applications use your organization's proxy settings through a
local proxy running on your computer.

## Install

Download the package for your operating system from the project's Releases
page, then follow [the installation steps](docs/installation.md).

On Windows, the install script also supports service installation with
install.ps1 -AsService.

## Use it

1. Start Unproxy. Windows and macOS desktop apps have a tray or menu bar
   control. On Debian or Ubuntu, run `systemctl --user enable --now unproxy`.
2. In the application you want to use, set both its HTTP and HTTPS proxy to
   `127.0.0.1`, port `3128` (or `[::1]` if it uses IPv6 loopback).
3. If your organization gave you a PAC file, select it in the desktop app or
   start Unproxy with `--pac-file /path/to/company.pac`.

See [Use Unproxy](docs/user-guide.md) for copyable setup steps, credentials, and
troubleshooting.

## Limitations

- Unproxy does not enforce a process memory limit. Memory use depends on traffic
  and the configured PAC and filter data.
- Client authentication is not available on the proxy listeners. Anyone who can
  connect to a listener can use it as a proxy.
- The status page and its JSON endpoint are served on the proxy listeners
  without authentication. If a listener is reachable remotely, remote clients
  can also read the status. Bind only to trusted networks and use firewall rules
  to restrict access when needed.

## Build from source

With Rust installed, run:

```sh
cargo build --release --locked --bins
```

Run `./target/release/unproxy` (Windows:
`target\release\unproxy.exe`) to start it from a terminal. For setup steps, see
[Install Unproxy](docs/installation.md).

## Before committing

With [pre-commit](https://pre-commit.com/) installed, run `pre-commit install`
to enable the repository's commit checks. If your environment uses a shared
Git hook dispatcher, register `pre-commit run --hook-stage pre-commit` with
that dispatcher instead. The hook checks formatting with `cargo fmt`, runs
Clippy with warnings denied, and runs the test suites with all features and
with default features disabled through `cargo xtask test`.


## Inspiration

Inspired by [proxydetox](https://github.com/kiron1/proxydetox).

MIT license. Release packages are assembled in CI from tagged versions.
