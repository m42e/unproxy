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
that dispatcher instead. The hook runs `cargo xtask check`, which checks
formatting, runs Clippy with warnings denied, and runs the test suites with all
features and with default features disabled.

MIT license. Release packages are assembled in CI from tagged versions.
