# Unproxy

Unproxy lets your applications use your organization's proxy settings through a
local proxy running on your computer.

## Install

Download the package for your operating system from the project's Releases
page, then follow [the installation steps](docs/installation.md).

## Use it

1. Start Unproxy. Windows and macOS desktop apps have a tray or menu bar
   control. On Debian or Ubuntu, run `systemctl --user enable --now unproxy`.
2. In the application you want to use, set both its HTTP and HTTPS proxy to
   `127.0.0.1`, port `3128`.
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

MIT license. Release packages are assembled in CI from tagged versions.
