# Building, validation and artifacts

Rust stable with Cargo is required. Linux builds need a C compiler, pkg-config
and OpenSSL headers (Debian: build-essential pkg-config libssl-dev). Native
Negotiate dynamically loads installed GSSAPI on Unix and uses SSPI on Windows.
macOS requires the Command Line Tools and frameworks supplied by the SDK.

```sh
cargo build --locked --bins
cargo build --release --locked --no-default-features
cargo xtask check
cargo xtask docs --repository OWNER/REPOSITORY
cargo xtask package --format native
cargo xtask package --format portable
cargo xtask package --format macos
cargo xtask package --format app
```

`cargo xtask` is the repository's Rust-based task runner. Its `native` package
set builds the release binaries once and assembles the formats for the current
host: Windows produces an installer ZIP, macOS produces a portable ZIP, PKG,
and app ZIP, and Linux produces a portable ZIP and Debian package. Run it on
each operating system to create native packages; macOS PKG assembly and Debian
packages require their platform packaging tools.

Build metadata may be supplied as UNPROXY_VERSION, UNPROXY_REVISION,
UNPROXY_PLATFORM and UNPROXY_ARCH. Running identity uses embedded metadata,
without fetching anything. Package names contain version and target information.
macOS pkgbuild creates genuine .pkg files only on macOS; other hosts produce a
clearly named staging ZIP when supplied cross-built macOS binaries. Debian
assembly requires dpkg-deb and supports amd64, arm64 and i386.

For Windows GNU cross builds on Linux install a MinGW compiler, add
x86_64-pc-windows-gnu (or aarch64-pc-windows-gnullvm with its LLVM toolchain),
configure Cargo's target linker, and run cargo build --release --locked
--target x86_64-pc-windows-gnu. Native Windows builds use MSVC. TLS uses Schannel
for the Windows target and requires no cross OpenSSL installation. macOS
x86-64 and ARM64 builds require the corresponding rustup targets and Apple SDK.

xtask supports build/check/docs/package/copy/unpack/bump/release-notes/coverage.
Coverage requires cargo-llvm-cov and llvm-tools-preview and writes an HTML report.
toml-query -f FILE [-n NAME] KEY [INDEX ...] prints a nested value; strings have
no surrounding quotes. unproxy-version defaults to version=VALUE and accepts
dnsdetox or -r for raw output. Version bumping is explicit and updates manifest
and lockfile. Tagged CI releases validate, package, publish artifacts and deploy
the static site; ordinary runtime startup has none of those side effects.
