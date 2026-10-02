# Unproxy in Rust

A local HTTP/1 proxy that evaluates a PAC policy, selects direct or HTTP/HTTPS
upstream connections, and supplies Basic/netrc or native Negotiate credentials.
The repository implements [SPECIFICATION.md](SPECIFICATION.md) independently.

```sh
cargo build --locked --bins
UNPROXY_NORC=1 cargo run --bin unproxy -- --listen 127.0.0.1:3128
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export no_proxy=127.0.0.1,localhost,::1
```

Repeat `--pac-file FILE_OR_URL` for ordered, independent PAC policies. All sources
load and validate before serving; reload failures retain the previous policy.
No policy means DIRECT. PAC evaluation failures return 502, including with direct
fallback enabled. macOS Kerberos SSO availability notifications switch the running
daemon between policy and deliberate direct mode; see [platforms](docs/platforms.md).
Basic/netrc is the command-line default; unauthenticated upstream routes can use
the library's no-auth factory. Add `--negotiate` to use the current native identity.

```sh
cargo run --bin paceval -- assets/proxy.pac https://example.org/
cargo run --bin dnsdetox -- --primary 192.0.2.53:53
cargo run --bin xtask -- check
cargo run --bin xtask -- docs --repository OWNER/REPOSITORY
cargo run --bin xtask -- package --format portable
```

Runtime APIs are public modules in `src/lib.rs`. See `docs/` for installation,
settings, authentication, services, platform integration, building, API usage,
compatibility corrections, and validation. `xtask docs` produces a static book and
landing page in `dist/site`; its CLI reference comes from executable help with
settings reading disabled. Native packages contain the primary proxy and native
integration; generic portable archives also contain paceval and dnsdetox.

Negotiate is enabled by default and dynamically uses native GSSAPI or SSPI.
`cargo build --no-default-features` removes its CLI and adapter. Linux native TLS
requires OpenSSL development libraries at build time. macOS uses Security.framework
and Windows uses Schannel. Native service, security and desktop integration tests
require their respective operating systems and, where applicable, a configured
identity; see `docs/validation.md`.

MIT license. Release tooling assembles artifacts locally; publishing is confined
to the explicit tagged CI release workflow.
