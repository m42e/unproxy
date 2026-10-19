# Changelog

## 0.4.2

- Improve the documentation site with platform-specific setup and removal steps,
  shell tabs, and a traffic-flow guide.
- Include PAC parsing and matching measurements in the routing guide.

## 0.4.1

- Add the Unproxy icon to the macOS app bundle and documentation.
- Publish the documentation site through GitHub Pages.

## 0.4.0

- Add `unproxy doctor` diagnostics for PAC routes, upstream connectivity,
  credential readiness, filter lists, and live runtime status.
- Add `unproxy shell-setup` to generate proxy environment settings and shell
  completions for Bash, Zsh, Fish, PowerShell, and Command Prompt.
- Expand installation, configuration, routing, authentication, desktop, and
  troubleshooting guides with platform-specific instructions, status page
  access, and tabbed removal steps.

## 0.3.1

- Improve PAC performance with cached route directives, faster IP and glob
  matching, and bounded resolver work.
- Add live PAC evaluation timings and diagnostics.
- Configure Windows proxy settings during installation and improve tray status
  and lifecycle updates; document Windows setup and macOS proxy configuration.

## 0.3.0

- Add resilient ad blocking filter lists and live diagnostics.
- Correct PAC helper matching and Windows tray proxy status, settings callbacks,
  and lifecycle updates.
- Report failed upstream proxy routes as errors instead of direct connections.

## 0.2.3

- Correct Windows tray proxy status and lifecycle updates.
- Report failed upstream proxy routes as errors instead of direct connections.
- Publish stable versioned package names with SHA-256 checksums.

## 0.2.2

- Add optional ad blocking filter lists, with runtime enforcement and desktop
  settings for managing sources.
- Support SOCKS4/4a and SOCKS5 upstream proxies, including SOCKS5 GSSAPI
  authentication.
- Improve corporate authentication reliability, bounded log rotation, and
  proxy routing coverage.

## 0.2.1

- Bound PAC initialization and evaluation, resolver work, DoH bodies, proxy
  sessions and configurable header, exchange and idle deadlines. Management resources now require a loopback
  peer and trusted Host authority; HTTPS PAC redirects cannot downgrade.
- Reject ordinary absolute-form HTTPS requests; clients must use CONNECT.
  Add opt-in `--strict-policy`; compatibility defaults still use DIRECT when
  PAC loading or evaluation fails.
- Regenerate forwarded Host from the request authority and support IPv6 primary
  DNS endpoints. Boa 0.22 removes the unmaintained `paste` dependency.

## Unreleased

## 0.13.0

Independent Rust implementation of the supplied specification, including PAC,
HTTP/CONNECT routing, authentication, management events, DNS companion, native
platform integration and build/distribution tooling. Compatibility corrections
are recorded in docs/compatibility.md.
