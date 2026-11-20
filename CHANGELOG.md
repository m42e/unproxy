# Changelog

## 0.5.0

- Match valid single-label filter-list entries against their exact normalized host.
- Cap `undns` at 64 concurrent DNS exchanges and drop excess datagrams when
  upstream work is saturated.
- Route `undns` primary DNS queries through the selected proxy using DNS-over-TCP
  and fail closed when that route cannot carry the query. The public
  `dns::exchange_primary` signature now requires the selected route and
  connection options; this is a source compatibility change for Rust callers.
- Require HTTPS for remote PAC files, filter lists, and update metadata; protect
  management diagnostics and prevent direct routing from bypassing PAC DNS.
- Strengthen proxy authentication and Windows service package and policy-file
  verification, and bound DNS, retry, status, and diagnostic resources.
- Expire idle CONNECT tunnels and cancel unfinished authentication relays on drop.

## Unreleased

## 0.4.7

- Fix the macOS proxy child aborting when its inherited sandbox entitlements
  include an unsupported extra permission.

## 0.4.6

- Fix the macOS sandbox permissions for the shared PAC, preferences, and log
  directory so the menu bar app can start the proxy and open PAC files.

## 0.4.5

- Add `unproxy check-upgrade` and desktop update checks, with GitHub Releases
  as the default source and support for custom release metadata.
- Improve desktop startup, settings recovery, and proxy lifecycle behavior.
- Add a separately named macOS CLI package.

## 0.4.4

- Fix the macOS menu bar icon in light mode and launch the app automatically
  after installation.

## 0.4.3

- Add a native Windows tray settings dialog and reload saved preferences when
  the proxy restarts.
- Keep the proxy available when a remote PAC source is unavailable at startup,
  retrying the load in the background.
- Include the request URL in PAC evaluation errors.
- Strip ANSI escape sequences from persisted log files.
- Include the OS-specific installation guide in release packages and clarify
  Windows `RemoteSigned` installation and PAC performance measurements.

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
