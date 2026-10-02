# Validation and native integration fixtures

Run cargo run --bin xtask -- check for formatting, Clippy and tests with native
authentication enabled and disabled. Tests use controlled loopback origins,
upstream proxies and UDP responders, with binary CONNECT data, hop-header and
authentication assertions, ordered/racing routes, policy failure cases and
DNS wire validation. Helper tests freeze the JavaScript Date constructor to
exercise local and GMT forms rather than depending on the test's wall clock.

CI runs Linux, macOS ARM64 and Windows builds/tests, plus cross builds for
Windows GNU, Linux ARM64/i386 and macOS x86-64. Native packages, app bundles and
the generated book/site are assembled as release artifacts. Cross-built
executables need native runtime verification before a distribution claims
platform interoperability. This checkout's test results apply to the host
on which the commands were run, not to every platform automatically.

GSSAPI and SSPI require an actual current-user identity/ticket fixture. Native
fixture tests are intentionally gated/ignored without it. On Unix obtain a
ticket with the organization's supported login method, configure an HTTP SPNEGO
test proxy and exercise --negotiate; inspect its service target and initial token.
On Windows use a domain login and a controlled Negotiate HTTP proxy. Confirm an
allowlist excludes other proxies, and verify a feature-disabled build omits -n.
No mocked success is claimed as a working native identity exchange.

On macOS, install a generated .pkg in a disposable GUI user session. Check
unproxyctl status/start/restart/stop/enable/disable, register install/uninstall,
and launchd socket activation ownership. Exercise the system-proxy utility with
an authorization fixture and inspect Ethernet/Wi-Fi protocol dictionaries;
confirm other hardware services are untouched. Run the app bundle, toggle all
three options, inspect supported child arguments and explicit PAC source, post
the documented Kerberos availability notifications, quit and verify the child
exits. Launch the login helper with the main app present and absent to validate
duplicates and its termination notification. These are native integration steps,
not ordinary unit tests that should alter the developer's system settings.

On Windows, launch a release executable from a parent console with
--attach-console --help and --version; run install.ps1 in a disposable profile
and inspect the HKCU Run entry. On Linux, test named activation using owned
descriptors 3 onward and environment errors, and inspect Debian user-unit hooks
through installation/upgrade/removal/purge in a disposable container.

The implementation was validated on macOS ARM64 with both feature modes,
strict all-target Clippy and rustfmt checks. Controlled tests cover verified TLS
to upstream HTTPS proxies, TLS to DoH inside HTTPS-proxy CONNECT, PAC download
limits, fixed clocks, streaming/half-close, live SSE and subprocess Unix signals.
Windows GNU/ARM64 and macOS Intel targets compile; Windows ARM64 also passes
strict target-specific Clippy. Portable ZIP, native macOS installer and app ZIP
were assembled locally and their payloads, versions and plist metadata inspected.
Native credential success, privileged service installation and system proxy
changes still use the integration fixtures described above. Linux runtime and
other Windows runtime checks are supplied by CI and were not executed on this
macOS host.

## Open-PR addendum validation

The addendum is covered by proposal-specific tests and combined integration tests:

| Proposals | Regression evidence |
| --- | --- |
| #620 | Typed IPv4/IPv6 CLI parsing, startup selection and HUP/USR1 override preservation in `config`, `runtime` and `lifecycle` |
| #621 | Constructor syntax/missing/non-callable entry errors and mutation after initialization in `pac_policy_621` and `pac` |
| #622 | Last-known-good runtime/globals/cache and continued daemon service in `pac_policy_622`, `policy_composition` and `lifecycle` |
| #623 | Deterministic resolver-order family selection in `pac::tests` and IPv6 subnet rejection in `pac_policy_623` |
| #624 | Strict grammar/port/bracket/whitespace cases in `pac_routes`; IPv6 HTTP and HTTPS proxy/CONNECT fixtures in `ipv6_proxy` |
| #625 | 502 plus access error and zero origin connections for thrown/wrong-type/malformed/looping PAC, with both fallback settings, in `proxy` |
| #626 | Runaway evaluation recovery and failed top-level candidate rollback in `pac_policy_626` and `policy_composition` |
| #627 | Slow remote startup, failed startup sources and awaitable supplied-stream initialization in `lifecycle`, `policy_startup` and `streams` |
| #631 | State transitions, duplicate suppression, failed-restore retry and IP/listener preservation in `network_notifications` and `network_policy`; real private-name distributed delivery in `native_notifications_main` |
| #632 | The DNS companion already uses valid edition-2024 bindings; all-target builds/tests include `dnsdetox`, plus unchanged wire/transport tests in `dns` and `tls` |
| #633 | Exhaustive reversed weekday/hour pairs and exact date permutations under controlled local/GMT clocks in `pac_clock` |
| #634 | Repeatable CLI order, mixed symlink/HTTP sources, whole-set rollback, runtime/cache isolation and top-level IP in `config`, `policy_sources` and `policy_composition` |

`native_notifications_main` is a harness-free test: it registers and pumps from
its executable's real main thread, while a separate process posts private test
names. It does not alter a running daemon's Kerberos state. Normal Rust test
harness threads cannot verify native main-run-loop delivery. The test is inert
on non-macOS targets. Corporate SSO/MDM operation and established production
tunnels still use the native integration fixtures above.

Host validation for this change passes `cargo fmt --all -- --check`, strict
all-target/all-feature Clippy, all-target tests with all features and without
default features, all binary builds, Rust API documentation and the generated
book/site. Windows GNU all-target compilation also passes. The native identity
success fixture remains gated on a real ticket cache. Loop limits bound iterations
per loop and do not promise an evaluation wall-clock deadline. No automatic PAC
polling, extra notification service, or DNS packet behavior is introduced.
