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
