# Compatibility and completion decisions

The specification's section 16 is the compatibility ledger. This implementation
corrects strict PAC token/endpoint validation and brackets IPv6 authorities;
retains DomainTable parent membership when child domains overlap; parses IP and
DNS CLI values; applies accepted-client keepalive; performs verified DoH endpoint
TLS inside CONNECT; uses supported app flags and forwards the stored PAC source;
attaches Windows console before parsing; rejects self-addressed forwarding loops;
and displays true elapsed seconds with three decimals.

Forced CONNECT uses origin-form targets inside the resulting ordinary-HTTP
tunnel rather than the reference's absolute form. Negative, non-finite and
overflowing durations are rejected. Date/time helper boundaries are normalized
and GMT uses UTC construction. Initial inline scripts report load failures.
PAC initialization/evaluation has a 2-second deadline, instruction budget and
100,000-iteration loop limit. Explicit script replacement resets the runtime only
after the replacement validates. Startup awaits every configured file or URL;
failed reloads preserve the active policy. Ordered sources use isolated runtimes.
Evaluation errors return 502 and publish access errors, including with direct
fallback enabled. Startup IP detection is retained for every manual/native update,
and overrides remain authoritative. Ordinary absolute-form HTTPS receives 400 and
requires CONNECT. Management routes require a loopback peer and listener Host or
an explicit embedded alias.

macOS Kerberos availability notifications deliberately switch new decisions to
DIRECT and restore the complete source list. Failed automatic restores retry on
the next available notification; duplicate successful states are ignored.

The DNS companion already used valid Rust 2024 receiver bindings. Workspace/bin
build and tests continue to cover it; no DNS packet or transport change was needed
for #632. The DNS resolver is bounded and each evaluation permits at most four
uncached lookups.

Primary DNS errors do not trigger broader fallback. Native login helper enabling
remains unconditional; no working Autostart or app system-proxy UI is claimed.
Use the standalone macOS system utility for system settings. Upstream Basic
authentication still requires credentials even for an unauthenticated proxy.
Ordinary HTTP 407 becomes 502 after the request is transmitted, with no retry.

CONNECT tasks are tracked and cancelled when bounded process drain expires;
response access records describe
establishment rather than byte totals or tunnel lifetime. Transparent routing,
HTTP/2/3 frontend, incoming TLS, TLS interception, SOCKS, response caching,
general Upgrade, upstream pooling, multi-round Negotiate, WPAD, automatic policy
refresh and durable access history remain outside the specified product.
