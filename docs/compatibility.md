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
The open-PR addendum is also implemented: custom
entry functions are validated, loops are bounded per loop, ordered sources have
isolated runtimes, startup awaits all configured policies and complete candidate
sets replace active policy transactionally. PAC evaluation errors return 502 and
publish access errors, including with direct fallback enabled. Startup IP detection
is retained for every manual/native update, and overrides remain authoritative.
macOS Kerberos availability notifications deliberately switch new decisions to
DIRECT and restore the complete source list. Failed automatic restores retry on
the next available notification; duplicate successful states are ignored.

The DNS companion already used valid Rust 2024 receiver bindings. Workspace/bin
build and tests continue to cover it; no DNS packet or transport change was needed
for #632. Loop limits do not provide a wall-clock evaluation deadline.

Primary DNS errors do not trigger broader fallback. Native login helper enabling
remains unconditional; no working Autostart or app system-proxy UI is claimed.
Use the standalone macOS system utility for system settings. Upstream Basic
authentication still requires credentials even for an unauthenticated proxy.
Ordinary HTTP 407 becomes 502 after the request is transmitted, with no retry.

CONNECT tasks are bounded by process shutdown; response access records describe
establishment rather than byte totals or tunnel lifetime. Transparent routing,
HTTP/2/3 frontend, incoming TLS, TLS interception, SOCKS, response caching,
general Upgrade, upstream pooling, multi-round Negotiate, WPAD, automatic policy
refresh and durable access history remain outside the specified product.
