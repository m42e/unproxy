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
PAC initialization/evaluation has a 2-second deadline and instruction budget.
An explicit script replacement resets the runtime before script execution;
there is no last-known-good guarantee. Startup file/network loading remains
asynchronous. Default request evaluation errors still select DIRECT, while
`--strict-policy` fails closed. Ordinary absolute-form HTTPS receives 400 and
requires CONNECT. Management routes require a loopback peer and listener Host
or an explicit embedded alias.

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
