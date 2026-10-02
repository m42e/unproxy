# Security boundaries

The proxy trusts each configured PAC script to choose the route for a request.
Treat local and remote PAC sources as executable code. PAC initialization is
limited to 8 MiB and two seconds; evaluations have an execution budget and a
two-second cooperative execution deadline. These limits bound normal loops and
DNS calls; they are not a hard memory sandbox for Boa or a preemptive limit on
one expensive parser/engine operation. `dnsResolve` uses one bounded resolver worker and allows at
most four uncached lookups per evaluation. The management resources `/`,
`/proxy.pac`, `/access.html`, and `/access.log` require a loopback client and a
Host authority matching a bound listener (`localhost` is accepted) or an
explicit library alias configured with `trusted_management_host`. The event
log can contain requested URLs, so keep it on loopback and use an alias only
for a trusted reverse proxy.

The compatibility default uses DIRECT when no PAC policy exists, when initial
PAC loading fails, or when PAC evaluation fails. Use `--strict-policy` to
reject requests with 503 until a policy loads and with 502 after an evaluation
error. A failed policy replacement leaves strict routing unavailable until a
subsequent successful load. Clearing policy explicitly selects DIRECT.
Frontend and upstream HTTP streams have configurable idle deadlines; the
default is 60 seconds. CONNECT tunnels remain open under the separate
connection limit and graceful-shutdown timeout.

Absolute-form HTTPS requests receive HTTP 400 and must use CONNECT. This keeps
the proxy from sending plaintext HTTP to a destination selected as HTTPS. A
CONNECT tunnel carries opaque TLS bytes; the proxy cannot inspect or rewrite
origin HTTP headers inside that tunnel.

Remote PAC downloads bypass the proxy and proxy credentials. HTTPS redirects
must remain HTTPS; HTTP PAC sources remain available for compatibility and
should only be used on trusted networks. Upstream Basic credentials from
`.netrc` are sent to the selected upstream proxy. A plain HTTP upstream proxy
can observe those credentials and traffic metadata; use an HTTPS proxy when
the network between the client and proxy is not trusted. The `.netrc` file is
read at startup and contains reusable credentials in plaintext, so restrict
its filesystem permissions. The proxy does not automatically reload it.
