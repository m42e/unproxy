# Settings and PAC configuration

The main settings file is unproxyrc. The first readable file is selected;
files are not merged. User paths are Linux/BSD ~/.config/unproxy/unproxyrc
(respecting the platform configuration directory), macOS ~/Library/Application
Support/unproxy/unproxyrc, and Windows APPDATA/unproxy/unproxyrc.
Unix system fallbacks are /etc/unproxy and /usr/local/etc/unproxy; macOS
also searches /opt/unproxy/etc. Windows finally searches beside the executable
for unproxyrc and unproxyrc.txt.

Trim lines, discard blank lines and whole lines beginning with #, then split
remaining lines on ASCII whitespace. Settings contain ordinary CLI tokens.
There is no quoting, escaping, expansion or inline comment syntax. CLI tokens
follow settings tokens: later scalar values override; listener lists, Negotiate
host lists, PAC sources and verbosity counts accumulate.

```text
--listen 127.0.0.1:3128
--pac-file /etc/unproxy/proxy.pac
--connect-timeout 10
--parallel-connect 2
--direct-fallback
--strict-policy
--header-timeout 15
--idle-timeout 60
--exchange-timeout 30
--max-sessions 256
```

A nonempty UNPROXY_NORC disables only settings reading. PAC discovery still
selects the first existing regular proxy.pac in equivalent product directories.
Explicit --pac-file occurrences take precedence over discovery and append in order. Exact http:// and https:// prefixes
select remote files; other values are local paths. Remote PAC uses direct TLS,
verified platform roots, a 15-second total deadline, at most nine followed
redirects (301/302/307/308 with absolute Location), an 8 MiB limit and UTF-8.

Startup awaits retrieval and validation of every configured source before serving.
Any startup failure exits unsuccessfully. SIGHUP reloads the entire configured
source list, while SIGUSR1 installs deliberate DIRECT mode. Failed reloads log
the sources and cause, preserve all previous runtimes and keep serving.
Successful replacement resets each runtime's globals and DNS cache together.
Native helper DNS results and failures remain cached for five minutes; DNS prefers
the first IPv4 result, falling back to the first IPv6 when there is no IPv4.
IPv4 isInNet returns false for IPv6-only resolution.

--my-ip-address accepts an IPv4 or IPv6 override. Otherwise the first IPv4 address
on the default interface is detected once at startup, falling back to 127.0.0.1.
The effective address persists across HUP, USR1, source replacement and macOS
notifications. Every new runtime receives it before top-level custom code runs.

Repeat -p/--pac-file for mixed local paths (including symlinks) and HTTP/HTTPS URLs:

```text
--pac-file /etc/company/corporate.pac
--pac-file https://example.test/secondary.pac
```

Each source has independent globals, functions and DNS cache. Evaluation proceeds
in source order: DIRECT-only results fall through, and the first result containing
any proxy wins as a whole list. A list beginning with DIRECT can therefore win and
route directly. All DIRECT-only sources, or an empty collection, yield one DIRECT.
An evaluation error stops source selection. Connection failures in a selected
list do not evaluate later files. Remote sources are downloaded sequentially,
each with its own 15-second deadline and 8 MiB limit.

PAC must define FindProxyForURL(url, host), returning a semicolon list of DIRECT,
PROXY host:port, HTTP host:port or HTTPS host:port. Directive keywords are
case-sensitive; HTTP is the normalized plain-proxy spelling. Bracket IPv6
endpoints. Evaluation errors produce HTTP 502 and an access-stream error;
`--strict-policy` returns 503 while no configured policy is loaded. `paceval`
reports evaluation errors. PAC scripts are limited to 8 MiB, 100,000 iterations
per loop and two seconds for initialization and evaluation. Native PAC DNS
resolution uses one bounded worker and allows at most four uncached lookups per
evaluation. DomainTable matches case-sensitive label suffixes.

Frontend headers default to a 15-second read deadline. The 60-second idle deadline
applies to frontend and upstream HTTP I/O; it is disabled after CONNECT upgrades.
Upstream exchange/header time is capped at 30 seconds. At most 256 client
connections, including CONNECT tunnels, run at once.

Custom scripts must have a callable FindProxyForURL; missing functions,
syntax errors and top-level exceptions fail construction. A loop-limit error
leaves the runtime usable for later calls; ordinary script side effects are retained.

Thrown exceptions, non-string results and malformed route lists produce HTTP 502,
with diagnostics and an access-stream error, even with --direct-fallback. No origin
connection is attempted. For a successfully evaluated list without DIRECT,
--direct-fallback still appends DIRECT for proxy connection failover. Explicit
DIRECT and macOS automatic direct mode remain deliberate choices. paceval reports
policy errors and continues to accept one PAC file with multiple URLs.
DomainTable matches case-sensitive label suffixes.

Reversed weekday and two-hour ranges match only their two endpoints. Ordinary
inclusive ranges and four/six-argument clock ranges retain their behavior.
dateRange(day, month) and dateRange(day, month, year) match exact current date
components, including recognized permutations and a final GMT for UTC.

UNPROXY_LOG selects a valid tracing filter; otherwise INFO is the default,
with -v/-q saturating through OFF/ERROR/WARN/INFO/DEBUG/TRACE. --logfile truncates
the chosen file; creation failure falls back to stderr. It is a diagnostic log,
not a persistent access log.
