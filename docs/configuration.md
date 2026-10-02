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
host lists and verbosity counts accumulate.

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
An explicit --pac-file takes precedence. Exact http:// and https:// prefixes
select remote files; other values are local paths. Remote PAC uses direct TLS,
verified platform roots, a 15-second total deadline, at most nine followed
redirects (301/302/307/308 with absolute Location), an 8 MiB limit and UTF-8.

Startup loading is asynchronous: by default DIRECT can serve before the PAC is loaded;
startup failures are logged. `--strict-policy` returns 503 until a configured PAC
loads and 502 after evaluation errors. A failed replacement leaves strict mode
unavailable. SIGHUP reloads the configured source, while SIGUSR1
restores DIRECT. Both refresh myIpAddress from the default IPv4 interface.
Explicit reload failure is fatal. Script replacement resets globals and DNS
cache. Native helper DNS results and failures remain cached for five minutes.

PAC must define FindProxyForURL(url, host), returning a semicolon list of DIRECT,
PROXY host:port, HTTP host:port or HTTPS host:port. Directive keywords are
case-sensitive; HTTP is the normalized plain-proxy spelling. Bracket IPv6
endpoints. Invalid policy evaluation falls back to DIRECT in the server;
paceval reports an error. `--strict-policy` closes that compatibility fallback.
PAC scripts are limited to 8 MiB and two seconds for initialization and evaluation;
native PAC DNS resolution has one bounded worker and at most four uncached lookups
per evaluation. DomainTable matches case-sensitive label suffixes.

Frontend headers default to a 15-second read deadline. The 60-second idle deadline
applies to frontend and upstream HTTP I/O; it is disabled after CONNECT upgrades.
Upstream exchange/header time is capped at 30 seconds. At most 256 client
connections, including CONNECT tunnels, run at once.

UNPROXY_LOG selects a valid tracing filter; otherwise INFO is the default,
with -v/-q saturating through OFF/ERROR/WARN/INFO/DEBUG/TRACE. --logfile truncates
the chosen file; creation failure falls back to stderr. It is a diagnostic log,
not a persistent access log.
