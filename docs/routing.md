# PAC & routing

Your applications send requests to Unproxy. Unproxy evaluates your PAC policy and connects directly or through the upstream proxy chosen for that destination.

## Load a local or remote PAC file

Use desktop Settings or pass a local path or HTTP(S) URL:

```sh
unproxy --pac-file /path/to/company.pac
```

```sh
unproxy --pac-file https://proxy.example.org/company.pac
```

**When to use it:** Pass `--pac-file` when this process should use a specific
organization policy instead of the discovered default. A local path suits a
PAC file installed or maintained on the machine; a URL suits a centrally
maintained policy that should be fetched from the organization’s server.

A PAC script defines `FindProxyForURL(url, host)` and returns routes such as `PROXY proxy.example.org:8080` or `DIRECT`. Use trusted PAC sources supplied by your organization.

With no explicit `--pac-file`, the CLI looks for a default `proxy.pac` in its [configuration locations](configuration.md#cli-settings-file). Without a loaded policy, normal mode permits direct routing.

## Combine sources in order

Repeat the option to compose policies:

```sh
unproxy --pac-file /path/to/local-overrides.pac --pac-file https://proxy.example.org/company.pac
```

Sources run from first to last. A result containing a proxy route is used; an all-`DIRECT` result lets the next source run. If every source returns only `DIRECT`, the request connects directly. In particular, `DIRECT` in an earlier file does not force a bypass of later policies.

**When to use multiple sources:** Put a policy first when its proxy decisions
should take priority, then add a general policy for destinations it returns as
`DIRECT`. This is useful when a specialized PAC should handle the destinations
it knows about and a broader organization policy should handle the rest.

Within the selected PAC result, routes describe available connection attempts. A PAC-provided `DIRECT` route already permits a direct attempt. The separate `--direct-fallback` option adds a direct attempt after selected proxy routes fail; it is off by default.

> Use `--direct-fallback` when maintaining access during an upstream outage is more important than requiring proxy inspection, and only if your organization allows traffic to bypass the upstream proxy. It is a connection behavior preference, not a way to repair authentication.

## Check a routing decision

Use the packaged `paceval` tool with a local PAC file and destination:

```sh
paceval /path/to/company.pac https://example.com/
```

`paceval` reads a local PAC file; it does not fetch a PAC URL. If it is not on PATH, use the full path to the executable. This inspects the routing decision; it does not prove the selected upstream is reachable or that credentials work.

**When to use it:** Run `paceval` while writing or troubleshooting a PAC file
to check which route it returns for a destination before investigating proxy
reachability or credentials.

## PAC parsing and matching performance

The documentation build runs release-mode benchmarks for route parsing, PAC
matching, and DNS resolution. The generated report below records results from
the same machine and build that produced this guide. These synthetic workloads
do not represent full request latency or proxy connection time.

<!-- PAC_PERFORMANCE_RESULTS -->

## Reload a policy

Restart Unproxy after editing local PAC contents or to fetch an updated remote script. On Linux, the installed user service also supports:

```sh
systemctl --user reload unproxy
```

For the CLI, use `--reload-pac-on-network-change` to automatically reload after changes to the default-route local address:

```sh
unproxy --pac-file https://proxy.example.org/company.pac --reload-pac-on-network-change
```

**When to use it:** Enable this on a roaming machine or service whose PAC
decisions depend on the active network or local address, such as when moving
between office Wi-Fi and a VPN. This option is off by default and works on
Windows, macOS, and Linux. Changes are coalesced for one second. Failed reloads
retain the current policy. ETags allow remote sources to respond with `304 Not
Modified` when unchanged. Route changes that keep the selected local address
may not be detected.

## Require a loaded policy

Normal mode permits direct routing before a policy loads. PAC evaluation errors fail the request. If requests must wait for a loaded routing policy, use:

```sh
unproxy --strict-policy --pac-file https://proxy.example.org/company.pac
```

Strict mode rejects requests until a policy loads and rejects PAC evaluation errors. It still honors `DIRECT` returned by a valid PAC script. It does not turn a policy that permits direct connections into a proxy-only policy.

**When to use it:** Enable `--strict-policy` when serving traffic before the
configured policy is ready, or after its evaluation fails, would violate your
network requirements. Leave it off when direct routing during startup is
acceptable. Strict mode does not override a valid PAC decision to use `DIRECT`.

## Use a SOCKS upstream

Applications continue using Unproxy’s **HTTP** listener. Your PAC script can select a SOCKS upstream:

```javascript
function FindProxyForURL(url, host) {
    return "SOCKS5 proxy.example.org:1080; DIRECT";
}
```

`SOCKS5` supports IPv6 destinations and optional username/password authentication through [netrc](authentication.md). Enable Negotiate for SOCKS5 GSSAPI with system credentials; it requests integrity and confidentiality protection.

**When to use it:** Select a SOCKS route when the upstream provided by your
organization speaks SOCKS instead of HTTP. Prefer `SOCKS5` when the upstream
supports it and you need IPv6 destinations or username/password authentication.

`SOCKS`, `SOCKS4`, and `SOCKS4A` select SOCKS4a with an empty user ID. Destination hostnames are resolved by the upstream. Both families support HTTP requests and HTTPS CONNECT tunnels; UDP ASSOCIATE and BIND are unsupported.

The `undns` utility also accepts `--proxy socks5://proxy.example.org:1080`. Schemes `socks://`, `socks4://`, and `socks4a://` select SOCKS4a. The default SOCKS port is 1080.

Use `undns --proxy` when DNS forwarding by `undns` must travel through an
upstream proxy; this option configures that utility’s upstream connection.

## Block domains with filter lists

Add sources in desktop Settings or repeat `--filter-list`:

```sh
unproxy --filter-list /path/to/hosts.txt --filter-list https://example.org/hosts.txt
```

Supported formats include plain domains and hosts-style entries:

```text
ads.example.org
0.0.0.0 tracker.example.org
127.0.0.1 unwanted.example.org
```

A listed domain and its subdomains receive HTTP 403 before any upstream connection opens. Blocking uses the hostname; it does not inspect page content or individual HTTPS URL paths.

**When to use it:** Add `--filter-list` when clients using this listener should
be denied access to selected whole domains, such as known ad or tracking
domains. It is hostname-level blocking, so it cannot block only a page path or
inspect encrypted page content.

Lists are loaded at startup. Restart to load changes. The combined list size limit is 64 MiB. Check logs for failed sources; do not assume every configured list loaded successfully. Leaving desktop filter sources empty turns blocking off.
