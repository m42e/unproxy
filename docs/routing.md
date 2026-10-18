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

A PAC script defines `FindProxyForURL(url, host)` and returns routes such as `PROXY proxy.example.org:8080` or `DIRECT`. Use trusted PAC sources supplied by your organization.

With no explicit `--pac-file`, the CLI looks for a default `proxy.pac` in its [configuration locations](configuration.md#cli-settings-file). Without a loaded policy, normal mode permits direct routing.

## Combine sources in order

Repeat the option to compose policies:

```sh
unproxy --pac-file /path/to/local-overrides.pac --pac-file https://proxy.example.org/company.pac
```

Sources run from first to last. A result containing a proxy route is used; an all-`DIRECT` result lets the next source run. If every source returns only `DIRECT`, the request connects directly. In particular, `DIRECT` in an earlier file does not force a bypass of later policies.

Within the selected PAC result, routes describe available connection attempts. A PAC-provided `DIRECT` route already permits a direct attempt. The separate `--direct-fallback` option adds a direct attempt after selected proxy routes fail; it is off by default.

> Enable **DIRECT fallback** only if your organization allows traffic to bypass the upstream proxy. It is a connection behavior preference, not a way to repair authentication.

## Check a routing decision

Use the packaged `paceval` tool with a PAC path or URL and destination:

```sh
paceval /path/to/company.pac https://example.com/
```

```sh
paceval https://proxy.example.org/company.pac https://intranet.example.org/
```

If it is not on PATH, use the full path to the executable. This inspects the routing decision; it does not prove the selected upstream is reachable or that credentials work.

## PAC parsing and matching performance

Local release-mode microbenchmarks on macOS ARM64 measured these medians:

| Workload | Median |
| --- | ---: |
| 96 substring checks | 13.28 µs per evaluation (138 ns per check) |
| 96 warm wildcard checks | 36.33 µs per evaluation (378 ns per check) |
| 96 substring and cold wildcard pairs | 103.06 µs per evaluation (1.07 µs per pair) |
| Repeated route-result cache hit, parser only | 50 ns |

The matching measurements include JavaScript execution and route parsing. The parser-only measurement is for a repeated route result that hits the cache. These synthetic timings exclude network and connection time, vary by PAC script and hardware, and do not represent full request latency.

## Reload a policy

Restart Unproxy after editing local PAC contents or to fetch an updated remote script. On Linux, the installed user service also supports:

```sh
systemctl --user reload unproxy
```

For the CLI, enable automatic reload after changes to the default-route local address:

```sh
unproxy --pac-file https://proxy.example.org/company.pac --reload-pac-on-network-change
```

This option is off by default and works on Windows, macOS, and Linux. Changes are coalesced for one second. Failed reloads retain the current policy. ETags allow remote sources to respond with `304 Not Modified` when unchanged. Route changes that keep the selected local address may not be detected.

## Require a loaded policy

Normal mode permits direct routing before a policy loads. PAC evaluation errors fail the request. If requests must wait for a loaded routing policy, use:

```sh
unproxy --strict-policy --pac-file https://proxy.example.org/company.pac
```

Strict mode rejects requests until a policy loads and rejects PAC evaluation errors. It still honors `DIRECT` returned by a valid PAC script. It does not turn a policy that permits direct connections into a proxy-only policy.

## Use a SOCKS upstream

Applications continue using Unproxy’s **HTTP** listener. Your PAC script can select a SOCKS upstream:

```javascript
function FindProxyForURL(url, host) {
    return "SOCKS5 proxy.example.org:1080; DIRECT";
}
```

`SOCKS5` supports IPv6 destinations and optional username/password authentication through [netrc](authentication.md). Enable Negotiate for SOCKS5 GSSAPI with system credentials; it requests integrity and confidentiality protection.

`SOCKS`, `SOCKS4`, and `SOCKS4A` select SOCKS4a with an empty user ID. Destination hostnames are resolved by the upstream. Both families support HTTP requests and HTTPS CONNECT tunnels; UDP ASSOCIATE and BIND are unsupported.

The `undns` utility also accepts `--proxy socks5://proxy.example.org:1080`. Schemes `socks://`, `socks4://`, and `socks4a://` select SOCKS4a. The default SOCKS port is 1080.

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

Lists are loaded at startup. Restart to load changes. The combined list size limit is 64 MiB. Check logs for failed sources; do not assume every configured list loaded successfully. Leaving desktop filter sources empty turns blocking off.
