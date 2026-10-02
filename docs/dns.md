# DNS companion

```sh
dnsdetox --primary 192.0.2.53:53 --port 5353 --proxy http://127.0.0.1:3128 --secondary https://8.8.8.8/dns-query
```

--primary is required and numeric IP:port. The loopback UDP port defaults to
5353 (zero chooses an ephemeral port). --proxy overrides http_proxy, which
overrides http://127.0.0.1:3128. HTTP and HTTPS proxy URLs are accepted.
The secondary URI defaults to https://8.8.8.8/dns-query.

dnsdetoxrc discovery uses the dnsdetox product configuration directory, then
Unix /etc/dnsdetox and /usr/local/etc/dnsdetox or Windows executable-adjacent
dnsdetoxrc/dnsdetoxrc.txt. It uses the same token-only settings syntax and CLI
scalar overrides, with RUST_LOG diagnostics and no NORC switch.

Primary queries use fresh UDP sockets and independently bounded 500 ms send
and receive operations. Answered or questionless responses return byte-for-byte.
Only parsed responses with questions and no answers invoke the secondary.
Malformed responses/timeouts are logged without fallback or synthesized SERVFAIL.

Secondary POST requests carry the original DNS bytes and application/dns-message
Accept/Content-Type. A CONNECT tunnel through the configured proxy is followed
by verified TLS to an HTTPS endpoint, independently of HTTPS proxy TLS. Tunnel
and request/header phases each have 1.5-second deadlines; only HTTP 200 succeeds.
The body is collected without that header deadline. There is no answer cache,
TCP DNS, direct-secondary mode or query rewriting.
