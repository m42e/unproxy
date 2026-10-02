# Reusable Rust interfaces

The library can be used without settings discovery or command-line parsing.
Pac is a synchronous JavaScript environment. Policy offers asynchronous
operations backed by one serialized worker; cloned handles share script state.
Script replacement and DNS work occur on that worker, independently of async
socket processing. PAC update/evaluation errors return through Result.

```rust
use unproxy::{pac::Policy, net::ConnectionOptions, proxy::ContextBuilder};
use std::sync::Arc;

// API connection timeout defaults to 30 seconds and authentication to None.
let policy = Arc::new(Policy::new(None)?);
let server = ContextBuilder::new(policy.clone(), ConnectionOptions::default())
    .listen("127.0.0.1:0".parse()?)
    .bind().await?;
policy.set_script(Some("function FindProxyForURL(u,h){return 'DIRECT'}".into())).await?;
policy.set_ip("::1".parse()?).await?;
let records = server.subscribe();
server.shutdown();
server.wait().await;
```

Routes preserve order and repeats; Endpoint parses/displays bracketed IPv6,
Destination normalizes URI/PAC input, and PathOrUri distinguishes exact HTTP(S)
prefixes from filesystem paths. ConnectionOptions accepts a custom native TLS
connector, AuthFactory and outbound keepalive settings. The `connection::Connection` service supports TCP, proxy TLS, CONNECT and direct
destination TLS, implements asynchronous read/write, and retains route identity.
Its HTTP sender applies upstream credentials only on a forward-proxy transport.
`access::AccessEntry` provides typed timestamps, outcomes, real elapsed seconds
and safe event formatting; `Context::publish_access` publishes these entries.
Absolute-form HTTPS requests receive HTTP 400; clients must use CONNECT for
end-to-end TLS. `ContextBuilder` exposes `header_timeout`, `idle_timeout`,
`exchange_timeout`, `max_sessions`, `strict_policy`, and
`trusted_management_host` for deadline, capacity, routing and management-alias
configuration.

CredentialStore supports atomic replacement and hostname enumeration. Native
NegotiateContext exposes token stepping separately from the one-token HTTP path.
Metered streams and bidirectional relay expose byte counters, and remote PAC
retrieval operates directly without consulting proxy policy or environment.
The server supports application-owned listeners/streams, peer-aware sessions,
live bounded event subscriptions and programmatic shutdown/completion. `wait`
observes the lifecycle and does not initiate shutdown; `wait_timeout` requests
shutdown and cancels outstanding CONNECT relays after its grace period.

For a source or embedding application, create/replace the policy explicitly,
configure `ContextBuilder::inline_pac` or `pac_source`, or use the live context
load/reload/clear methods. Source loading occurs asynchronously after binding.
`serve_stream` and `serve_connections` support application-owned transports. DNS wire parsing and exchange APIs similarly operate independently of
the companion CLI. See cargo doc --no-deps for signatures and examples.
