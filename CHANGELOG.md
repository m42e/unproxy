# Changelog

## Unreleased

- Bound PAC initialization and evaluation, resolver work, DoH bodies, proxy
  sessions and configurable header, exchange and idle deadlines. Management resources now require a loopback
  peer and trusted Host authority; HTTPS PAC redirects cannot downgrade.
- Reject ordinary absolute-form HTTPS requests; clients must use CONNECT.
  Add opt-in `--strict-policy`; compatibility defaults still use DIRECT when
  PAC loading or evaluation fails.
- Regenerate forwarded Host from the request authority and support IPv6 primary
  DNS endpoints. Boa 0.22 removes the unmaintained `paste` dependency.

## 0.13.0

Independent Rust implementation of the supplied specification, including PAC,
HTTP/CONNECT routing, authentication, management events, DNS companion, native
platform integration and build/distribution tooling. Compatibility corrections
are recorded in docs/compatibility.md.
