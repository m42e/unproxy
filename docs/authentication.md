# Upstream authentication

The CLI defaults to Basic/netrc. A machine entry matching the upstream host
exactly wins over a default entry. A login is required; missing password is
empty. The default file is the user's .netrc. A readable malformed file is a
startup error; an unreadable default gives an empty store. Explicit paths must
be existing files. Credentials are sent preemptively; an empty Basic store
cannot connect to an otherwise unauthenticated upstream.

```text
machine proxy.example.org login user password secret
default login fallback password fallback-secret
```

Client Proxy-Authorization is discarded. Origin Authorization remains an
end-to-end header. CONNECT credentials appear only in the proxy handshake,
never inside the tunnel. Library callers can select AuthFactory::default()
for no authentication or replace a shared CredentialStore atomically.

--negotiate uses the native current login/ticket identity with SPNEGO and the
HTTP service. Unix GSSAPI targets HTTP@hostname; Windows SSPI targets HTTP/hostname.
No password prompt or ticket acquisition is implemented. Repeating --negotiate
with hosts creates an exact host allowlist; excluded hosts use no authentication.
The option conflicts with --netrc-file and is absent in feature-disabled builds.
One preemptive token step has a two-second deadline and runs away from async
socket processing. Multi-round 407 authentication is outside the HTTP integration.
