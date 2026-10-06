# Corporate authentication integration tests

`tests/corporate_auth.rs` contains opt-in tests for the native GSSAPI (Unix) and
SSPI (Windows) adapters. They run the native adapter against a proxy that
accepts Kerberos Negotiate, check rejection without credentials and when the
proxy host is excluded, then verify HTTP forwarding and CONNECT. A separate case
creates and drops several native contexts and requires a nonempty first SPNEGO
token. Fixture configuration is mandatory: a missing value fails the test.

## Disposable Linux Kerberos realm

On Ubuntu 24.04, run:

```sh
sudo apt-get install krb5-kdc krb5-admin-server krb5-user squid
sudo systemctl stop squid.service
bash scripts/test_corporate_auth.sh
```

The script creates a temporary `UNPROXY.TEST` realm, client and `HTTP/localhost`
principals, keytabs, ticket cache, a Squid proxy, and an HTTP origin. All runtime
files are under a temporary directory and removed on exit. It starts isolated
listeners on loopback ports 61088, 61880, and 63128. Stop any package-managed
Squid service first because Squid instances share a system-wide shared-memory
name; CI does this on its ephemeral runner. It verifies that the client can
obtain a service ticket before running the ignored integration tests. The test command
can be replaced by appending a command to the script, for example:

```sh
bash scripts/test_corporate_auth.sh cargo test --locked --test corporate_auth -- --ignored --test-threads=1
```

CI runs this fixture on every push and pull request using an ephemeral runner.

## Windows SSPI with a domain identity

GitHub-hosted Windows runners do not have a corporate Kerberos identity. The
`windows-sspi` workflow job therefore runs only when manually dispatched on
`main` with `windows_sspi` enabled, and requires a protected self-hosted runner
labelled `self-hosted`, `Windows`, and `unproxy-auth`. Configure the runner to
run as a dedicated, low-privilege domain test account. Do not use a developer's
or production service account.

Provide these repository or `corporate-auth` environment variables:

| Variable | Value |
| --- | --- |
| `UNPROXY_AUTH_PROXY_HOST` | Proxy DNS name with a registered `HTTP/<name>` SPN |
| `UNPROXY_AUTH_PROXY_PORT` | HTTP listener port for Negotiate authentication |
| `UNPROXY_AUTH_ORIGIN_HOST` | Origin host reachable through that proxy |
| `UNPROXY_AUTH_ORIGIN_PORT` | Origin HTTP listener port |
| `UNPROXY_AUTH_EXPECTED_BODY` | Exact body returned by `GET /identity.txt` |

The proxy must require Kerberos Negotiate for the origin, reject anonymous
requests, and return the configured body only to authenticated requests. Its
service identity must own the HTTP SPN and have access to the matching keytab.
Keep the proxy and origin restricted to the test network. The workflow checks
that the runner is domain-authenticated and can obtain a service ticket for the
proxy before running the tests. Because the proxy allows Kerberos authentication
only, the successful requests also verify that SSPI selected Kerberos rather
than falling back to NTLM.

Run the exact Windows test command locally from the configured domain account:

```powershell
$env:UNPROXY_AUTH_BACKEND = 'sspi'
cargo test --locked --test corporate_auth -- --ignored --test-threads=1
```
