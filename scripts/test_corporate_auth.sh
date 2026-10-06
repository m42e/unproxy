#!/usr/bin/env bash
# Disposable Linux MIT Kerberos + Squid fixture; no system config or credentials.
set -euo pipefail
if [[ $(uname -s) != Linux ]]; then
    echo 'This fixture requires Linux; see docs/corporate-auth-tests.md for Windows.' >&2
    exit 1
fi
for tool in krb5kdc kdb5_util kadmin.local kinit klist kvno squid python3; do
    command -v "$tool" >/dev/null || { echo "Missing fixture tool: $tool" >&2; exit 1; }
done
fixture=$(mktemp -d /tmp/unproxy-auth.XXXXXXXX)
pids=()
cleanup() {
    status=$?
    if (( status != 0 )); then
        for log in "$fixture/kdc.log" "$fixture/squid-output.log" "$fixture/squid.log" "$fixture/origin.log"; do
            [[ ! -f $log ]] || cat "$log" >&2
        done
    fi
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "$fixture"
    return "$status"
}
trap cleanup EXIT
export KRB5_CONFIG="$fixture/krb5.conf"
export KRB5_KDC_PROFILE="$fixture/kdc.conf"
export KRB5CCNAME="FILE:$fixture/client.ccache"
export KRB5_KTNAME="FILE:$fixture/proxy.keytab"
cat > "$KRB5_CONFIG" <<'CONFIG'
[libdefaults]
 default_realm = UNPROXY.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_canonicalize_hostname = false
 qualify_shortname = ""
 rdns = false
[realms]
 UNPROXY.TEST = {
  kdc = 127.0.0.1:61088
 }
[domain_realm]
 localhost = UNPROXY.TEST
CONFIG
cat > "$KRB5_KDC_PROFILE" <<CONFIG
[kdcdefaults]
 kdc_ports = 61088
 kdc_tcp_ports = 61088
[realms]
 UNPROXY.TEST = {
  database_name = $fixture/principal
  key_stash_file = $fixture/stash
  acl_file = $fixture/kadm5.acl
 }
CONFIG
# All keys are ephemeral and never uploaded as CI artifacts.
kdb5_util create -s -P disposable-fixture-master-key
kadmin.local -q 'addprinc -randkey alice@UNPROXY.TEST'
kadmin.local -q "ktadd -k $fixture/client.keytab alice@UNPROXY.TEST"
kadmin.local -q 'addprinc -randkey HTTP/localhost@UNPROXY.TEST'
kadmin.local -q "ktadd -k $fixture/proxy.keytab HTTP/localhost@UNPROXY.TEST"
krb5kdc -n > "$fixture/kdc.log" 2>&1 &
pids+=("$!")

cp tests/fixtures/corporate-auth/squid.conf "$fixture/squid.conf"
cat >> "$fixture/squid.conf" <<CONFIG
pid_filename $fixture/squid.pid
cache_log $fixture/squid.log
access_log none
cache_store_log none
coredump_dir $fixture
CONFIG
mkdir "$fixture/origin"
printf '%s' 'unproxy authenticated fixture' > "$fixture/origin/identity.txt"
python3 -m http.server 61880 --bind 127.0.0.1 --directory "$fixture/origin" > "$fixture/origin.log" 2>&1 &
pids+=("$!")
squid -N -f "$fixture/squid.conf" > "$fixture/squid-output.log" 2>&1 &
pids+=("$!")
# Bound readiness checks; fail on fixture setup instead of silently skipping.
if ! python3 - <<'PY'
import socket
import time
for port in (61088, 61880, 63128):
    deadline = time.monotonic() + 15
    while True:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise SystemExit(f'Fixture listener {port} did not start')
            time.sleep(0.1)
PY
then
    cat "$fixture/kdc.log" "$fixture/squid-output.log" >&2
    exit 1
fi
kinit -k -t "$fixture/client.keytab" alice@UNPROXY.TEST
klist -s
# Verify the fixture can issue the exact service ticket before invoking Rust.
kvno HTTP/localhost@UNPROXY.TEST
export UNPROXY_AUTH_BACKEND=gssapi
export UNPROXY_AUTH_PROXY_HOST=localhost
export UNPROXY_AUTH_PROXY_PORT=63128
export UNPROXY_AUTH_ORIGIN_HOST=127.0.0.1
export UNPROXY_AUTH_ORIGIN_PORT=61880
export UNPROXY_AUTH_EXPECTED_BODY='unproxy authenticated fixture'
if [[ $# == 0 ]]; then
    set -- cargo test --locked --test corporate_auth -- --ignored --test-threads=1
fi
"$@"
