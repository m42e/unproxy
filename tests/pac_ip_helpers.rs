use unproxy::pac::Pac;

fn check(expression: &str) {
    let source = format!(
        "function FindProxyForURL() {{ if (!({expression})) throw Error('failed: ' + {quoted}); return 'DIRECT'; }}",
        quoted = serde_json::to_string(expression).unwrap()
    );
    let mut pac = Pac::new(Some(&source)).unwrap();
    pac.evaluate("http://example.test/", "example.test")
        .unwrap();
}

#[test]
fn ipv4_validator_matches_the_previous_ecmascript_regex_behavior() {
    let source = r#"
      function legacyIsValidIpAddress(s) { return typeof s==='string' && /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(x=>+x<=255); }
      function FindProxyForURL() {
        const values = [
          '1.2.3.4', '001.002.003.255', '', '1.2.3', '1.2.3.4.5',
          '256.2.3.4', '-1.2.3.4', '1.2.3.a', '1.2.3.4\n',
          '1.2.3.4\r', '1.2.3.4\r\n', '1.2.3.4\u2028', '1.2.3.4\u2029',
          '1.2.3.4\n\n', '1.2.3.4.5.6.7.8.9.0.1.2.3.4.5',
          ' 1.2.3.4', '1.2.3.4 ', '１.2.3.4', null, new String('1.2.3.4')
        ];
        return values.every(s => legacyIsValidIpAddress(s) === isValidIpAddress(s)) ? 'DIRECT' : 'PROXY fail.invalid:1';
      }
    "#;
    let mut pac = Pac::new(Some(source)).unwrap();
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn ipv4_helpers_preserve_validation_and_signed_conversion() {
    for expression in [
        "isValidIpAddress('0.0.0.0') && isValidIpAddress('001.002.003.255')",
        "!isValidIpAddress('') && !isValidIpAddress('1.2.3') && !isValidIpAddress('1.2.3.4.5')",
        "!isValidIpAddress('256.2.3.4') && !isValidIpAddress('-1.2.3.4') && !isValidIpAddress('1.2.3.a')",
        "!isValidIpAddress(new String('1.2.3.4')) && !isValidIpAddress(null)",
        "convert_addr('192.168.1.2') === -1062731518 && convert_addr('255.255.255.255') === -1",
        "convert_addr('001.002.003.004') === 16909060 && convert_addr('999.2.3.4') === 0",
    ] {
        check(expression);
    }
}

#[test]
fn is_in_net_handles_numeric_and_dns_resolved_addresses() {
    for expression in [
        "isInNet('192.168.2.3','192.168.0.0','255.255.0.0')",
        "!isInNet('192.169.2.3','192.168.0.0','255.255.0.0')",
        "isInNet('001.002.003.004','1.2.3.0','255.255.255.0')",
        "(()=>{ dnsResolve = () => '10.4.5.6'; return isInNet('proxy.test','10.4.0.0','255.255.0.0'); })()",
        "(()=>{ dnsResolve = () => null; return !isInNet('unresolved.test','10.4.0.0','255.255.0.0'); })()",
        "!isInNet('192.168.1.1','not-an-ip','255.255.255.0')",
        "!isInNet('192.168.1.1','192.168.1.0','not-an-ip')",
    ] {
        check(expression);
    }
}

#[test]
fn ip_helpers_respect_overridden_global_helpers() {
    check(
        "(()=>{ const host = { toString(){ convert_addr = () => 7; return '127.0.0.1'; } }; return isInNet(host,'10.0.0.0','255.255.255.0'); })()",
    );
    check(
        "(()=>{ dnsResolve = () => { convert_addr = () => 7; return '192.168.1.1'; }; return isInNet('host.test','10.0.0.0','255.255.255.0'); })()",
    );

    check(
        "(()=>{ isValidIpAddress = () => true; return isValidIpAddress('x') && convert_addr('x') === 0; })()",
    );
    check(
        "(()=>{ isValidIpAddress = () => true; convert_addr = () => 7; return convert_addr('x') === 7 && isInNet('x','y','z'); })()",
    );
}
