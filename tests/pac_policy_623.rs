use unproxy::pac::Pac;

#[test]
fn is_in_net_rejects_ipv6_dns_results() {
    let mut pac = Pac::new(Some(
        "function FindProxyForURL(){ return isInNet('::1','0.0.0.0','0.0.0.0') ? 'PROXY bad:1' : 'DIRECT'; }",
    ))
    .unwrap();
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}
