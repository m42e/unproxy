use unproxy::pac::Pac;

#[test]
fn failed_pac_replacement_retains_previous_policy_and_ip() {
    let mut pac = Pac::new(Some("let n=0; function FindProxyForURL(){n++; return myIpAddress()==='::1' && n===1 ? 'DIRECT' : 'PROXY old:80';}" )).unwrap();
    pac.set_ip("::1".parse().unwrap());
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
    assert!(
        pac.set_script(Some("function replacement(){ return 'DIRECT'; }"))
            .is_err()
    );
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "HTTP old:80");
}
