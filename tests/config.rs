use clap::Parser;
use unproxy::config::{MainArgs, token_file};
use std::fs;
#[test]
fn defaults_and_listener_validation() {
    let a = MainArgs::try_parse_from(["unproxy"]).unwrap();
    assert_eq!(a.listen_addrs().unwrap()[0].to_string(), "127.0.0.1:3128");
    let a = MainArgs::try_parse_from(["unproxy", "-L", "[::1]:3128"]).unwrap();
    assert_eq!(a.listen_addrs().unwrap()[0].to_string(), "[::1]:3128");
    let a = MainArgs::try_parse_from(["unproxy", "-L", "0.0.0.0:80"]).unwrap();
    assert!(a.listen_addrs().is_err())
}
#[test]
fn settings_are_whitespace_tokens() {
    let p = std::env::temp_dir().join("unproxyrc-test");
    fs::write(
        &p,
        "# comment\n --listen 127.0.0.1:4567  \n\n--direct-fallback\n",
    )
    .unwrap();
    assert_eq!(
        token_file(&p),
        vec!["--listen", "127.0.0.1:4567", "--direct-fallback"]
    );
    let _ = fs::remove_file(p);
}

#[test]
fn my_ip_address_accepts_both_families_and_rejects_invalid_values() {
    for ip in ["192.0.2.7", "2001:db8::7"] {
        let args = MainArgs::try_parse_from(["unproxy", "--my-ip-address", ip]).unwrap();
        assert_eq!(args.my_ip_address, Some(ip.parse().unwrap()));
    }
    assert!(MainArgs::try_parse_from(["unproxy", "--my-ip-address", "not-an-ip"]).is_err());
}
