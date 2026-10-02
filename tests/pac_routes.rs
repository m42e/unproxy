use unproxy::route::{Endpoint, Route, Routes};
use std::str::FromStr;

#[test]
fn proxy_directives_require_separators_and_trim_outer_whitespace() {
    assert_eq!(Route::from_str("  DIRECT \t").unwrap(), Route::Direct);
    assert_eq!(
        Route::from_str(" HTTPS\t [2001:db8::1]:8443 ").unwrap().to_string(),
        "HTTPS [2001:db8::1]:8443"
    );
    for malformed in [
        "PROXYexample.org:3128",
        "HTTPexample.org:3128",
        "HTTPSexample.org:3128",
        "PROXY",
        "HTTPS host.example",
        "SOCKS host.example:1080",
    ] {
        assert!(Route::from_str(malformed).is_err(), "{malformed}");
    }
    assert_eq!(
        Routes::from_str("PROXY proxy.example:3128; HTTPS [::1]:8443").unwrap().to_string(),
        "HTTP proxy.example:3128; HTTPS [::1]:8443"
    );
}

#[test]
fn endpoint_accepts_only_well_formed_bracketed_ipv6() {
    let endpoint = Endpoint::from_str("  [2001:db8::5]:8080 \t").unwrap();
    assert_eq!(endpoint.host, "2001:db8::5");
    assert_eq!(endpoint.port, 8080);
    assert_eq!(endpoint.authority(), "[2001:db8::5]:8080");
    for malformed in [
        "2001:db8::5:8080",
        "[2001:db8::5]8080",
        "[2001:db8::5]:",
        "[not-v6]:8080",
        "[::1]:80 extra",
        "host name:80",
    ] {
        assert!(Endpoint::from_str(malformed).is_err(), "{malformed}");
    }
}
