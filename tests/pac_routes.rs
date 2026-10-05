use std::str::FromStr;
use unproxy::route::{Destination, PathOrUri};
use unproxy::route::{Endpoint, Route, Routes};

#[test]
fn proxy_directives_require_separators_and_trim_outer_whitespace() {
    assert_eq!(Route::from_str("  DIRECT \t").unwrap(), Route::Direct);
    assert_eq!(
        Route::from_str(" HTTPS\t [2001:db8::1]:8443 ")
            .unwrap()
            .to_string(),
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
        Routes::from_str("PROXY proxy.example:3128; HTTPS [::1]:8443")
            .unwrap()
            .to_string(),
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
        ":80",
    ] {
        assert!(Endpoint::from_str(malformed).is_err(), "{malformed}");
    }
}

#[test]
fn rejects_mismatched_hostname_brackets_and_unicode_whitespace() {
    for endpoint in [
        "example]:80",
        "example[:80",
        "proxy\u{a0}.test:80",
        "proxy\\evil:80",
    ] {
        assert!(endpoint.parse::<Endpoint>().is_err(), "{endpoint}");
    }
}

#[test]
fn uri_destinations_keep_explicit_ports_and_apply_http_scheme_defaults() {
    for (raw, expected_port) in [
        ("http://example.org/", 80),
        ("http://example.org:8080/path", 8080),
        ("https://example.org/", 443),
        ("https://example.org:8443/path", 8443),
    ] {
        let uri = raw.parse().unwrap();
        assert_eq!(
            Destination::from_uri(&uri).unwrap().endpoint.port,
            expected_port
        );
    }
    let without_scheme = "example.org:443".parse().unwrap();
    let destination = Destination::from_uri(&without_scheme).unwrap();
    assert_eq!(destination.scheme, "https");
    assert_eq!(destination.pac_url, "https://example.org:443/");

    let without_scheme_and_https_port = "example.org:80".parse().unwrap();
    assert_eq!(
        Destination::from_uri(&without_scheme_and_https_port)
            .unwrap()
            .scheme,
        "http"
    );
    assert!(Destination::from_uri(&"http://user@example.org/path".parse().unwrap()).is_err());
    assert!(Destination::from_uri(&"http://:8080/path".parse().unwrap()).is_err());
}

#[test]
fn path_or_uri_distinguishes_local_paths_from_http_sources() {
    assert!(matches!(
        "proxy.pac".parse::<PathOrUri>().unwrap(),
        PathOrUri::Path(_)
    ));
    assert!(matches!(
        "./config/proxy.pac".parse::<PathOrUri>().unwrap(),
        PathOrUri::Path(_)
    ));
    assert!(matches!(
        "/etc/unproxy/proxy.pac".parse::<PathOrUri>().unwrap(),
        PathOrUri::Path(_)
    ));
    assert!(matches!(
        "http://example.org/proxy.pac".parse::<PathOrUri>().unwrap(),
        PathOrUri::Uri(_)
    ));
    assert!(matches!(
        "https://example.org/proxy.pac"
            .parse::<PathOrUri>()
            .unwrap(),
        PathOrUri::Uri(_)
    ));
}

#[test]
fn endpoint_and_route_formatting_preserves_host_and_route_kinds() {
    let hostname = Endpoint::from_str("proxy.example:3128").unwrap();
    assert_eq!(hostname.authority(), "proxy.example:3128");
    assert_eq!(hostname.to_string(), "proxy.example:3128");
    assert_eq!(
        Endpoint::from_str("[2001:db8::1]:8443")
            .unwrap()
            .to_string(),
        "[2001:db8::1]:8443"
    );
    assert_eq!(
        Route::from_str("HTTP proxy.example:3128")
            .unwrap()
            .to_string(),
        "HTTP proxy.example:3128"
    );
    assert_eq!(
        Route::from_str("HTTPS proxy.example:443")
            .unwrap()
            .to_string(),
        "HTTPS proxy.example:443"
    );
}

#[test]
fn endpoint_and_route_parsers_reject_invalid_boundaries() {
    for malformed in [
        "proxy.example",
        "[]:80",
        "[2001:db8::1]80",
        "proxy@example.org:80",
        "proxy/example:80",
        "proxy?query:80",
        "proxy#fragment:80",
        "proxy[bad]:80",
        "proxy]bad:80",
        "proxy:port",
        "proxy:+80",
        "proxy:65536",
    ] {
        assert!(Endpoint::from_str(malformed).is_err(), "{malformed}");
    }
    for malformed in ["", "HTTP", "HTTP proxy.example:3128 extra"] {
        assert!(Route::from_str(malformed).is_err(), "{malformed}");
    }
    for malformed in ["", " ; \t; ", "DIRECT; NOT_A_ROUTE proxy:80"] {
        assert!(Routes::from_str(malformed).is_err(), "{malformed}");
    }
}

#[test]
fn destination_and_path_or_uri_cover_authority_and_display_edges() {
    assert!(Destination::from_uri(&"/relative/path".parse().unwrap()).is_err());
    assert!(Destination::from_uri(&"ftp://example.org/resource".parse().unwrap()).is_err());
    let destination = Destination::from_uri(&"http://example.org".parse().unwrap()).unwrap();
    assert_eq!(destination.path, "/");
    assert_eq!(destination.pac_url, "http://example.org/");

    let path = PathOrUri::from_str("/etc/unproxy/proxy.pac").unwrap();
    assert_eq!(path.to_string(), "/etc/unproxy/proxy.pac");
    let uri = PathOrUri::from_str("https://example.org/policy.pac").unwrap();
    assert_eq!(uri.to_string(), "https://example.org/policy.pac");
    assert!(PathOrUri::from_str("http://[invalid").is_err());
}
