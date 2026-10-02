use unproxy::{pac::Pac, route::{Endpoint, Route, Routes}};
use std::str::FromStr;

#[test]
fn endpoint_and_pac_directives_are_strict_and_normalized() {
    assert_eq!("[2001:db8::1]:8443".parse::<Endpoint>().unwrap().to_string(), "[2001:db8::1]:8443");
    assert!("2001:db8::1:80".parse::<Endpoint>().is_err());
    let routes = Routes::from_str("PROXY proxy.test:80; HTTPS [::1]:443; DIRECT;").unwrap();
    assert_eq!(routes.to_string(), "HTTP proxy.test:80; HTTPS [::1]:443; DIRECT");
    assert!(Routes::from_str("DIRECT; SOCKS host:1").is_err());
    assert!(Routes::from_str(" ; ").is_err());
    assert_eq!("PROXY proxy.test:8080".parse::<Route>().unwrap().to_string(), "HTTP proxy.test:8080");
}

#[test]
fn pac_state_helpers_and_ip_survive_script_replacement() {
    let mut pac = Pac::new(Some("let n=0; function FindProxyForURL(u,h){ n++; return (n===1 && dnsDomainIs(h,'.test') && isInNet('192.168.1.9','192.168.1.0','255.255.255.0')) ? 'PROXY p.test:8080' : 'DIRECT'; }" )).unwrap();
    assert_eq!(pac.evaluate("http://a.test/", "a.test").unwrap().to_string(), "HTTP p.test:8080");
    assert_eq!(pac.evaluate("http://a.test/", "a.test").unwrap().to_string(), "DIRECT");
    pac.set_ip("::1".parse().unwrap());
    pac.set_script(Some("function FindProxyForURL(){ return myIpAddress()==='::1' ? 'DIRECT' : 'HTTPS proxy:443'; }" )).unwrap();
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn domain_table_uses_union_label_suffixes() {
    let mut p=Pac::new(Some("const t=new DomainTable([' example.org. ', 'sub.example.org']); function FindProxyForURL(){return t.contains('x.sub.example.org') && !t.contains('notexample.org') ? 'DIRECT':'BAD';}" )).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}
