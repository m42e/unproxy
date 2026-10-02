use unproxy::{
    pac::Pac,
    route::{Endpoint, Route, Routes},
};
use std::str::FromStr;

#[test]
fn endpoint_and_pac_directives_are_strict_and_normalized() {
    assert_eq!(
        "[2001:db8::1]:8443"
            .parse::<Endpoint>()
            .unwrap()
            .to_string(),
        "[2001:db8::1]:8443"
    );
    assert!("2001:db8::1:80".parse::<Endpoint>().is_err());
    let routes = Routes::from_str("PROXY proxy.test:80; HTTPS [::1]:443; DIRECT;").unwrap();
    assert_eq!(
        routes.to_string(),
        "HTTP proxy.test:80; HTTPS [::1]:443; DIRECT"
    );
    assert!(Routes::from_str("DIRECT; SOCKS host:1").is_err());
    assert!(Routes::from_str(" ; ").is_err());
    assert_eq!(
        "PROXY proxy.test:8080"
            .parse::<Route>()
            .unwrap()
            .to_string(),
        "HTTP proxy.test:8080"
    );
}

#[test]
fn pac_state_helpers_and_ip_survive_script_replacement() {
    let mut pac = Pac::new(Some("let n=0; function FindProxyForURL(u,h){ n++; return (n===1 && dnsDomainIs(h,'.test') && isInNet('192.168.1.9','192.168.1.0','255.255.255.0')) ? 'PROXY p.test:8080' : 'DIRECT'; }" )).unwrap();
    assert_eq!(
        pac.evaluate("http://a.test/", "a.test")
            .unwrap()
            .to_string(),
        "HTTP p.test:8080"
    );
    assert_eq!(
        pac.evaluate("http://a.test/", "a.test")
            .unwrap()
            .to_string(),
        "DIRECT"
    );
    pac.set_ip("::1".parse().unwrap());
    pac.set_script(Some("function FindProxyForURL(){ return myIpAddress()==='::1' ? 'DIRECT' : 'HTTPS proxy:443'; }" )).unwrap();
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn domain_table_uses_union_label_suffixes() {
    let mut p=Pac::new(Some("const t=new DomainTable([' example.org. ', 'sub.example.org']); function FindProxyForURL(){return t.contains('x.sub.example.org') && !t.contains('notexample.org') ? 'DIRECT':'BAD';}" )).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn pac_helper_surface_covers_globs_masks_ranges_and_dns_cache_hook() {
    let src = r#"
      function FindProxyForURL(){
        const d=new Date(), wd=['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getDay()];
        const day=d.getDate(), month=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getMonth()];
        return shExpMatch('proxy7.corp','proxy[0-9].*') && dnsDomainLevels('a.b.c')===2 &&
          isPlainHostName('node') && localHostOrDomainIs('foo','foo.example') &&
          isValidIpAddress('001.2.3.255') && !isValidIpAddress('256.2.3.4') &&
          convert_addr('192.168.1.2')===-1062731518 &&
          isInNet('192.168.1.9','192.168.1.0','255.255.255.0') &&
          weekdayRange(wd) && dateRange(day) && dateRange(month) &&
          timeRange(d.getHours()) && timeRange()===false &&
          typeof _dnsCache==='object' && new DomainTable(['example.org','sub.example.org']).contains('x.sub.example.org')
          ? 'DIRECT' : 'PROXY fail.invalid:1';
      }
    "#;
    let mut p = Pac::new(Some(src)).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
    let mut bad = Pac::new(Some(
        "function FindProxyForURL(){ shExpMatch('x', '['); return 'DIRECT'; }",
    ))
    .unwrap();
    assert!(bad.evaluate("x", "x").is_err());
    let mut wrong = Pac::new(Some("function FindProxyForURL(){ return 4; }")).unwrap();
    assert!(wrong.evaluate("x", "x").is_err());
}

#[test]
fn ip_update_preserves_javascript_state_and_dns_cache() {
    let mut p=Pac::new(Some("let n=0; function FindProxyForURL(){n++; return n===1 ? 'DIRECT' : myIpAddress()==='::1' ? 'HTTPS p.test:443' : 'PROXY p.test:80';}" )).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
    p.set_ip("::1".parse().unwrap());
    assert_eq!(
        p.evaluate("x", "x").unwrap().to_string(),
        "HTTPS p.test:443"
    );
}
