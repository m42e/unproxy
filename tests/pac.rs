use std::str::FromStr;
use unproxy::{
    pac::{Pac, Policy},
    route::{Endpoint, Route, Routes},
};

#[test]
fn synchronous_pac_api_bounds_initialization_and_evaluation() {
    let expensive = "function work(){let n=0; for(let i=0;i<99990;i++) n++;} for(let j=0;j<99990;j++) work(); function FindProxyForURL(){return 'DIRECT';}";
    let started = std::time::Instant::now();
    assert!(Pac::new(Some(expensive)).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    let mut pac = Pac::new(Some("function FindProxyForURL(){while(true){}}")).unwrap();
    let started = std::time::Instant::now();
    assert!(
        pac.evaluate("http://example.test/", "example.test")
            .is_err()
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}

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
    assert!(Routes::from_str("").is_err());
    assert!(Routes::from_str(" ; ").is_err());
    assert!("proxy host.test:80".parse::<Route>().is_err());
    assert!("PROXY host.test:99999".parse::<Route>().is_err());
    assert_eq!(
        "PROXY proxy.test:8080"
            .parse::<Route>()
            .unwrap()
            .to_string(),
        "HTTP proxy.test:8080"
    );
    assert!("PROXYx host.test:80".parse::<Route>().is_err());
    assert!("PROXY host.test:80 extra".parse::<Route>().is_err());
    assert!("PROXY user@host.test:80".parse::<Route>().is_err());
}

#[tokio::test]
async fn policy_bounds_script_execution_and_failed_replacement_keeps_previous_policy() {
    let policy = Policy::new(None).unwrap();
    policy
        .set_script(Some(
            "function FindProxyForURL(){ return 'DIRECT'; }".into(),
        ))
        .await
        .unwrap();
    assert!(policy.is_loaded());
    policy
        .set_script(Some("function FindProxyForURL(){ while(true){} }".into()))
        .await
        .unwrap();
    let start = std::time::Instant::now();
    assert!(
        policy
            .evaluate("http://example.test/".into(), "example.test".into())
            .await
            .is_err()
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    let failed = policy.set_script(Some("while(true){}".into())).await;
    assert!(failed.is_err());
    assert!(policy.is_loaded());
    assert!(
        policy
            .evaluate("http://example.test/".into(), "example.test".into())
            .await
            .is_err()
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
fn my_ip_address_returns_valid_ipv4_or_ipv6_syntax() {
    let script = "function FindProxyForURL(){ return /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(myIpAddress()) || /^[0-9a-f:]+$/i.test(myIpAddress()) ? 'DIRECT' : 'PROXY fail.invalid:1'; }";
    for ip in ["192.0.2.7", "2001:db8::7"] {
        let mut pac = Pac::new_with_ip(Some(script), ip.parse().unwrap()).unwrap();
        assert_eq!(
            pac.evaluate("http://localhost/", "localhost")
                .unwrap()
                .to_string(),
            "DIRECT"
        );
    }
}

#[test]
fn domain_table_uses_union_label_suffixes() {
    let mut p=Pac::new(Some("const t=new DomainTable([' example.org. ', 'sub.example.org']); function FindProxyForURL(){return t.contains('x.sub.example.org') && !t.contains('notexample.org') ? 'DIRECT':'BAD';}" )).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
    let mut overlap=Pac::new(Some("const t=new DomainTable(['example.org','sub.example.org']); function FindProxyForURL(){return t.contains('a.example.org') && t.contains('x.sub.example.org') && !t.contains('badexample.org') ? 'DIRECT':'BAD';}" )).unwrap();
    assert_eq!(overlap.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn domain_table_matches_exact_domains_and_label_boundaries_only() {
    let mut pac = Pac::new(Some(
        "const t=new DomainTable(['example.org','example.net','test.org']); function FindProxyForURL(){ return t.contains('example.org') && t.contains('www.example.org') && t.contains('example.net') && t.contains('test.org') && !t.contains('example.info') && !t.contains('net') && !t.contains('org') && !t.contains('badexample.org') ? 'DIRECT' : 'PROXY fail.invalid:1'; }",
    ))
    .unwrap();
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn alert_and_default_policy_evaluate_as_direct() {
    let mut default = Pac::new(None).unwrap();
    assert_eq!(
        default
            .evaluate("http://localhost/", "localhost")
            .unwrap()
            .to_string(),
        "DIRECT"
    );

    let mut alert = Pac::new(Some(
        "function FindProxyForURL(url, host){ alert('PAC evaluated'); return 'DIRECT'; }",
    ))
    .unwrap();
    assert_eq!(
        alert
            .evaluate("http://localhost/", "localhost")
            .unwrap()
            .to_string(),
        "DIRECT"
    );
}

#[test]
fn resolvability_and_common_shell_patterns_choose_expected_routes() {
    let mut resolvable = Pac::new(Some(
        "function dnsResolve(host){ return host === 'resolved.test' ? '192.0.2.1' : null; } function FindProxyForURL(url,host){ return isResolvable(host) ? 'DIRECT' : 'PROXY proxy.test:8080'; }",
    ))
    .unwrap();
    assert_eq!(
        resolvable
            .evaluate("http://resolved.test/", "resolved.test")
            .unwrap()
            .to_string(),
        "DIRECT"
    );
    assert_eq!(
        resolvable
            .evaluate("http://unresolved.test/", "unresolved.test")
            .unwrap()
            .to_string(),
        "HTTP proxy.test:8080"
    );

    let mut globs = Pac::new(Some(
        "function FindProxyForURL(url,host){ return shExpMatch(host,'*.example.net') || shExpMatch(host,'www?') ? 'DIRECT' : 'PROXY proxy.test:8080'; }",
    ))
    .unwrap();
    for matching in ["www.example.net", "www1"] {
        assert_eq!(globs.evaluate("x", matching).unwrap().to_string(), "DIRECT");
    }
    for nonmatching in ["example.net", "www", "www12"] {
        assert_eq!(
            globs.evaluate("x", nonmatching).unwrap().to_string(),
            "HTTP proxy.test:8080"
        );
    }
}

#[test]
fn pac_helper_surface_covers_globs_masks_ranges_and_dns_cache_hook() {
    let src = r#"
      const RealDate=Date;
      Date=class extends RealDate {
        constructor(...args) { super(...(args.length ? args : ['2026-10-02T12:34:56Z'])); }
        static now() { return new RealDate('2026-10-02T12:34:56Z').getTime(); }
      };
      function FindProxyForURL(){
        const d=new Date(), wd=['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getUTCDay()];
        const day=d.getUTCDate(), month=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getUTCMonth()];
        return shExpMatch('proxy7.corp','proxy[0-9].*') && dnsDomainLevels('a.b.c')===2 &&
          isPlainHostName('node') && localHostOrDomainIs('foo','foo.example') &&
          isValidIpAddress('001.2.3.255') && !isValidIpAddress('256.2.3.4') &&
          convert_addr('192.168.1.2')===-1062731518 &&
          isInNet('192.168.1.9','192.168.1.0','255.255.255.0') &&
          weekdayRange(wd,'GMT') && dateRange(day,'GMT') && dateRange(month,'GMT') &&
          timeRange(d.getUTCHours(),'GMT') && timeRange(d.getUTCHours(),d.getUTCHours(),'GMT') &&
          timeRange(d.getUTCHours(),d.getUTCMinutes(),d.getUTCHours(),d.getUTCMinutes(),'GMT') &&
          timeRange(d.getUTCHours(),d.getUTCMinutes(),d.getUTCSeconds(),d.getUTCHours(),d.getUTCMinutes(),d.getUTCSeconds(),'GMT') &&
          timeRange()===false &&
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
    let mut wrong_helper = Pac::new(Some(
        "function FindProxyForURL(){ shExpMatch(1,'*'); return 'DIRECT'; }",
    ))
    .unwrap();
    assert!(wrong_helper.evaluate("x", "x").is_err());
    let mut wrong_domain = Pac::new(Some(
        "function FindProxyForURL(){ new DomainTable([1]); return 'DIRECT'; }",
    ))
    .unwrap();
    assert!(wrong_domain.evaluate("x", "x").is_err());
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

#[test]
fn helper_ranges_cover_valid_arity_wrap_gmt_and_empty_cases() {
    let mut p=Pac::new(Some(r#"
      function FindProxyForURL(){
        const d=new Date(), day=d.getDate(), mon=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getMonth()], year=d.getFullYear();
        const wd=['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getDay()], gday=d.getUTCDate(), gmon=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][d.getUTCMonth()], gy=d.getUTCFullYear(), gwd=['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getUTCDay()];
        return dateRange(day) && dateRange(day,day) && dateRange(mon) && dateRange(mon,mon) && dateRange(year) && dateRange(year,year) && dateRange(day,mon) && dateRange(mon,year) && dateRange(day,mon,day,mon) && dateRange(mon,year,mon,year) && dateRange(day,mon,year,day,mon,year) &&
          dateRange(gday,'GMT') && dateRange(gmon,'GMT') && dateRange(gy,'GMT') && dateRange(gday,gmon,'GMT') && dateRange(gmon,gy,'GMT') && dateRange(gday,gmon,gday,gmon,'GMT') && dateRange(gday,gmon,gy,gday,gmon,gy,'GMT') &&
          weekdayRange(wd) && weekdayRange(wd,wd) && weekdayRange(wd,wd,'GMT') && weekdayRange('bad')===false && dateRange()===false && weekdayRange()===false && timeRange()===false &&
          (function(){try{timeRange(1,2,3);return false}catch(_){return true}})() ? 'DIRECT':'PROXY fail.invalid:1';
      }
    "#)).unwrap();
    assert_eq!(p.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn script_replacement_clears_dns_cache_and_missing_functions_error() {
    let mut p = Pac::new(Some(
        "function FindProxyForURL(){ dnsResolve('nonexistent.invalid'); return 'DIRECT'; }",
    ))
    .unwrap();
    p.evaluate("x", "x").unwrap();
    assert_eq!(p.cache_snapshot().len(), 1);
    p.evaluate("x", "x").unwrap();
    assert_eq!(p.cache_snapshot().len(), 1);
    p.set_script(Some("function FindProxyForURL(){return 'DIRECT'}"))
        .unwrap();
    assert_eq!(p.cache_snapshot().len(), 0);
    for src in ["", "var FindProxyForURL=1;"] {
        assert!(Pac::new(Some(src)).is_err());
    }
    let mut q = Pac::new(Some("function FindProxyForURL(){throw new Error('no')}")).unwrap();
    assert!(q.evaluate("x", "x").is_err());
}

#[test]
fn uri_destinations_supply_defaults_and_preserve_path_query() {
    use unproxy::route::Destination;
    let uri: http::Uri = "https://[::1]/a?q=1".parse().unwrap();
    let d = Destination::from_uri(&uri).unwrap();
    assert_eq!(d.endpoint.host, "::1");
    assert_eq!(d.endpoint.port, 443);
    assert_eq!(d.path, "/a?q=1");
    assert_eq!(d.scheme, "https");
    assert!(Destination::from_uri(&"file://example.test/path".parse().unwrap()).is_err());
    let authority: http::Uri = "example.test:443".parse().unwrap();
    let c = Destination::from_uri(&authority).unwrap();
    assert_eq!(c.scheme, "https");
    assert_eq!(c.pac_url, "https://example.test:443/");
}
