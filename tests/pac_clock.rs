use unproxy::pac::Pac;

fn check(at: &str, expression: &str) {
    let source = format!(
        r#"
        const RealDate = Date;
        Date = class extends RealDate {{
            constructor(...args) {{ super(...(args.length ? args : ['{at}'])); }}
            static now() {{ return new RealDate('{at}').getTime(); }}
        }};
        function FindProxyForURL() {{
            if (!({expression})) throw Error('failed: ' + {quoted});
            return 'DIRECT';
        }}
    "#,
        quoted = serde_json::to_string(expression).unwrap()
    );
    let mut pac = Pac::new(Some(&source)).unwrap();
    pac.evaluate("http://example.test/", "example.test")
        .unwrap();
}

#[test]
fn frozen_clock_covers_date_forms_and_utc_boundaries() {
    let expressions = [
        "dateRange(2, 'GMT')",
        "dateRange('OCT', 'GMT')",
        "dateRange(2026, 'GMT')",
        "dateRange(2, 2, 'GMT')",
        "dateRange('OCT', 'OCT', 'GMT')",
        "dateRange(2026, 2026, 'GMT')",
        "dateRange(1, 'OCT', 2, 'OCT', 'GMT')",
        "dateRange(2, 'OCT', 'GMT') && dateRange('OCT', 2, 'GMT')",
        "dateRange(2026, 2, 'OCT', 'GMT') && dateRange('OCT', 2026, 2, 'GMT')",
        "dateRange('OCT', 2026, 'OCT', 2026, 'GMT')",
        "dateRange(2, 'OCT', 2026, 2, 'OCT', 2026, 'GMT')",
        "dateRange('DEC', 'OCT', 'GMT')",
        "!dateRange(3, 'GMT')",
        "!dateRange('NOV', 'GMT')",
        "!dateRange(2027, 'GMT')",
        "weekdayRange('FRI', 'GMT')",
        "weekdayRange('FRI', 'MON', 'GMT')",
        "!weekdayRange('SAT', 'MON', 'GMT') && !weekdayRange('SUN', 'MON', 'GMT')",
        "!weekdayRange('SAT', 'GMT')",
        "!weekdayRange('invalid', 'GMT')",
        "dateRange() === false && weekdayRange() === false && timeRange() === false",
    ];
    for expression in expressions {
        check("2026-10-02T23:59:59.900Z", expression);
    }
}

#[test]
fn clock_ranges_include_last_second_and_wrap_only_clock_forms() {
    for expression in [
        "timeRange(23, 'GMT')",
        "timeRange(23, 23, 'GMT')",
        "timeRange(23, 1, 'GMT')",
        "timeRange(23, 59, 23, 59, 'GMT')",
        "timeRange(23, 0, 1, 0, 'GMT')",
        "timeRange(23, 59, 59, 23, 59, 59, 'GMT')",
        "timeRange(23, 0, 0, 1, 0, 0, 'GMT')",
        "!timeRange(0, 22, 'GMT')",
        "timeRange(23, 1, 'GMT')",
        "!timeRange(0, 0, 22, 59, 'GMT')",
    ] {
        check("2026-10-02T23:59:59.900Z", expression);
    }
    check("2026-10-02T23:00:00.000Z", "timeRange(23, 2, 'GMT')");
    check("2026-10-02T12:00:00.000Z", "!timeRange(23, 2, 'GMT')");
    check("2026-10-03T02:00:00.000Z", "timeRange(23, 2, 'GMT')");
    check(
        "2026-10-03T00:00:00.000Z",
        "timeRange(23, 0, 1, 0, 'GMT') && weekdayRange('SAT','GMT') && dateRange(3,'GMT')",
    );
}

#[test]
fn invalid_helpers_throw_and_domains_obey_label_boundaries_and_case() {
    for expression in [
        "(()=>{try {new DomainTable(); return false} catch(e) {return e instanceof TypeError}})()",
        "(()=>{try {new DomainTable(['example.org']).contains(); return false} catch(e) {return e instanceof TypeError}})()",
        "(()=>{try {dnsResolve(); return false} catch(e) {return e instanceof TypeError}})()",
        "(()=>{try {timeRange(1,2,3); return false} catch(e) {return true}})()",
        "(()=>{try {shExpMatch('x','[z-a]'); return false} catch(e) {return true}})()",
        "new DomainTable([' .example.org.\t','sub.example.org']).contains(' .other.example.org.\t')",
        "!new DomainTable(['example.org']).contains('EXAMPLE.org')",
        "!new DomainTable(['example.org']).contains('notexample.org')",
        "shExpMatch('proxy9', 'proxy[0-9]') && shExpMatch('a', '[!b]') && !shExpMatch('b', '[!b]')",
        "isValidIpAddress('001.002.003.255') && !isValidIpAddress('1.2.3.256')",
        "isInNet('192.168.2.3','192.168.0.0','255.255.0.0') && !isInNet('192.169.2.3','192.168.0.0','255.255.0.0')",
    ] {
        check("2026-10-02T12:00:00Z", expression);
    }
}

#[test]
fn reversed_weekday_and_hour_pairs_match_only_their_endpoints() {
    let weekdays = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
    for gmt in [false, true] {
        for day in 0..7 {
            let date_expr = if gmt {
                format!("new RealDate(Date.UTC(2026, 9, {}))", 4 + day)
            } else {
                format!("new RealDate(2026, 9, {})", 4 + day)
            };
            let expected_day = if gmt { "getUTCDay" } else { "getDay" };
            let expression = format!(
                "(()=>{{const d={date_expr}; Date=class extends RealDate{{constructor(...a){{super(...(a.length?a:[d]))}} static now(){{return d.getTime()}}}}; const v=new Date().{expected_day}(); const w={weekdays:?}; for(let x=0;x<7;x++)for(let y=0;y<7;y++){{const ordered=x<=y, expect=ordered?(v>=x&&v<=y):(v===x||v===y), got=weekdayRange(w[x],w[y]{gmt_arg}); if(got!==expect)throw Error(x+','+y)}} return true}})()",
                gmt_arg = if gmt { ", 'GMT'" } else { "" },
            );
            check("2026-10-04T12:00:00Z", &expression);
        }
        for hour in 0..24 {
            let instant = if gmt {
                format!("new RealDate(Date.UTC(2026, 9, 2, {hour}))")
            } else {
                format!("new RealDate(2026, 9, 2, {hour})")
            };
            let getter = if gmt { "getUTCHours" } else { "getHours" };
            let expression = format!(
                "(()=>{{const d={instant}; Date=class extends RealDate{{constructor(...a){{super(...(a.length?a:[d]))}} static now(){{return d.getTime()}}}}; const v=new Date().{getter}(); for(let x=0;x<24;x++)for(let y=0;y<24;y++){{const expect=x<=y?(v>=x&&v<=y):(v===x||v===y), got=timeRange(x,y{gmt_arg}); if(got!==expect)throw Error(x+','+y)}} return true}})()",
                gmt_arg = if gmt { ", 'GMT'" } else { "" },
            );
            check("2026-10-02T12:00:00Z", &expression);
        }
    }
}

#[test]
fn exact_date_permutations_and_mismatches_work_in_local_and_gmt() {
    for gmt in [false, true] {
        let suffix = if gmt { ", 'GMT'" } else { "" };
        for good in [
            "dateRange(2, 'OCT')",
            "dateRange('OCT', 2)",
            "dateRange(2, 'OCT', 2026)",
            "dateRange(2, 2026, 'OCT')",
            "dateRange('OCT', 2, 2026)",
            "dateRange('OCT', 2026, 2)",
            "dateRange(2026, 2, 'OCT')",
            "dateRange(2026, 'OCT', 2)",
        ] {
            check("2026-10-02T12:00:00Z", &format!("{good}{suffix}"));
        }
        for bad in [
            "dateRange(3, 'OCT')",
            "dateRange('SEP', 2)",
            "dateRange(2, 'OCT', 2025)",
            "dateRange(3, 'OCT', 2026)",
            "dateRange(2, 'SEP', 2026)",
        ] {
            check("2026-10-02T12:00:00Z", &format!("!{bad}{suffix}"));
        }
    }
}
