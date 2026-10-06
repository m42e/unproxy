use std::time::{Duration, Instant};
use unproxy::pac::Policy;

const SAMPLES: usize = 5;
const WARMUP: usize = 20;
const ITERATIONS: usize = 120;
const WILDCARD_COUNT: usize = 600;
const CONCURRENT_CLIENTS: usize = 16;
const CONCURRENT_BATCHES: usize = 20;

#[tokio::test]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn generated_pac_substr_and_shell_match_throughput() {
    const MATCHES: usize = 96;
    let mut script = String::from("function FindProxyForURL(url, host) {\nvar matched = false;\n");
    for index in 0..MATCHES {
        script.push_str(&format!(
            "var part{index} = url.substr({index}, 12); if (shExpMatch(part{index}, '*')) matched = true;\n"
        ));
    }
    script.push_str("return matched ? 'HTTP proxy.example:8080' : 'DIRECT';\n}");
    let policy = Policy::new(Some(script)).unwrap();
    let url = format!(
        "https://example.test/{}",
        (0..MATCHES)
            .map(|index| format!("segment{index:03}-payload/"))
            .collect::<String>()
    );
    let host = "example.test";

    let timings = measure(ITERATIONS, || async {
        let routes = policy.evaluate(url.clone(), host.to_owned()).await.unwrap();
        assert_eq!(routes.to_string(), "HTTP proxy.example:8080");
    })
    .await;
    report("96 substr/shExpMatch pairs", &timings, ITERATIONS);
}

#[tokio::test]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn varied_shell_match_patterns_over_large_working_set() {
    let script = generated_wildcard_pac(WILDCARD_COUNT, 32);
    let policy = Policy::new(Some(script)).unwrap();
    let cases = (0..WILDCARD_COUNT)
        .map(|index| {
            let offset = (index * 5) % WILDCARD_COUNT;
            let target = (offset + 31) % WILDCARD_COUNT;
            (
                format!("https://example.test/path/segment-{target:03}-tail"),
                format!("{offset:03}"),
            )
        })
        .collect::<Vec<_>>();
    let mut next = 0usize;
    let timings = measure(ITERATIONS, || {
        let (url, host) = &cases[next % cases.len()];
        next += 1;
        async {
            let routes = policy.evaluate(url.clone(), host.clone()).await.unwrap();
            assert_eq!(routes.to_string(), "HTTP wildcard.example:8080");
        }
    })
    .await;
    report(
        &format!("varied shExpMatch patterns, {WILDCARD_COUNT} pattern working set"),
        &timings,
        ITERATIONS,
    );
}

fn generated_wildcard_pac(patterns: usize, checks: usize) -> String {
    let mut script = String::from("var patterns = [");
    for index in 0..patterns {
        if index != 0 {
            script.push(',');
        }
        script.push_str(&format!("'*/segment-{index:03}-tail'"));
    }
    script.push_str(
        "]; function FindProxyForURL(url, host) {\nvar offset = parseInt(host.substr(0,3), 10);\nfor (var i=0; i<32; i++) { if (shExpMatch(url, patterns[(offset+i)%patterns.length])) return 'PROXY wildcard.example:8080'; }\nreturn 'DIRECT';\n}",
    );
    // Keep `checks` visible in the generated script so a changed workload cannot silently
    // diverge from the case description.
    script = script.replace("i<32", &format!("i<{checks}"));
    script
}

#[tokio::test]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn repeated_subnet_checks() {
    const CHECKS: usize = 48;
    let mut script = String::from("function FindProxyForURL(url, host) { var matched = false;\n");
    for index in 0..CHECKS {
        let third = index % 16;
        script.push_str(&format!(
            "if (isInNet('10.20.{third}.42','10.20.{third}.0','255.255.255.0')) matched = true;\n"
        ));
    }
    script.push_str("return matched ? 'PROXY subnet.example:8080' : 'DIRECT'; }");
    let policy = Policy::new(Some(script)).unwrap();
    let timings = measure(ITERATIONS, || async {
        let routes = policy
            .evaluate(
                "https://subnet.example/".to_owned(),
                "subnet.example".to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(routes.to_string(), "HTTP subnet.example:8080");
    })
    .await;
    report("48 isInNet checks", &timings, ITERATIONS);
}

#[tokio::test]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn repeated_route_result_parsing() {
    let policy = Policy::new(Some(
        "function FindProxyForURL(url, host) { return 'PROXY edge.example:8080; HTTPS secure.example:8443; SOCKS socks.example:1080; DIRECT'; }".to_owned(),
    ))
    .unwrap();
    let timings = measure(ITERATIONS, || async {
        let routes = policy
            .evaluate(
                "https://routes.example/".to_owned(),
                "routes.example".to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(
            routes.to_string(),
            "HTTP edge.example:8080; HTTPS secure.example:8443; SOCKS4 socks.example:1080; DIRECT"
        );
    })
    .await;
    report("four repeated route entries", &timings, ITERATIONS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn concurrent_policy_requests() {
    const BATCHES: usize = CONCURRENT_BATCHES;
    let policy = Policy::new(Some(
        "function FindProxyForURL(url, host) { return shExpMatch(host, '*.example.test') ? 'PROXY shared.example:8080' : 'DIRECT'; }".to_owned(),
    ))
    .unwrap();
    for _ in 0..WARMUP {
        for client in 0..CONCURRENT_CLIENTS {
            let routes = policy
                .clone()
                .evaluate(
                    format!("https://client{client}.example.test/"),
                    format!("client{client}.example.test"),
                )
                .await
                .unwrap();
            assert_eq!(routes.to_string(), "HTTP shared.example:8080");
        }
    }
    let mut timings = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        for _ in 0..BATCHES {
            let mut requests = tokio::task::JoinSet::new();
            for client in 0..CONCURRENT_CLIENTS {
                let policy = policy.clone();
                requests.spawn(async move {
                    let routes = policy
                        .evaluate(
                            format!("https://client{client}.example.test/"),
                            format!("client{client}.example.test"),
                        )
                        .await
                        .unwrap();
                    assert_eq!(routes.to_string(), "HTTP shared.example:8080");
                });
            }
            while let Some(result) = requests.join_next().await {
                result.unwrap();
            }
        }
        timings.push(started.elapsed());
    }
    report(
        &format!("{CONCURRENT_CLIENTS} concurrent requests per batch"),
        &timings,
        BATCHES * CONCURRENT_CLIENTS,
    );
}

async fn measure<F, Fut>(iterations: usize, mut operation: F) -> Vec<Duration>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for _ in 0..WARMUP {
        operation().await;
    }
    let mut timings = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        for _ in 0..iterations {
            operation().await;
        }
        timings.push(started.elapsed());
    }
    timings
}

fn report(label: &str, timings: &[Duration], operations: usize) {
    let total: Duration = timings.iter().sum();
    let count = operations * timings.len();
    let mean = total / count as u32;
    let mut ordered = timings.to_vec();
    ordered.sort_unstable();
    let median = ordered[ordered.len() / 2] / operations as u32;
    let min = *ordered.first().unwrap() / operations as u32;
    let max = *ordered.last().unwrap() / operations as u32;
    println!(
        "PAC performance: {label}; {count} evaluations total, min {min:.2?}, median {median:.2?}, mean {mean:.2?}, max {max:.2?} per evaluation"
    );
}
