use std::time::Instant;
use unproxy::pac::Policy;

const MATCHES: usize = 96;
const ITERATIONS: usize = 500;

fn generated_pac() -> String {
    let mut script = String::from("function FindProxyForURL(url, host) {\nvar matched = false;\n");
    for index in 0..MATCHES {
        // Build URL substrings at runtime so the benchmark exercises PAC string
        // operations on each request rather than constant-folded literals.
        script.push_str(&format!(
            "var part{index} = url.substr({index}, 12); if (shExpMatch(part{index}, '*')) matched = true;\n"
        ));
    }
    script.push_str("return matched ? 'HTTP proxy.example:8080' : 'DIRECT';\n}");
    script
}

#[tokio::test]
#[ignore = "performance measurement; run with cargo xtask perf"]
async fn generated_pac_substr_and_shell_match_throughput() {
    let policy = Policy::new(Some(generated_pac())).unwrap();
    let url = format!(
        "https://example.test/{}",
        (0..MATCHES)
            .map(|index| format!("segment{index:03}-payload/"))
            .collect::<String>()
    );
    let host = "example.test".to_owned();

    for _ in 0..20 {
        let routes = policy.evaluate(url.clone(), host.clone()).await.unwrap();
        assert_eq!(routes.to_string(), "HTTP proxy.example:8080");
    }

    let mut durations = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let routes = policy.evaluate(url.clone(), host.clone()).await.unwrap();
        durations.push(started.elapsed());
        assert_eq!(routes.to_string(), "HTTP proxy.example:8080");
    }
    let total: std::time::Duration = durations.iter().sum();
    let min = durations.iter().min().unwrap();
    let max = durations.iter().max().unwrap();
    let mean = total / ITERATIONS as u32;
    let mut ordered = durations.clone();
    ordered.sort_unstable();
    let median = ordered[ordered.len() / 2];
    println!(
        "PAC performance: {ITERATIONS} evaluations, {MATCHES} substr/shExpMatch pairs per evaluation; min {min:.2?}, median {median:.2?}, mean {mean:.2?}, max {max:.2?}"
    );
}
