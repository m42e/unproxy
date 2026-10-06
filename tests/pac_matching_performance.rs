use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use unproxy::{pac::Pac, route::Routes};

const SAMPLES: usize = 5;
const WARMUP: usize = 20;
const BATCH_SIZE: usize = 120;
const HELPERS: usize = 96;
const GROUPS: usize = 32;

struct Case {
    url: String,
    host: String,
    expected: String,
}

fn cases() -> Vec<Case> {
    (0..WARMUP + SAMPLES * BATCH_SIZE)
        .map(|index| {
            let host = format!("node{index:04}.group{:02}.example.test", index % GROUPS);
            Case {
                url: format!("https://{host}/path/segment{index:04}"),
                expected: format!("HTTP {host}:8080"),
                host,
            }
        })
        .collect()
}

fn substr_script() -> String {
    let mut script = String::from("function FindProxyForURL(url,host){var total=0,part;");
    for index in 0..HELPERS {
        script.push_str(&format!(
            "part=url.substr({},12);total+=part.length;",
            index % GROUPS
        ));
    }
    script.push_str(
        "if(total!==1152)throw Error('substring length mismatch');return 'PROXY '+host+':8080';}",
    );
    script
}

fn warm_glob_script() -> String {
    let patterns = (0..GROUPS)
        .flat_map(|group| {
            [
                format!("*.group{group:02}.example.test"),
                format!("node????.group{group:02}.example.test"),
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "var patterns={};function FindProxyForURL(url,host){{var hits=0,misses=0;for(var i=0;i<32;i++){{if(shExpMatch(host,patterns[2*i]))hits++;else misses++;if(shExpMatch(host,patterns[2*i+1]))hits++;else misses++;if(shExpMatch(host,'*.example.test'))hits++;else misses++;}}if(hits===0&&misses===96)return 'DIRECT';if(hits!==34||misses!==62)throw Error('glob count mismatch');return 'PROXY '+host+':8080';}}",
        serde_json::to_string(&patterns).unwrap(),
    )
}

fn cold_combined_script() -> &'static str {
    // Fill the 512-entry glob cache at initialization, outside the measurement.
    // Dynamic patterns cannot be inserted afterward, so every pair compiles one.
    "for(var seed=0;seed<512;seed++)shExpMatch('other','seed'+seed+'.test');function FindProxyForURL(url,host){var hits=0;for(var i=0;i<96;i++){var part=host.substr(0,8);if(shExpMatch(host,part+'.group??.example.test'))hits++;}if(hits===0)return 'DIRECT';if(hits!==96)throw Error('combined count mismatch');return 'PROXY '+host+':8080';}"
}

fn assert_routes(routes: &Routes, case: &Case) {
    assert_eq!(routes.to_string(), case.expected);
}

fn benchmark(label: &str, script: &str, unit: &str) {
    let mut pac = Pac::new(Some(script)).unwrap();
    let inputs = cases();
    for input in &inputs[..WARMUP] {
        assert_routes(&pac.evaluate(&input.url, &input.host).unwrap(), input);
    }
    let mut outputs = Vec::with_capacity(BATCH_SIZE);
    let mut timings = Vec::with_capacity(SAMPLES);
    for batch in inputs[WARMUP..].as_chunks::<BATCH_SIZE>().0 {
        let started = Instant::now();
        for input in batch {
            outputs.push(pac.evaluate(&input.url, &input.host).unwrap());
        }
        timings.push(started.elapsed());
        for (output, input) in outputs.iter().zip(batch) {
            assert_routes(output, input);
        }
        outputs.clear();
    }
    report(label, &timings, unit);
}

fn report(label: &str, timings: &[Duration], unit: &str) {
    let total: Duration = timings.iter().sum();
    let count = BATCH_SIZE * timings.len();
    let mean = total / count as u32;
    let mut ordered = timings.to_vec();
    ordered.sort_unstable();
    let median = ordered[ordered.len() / 2] / BATCH_SIZE as u32;
    println!(
        "PAC matching performance: {label}; {count} evaluations; median {median:.2?}, mean {mean:.2?} per evaluation; median {:.2?}, mean {:.2?} per {unit} (amortized, includes JavaScript and one route parse)",
        median / HELPERS as u32,
        mean / HELPERS as u32,
    );
}

#[test]
fn matching_workloads_use_distinct_inputs_and_return_correct_routes() {
    let inputs = cases();
    assert_eq!(
        inputs
            .iter()
            .map(|case| &case.host)
            .collect::<HashSet<_>>()
            .len(),
        inputs.len()
    );
    assert_eq!(
        inputs
            .iter()
            .map(|case| &case.url)
            .collect::<HashSet<_>>()
            .len(),
        inputs.len()
    );
    assert_eq!(
        inputs
            .iter()
            .map(|case| &case.expected)
            .collect::<HashSet<_>>()
            .len(),
        inputs.len()
    );
    for script in [
        substr_script(),
        warm_glob_script(),
        cold_combined_script().into(),
    ] {
        let mut pac = Pac::new(Some(&script)).unwrap();
        for index in [0, 31, 32, inputs.len() - 1] {
            let input = &inputs[index];
            assert_routes(&pac.evaluate(&input.url, &input.host).unwrap(), input);
        }
    }
    for script in [warm_glob_script(), cold_combined_script().into()] {
        let mut pac = Pac::new(Some(&script)).unwrap();
        assert_eq!(
            pac.evaluate("https://node0000.other.test/", "node0000.other.test")
                .unwrap()
                .to_string(),
            "DIRECT"
        );
    }
}

#[test]
#[ignore = "performance measurement; run with cargo xtask perf"]
fn substr_only_throughput() {
    benchmark(
        "96 substr calls, unique hosts and routes",
        &substr_script(),
        "substr call",
    );
}

#[test]
#[ignore = "performance measurement; run with cargo xtask perf"]
fn warm_realistic_glob_patterns() {
    benchmark(
        "96 warm glob checks, unique hosts and routes",
        &warm_glob_script(),
        "glob call",
    );
}

#[test]
#[ignore = "performance measurement; run with cargo xtask perf"]
fn substr_and_cold_glob_pattern() {
    benchmark(
        "96 substr/cold-glob pairs, unique hosts and routes",
        cold_combined_script(),
        "pair",
    );
}
