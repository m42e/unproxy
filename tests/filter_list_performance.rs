use std::time::{Duration, Instant};
use unproxy::filter_list::FilterList;

const DOMAINS: usize = 100_000;
const LOOKUPS_PER_SAMPLE: usize = 100_000;
const SAMPLES: usize = 5;

#[test]
#[ignore = "performance measurement; run with cargo xtask performance"]
fn hundred_thousand_domain_filter_lookup_throughput() {
    let source = (0..DOMAINS)
        .map(|index| format!("0.0.0.0 blocked-{index}.example.test\n"))
        .collect::<String>();

    let parse_started = Instant::now();
    let list = FilterList::parse(&source);
    let parse_duration = parse_started.elapsed();
    assert!(list.contains("blocked-99999.example.test"));

    // Exercise both the common allow case and successful blocked lookups.
    let cases = [
        ("safe.example.test", false),
        ("sub.blocked-99999.example.test", true),
    ];
    for (host, expected) in cases {
        for _ in 0..10_000 {
            assert_eq!(list.contains(std::hint::black_box(host)), expected);
        }
        let mut durations = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let started = Instant::now();
            let mut matches = 0;
            for _ in 0..LOOKUPS_PER_SAMPLE {
                matches += usize::from(list.contains(std::hint::black_box(host)));
            }
            let elapsed = started.elapsed();
            assert_eq!(matches, if expected { LOOKUPS_PER_SAMPLE } else { 0 });
            durations.push(elapsed);
        }
        report(host, expected, &durations);
    }
    println!("Filter-list parse: {DOMAINS} domains in {parse_duration:.2?}");
}

fn report(host: &str, matched: bool, durations: &[Duration]) {
    let total: Duration = durations.iter().sum();
    let count = LOOKUPS_PER_SAMPLE * durations.len();
    let mean = total / count as u32;
    let min = *durations.iter().min().unwrap() / LOOKUPS_PER_SAMPLE as u32;
    let max = *durations.iter().max().unwrap() / LOOKUPS_PER_SAMPLE as u32;
    let mut ordered = durations.to_vec();
    ordered.sort_unstable();
    let median = ordered[ordered.len() / 2] / LOOKUPS_PER_SAMPLE as u32;
    println!(
        "Filter-list {kind} lookup: {count} checks against {DOMAINS} domains ({host}); min {min:.2?}, median {median:.2?}, mean {mean:.2?}, max {max:.2?} per check",
        kind = if matched { "blocked" } else { "unblocked" },
    );
}
