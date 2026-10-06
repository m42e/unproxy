# PAC performance checks

Run the ignored measurements in release mode, with one test at a time:

```sh
cargo test --release --locked --test pac_performance -- --ignored --nocapture --test-threads=1
cargo test --release --locked --test pac_matching_performance -- --ignored --nocapture --test-threads=1
cargo test --release --locked --lib performance -- --ignored --nocapture --test-threads=1
```

The integration cases include the policy worker and its request/reply channels.
They warm up each policy, then report five batches of measurements. Concurrent
results are amortized time per completed evaluation, not individual request
latency. The internal DNS case measures individual synchronous evaluations with
seeded caches, so it does not depend on network DNS service performance. The
parser case compares the previous string conversion/parsing path with reuse of
an already parsed result, excluding JavaScript and worker scheduling.

## Matching with unique hostnames

`tests/pac_matching_performance.rs` separates substring calls, warm wildcard
matching, and substring-plus-cold-wildcard pairs. Each evaluation performs 96
calls or pairs and returns one route. All 620 inputs, including warmup requests,
have unique hostnames, URLs, and returned proxy directives. Changing the returned
directive is necessary because the route cache is keyed by that string, rather
than the hostname. This prevents both the last-result shortcut and the parsed
route map from hitting.

These cases use synchronous `Pac` evaluation to exclude policy-worker dispatch.
Inputs and warm wildcard patterns are prepared before timing, and route
assertions run afterward. The cold case fills the 512-pattern glob cache with
unrelated patterns during initialization; every measured dynamic pattern then
requires compilation. Its pairs contain one substring call and one wildcard
call. No DNS resolution or proxy connection occurs. Reported per-call and
per-pair costs are amortized: they still include JavaScript execution and one
uncached route parse per evaluation. The ordinary regression test exercises the
same workload scripts and checks input uniqueness and matching results.

Local release medians for these workloads:

| Workload | Per evaluation (96 calls or pairs) | Amortized per call or pair |
| --- | ---: | ---: |
| Substring calls | 13.28 µs | 138 ns / call |
| Warm wildcard matching | 36.33 µs | 378 ns / call |
| Substring plus cold wildcard compilation | 103.06 µs | 1.07 µs / pair |

`cargo xtask perf` includes these cases and runs the PAC integration benchmarks
one at a time. Use the release command above for comparable timing results.

## Measurements on 2026-10-06

Measured locally on macOS ARM64. The original evaluator was revision `718226c`;
the expanded benchmark source was identical for the integration comparisons.
The original executable was retained before changing the evaluator. The final
pair below ran the original and optimized executables sequentially, with no
build or other test run in progress. DNS baselines were captured before editing
its lookup path. Parser measurements compare both paths within one executable.

| Workload | Before median | After median |
| --- | ---: | ---: |
| 32 warm DNS hits, 64 cached names | 22.167 µs | 8.667 µs |
| 32 warm DNS hits, 4,096 cached names | 279.291 µs | 7.625 µs |
| 96 substring / `shExpMatch` pairs | 254.68 µs | 249.56 µs |
| 32 wildcard checks, 600-pattern working set | 103.66 µs | 102.19 µs |
| 48 `isInNet` checks | 6.07 ms | 442.65 µs |
| Four repeated route directives, through worker | 5.29 µs | 6.74 µs |
| 16 concurrent callers, amortized | 2.85 µs | 2.38 µs |
| Repeated route result, parser only | 403 ns | 50 ns |

The large DNS cache no longer requires a full scan on every lookup. The subnet
case improves by about 14 times; isolated repeated-result parsing improves by
about eight times. Glob improvements are small in these interpreter-heavy
workloads.

The final end-to-end repeated-route sample is slower by 1.45 µs despite faster
parsing. Small worker cases varied substantially between runs, so these results
do not establish an end-to-end route latency improvement. An additional
comparison against the immediately preceding IPv4-helper commit produced
repeated-route medians of 7.67–12.21 µs before route caching and 6.58–8.01 µs
afterward. Treat the small latency differences as inconclusive, and rerun on the
deployment system before drawing a throughput conclusion for trivial PACs.
These synthetic measurements are not CI performance thresholds.

## Behavior and regression coverage

DNS lookup checks the requested hostname's expiry; periodic pruning still
removes other expired entries. Glob caching retains the 512-pattern limit,
borrows compiled patterns, and validates argument types before the `*` shortcut.
IPv4 parsing accepts the same decimal octets, including leading zeros, and
preserves signed conversion and public helper overrides. Route parsing uses a
64-result FIFO cache with a shortcut for consecutive identical strings. Each
request still executes JavaScript; only successful parsed results are reused.
Returned routes are independent owned copies, and script replacement resets the
cache.

Regression coverage is in `tests/pac_glob_optimized.rs`,
`tests/pac_ip_helpers.rs`, `tests/pac_route_cache.rs`, and the internal PAC tests.
Every optimization commit runs the configured formatting, Clippy, all-feature
tests, and no-default-feature tests through the pre-commit hook. One no-default
test run hit an intermittent timeout in the existing nested TLS fixture; the
isolated test and complete hook passed on retry.
