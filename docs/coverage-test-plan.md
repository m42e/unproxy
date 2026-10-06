# Coverage gap closure plan

Prepared on 2026-10-03 against source commit `f621a9d199798f1721d7534335d69717dc058046`.
Implementation status: the coverage objectives are met on the local macOS runner for default, all-feature, and no-default-feature collections. The implementation adds deterministic tests and small test seams, separates portable logic from native adapters for reporting, and makes the objectives CI gates. The scenario catalog below remains a follow-up map; meeting the thresholds does not mean every listed scenario is complete.

## 1. Measured baseline, result, and objective

The existing LLVM profiles reproduce **67.23% line coverage: 3,708 / 5,515 lines**, leaving **1,807 lines uncovered**. Region coverage is **64.89%: 5,687 / 8,764**; function coverage is **68.77%: 425 / 618**. Branch and MC/DC counts are zero in this report, so branch coverage is unavailable rather than a measured 0% result.

The archived baseline was obtained with `cargo llvm-cov report`, `report --json`, `report --text`, and `report --show-missing-lines`, using the then-existing `target/llvm-cov-target` profiles; tests were not rerun for that snapshot. The host was `aarch64-apple-darwin`, Rust 1.98.1, LLVM 22.1.8, and cargo-llvm-cov 0.8.5. The library test fingerprint declares `default` and `negotiate`; the original collection command and whether every test completed are not recorded. This is a local macOS baseline, not the Linux CI baseline.

[coverage-baseline.json](coverage-baseline.json) preserves all 26 file summaries, source hashes, and uncovered line ranges from `--show-missing-lines`. Some summary missed-line counts exceed the enumerated missing locations; budget from the summary counts and use the ranges to locate code. Source line references below describe this snapshot and will move during refactoring.

The raw source-file scope also includes compiled inline unit-test bodies, including the ignored credential-dependent GSS probe. Record that contribution when comparing reports; preserve this baseline scope and report any production-only subtotal separately.

Proposed acceptance target: **at least 90% total line coverage and 85% region coverage**, with **95% lines and 90% regions across the portable runtime modules** (`access`, `auth` portable logic, `config`, `connection`, `dns`, `net`, `pac`, `proxy`, `route`, `runtime`, and notification state logic). Track native authentication and native notification adapters explicitly alongside that portable subtotal. Retain the full project total, including desktop and packaging code.

Fresh clean collections were completed locally on `aarch64-apple-darwin` with Rust 1.98.1, LLVM 22.1.8, and cargo-llvm-cov 0.8.5. Default and all-feature collections passed every runnable test with the credential-dependent GSS probe intentionally ignored; the no-default collection passed all tests. Each scope meets the gates:

| Feature scope | Full lines | Full regions | Portable lines | Portable regions |
| --- | ---: | ---: | ---: | ---: |
| Default | **91.51%** (6,696 / 7,317) | **89.75%** (10,470 / 11,666) | **95.73%** (4,215 / 4,403) | **94.22%** (6,501 / 6,900) |
| All features | **91.50%** (6,695 / 7,317) | **89.72%** (10,467 / 11,666) | **95.71%** (4,214 / 4,403) | **94.17%** (6,498 / 6,900) |
| No default features | **91.77%** (6,398 / 6,972) | **90.05%** (10,086 / 11,200) | **95.70%** (4,097 / 4,281) | **94.18%** (6,328 / 6,719) |

The portable subtotal is the sum of the 11 named `src/*.rs` modules above. Native adapters are separate source files and remain in the full project total: default/all-features `src/auth/native.rs` is 80.10% lines and 71.98% regions; `src/network_notifications/macos.rs` is 83.91% lines and 85.88% regions. The no-default report omits the feature-gated authentication adapter. Raw counts include source and inline test code; branch and MC/DC instrumentation remain unavailable in this LLVM report.

For the current fixed line denominator:

| Total line target | Minimum newly covered lines | Maximum remaining uncovered lines |
| --- | ---: | ---: |
| 80% | 704 | 1,103 |
| 85% | 980 | 827 |
| 90% | 1,256 | 551 |
| 95% | 1,532 | 275 |

These are planning thresholds. New production code, refactors, features, and platform differences change the denominator; recalculate after every batch. A gain must reflect executed behavior with assertions. Moving code, adding exclusions, or changing feature scope is not evidence of test coverage improvement.

## 2. Original hotspot ranking and remaining gaps

The table below is the ranking from the archived 67.23% baseline, before implementation. The current report reaches the target while retaining gaps in platform-heavy and packaging code. The largest remaining default-feature line gaps are:

| Source file | Covered / total lines | Missing lines | Main remaining area |
| --- | ---: | ---: | --- |
| `src/desktop.rs` | 1,144 / 1,311 | 167 | Native UI startup, preference adapters, and platform-only selectors |
| `src/platform.rs` | 368 / 467 | 99 | SystemConfiguration/Windows native service failure paths |
| `src/bin/xtask.rs` | 410 / 492 | 82 | Packaging, signing, and archive error branches |
| `src/net.rs` | 698 / 754 | 56 | Rare stream/response framing failures and native socket cases |
| `src/proxy.rs` | 1,011 / 1,054 | 43 | Listener failures, drain edges, and unusual request forms |
| `src/auth/native.rs` | 165 / 206 | 41 | GSS/SSPI symbol, status, and resource cleanup paths |
| `src/network_notifications/macos.rs` | 73 / 87 | 14 | CoreFoundation allocation/registration failures |

The portable subtotal has 188 missed lines at the default scope and remains above both module floors. Exact remaining line locations are archived by the CI `coverage-*-missing.txt` artifacts and can be regenerated using the commands in section 13.

### Archived baseline hotspot ranking

| Source file | Covered / total lines | Line coverage | Missing lines | Planned recovery budget |
| --- | ---: | ---: | ---: | ---: |
| `src/desktop.rs` | 209 / 749 | 27.90% | 540 | 380 |
| `src/bin/xtask.rs` | 92 / 492 | 18.70% | 400 | 320 |
| `src/platform.rs` | 36 / 228 | 15.79% | 192 | 140 |
| `src/auth.rs` | 353 / 464 | 76.08% | 111 | 75 |
| `src/runtime.rs` | 152 / 253 | 60.08% | 101 | 80 |
| `src/dns.rs` | 237 / 315 | 75.24% | 78 | 60 |
| `src/net.rs` | 404 / 478 | 84.52% | 74 | 50 |
| `src/proxy.rs` | 982 / 1,054 | 93.17% | 72 | 40 |
| `src/pac.rs` | 360 / 411 | 87.59% | 51 | 35 |
| `src/config.rs` | 205 / 253 | 81.03% | 48 | 40 |
| `src/bin/undns.rs` | 40 / 85 | 47.06% | 45 | 35 |
| `src/connection.rs` | 92 / 130 | 70.77% | 38 | 30 |
| `src/network_notifications.rs` | 144 / 165 | 87.27% | 21 | 15 |
| `src/route.rs` | 143 / 152 | 94.08% | 9 | 6 |
| `src/bin/paceval.rs` | 32 / 40 | 80.00% | 8 | Follow up |
| `src/bin/unproxy-system-proxy.rs` | 21 / 28 | 75.00% | 7 | Follow up |
| `src/access.rs` | 62 / 64 | 96.88% | 2 | 2 |
| `src/tools.rs` | 84 / 86 | 97.67% | 2 | 2 |
| Remaining eight binaries | 60 / 68 | 88.24% combined | 8 | 4 |
| **Total** | **3,708 / 5,515** | **67.23%** | **1,807** | **1,314** |

The recovery budget is an estimate to guide scope, not a promise. At an unchanged denominator it would yield **91.06%** total line coverage, leaving a small margin above 90%. It requires automated native macOS coverage as well as portable tests.

Desktop, xtask, and platform account for **1,132 missing lines, 62.65% of the gap**. Even covering every missing line in all other files would reach only **79.47%** if those three files stayed unchanged. More proxy happy path tests cannot achieve the project target on their own.

## 3. Measurement and CI status

Coverage CI in `.github/workflows/ci.yml` now collects default, all-feature, and no-default reports on Ubuntu, macOS, and Windows. It archives JSON, LCOV, HTML, missing-line text, and environment metadata, and applies the total and portable gates to every report. Linux and Windows execution remains CI evidence rather than a locally measured result.

`tests/lifecycle.rs` inherits LLVM profile patterns in child processes, requests SIGTERM on Unix, and awaits successful termination. Readiness and reload probes tolerate transient connection resets while policy reload completes. Child-process paths appear covered in fresh reports.

| ID | Work and observation | Acceptance and status |
| --- | --- | --- |
| M01 | Establish fresh default-feature, all-feature, and no-default-feature baselines. Record commit, source changes, OS/architecture, tool versions, commands, scope, test outcome, and ignored tests. | **Done locally on macOS.** Three clean collections and the ignored-test inventory are recorded above; CI runs the same scopes on its OS matrix. |
| M02 | Process fixtures inherit `LLVM_PROFILE_FILE`; child processes receive unique `%p-%m` names when the parent pattern does not already have them. | **Done.** Child-only paths appear in the measured report; profiles do not collide. |
| M03 | Normal Unix lifecycle teardown sends SIGTERM and awaits successful exit. Windows fixture teardown remains bounded process cleanup; native console Ctrl-C is not part of this implementation. | **Done for Unix lifecycle coverage.** Successful shutdown and reload paths are measured. |
| M04 | Capture JSON, HTML, LCOV, missing lines, and metadata for each OS and feature scope. | **Done in CI configuration.** Workspace collection includes test binaries, spawned products, and harness-free native probes. |
| M05 | Collect separate macOS, Windows, and Linux reports without averaging scopes. | **Done in CI configuration.** Each runner keeps its own three feature reports and artifacts. |
| M06 | Check the full and portable thresholds after collection. | **Done.** `scripts/check_coverage.py` gates 90% total lines/85% regions and 95% portable lines/90% regions, and reports native adapter totals separately. |

## 4. Shared fixtures and limited test seams

Build these once, then extend existing suites. Keep orchestration tests on the production paths.

| Fixture or seam | Needed by | Design |
| --- | --- | --- |
| Isolated process fixture | Runtime, config, desktop, undns, CLI | Temporary config/home paths set only in the child environment; bounded readiness and exit waits; inherited coverage environment; stdout/stderr collection; guaranteed reaping. Prefer inherited listeners or readiness messages to releasing a reserved port and hoping it stays free. |
| Child executable fixture | Desktop lifecycle | Modes for ready/running, immediate exit, ignored TERM, captured argv/environment, and stdout/stderr. Supply a native executable on Windows as well as Unix. Inject a short stop deadline for escalation tests. |
| Scripted asynchronous stream | IdleIo, Metered, relay, connection | Return Pending, partial reads/writes, EOF, flush/shutdown errors, and errors after known byte counts. Use it to assert counts, deadlines, and error propagation. |
| Local HTTP/TLS/UDP fixtures | DNS, connection, PAC fetch, proxy | Reuse the certificate/key in `tests/fixtures`, loopback listeners, one-shot readiness channels, request capture, explicit server completion, and bounded operations. Assert verification success with the fixture root and rejection without it. |
| Command executor | xtask, service controls, prompts, tray | Inject executable, argv, cwd, environment, status, and stdout/stderr. Keep the same production dispatch and error handling. Necessary for hardcoded `/bin/launchctl`; a PATH stub alone will not intercept it. |
| Build and staging inputs | xtask packaging | Inject repository root, binary input directory, target/host, feature selection, signing configuration, and command executor. Real temporary files exercise the existing staging logic. Avoid running nested cargo builds during coverage tests. |
| Native desktop dependencies | macOS controller | Pass a preferences store, child controller, prompt/alert sink, login-item adapter, and termination sink into controller actions. Keep Objective-C callbacks delegating to this logic and test those callbacks in a main-thread probe too. |
| Native API calls | SystemConfiguration, GSSAPI, SSPI, activation | Small function tables/backend seams at the external call boundary; fake outcomes and record releases. Retain native binding probes for ABI/selector validation and real adapter behavior. |
| Runtime events and listener failures | Runtime/proxy | Inject stop/control/network events and scripted accept results where a real OS failure is unreliable. Continue testing real signal delivery in subprocesses. |

Do not change global process environment from parallel tests. Keep Cocoa and CoreFoundation operations on a harness-free executable's main thread, following `tests/native_notifications_main.rs`. Use a private NSUserDefaults suite and temporary support directory. Do not automate changes to the developer's login items, launchd services, or system network preferences.

For purely asynchronous deadline tests, add Tokio's `test-util` dev feature if virtual time is used; `full` alone does not provide it. Use real bounded deadlines for subprocess and native event tests.

## 5. Desktop: 167 default-feature lines remain uncovered

The implementation added child lifecycle and controller action tests, injected prompt/alert/login adapters, startup seams, and a harness-free main-thread probe. The remaining gap is concentrated in native preference handling, UI setup, and uncommon startup failures. The cases below remain a follow-up map; the full and portable coverage gates already pass.

Coverage anchors: child lifecycle **142–160, 213–244**; actions **340–434**; menu/polling/notifications **436–607**; prompts/login items **705–727**; native preferences **732–787**; app startup/shutdown and helper **791–979**.

| ID | Scenario | Required assertions |
| --- | --- | --- |
| D01 | Port boundaries 1023, 1024, 65534, 65535, u32 max; saved negative, float, string, null, oversized integer, and absent port. | Exact effective port, stored sentinel/default behavior, valid values preserved, independent flags preserved. Extend existing repair tests. |
| D02 | Partial preferences object, malformed JSON, wrong field types, nested save path, filesystem write failure. | Serde defaults and returned errors; successful roundtrip preserves all fields; no child launched on invalid input. |
| D03 | Child already running, immediate successful/nonzero exit, restart after exit, missing executable, log open failure. | No duplicate PID; `last_exit` and log message on unexpected exit; spawn error context; restart launches once with current args. |
| D04 | Stop normal child, stop twice, TERM-ignoring child, query/wait error, Drop of running owner. | TERM then forced kill at injected deadline; child reaped; escalation logged; wait error preserved; no surviving child. |
| D05 | Capture child argv, `UNPROXY_NORC`, and stdout/stderr. | Listener/PAC/flags match preferences in both feature modes; no inherited stdin; both output streams reach isolated log. |
| D06 | Start/Stop/Quit actions while stopped/running; start or restart failure. | Exact child calls and state updates; relevant alert; Quit and application termination stop child; termination dispatched once. |
| D07 | Toggle tunnel, direct fallback, and Negotiate while stopped and running. | Only selected flag toggles; persisted value correct; running child restarted once; stopped child stays stopped; failure alert asserted. |
| D08 | Edit port/PAC: valid, invalid, relative path, missing absolute file, cancelled prompt. | Prompt cancellation leaves state untouched; invalid port/path produces alert; accepted value persists and reaches child args. Characterize current restart behavior on invalid edits and decide any behavior correction explicitly. |
| D09 | Autostart enable/disable accepted or rejected. | Store and login adapter agree on success; rejected change rolls preference back and persists rollback; error alert emitted. |
| D10 | Poll child: running, unexpected exit, state lock busy, null status button. | Titles and `last_running` transitions correct; exit alert once; busy callback returns without blocking. |
| D11 | Build menu for stopped/running, last exit, invalid saved port, each flag and network state. | Titles, order, action tags, enabled state, checked state, and Negotiate feature visibility. Use controller menu model plus real NSMenu projection checks. |
| D12 | Available/Unavailable callbacks and helper/application termination callbacks. | Exact network state transition; main-thread delivery; stop/terminate sink called; callback survives absent controller state. |
| D13 | Load/save native preferences from private defaults suite: missing/present keys, invalid port, relative PAC, all booleans. | Defaults initialized; port clamping characterized; path made absolute; JSON/defaults roundtrip; return filesystem errors. |
| D14 | Prompt subprocess: escaping quotes/backslashes, success output, cancel/nonzero exit, missing result, spawn failure. | Exact command/script and decoded result; None on cancelled/failed/malformed output. |
| D15 | App startup with fresh/existing sample PAC and controller lock held/free; child start succeeds/fails. | Sample created once and existing content preserved; second instance returns; correct bundle child path; failed start displayed; lock released on exit. |
| D16 | Real main-thread app probe builds menu, invokes action selectors, pumps timer/notifications, then shuts down. | Actual adapters exercised; no visible modal prompts; isolated preferences/logs; all observers/timers/child resources released; process exits normally and emits coverage. |
| D17 | Login helper when app already running, app absent, open failure, and terminate notification. | Exactly one launch when needed, correct bundle ID/notification, normal helper termination. Characterize current behavior: spawn error propagates but nonzero `open` exit returns Ok. Stub command execution and use private notification names. |
| D18 | Unsupported desktop entry points and Windows tray script missing, spawn failure, success/nonzero exit. | Platform-specific errors and exact PowerShell args including STA/hidden execution; no UI launched in command tests. |

Original follow-up objective: automate D01–D18 in applicable platform jobs and recover roughly 380 baseline lines. The project coverage objective is met without completing every case; prioritize remaining native behavior according to correctness risk.

## 6. Packaging and developer tools: 82 default-feature lines remain uncovered

`tests/xtask_packages.rs` now exercises package staging, docs generation, command dispatch, and failure/collision behavior through temporary fixtures. Signing, archive tooling, and rare native package failures remain. The cases below retain the broader original follow-up catalog; they are not required to pass the current coverage gates.

Coverage anchors: dispatch **76–188**; archive/signing **190–251**; staging/package formats **252–528**; documentation **536–594**.

| ID | Scenario | Required assertions |
| --- | --- | --- |
| X01 | Build debug/release, native/explicit target, Negotiate on/off. | Exact `cargo build --locked --bins` args, profile/target flags, feature flags, and execution failure context. |
| X02 | Check dispatch; child command failure at each step. | fmt, clippy, all-feature tests, no-default-feature tests in order; stop at first failure. Stub commands to avoid recursive test runs. |
| X03 | Docs in fixture repo with headings/code/HTML-special text; repository set/absent/invalid; relative/absolute output. | Pages sorted, nav and index correct, placeholders replaced, escaping correct, source archive command path correct; no archive on validation error. |
| X04 | Docs missing input, missing site template, output write failure, git archive failure. | Context/status returned and no claimed success. Assert actual partial output behavior rather than assuming transactionality. |
| X05 | Unpack valid ZIP, missing/corrupt archive; Windows PowerShell path contains quotes/spaces. | File bytes/layout, output directory, exact safely quoted command, nonzero status/error propagation. |
| X06 | Copy source missing, existing destination, nested tree with empty directories, blocked destination path. | Contents/layout, overwrite behavior, and filesystem error; reuse current copy fixture. |
| X07 | Bump patch/minor/major in temporary manifest, unsupported part, malformed/overflow version, lockfile command failure. | Correct version and preserved comments/unrelated fields; repository files untouched; failure semantics explicit. |
| X08 | Coverage command dispatch. | Exact requested HTML directory and child failure propagation; stub `cargo llvm-cov` to prevent recursive collection. |
| X09 | Expand native format on Linux/macOS/Windows; native plus target; incompatible format/target; unsupported Debian architecture. | Correct format list/error and host/target classification. Validation errors before staging/build where intended. |
| X10 | Portable and Windows staging with fake input binaries. | Exact filenames (`UnproxyTray.exe` rename), sample PAC/README/install scripts, metadata version/target/features/components, executable bits, archive command and destination. |
| X11 | Debian x86_64/aarch64/i686 with/without Negotiate. | `amd64`/`arm64`/`i386`, dependency string, hooks and modes, service path, binary/doc placement, `dpkg-deb --root-owner-group` args. |
| X12 | macOS service package on macOS and explicit Darwin staging from another host. | Four binaries, launch agent, paths.d, hooks, pkgbuild identity/version/root/scripts; cross-host staging ZIP naming. |
| X13 | App bundle and embedded login helper staging. | All executables, plists and minimum OS versions, entitlements, metadata, Resources directory, app ZIP and installer root/layout. |
| X14 | Signing absent/blank identity, identity present, keychain set/unset, entitlement set/unset, signer failure. | Exact command args and nested signing order: proxy, helper, app; installer signing flag; release-only secrets never required in test fixture. |
| X15 | Native multi-format sequence, existing staging collision, missing binary/asset, archive/pkgbuild failure. | Separate artifacts have complete contents; no cross-format contamination; known staging/hook residue asserted and cleanup requirements explicit. |
| X16 | Small real unsigned artifact probes on each native OS. | Inspect ZIP entries, Debian control/file tree, and macOS package payload; generated products valid without installing them. |
| X17 | Markdown closed/unclosed fences, h1/h2/h3, blank lines, escaping, release note preamble/one/multiple sections. | Exact parsed/generated content; extend existing renderer and release-note cases only where branches remain uncovered. |

Run the staging/dispatch cases through the injected production executor, not a separate test implementation of packaging. X16 validates real external tools; it should execute an instrumented xtask with prebuilt inputs rather than rebuild the application inside every test.

Original follow-up objective: recover roughly 320 baseline lines and add layout/failure assertions for every supported package format. The current coverage objective is met; remaining package cases can be added where they improve release confidence. Generated docs include this plan unless excluded intentionally from the site input list.

## 7. Platform integration: 99 default-feature lines remain uncovered

The implementation adds a launchctl command seam, CoreFoundation proxy dictionary checks, and activation descriptor ownership tests. SystemConfiguration transaction failures and Windows-specific native error paths remain. Linux activation parsing tests still contribute when collected on Linux, so platform reports keep their own denominators.

Coverage anchors: activated descriptors **50–102**; service command execution **150–192**; system proxy transaction **346–494**.

| ID | Scenario | Required assertions |
| --- | --- | --- |
| P01 | Linux activation count invalid/negative/too large/zero, mismatched names, PID absent/malformed/wrong/non-Unicode, one/multiple/no matching names. | Exact selected descriptors or descriptive error; metadata rejected before ownership transfer. Extend current parser tests. |
| P02 | Real Linux inherited listener subprocess with matching name and multiple descriptors. | Traffic served on selected inherited listener; nonblocking mode; selected FD owned and closed exactly once; unrelated FDs remain owned by fixture. |
| P03 | macOS launch activation errors, embedded NUL name, zero/one/multiple descriptors; conversion failure. | Correct error mapping and transferred descriptor cleanup; allocated FD-array released. Use dedicated descriptors/process and API seam, never close arbitrary fixture-process FDs. |
| P04 | launchctl start/restart/stop/enable/disable/status/install/uninstall with recorded executor. | GUI UID domain, service label and plist path; exact command order; status PID causes expected ps command, absent PID omits it. |
| P05 | spawn/nonzero launchctl/ps outcomes; uninstall kill failure; invalid registration/control command. | Error propagation; uninstall tolerates initial kill failure then executes disable/bootout; unknown command invokes no executor. |
| P06 | Build system proxy config for zero and nonzero port using real CF dictionary construction on macOS. | HTTP/HTTPS enable flags and loopback hosts/ports, discovery/PAC/SOCKS/Gopher disabled, complete exceptions array, disable config semantics. No SCPreferences writes to the machine. |
| P07 | Service inventory: Ethernet, Wi-Fi, unsupported type, null interface/type, unchanged config. | Only supported changed services written; changed count correct; zero changes causes no commit/apply/synchronize. |
| P08 | Authorization, preference/session creation, service enumeration, protocol read/write, commit/apply failures. | Specific returned error; subsequent calls stop; CF Create/Copy objects and authorization released on every path. Inject SC/Security calls while exercising production transaction flow. |
| P09 | Successful changed preferences transaction. | Per-service writes before one commit, one apply, one synchronize; changed count accurate; resource ownership balanced. |
| P10 | Windows console attach succeeds, already attached, unexpected error; activation unsupported; non-macOS service/proxy calls. | Access denied treated as already attached; other errors contextualized; platform-specific unsupported errors. |
| P11 | Interface IP detection success/failure. | Supplied detector/socket outcome yields discovered address or localhost; do not assert a particular real NIC address. |

Original follow-up objective: recover roughly 140 baseline lines and automate Linux/Windows equivalents. The current coverage objective is met; native smoke tests can expand adapter confidence without changing system network preferences.

## 8. Authentication and controller lifecycle

The implementation expands portable credential, challenge parsing, runtime startup, and graceful child shutdown tests. Portable auth and runtime exceed their target contribution; native GSS/SSPI adapters remain separately visible. The nonignored GSS test remains only a best-effort smoke test. Real identity tests now live in `tests/corporate_auth.rs` and are run by `.github/workflows/corporate-auth.yml` against a disposable MIT Kerberos realm and Squid on Linux, plus an opt-in SSPI job on a controlled domain runner. See `docs/corporate-auth-tests.md` for fixture setup. The cases below describe additional native and lifecycle confidence work.

| ID | Scenario and coverage anchor | Required assertions |
| --- | --- | --- |
| A01 | Netrc quoting, escapes, comments adjacent to tokens, `user`/`passwd` aliases, `account`, duplicate hosts/default entries; auth **44, 75–81, 151–187**. | Exact parsed credentials and duplicate behavior; missing host/login, unknown token, dangling escape and open quote rejected; secrets absent from Debug/error output. |
| A02 | `from_netrc` and `replace_file` success/missing/malformed file; auth **34–36, 137–145**. | Sorted hosts; failed replacement leaves all prior host/default credentials intact; successful replacement visible to cloned factories. |
| A03 | Repeated/mixed-case/comma-separated Negotiate challenges, empty/malformed tokens, invalid header text; auth **224–231**. | Correct first valid decoded token or None. Include a quoted Basic realm containing commas to characterize parser behavior. |
| A04 | No-auth/basic/Negotiate Debug, host restriction matched/unmatched/empty; auth **243–283**. | Correct header or None; unmatched host never initializes native auth; global mode allows any host; error includes upstream context. |
| A05 | Auth blocking task error, panic/join failure, timeout. | Returned context and bounded result; injected blocked task released/reaped after timeout. Timeout of spawn_blocking does not itself cancel native work. |
| A06 | GSS native seam: name-import failure, empty/nonempty token, continue/completion/error statuses, server token present/absent, multi-part status diagnostics; auth **380–404, 437–450, 475–535**. | Service name `HTTP@host`, SPNEGO mechanism and flags, input bytes, returned token and errors; name/context/output buffers released exactly once, including error paths. |
| A07 | Windows SSPI seam: acquire failure, first/subsequent step, empty/nonempty/error result, Drop with/without handles. | Service name `HTTP/host`, context reuse, token size, cleanup, error codes. Characterize the current adapter's deliberate ignoring of server challenges; a protocol change needs separate implementation work. |
| A08 | Controlled native identity integration job. | **Implemented.** The Linux job creates an ephemeral MIT Kerberos identity and Squid proxy; the Windows dispatch job requires a domain account and Kerberos service ticket. Both run ignored strict tests for a nonempty token, repeated context teardown, unauthenticated/host-restricted rejection, authenticated forwarding, and CONNECT. Missing fixture configuration fails. The tests remain ignored in ordinary collections; the dedicated job reports native identity behavior separately from portable source coverage. |
| R01 | Graceful SIGTERM/SIGINT after ready, idle shutdown, active HTTP/CONNECT drain, zero/short shutdown timeout; runtime **159–219**. | Successful exit, bounded drain/escalation behavior, listener closes, active resources released, child coverage emitted. Extend existing lifecycle fixtures after M03. |
| R02 | Logging file create/truncate, invalid destination fallback, valid/invalid `UNPROXY_LOG`; runtime **23–40**. | Old content truncated; expected log level and sink; logging failure does not prevent otherwise valid startup. Exercise global subscriber setup in isolated subprocesses. |
| R03 | No explicit PAC source with discovered file/none; default netrc found/missing/unreadable; runtime **50–53, 240–243**. | Correct selected policy/auth and startup result from isolated configuration roots; no accidental use of developer files. |
| R04 | Global/host-specific Negotiate startup and explicit netrc conflict; runtime **224–229**. | Actual factory selected and allowed-host behavior; no-default-feature build rejects Negotiate option. Extend existing argument conflict coverage. |
| R05 | Runtime receiving native Available/Unavailable, duplicate events, failed restore/retry; runtime **126–137, 171–192**. | Policy route and effective IP change/preservation, error logged, continued service; event pumping/receiving occurs in real controller loop via injected private adapter. Existing state/composition tests remain the oracle. |
| R06 | Supplied activation listener startup and listener fatal failure; runtime **92, 164–167**. | Activated address accepts requests; repeated fatal accept failure notifies shutdown and returns the documented runtime error; transient failure recovers. Use scripted accept seam for deterministic failure. |
| R07 | Embedded entry normal run terminated through injected stop; runtime **263–266**. | Embedded runtime starts/serves/drains and returns; help/version/error cases already covered need no duplicate tests. |

The coverage target is met. Remaining default-scope gaps include 14 portable auth lines, 24 runtime lines, and 41 lines in the separately reported native auth adapter; use refreshed reports rather than the original recovery budget when selecting follow-up cases.

## 9. DNS and undns CLI

The implementation adds malformed-message and compression cases, bounded DoH behavior, and a deterministic DNS serve shutdown seam; the existing TLS and CLI suites cover additional transport paths. The remaining default-scope gaps are 12 lines in DNS and 7 in the undns binary. The catalog below is a source of focused follow-up cases, not a claim that every row remains uncovered.

Coverage anchors: compressed name validation **71–131**; DoH errors **184, 192**; DNS serve loop **306–341**; undns settings/URL/serve **30, 49–57, 73–113**.

| ID | Scenario | Required assertions |
| --- | --- | --- |
| N01 | Valid backward compression including pointer chains; depth boundary and limit+1; reserved label tags, missing pointer/label bytes, excessive label sequence, oversized expanded name. | Correct parsed counts or specific error. Private parser unit tests may target overflow arithmetic directly; unreachable guard branches must be documented, not forced through unsafe inputs. |
| N02 | Truncated declared sections/RDATA and additional records; zero/one question and zero/nonzero answer combinations. | All declared sections validated before fallback; exact `needs_fallback` result. Extend existing wire fixtures. |
| N03 | Primary UDP silence, malformed reply, and socket error. | Timeout/error context; no DoH connection attempted when primary exchange itself fails, matching current behavior. |
| N04 | DoH non-200, invalid DNS body, truncated HTTP body, TLS rejection, trailers, exact payload bound across chunks. | Status/parse/TLS cause preserved; valid trailers do not corrupt bytes; current 65,507-byte limit enforced. Reuse current bound tests. |
| N05 | Secondary HTTPS authority/path variants and proxy tunnel failure. | Request Host/path, verified TLS name, original query bytes; nested connection timeout/error propagated. |
| N06 | Serve loop with two clients, successive requests, primary answer and empty-answer fallback. | Response bytes and transaction IDs return to correct peer; server remains available; abort/reap server task explicitly after test. Inject prebound UDP socket/readiness to avoid fixed ports. |
| N07 | Query failure then valid query; reply-send failure via socket seam; bind failure. | Failure logged, subsequent valid traffic served, failed bind returned; no task leakage. |
| U01 | undns rc comments/blank lines, values loaded, CLI override, missing/malformed required primary. | Exact effective args or early CLI error; use isolated config directory and extracted candidate-list helper for system paths. |
| U02 | Explicit proxy / `http_proxy` / fallback default precedence; HTTP/HTTPS, default/explicit ports and bracketed IPv6. | Exact Route and Endpoint, default 80/443, brackets removed, valid defaults selected. Prefer extracted config resolver plus subprocess dispatch checks. |
| U03 | Proxy URL no host/scheme, unsupported scheme, credentials, invalid/zero/overflow port; secondary invalid URI. | Specific error and nonzero exit before listener binds; no unintended network request. |
| U04 | undns process normal query and failure-then-recovery sequence. | Real UDP response through configured primary/fallback, logs/readiness captured, bounded cleanup; provide shutdown seam or graceful signal handling so coverage is emitted. |

The current coverage target is met. Preserve the observed fallback policy in future changes: an empty answer with a question triggers DoH, while a failed primary exchange returns its error.

## 10. Streams, connections, and remaining proxy paths

The implementation expands relay partial-error accounting, CONNECT parsing failures, stream behavior, TLS/connection paths, and proxy lifecycle checks. Remaining default-scope gaps are 56 lines in `net`, 1 in `connection`, and 43 in `proxy`; prioritize failure correctness and public entry points as follow-up.

| ID | Scenario and anchor | Required assertions |
| --- | --- | --- |
| S01 | Pending IdleIo write/flush/shutdown, **90–139**; active read/write resets both timers, disabled upgrade deadline, underlying errors/EOF/zero writes. | Correct operation-specific TimedOut error, exact deadline reset behavior, Pending when disabled, unchanged underlying errors. Use scripted stream/virtual time. |
| S02 | Keepalive time/interval/retries individually and together, **187–194**. | A setter seam asserts the exact requested time/interval/retries reach the socket backend on every platform; the integration test reads them back on Linux/macOS and checks `TCP_NODELAY` plus `SO_KEEPALIVE` on all platforms. |
| S03 | Direct TLS connection API, **235–244** and connection **36–47**. | `DirectTls`/Direct identity, verified request and response, rejection without fixture trust; connect/TLS failure bounded by timeout. |
| S04 | Public HTTPS proxy/tunnel constructors, connection **55–78**, plus direct/tunnel send. | Correct transport/route, CONNECT handshake before payload, client-supplied proxy auth removed, configured proxy auth confined to handshake for tunnel/direct origin traffic. |
| S05 | Connection flush/shutdown and exchange/driver error, **129, 155–166**. | Bytes flushed, half-close observed by peer, error context preserved, no hanging driver. |
| S06 | Relay/Metered read/write failure after partial traffic, **519–548**, plus `into_inner`/`parse_ip`, **567–612**. | Exact four counters and underlying error/source/display, no count increase on Pending/error, successful half-close behavior preserved. |
| S07 | CONNECT EOF, stalled/oversized head, invalid UTF-8/status, non-2xx; net **314–321**. | Exact error, no usable tunnel returned, socket closed; extend existing rejected CONNECT case. |
| S08 | PAC HTTP head >64 KiB, chunk line >8 KiB, chunk size/framing errors, body EOF/over-limit, malformed redirects; net **345–484**. | Error and bounded completion, precise accepted boundary. Existing body-size/redirect cases cover much of this; select remaining zero-count regions from refreshed report. |
| Q01 | Public Context convenience APIs: listeners/bind_listener, policy, set_script(s), set_ip, load_pac(s), publish_access; proxy **148–154, 389–425**. | Supplied listener serves; actual policy state/routes and event contents change correctly; failed load preserves previous state. |
| Q02 | Bound-address policy initialization and multiple listeners, **216–237**. | All listeners use loaded policy before accepting; invalid one-listener bind cleans up previously acquired listeners. |
| Q03 | `wait` and `wait_timeout` expiration/normal completion, **453–457**. | Return value matches completion, pending relays cancelled/reaped, semaphore permits restored. Existing wait test covers only observation behavior. |
| Q04 | Trusted-management Host absent/nontext/invalid; nonloopback peer; custom trusted host; proxy **936–956**. | Request cannot mutate policy unless trust checks pass; use handler/unit seam for peer/header variants unavailable through a normal client. |
| Q05 | Absolute HTTPS request without CONNECT, invalid CONNECT authority, self-loop IPv4/IPv6/localhost variants, strict loaded-policy error; proxy **715–772, 1037**. | Correct 400/502/503 distinction and no destination connection; error HTML escaped; access event where production publishes one. |
| Q06 | Accept transient/fatal errors and malformed client exchange, **512–519, 581–583**. | Retry backoff, fatal threshold triggers notification, other listeners/tasks drained; observable serving failure context. |
| Q07 | CONNECT relay reset/broken pipe/NotConnected with balanced counts/other error, **852–865**. | Cleanup and byte-accounting classification; logging level via isolated trace capture; use stream seam rather than flaky TCP reset timing. |

The coverage target is met. Keep client and upstream I/O bounded in additional tests; use the refreshed missing-line report to avoid duplicating now-covered cases in this catalog.

## 11. Configuration, PAC state, notifications, and small gaps

Portable tests now cover configuration discovery and merging, PAC state and worker behavior, notification transitions, and small public APIs. The original scenario IDs below remain useful where a specific uncovered branch still appears in the refreshed report.

| ID | Suite / scenario | Required assertions |
| --- | --- | --- |
| C01 | `tests/config.rs`: first-readable search with missing file, directory, readable candidates, empty input; discovery **30–76**. | First usable candidate selected in order; no candidate gives None; test candidate construction for each OS without requiring writes to system directories. |
| C02 | Configured rc loaded/skipped with `UNPROXY_NORC` unset/empty/nonempty; merged args **225–233**. | Actual rc effect and scalar CLI precedence; repeated PAC sources preserve intended order. Discovery and environment behavior have integration coverage; add only uncovered precedence cases. |
| C03 | MainArgs timeout accessor and all verbosity differences, **181–183, 207**; malformed settings tokens/UTF-8. | Exact durations/levels and parser behavior; do not duplicate existing duration/listener boundary tests. |
| J01 | `tests/pac.rs`/unit tests: bounded async Pac API **149–187**, policy snapshot **306–311, 366–374**. | Route/error result, merged cache snapshot including None and duplicate-host precedence, worker remains usable. |
| J02 | Strict worker evaluation while marked unloaded **282**, replacement success/failure and subsequent restore. | Strict error, exact loaded state, previous script/IP preserved after failed replacement, successful reload restores service. |
| J03 | Policy worker shutdown/channel rejection and failed response delivery **352–354**. | Descriptive stopped-worker error; cancelled caller does not break subsequent jobs; use deterministic test seam, not timing guesses. |
| J04 | Numeric IP and hostname DNS cache seeding/miss/negative entries; missing/helper function paths **81, 107**. | Deterministic supplied-resolver results; no public DNS dependency; replacement clears cache only where specified. |
| E01 | `tests/network_notifications.rs`: await `recv`, receiver closure and `TransitionState::default`, **37–39, 89–91**. | Queued event returned; closed receiver yields None; default matches new. On non-macOS the native sender is dropped, so recv should complete with None. |
| E02 | Native registration NUL first/second name, CF allocation/center failure, **190–223**. | InvalidInput/resource error; first allocation released on second-name failure; no partially registered observer left behind. |
| E03 | Private-name distributed notifications after unregister/re-register, callback receiver dropped. | Still needs an observable unregistration check, such as counting both native remove calls through an injected backend. The existing adapter-drop test is explicitly a no-panic smoke test and does not verify that observers were removed. |
| L01 | `tests/pac.rs`/route: remaining Endpoint/PathOrUri/Destination parse/display regions **59, 157–166, 226**. | Roundtrip for relative/absolute path, HTTP/HTTPS and IPv6; invalid empty host/port and unsupported scheme; only add cases absent from current route suite. |
| L02 | `tests/access.rs`: remaining status/agent/error quoting at **77, 89**. | Exact access line for error/no request agent, escaped quotes/backslashes/newlines, no fabricated size for failure. |
| L03 | `tests/tools.rs`: scalar descent error and unknown product, **21, 34**; binary wrappers. | Specific error and CLI nonzero status; preserve currently covered successful TOML/version paths. |
| L04 | `tests/cli.rs`: paceval missing/bad PAC and bad URL, system-proxy help/port boundaries and mocked success/error, desktop entry failures. | Exact exit status/stdout/stderr; subprocess coverage flushed; no host settings modified. Some tiny wrapper closure lines may remain and should be accounted for explicitly. |

The coverage target is met. Any remaining cases in this group should be selected from the latest per-file and missing-region reports, since the archived line anchors and original recovery estimates predate implementation.

## 12. Delivery status and remaining work

The effort estimates below describe the original plan. Coverage targets are now met locally; remaining scenario rows are follow-up work for native failure paths and higher confidence, not prerequisites for the current thresholds.

| Batch | Implemented work | Status and remaining follow-up |
| --- | --- | --- |
| 0 | CI matrix and artifact collection; child profile inheritance; graceful Unix teardown; clean local default/all/no-default baselines. | **Complete locally.** Linux and Windows thresholds will be verified by CI. |
| 1 | Isolated subprocess, UDP/TCP/TLS, async stream, PAC, DNS, config, connection, portable auth, and notification-state tests. | **Complete for the coverage objective.** Some uncommon parser and error branches remain in the ledger above. |
| 2 | `tests/xtask_packages.rs` exercises package staging, docs generation, command dispatch, and failure/collision cases through temporary fixtures. | **Partial scenario catalog.** 82 `xtask` lines remain, chiefly signing/archive and rare package failures. |
| 3 | macOS service command seam, proxy dictionary builder, activation descriptor ownership tests, and separate native auth/notification modules. | **Partial scenario catalog.** Native auth has 41 missing lines; macOS notification has 14; platform adapters have 99. |
| 4 | Desktop child lifecycle, injected actions/prompts/login behavior, startup seams, and a main-thread desktop probe. | **Partial scenario catalog.** 167 desktop lines remain, concentrated in native preferences, UI setup, and uncommon startup failures. |
| 5 | Refreshed reports and executable total/portable gates in CI. | **Complete locally.** Each CI runner evaluates its own totals; no cross-platform averaging occurs. |

The local milestones crossed 80%, 85%, and 90% total line coverage in the final clean default-feature report. The portable line and region floors are also exceeded in all three local feature scopes.

## 13. Collection and validation procedure

Use this recipe to regenerate the reports in section 1. Save reports to separate paths and clean between scopes. `cargo llvm-cov report` consumes the already-collected profile; feature flags belong on the collection command, not the report command.

```sh
# Preserve current profiles/reports first. Run from the repository root.
mkdir -p dist/coverage/default
cargo llvm-cov report --json --output-path dist/coverage/default/before.json
cargo llvm-cov report --html --output-dir dist/coverage/default/before-html

cargo llvm-cov clean --workspace
cargo llvm-cov --locked --workspace --no-report
cargo llvm-cov report --json --output-path dist/coverage/default/after.json
cargo llvm-cov report --lcov --output-path dist/coverage/default/after.lcov
cargo llvm-cov report --html --output-dir dist/coverage/default/after-html
cargo llvm-cov report --show-missing-lines > dist/coverage/default/after-missing.txt
python3 scripts/check_coverage.py dist/coverage/default/after.json

# Repeat into distinct directories, cleaning between feature scopes:
mkdir -p dist/coverage/all-features dist/coverage/no-default
cargo llvm-cov clean --workspace
cargo llvm-cov --locked --all-features --workspace --no-report
cargo llvm-cov report --json --output-path dist/coverage/all-features/after.json
cargo llvm-cov report --lcov --output-path dist/coverage/all-features/after.lcov
cargo llvm-cov report --html --output-dir dist/coverage/all-features/after-html
cargo llvm-cov report --show-missing-lines > dist/coverage/all-features/after-missing.txt
python3 scripts/check_coverage.py dist/coverage/all-features/after.json

cargo llvm-cov clean --workspace
cargo llvm-cov --locked --no-default-features --workspace --no-report
cargo llvm-cov report --json --output-path dist/coverage/no-default/after.json
cargo llvm-cov report --lcov --output-path dist/coverage/no-default/after.lcov
cargo llvm-cov report --html --output-dir dist/coverage/no-default/after-html
cargo llvm-cov report --show-missing-lines > dist/coverage/no-default/after-missing.txt
python3 scripts/check_coverage.py dist/coverage/no-default/after.json
```

For a focused implementation cycle, select the affected test/bin target with cargo-llvm-cov; finish the batch with one complete collection for each affected supported scope. A focused run's total is not comparable to the complete baseline. Feature flags belong on the collection command; report commands consume the profile most recently collected. Follow existing fmt/clippy checks as part of implementation validation.

CI installs the pinned cargo-llvm-cov 0.8.5 and Python 3, then uploads JSON/LCOV/HTML/text plus metadata even when a threshold fails. Each OS/feature profile is cleaned before collection. The macOS main-thread probes are harness-free and run as part of workspace collection; Windows native console coverage remains a follow-up because the current tests use bounded child cleanup there.

Every completed batch records:

1. Case IDs implemented and exact production behavior asserted.
2. Before/after total and per-file line/region/function counts under identical scope.
3. Absolute old missing lines newly hit, new production lines added, and remaining gaps.
4. Tests that skipped or failed to collect a profile, with a reason and follow-up.
5. Any behavior change discovered during testing, including rollback/cleanup semantics.

## 14. Final acceptance and remaining-gap accounting

- **Met locally:** full raw project line coverage is above 90% and region coverage above 85%; portable runtime subtotal is above 95% lines and 90% regions in default, all-feature, and no-default collections. Platform-specific reports are evaluated in their own scopes.
- No headline improvement comes from new filename exclusions, omitting binaries, changing features, skipping required probes, or counting uninstrumented commands as covered.
- Child processes and native probes exit normally for successful tests and emit profiles; failed-test cleanup leaves no processes or tasks behind.
- Newly added failure cases check status/error and state/resource behavior, not only `is_err()` or lack of panic.
- Remaining high-impact gaps are listed in section 2 and exact current ranges are available in CI missing-line artifacts. They are mainly native adapter failures, desktop UI/preferences, platform transaction errors, and packaging/signing paths; none is silently excluded from the raw total.
- Allocation failures, native symbol absence, poisoned locks, or deliberately fatal paths are covered through small deterministic seams where useful; otherwise record their actual remaining line/region counts. Do not remove them silently to satisfy a percentage.
- Full-project 95% remains a possible follow-up: at the current default denominator it would need 256 additional covered lines. The portable 95% line target is already met. Any further work should prioritize correctness and the native gaps above rather than alter report scope.
