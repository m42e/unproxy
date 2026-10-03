use std::process::{Command, Output};

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(binary).args(args).output().unwrap()
}

#[test]
fn paceval_evaluates_a_local_pac_file() {
    let temp = tempfile::tempdir().unwrap();
    let pac = temp.path().join("proxy.pac");
    std::fs::write(
        &pac,
        "function FindProxyForURL(url, host) { return host === 'internal.test' ? 'PROXY proxy.test:8080' : 'DIRECT'; }",
    )
    .unwrap();

    let output = run(
        env!("CARGO_BIN_EXE_paceval"),
        &[pac.to_str().unwrap(), "http://internal.test/resource"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "http://internal.test/resource: HTTP proxy.test:8080"
    );
}

#[test]
fn toml_query_cli_walks_table_and_array_paths() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("config.toml");
    std::fs::write(&file, "[[servers]]\nname = 'primary'\nport = 8080\n").unwrap();

    let output = run(
        env!("CARGO_BIN_EXE_toml-query"),
        &[
            "--file",
            file.to_str().unwrap(),
            "--name",
            "selected",
            "servers",
            "0",
            "name",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "selected=primary"
    );
}

#[test]
fn version_cli_supports_default_and_raw_output() {
    let default = run(env!("CARGO_BIN_EXE_unproxy-version"), &[]);
    assert!(default.status.success());
    assert_eq!(
        String::from_utf8(default.stdout).unwrap().trim(),
        format!("version={}", unproxy::VERSION)
    );

    let raw = run(env!("CARGO_BIN_EXE_unproxy-version"), &["-r", "undns"]);
    assert!(raw.status.success());
    assert_eq!(
        String::from_utf8(raw.stdout).unwrap().trim(),
        unproxy::DNS_VERSION
    );
}

#[test]
fn control_clis_report_invalid_commands_and_values_without_side_effects() {
    let control = run(env!("CARGO_BIN_EXE_unproxyctl"), &["bogus"]);
    assert!(!control.status.success());
    assert!(String::from_utf8_lossy(&control.stderr).contains("unknown command"));

    let registration = run(env!("CARGO_BIN_EXE_unproxy-register"), &["bogus"]);
    assert!(!registration.status.success());
    assert!(String::from_utf8_lossy(&registration.stderr).contains("unknown command"));

    let system_proxy = run(env!("CARGO_BIN_EXE_unproxy-system-proxy"), &["not-a-port"]);
    assert!(!system_proxy.status.success());
    assert!(String::from_utf8_lossy(&system_proxy.stderr).contains("invalid unsigned 16-bit port"));
}

#[test]
fn undns_reports_invalid_argument_types_before_starting() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_undns"))
        .args(["--port", "not-a-port"])
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value"));
}
