use std::{
    path::Path,
    process::{Command, Output},
};

fn isolate_config_dir(command: &mut Command, root: &Path) {
    command
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"));
}

fn run(binary: &str, args: &[&str]) -> Output {
    let mut command = Command::new(binary);
    command.args(args);
    inherit_coverage_profile(&mut command);
    command.output().unwrap()
}

fn inherit_coverage_profile(command: &mut Command) {
    let Some(pattern) = std::env::var_os("LLVM_PROFILE_FILE") else {
        return;
    };
    let pattern = pattern.to_string_lossy();
    let unique = if pattern.contains("%p") && pattern.contains("%m") {
        pattern.into_owned()
    } else {
        format!("{pattern}.child-%p-%m.profraw")
    };
    command.env("LLVM_PROFILE_FILE", unique);
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_undns"));
    command.args(["--port", "not-a-port"]);
    isolate_config_dir(&mut command, temp.path());
    inherit_coverage_profile(&mut command);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value"));
}

#[cfg(not(windows))]
#[test]
fn unproxy_reads_the_isolated_rc() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    let config = temp.path().join("Library/Application Support/unproxy");
    #[cfg(target_os = "windows")]
    let config = temp.path().join("AppData/Roaming/unproxy");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let config = temp.path().join("config/unproxy");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("unproxyrc"), "--not-a-real-settings-option\n").unwrap();

    let mut with_rc_command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
    with_rc_command.arg("--help");
    isolate_config_dir(&mut with_rc_command, temp.path());
    with_rc_command.env_remove("UNPROXY_NORC");
    inherit_coverage_profile(&mut with_rc_command);
    let with_rc = with_rc_command.output().unwrap();
    assert!(!with_rc.status.success());
    assert!(String::from_utf8_lossy(&with_rc.stderr).contains("not-a-real-settings-option"));
}

#[test]
fn unproxy_norc_skips_settings_and_displays_help() {
    let mut ignored_command = Command::new(env!("CARGO_BIN_EXE_unproxy"));
    ignored_command.arg("--help").env("UNPROXY_NORC", "1");
    inherit_coverage_profile(&mut ignored_command);
    let ignored = ignored_command.output().unwrap();
    assert!(
        ignored.status.success(),
        "{}",
        String::from_utf8_lossy(&ignored.stderr)
    );
    assert!(String::from_utf8_lossy(&ignored.stdout).contains("Usage:"));
}

#[cfg(not(windows))]
#[test]
fn undns_reads_the_isolated_rc_before_help() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    let config = temp.path().join("Library/Application Support/undns");
    #[cfg(target_os = "windows")]
    let config = temp.path().join("AppData/Roaming/undns");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let config = temp.path().join("config/undns");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("undnsrc"), "--not-a-real-settings-option\n").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_undns"));
    command.arg("--help");
    isolate_config_dir(&mut command, temp.path());
    inherit_coverage_profile(&mut command);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not-a-real-settings-option"));
}
