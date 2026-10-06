use unproxy::desktop::{BundlePaths, ChildLifecycle, Preferences};

#[test]
fn preferences_have_expected_defaults_and_supported_flags() {
    let p = Preferences::default();
    assert_eq!(p.port, 3128);
    assert!(!p.negotiate && !p.proxytunnel && !p.direct_fallback && p.autostart);
    let args = p.child_args();
    assert!(args.windows(2).any(|a| a == ["--listen", "127.0.0.1:3128"]));
    assert!(args.contains(&"--pac-file".into()));
    assert!(p.effective_filter_lists().is_empty());
    let mut with_filters = p.clone();
    with_filters.filter_lists = Some(vec![
        std::path::PathBuf::from("/tmp/hosts.txt"),
        std::path::PathBuf::from("https://filters.example.test/hosts.txt"),
    ]);
    let filter_args = with_filters.child_args();
    assert_eq!(
        filter_args
            .windows(2)
            .filter(|args| args[0] == "--filter-list")
            .map(|args| args[1].as_str())
            .collect::<Vec<_>>(),
        ["/tmp/hosts.txt", "https://filters.example.test/hosts.txt"]
    );
    assert!(
        args.windows(2)
            .any(|a| a == ["--graceful-shutdown-timeout", "0"])
    );
    let mut p = p;
    p.port = 65535;
    p.proxytunnel = true;
    p.direct_fallback = true;
    p.negotiate = true;
    let a = p.child_args();
    assert!(a.contains(&"127.0.0.1:3128".into()));
    assert!(a.contains(&"--proxytunnel".into()));
    assert!(a.contains(&"--direct-fallback".into()));
    #[cfg(feature = "negotiate")]
    assert!(a.contains(&"--negotiate".into()));
    #[cfg(not(feature = "negotiate"))]
    assert!(!a.contains(&"--negotiate".into()));
}

#[test]
fn windows_settings_dialog_exposes_optional_local_and_remote_filter_sources() {
    let script = include_str!("../assets/unproxy-tray.ps1");
    for expected in [
        "Optional ad blocking lists (Pi-hole / hosts format)",
        "Add Local List...",
        "Add Remote URL...",
        "filterLists = $filterLists",
    ] {
        assert!(
            script.contains(expected),
            "missing Windows settings UI: {expected}"
        );
    }
}

#[test]
fn primary_listener_uses_the_first_configured_listener_or_loopback_default() {
    assert_eq!(Preferences::default().primary_listener(), "127.0.0.1:3128");

    let preferences = Preferences {
        listeners: Some(vec!["127.0.0.2:8080".into(), "127.0.0.1:3128".into()]),
        ..Preferences::default()
    };
    assert_eq!(preferences.primary_listener(), "127.0.0.2:8080");
}

#[test]
fn app_bundle_paths_point_to_packaged_child_and_login_item() {
    let exe = std::path::Path::new("/Applications/Unproxy.app/Contents/MacOS/unproxy-app");
    let paths = BundlePaths::from_main_executable(exe).unwrap();
    assert_eq!(
        paths.child,
        std::path::PathBuf::from("/Applications/Unproxy.app/Contents/MacOS/unproxy")
    );
    assert_eq!(
        paths.login_helper,
        std::path::PathBuf::from(
            "/Applications/Unproxy.app/Contents/Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper"
        )
    );
}

#[cfg(unix)]
#[test]
fn embedded_child_gets_no_rc_environment_without_suppressing_cli_arguments() {
    use std::{
        os::unix::fs::PermissionsExt,
        thread,
        time::{Duration, Instant},
    };

    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("norrc-value");
    let program = temp.path().join("child-fixture.sh");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\nprintf '%s' \"$UNPROXY_NORC\" > '{}'\nexec sleep 30\n",
            marker.display()
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&program).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&program, perms).unwrap();
    let prefs = Preferences {
        pac_file: temp.path().join("proxy.pac"),
        ..Preferences::default()
    };
    std::fs::write(
        &prefs.pac_file,
        "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
    )
    .unwrap();
    assert!(prefs.child_args().contains(&"--pac-file".into()));
    let mut child = ChildLifecycle::default();
    child.start(&program, &prefs).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "1");
    child.stop().unwrap();
}

#[cfg(windows)]
#[test]
fn windows_child_lifecycle_captures_arguments_and_reaps_children() {
    use std::{
        path::Path,
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    fn compile_child_fixture(directory: &Path, marker: &Path) -> std::path::PathBuf {
        let source = directory.join("child-fixture.rs");
        let executable = directory.join("child-fixture.exe");
        let source_text = r#"
use std::{fs, io::Write, thread, time::Duration};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    fs::write(@MARKER@, format!("{}|{}", std::env::var("UNPROXY_NORC").unwrap(), args)).unwrap();
    println!("fixture stdout");
    eprintln!("fixture stderr");
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    if std::env::current_exe().unwrap().file_stem().unwrap() == "child-exit" {
        std::process::exit(7);
    }
    thread::sleep(Duration::from_secs(30));
}
"#
        .replace("@MARKER@", &format!("{:?}", marker.to_string_lossy()));
        std::fs::write(&source, source_text).unwrap();
        let output = Command::new("rustc")
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rustc stdout: {}\nrustc stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        executable
    }

    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("child-arguments.txt");
    let sleeper = compile_child_fixture(temp.path(), &marker);
    let pac = temp.path().join("proxy.pac");
    std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    let prefs = Preferences {
        port: 4321,
        pac_file: pac,
        ..Preferences::default()
    };
    let support = temp.path().join("support");
    let mut child = ChildLifecycle::with_support_dir(support.clone());
    child.start(&sleeper, &prefs).unwrap();
    assert!(child.is_running());
    child.start(&sleeper, &prefs).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let captured = std::fs::read_to_string(&marker).expect("child did not capture its arguments");
    assert!(
        captured.starts_with("1|--listen 127.0.0.1:4321"),
        "{captured}"
    );
    assert!(captured.contains("--graceful-shutdown-timeout 0"));
    assert!(captured.contains("--pac-file"));

    child.stop().unwrap();
    assert!(!child.is_running());
    let log = std::fs::read_to_string(support.join("unproxy.log")).unwrap();
    assert!(log.contains("fixture stdout"));
    assert!(log.contains("fixture stderr"));

    let exits = temp.path().join("child-exit.exe");
    std::fs::copy(&sleeper, &exits).unwrap();
    child.start(&exits, &prefs).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.is_running() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!child.is_running());
    assert!(
        child
            .last_exit
            .as_deref()
            .unwrap()
            .contains("Proxy exited unexpectedly")
    );
    assert!(
        std::fs::read_to_string(support.join("unproxy.log"))
            .unwrap()
            .contains("Proxy exited unexpectedly")
    );
}

#[test]
fn preferences_roundtrip_and_child_lifecycle_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let p = Preferences::default();
    p.save(&path).unwrap();
    assert_eq!(Preferences::load(&path).unwrap(), p);
    let mut child = ChildLifecycle::default();
    assert!(!child.is_running());
    child.stop().unwrap();
}

#[test]
fn preferences_roundtrip_with_camel_case_settings_format_and_load_legacy_snake_case() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preferences.json");
    let pac_file = dir.path().join("proxy.pac");
    let prefs = Preferences {
        pac_file: pac_file.clone(),
        pac_files: Some(vec![pac_file.clone()]),
        filter_lists: Some(vec![
            dir.path().join("hosts.txt"),
            "https://filters.example.test/hosts.txt".into(),
        ]),
        direct_fallback: true,
        ..Preferences::default()
    };
    prefs.save(&path).unwrap();

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(saved.get("pacFile").is_some());
    assert!(saved.get("pacFiles").is_some());
    assert!(saved.get("filterLists").is_some());
    assert_eq!(saved["directFallback"], true);
    assert!(saved.get("pac_file").is_none());

    let helper_json = serde_json::json!({
        "pacFile": pac_file,
        "pacFiles": [pac_file],
        "filterLists": [dir.path().join("hosts.txt"), "https://filters.example.test/hosts.txt"],
        "directFallback": true
    })
    .to_string();
    let mut helper_bytes = vec![0xef, 0xbb, 0xbf];
    helper_bytes.extend_from_slice(helper_json.as_bytes());
    std::fs::write(&path, helper_bytes).unwrap();
    let helper_preferences = Preferences::load(&path).unwrap();
    assert!(helper_preferences.direct_fallback);
    assert_eq!(helper_preferences.pac_file, pac_file);
    assert_eq!(helper_preferences.pac_files, Some(vec![pac_file.clone()]));
    assert_eq!(helper_preferences.filter_lists, prefs.filter_lists);

    std::fs::write(
        &path,
        serde_json::json!({
            "pac_file": pac_file,
            "pac_files": [pac_file],
            "filter_lists": [dir.path().join("hosts.txt"), "https://filters.example.test/hosts.txt"],
            "direct_fallback": true
        })
        .to_string(),
    )
    .unwrap();
    let loaded = Preferences::load(&path).unwrap();
    assert!(loaded.direct_fallback);
    assert_eq!(loaded.pac_file, pac_file);
    assert_eq!(loaded.pac_files, Some(vec![pac_file]));
    assert_eq!(loaded.filter_lists, prefs.filter_lists);
}

#[test]
fn preferences_create_defaults_and_sanitize_invalid_saved_ports() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let defaults = Preferences::load(&path).unwrap();
    assert_eq!(defaults, Preferences::default());
    assert!(path.is_file());

    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    saved["port"] = serde_json::Value::from(-1);
    std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let repaired = Preferences::load(&path).unwrap();
    assert_eq!(repaired.port, u32::MAX);
    assert_eq!(repaired.effective_port(), 3128);

    saved["port"] = serde_json::Value::from(65534);
    std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    assert_eq!(Preferences::load(&path).unwrap().effective_port(), 65534);

    std::fs::write(&path, "not json").unwrap();
    assert!(Preferences::load(&path).is_err());
}

#[test]
fn child_start_rejects_relative_and_missing_pac_paths_before_launching() {
    let mut child = ChildLifecycle::default();
    let mut prefs = Preferences {
        pac_file: "relative.pac".into(),
        ..Preferences::default()
    };
    assert!(child.start(std::path::Path::new("unused"), &prefs).is_err());

    let temp = tempfile::tempdir().unwrap();
    prefs.pac_file = temp.path().join("missing.pac");
    let error = child
        .start(std::path::Path::new("unused"), &prefs)
        .unwrap_err();
    assert!(error.to_string().contains("PAC file is missing"));
    assert!(!child.is_running());
}

#[cfg(unix)]
#[test]
fn child_start_accepts_remote_pac_urls_without_treating_them_as_paths() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let program = temp.path().join("child-fixture.sh");
    std::fs::write(&program, "#!/bin/sh\nexec sleep 30\n").unwrap();
    let mut permissions = std::fs::metadata(&program).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&program, permissions).unwrap();

    let prefs = Preferences {
        pac_file: "HTTPS://proxy.example.org/company.pac".into(),
        ..Preferences::default()
    };
    assert!(
        prefs
            .child_args()
            .windows(2)
            .any(|args| { args == ["--pac-file", "https://proxy.example.org/company.pac"] })
    );

    let mut child = ChildLifecycle::with_support_dir(temp.path().to_owned());
    child.start(&program, &prefs).unwrap();
    assert!(child.is_running());
    child.stop().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn native_objc_bindings_validate_without_launching_or_mutating_settings() {
    unproxy::desktop::validate_native_bindings().unwrap();
}
