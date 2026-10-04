use unproxy::desktop::{BundlePaths, ChildLifecycle, Preferences};

#[test]
fn preferences_have_expected_defaults_and_supported_flags() {
    let p = Preferences::default();
    assert_eq!(p.port, 3128);
    assert!(!p.negotiate && !p.proxytunnel && !p.direct_fallback && p.autostart);
    let args = p.child_args();
    assert!(args.windows(2).any(|a| a == ["--listen", "127.0.0.1:3128"]));
    assert!(args.contains(&"--pac-file".into()));
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
