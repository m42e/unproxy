use unproxy::desktop::{BundlePaths, ChildLifecycle, Preferences};

#[test]
fn preferences_have_expected_defaults_and_supported_flags() {
    let p = Preferences::default();
    assert_eq!(p.port, 8080);
    assert!(!p.negotiate && !p.proxytunnel && !p.direct_fallback && !p.autostart);
    let args = p.child_args();
    assert!(args.windows(2).any(|a| a == ["--listen", "127.0.0.1:8080"]));
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
        std::path::PathBuf::from("/Applications/Unproxy.app/Contents/Resources/unproxy")
    );
    assert_eq!(
        paths.login_helper,
        std::path::PathBuf::from(
            "/Applications/Unproxy.app/Contents/Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper"
        )
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

#[cfg(target_os = "macos")]
#[test]
fn native_objc_bindings_validate_without_launching_or_mutating_settings() {
    unproxy::desktop::validate_native_bindings().unwrap();
}
