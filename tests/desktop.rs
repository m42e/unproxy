use unproxy::desktop::{ChildLifecycle, Preferences};

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
    assert!(a.contains(&"--negotiate".into()));
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
