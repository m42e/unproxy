use std::{
    net::TcpListener,
    path::Path,
    time::{Duration, Instant},
};
use unproxy::desktop::{ChildLifecycle, Preferences};

fn free_listener() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn setup(dir: &Path) -> (ChildLifecycle, Preferences, std::path::PathBuf) {
    let pac = dir.join("good.pac");
    std::fs::write(&pac, "function FindProxyForURL(){return 'DIRECT';}").unwrap();
    let prefs = Preferences {
        listeners: Some(vec![free_listener()]),
        pac_file: pac,
        ..Preferences::default()
    };
    let saved = dir.join("preferences.json");
    prefs.save(&saved).unwrap();
    let mut child = ChildLifecycle::with_support_dir(dir.to_owned());
    child
        .start(Path::new(env!("CARGO_BIN_EXE_unproxy")), &prefs)
        .unwrap();
    wait_ready(&mut child, &prefs);
    (child, prefs, saved)
}
fn wait_ready(child: &mut ChildLifecycle, prefs: &Preferences) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(child.is_running());
        if std::net::TcpStream::connect(prefs.primary_listener()).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "proxy did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn invalid_local_policy_and_occupied_listener_preserve_running_proxy_and_saved_settings() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, previous, saved) = setup(dir.path());
    let bad = dir.path().join("bad.pac");
    std::fs::write(&bad, "function {").unwrap();
    let updated = Preferences {
        pac_file: bad,
        ..previous.clone()
    };
    let error = child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &previous,
            &updated,
            |prefs| prefs.save(&saved),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("validate PAC"));
    wait_ready(&mut child, &previous);
    assert_eq!(Preferences::load(&saved).unwrap(), previous);

    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let updated = Preferences {
        listeners: Some(vec![occupied.local_addr().unwrap().to_string()]),
        ..previous.clone()
    };
    let error = child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &previous,
            &updated,
            |prefs| prefs.save(&saved),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("unavailable"));
    wait_ready(&mut child, &previous);
    assert_eq!(Preferences::load(&saved).unwrap(), previous);
}

#[test]
fn failed_remote_policy_restores_previous_process_without_saving_failed_settings() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, previous, saved) = setup(dir.path());
    let unavailable = free_listener();
    let updated = Preferences {
        pac_file: format!("http://{unavailable}/missing.pac").into(),
        ..previous.clone()
    };
    let error = child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &previous,
            &updated,
            |prefs| prefs.save(&saved),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("previous proxy settings restored"));
    wait_ready(&mut child, &previous);
    assert_eq!(Preferences::load(&saved).unwrap(), previous);
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("ready-")
    }));
}

#[test]
fn successful_listener_change_is_ready_before_save_and_save_failure_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, previous, saved) = setup(dir.path());
    let updated = Preferences {
        listeners: Some(vec![free_listener()]),
        ..previous.clone()
    };
    child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &previous,
            &updated,
            |prefs| {
                assert!(std::net::TcpStream::connect(prefs.primary_listener()).is_ok());
                prefs.save(&saved)
            },
        )
        .unwrap();
    assert_eq!(Preferences::load(&saved).unwrap(), updated);
    wait_ready(&mut child, &updated);
    let failed = Preferences {
        listeners: Some(vec![free_listener()]),
        ..updated.clone()
    };
    let error = child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &updated,
            &failed,
            |prefs| {
                prefs.save(&saved)?;
                anyhow::ensure!(prefs == &updated, "fixture persistence error after write");
                Ok(())
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("previous settings restored"));
    wait_ready(&mut child, &updated);
    assert_eq!(Preferences::load(&saved).unwrap(), updated);
}

#[test]
fn stopped_proxy_stays_stopped_and_login_preference_does_not_restart_running_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, previous, saved) = setup(dir.path());
    // Keep an active connection: a login-only setting must not kill the child.
    let mut connection = std::net::TcpStream::connect(previous.primary_listener()).unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let updated = Preferences {
        autostart: !previous.autostart,
        ..previous.clone()
    };
    child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &previous,
            &updated,
            |prefs| prefs.save(&saved),
        )
        .unwrap();
    use std::io::{Read, Write};
    connection
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0; 12];
    connection.read_exact(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "existing connection was lost"
    );

    child.stop().unwrap();
    let next = Preferences {
        listeners: Some(vec![free_listener()]),
        ..updated.clone()
    };
    child
        .apply_preferences(
            Path::new(env!("CARGO_BIN_EXE_unproxy")),
            &updated,
            &next,
            |prefs| prefs.save(&saved),
        )
        .unwrap();
    assert!(!child.is_running());
    assert_eq!(Preferences::load(&saved).unwrap(), next);
}
