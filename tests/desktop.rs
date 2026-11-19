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
fn windows_installer_checks_effective_listeners_and_manages_user_proxy_environment() {
    let installer = include_str!("../assets/install.ps1").replace("\r\n", "\n");
    let port_check = installer
        .find("Assert-ProxyListenersAvailable $configuredListeners")
        .expect("installer port check");
    let first_install_change = installer[port_check..]
        .find("Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe')")
        .map(|offset| port_check + offset)
        .expect("installer file changes");
    assert!(port_check < first_install_change);
    assert!(installer.contains("Get-NetTCPConnection -LocalPort $port -State Listen"));
    assert!(installer.contains("Assert-ProxyListenersAvailable $configuredListeners"));
    assert!(installer.contains("$configuredListeners = @($preferences.listeners"));
    assert!(installer.contains(
        "$configuredListeners = @(\"127.0.0.1:$configuredPort\", \"[::1]:$configuredPort\")"
    ));
    assert!(installer.contains("Test-ListenerAddressConflict $configuredAddress $_.LocalAddress"));
    assert!(!installer.contains("Get-NetTCPConnection -LocalPort 3128"));
    assert!(installer.contains("'127.0.0.1:3128', '[::1]:3128'"));
    assert!(installer.contains("proxy[\\s._-]*detox|detox[\\s._-]*proxy"));
    assert!(
        installer.contains("After uninstalling Proxy Detox, press Enter to check $endpoints again")
    );
    assert!(installer.contains("Get-Content $metadataFile -Raw | ConvertFrom-Json"));
    assert!(installer.contains("http_proxy = $proxyUrl"));
    assert!(installer.contains("https_proxy = $proxyUrl"));
    assert!(installer.contains("no_proxy = 'localhost,127.0.0.1,::1'"));
    assert!(installer.contains("SetEnvironmentVariable($name, $proxyEnvironment[$name], 'User')"));
    assert!(installer.contains("Remove-Item -LiteralPath $legacySettingsHelper -Force"));
    assert!(!installer.contains("Copy-Item (Join-Path $PSScriptRoot 'unproxy-tray.ps1')"));

    let uninstaller = include_str!("../assets/uninstall.ps1").replace("\r\n", "\n");
    assert!(uninstaller.contains("environment-before-install.json"));
    assert!(uninstaller.contains("$currentValue -ceq $installedValue"));
    assert!(uninstaller.contains("SetEnvironmentVariable($name, $previousValue, 'User')"));
}

#[test]
fn windows_service_installer_protects_policy_files_and_limits_service_write_access() {
    let installer = include_str!("../assets/install.ps1").replace("\r\n", "\n");
    let service_setup = installer
        .split("if ($AsService)")
        .nth(1)
        .expect("service installer branch");
    let protect = service_setup
        .find("Protect-ServiceData $serviceData")
        .expect("data ACL is secured");
    let protect_root = service_setup
        .find("Protect-ServiceRoot $serviceRoot")
        .expect("service root ACL is secured");
    let copy_binaries = service_setup
        .find("Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe')")
        .expect("service binary installation");
    let policy_migration = service_setup
        .find("$migrationReview = Join-Path $serviceData 'migration-review'")
        .expect("old settings are retained for explicit review");
    let config_write = service_setup
        .find("Set-Content -Encoding UTF8 $serviceConfig")
        .expect("fresh service settings are written");
    assert!(protect < copy_binaries);
    assert!(protect_root < protect);
    assert!(protect < policy_migration && policy_migration < config_write);
    assert!(service_setup.contains("$serviceListeners = @('127.0.0.1:3128', '[::1]:3128')"));
    assert!(!service_setup.contains("Get-ConfiguredServiceListeners $serviceConfig"));
    assert!(!service_setup.contains("$serviceData /grant '*S-1-5-20:(OI)(CI)M' /T"));
    assert!(
        installer
            .contains("Reparse points are not supported in the Unproxy service data directory")
    );
    assert!(installer.contains("'S-1-5-20'"));
    assert!(installer.contains("'S-1-5-32-544'"));
    assert!(installer.contains("'S-1-5-18'"));
    assert!(installer.contains("'S-1-5-32-545'"));
    assert!(installer.contains("function Assert-NoServicePathReparsePoints"));
    assert!(installer.contains("function Assert-ServiceFileHasSingleLink"));
    assert!(installer.contains("function Protect-ServiceRoot"));
    let root_acl = installer
        .split("function Protect-ServiceRoot")
        .nth(1)
        .unwrap()
        .split("function Protect-ServiceData")
        .next()
        .unwrap();
    assert!(
        root_acl.find("Assert-ServiceFileHasSingleLink").unwrap()
            < root_acl.find("/setowner '*S-1-5-32-544'").unwrap()
    );
    assert!(root_acl.find("/setowner '*S-1-5-32-544'").unwrap() < root_acl.find("/reset").unwrap());
    let data_acl = installer
        .split("function Protect-ServiceData")
        .nth(1)
        .unwrap()
        .split("function Grant-ServiceLogAccess")
        .next()
        .unwrap();
    assert!(
        data_acl.find("Assert-ServiceFileHasSingleLink").unwrap()
            < data_acl.find("/setowner '*S-1-5-32-544'").unwrap()
    );
    assert!(data_acl.find("/setowner '*S-1-5-32-544'").unwrap() < data_acl.find("/reset").unwrap());
    let service_read = installer
        .find("$networkServiceSid, 'ReadAndExecute'")
        .unwrap();
    let log_access = installer.find("function Grant-ServiceLogAccess").unwrap();
    let log_access_function = &installer[log_access..];
    assert!(log_access > service_read);
    assert!(log_access_function.contains("$networkServiceSid, 'Modify'"));
    assert!(log_access_function.contains("Logs cannot contain a reparse point"));
    assert!(log_access_function.contains("Assert-ServiceFileHasSingleLink $path"));
    assert!(
        log_access_function
            .find("foreach ($path in $files)")
            .unwrap()
            < log_access_function.find("$rootAcl = Get-Acl").unwrap()
    );
    assert!(
        log_access_function.contains("[System.IO.Directory]::EnumerateFileSystemEntries($path)")
    );
    assert!(installer.contains("Grant-ServiceLogAccess $logs $networkServiceSid"));
    assert!(installer.contains("function New-UnproxyManagementToken"));
    assert!(installer.contains("RNGCryptoServiceProvider"));
    assert!(installer.contains("BitConverter]::ToString($bytes)"));
    assert!(service_setup.contains("--management-token-file \"' + $serviceTokenFile"));
    assert!(service_setup.contains("$ownerSid, 'Read'"));
    assert!(service_setup.contains("$trayTokenFile = Join-Path $traySupport 'management.token'"));
    assert!(service_setup.contains("$allowedTokenSids -notcontains $rule.IdentityReference.Value"));
    assert!(
        service_setup.contains("$allowedTrayTokenSids -notcontains $rule.IdentityReference.Value")
    );
    assert!(service_setup.contains("$previousTokenOwner -eq $ownerSid.Value"));
    assert!(service_setup.contains("management.token.owner"));
    let token_provisioning = service_setup
        .split("$ownerSid = [Security.Principal.WindowsIdentity]")
        .nth(1)
        .unwrap()
        .split("Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe')")
        .next()
        .unwrap();
    assert!(!token_provisioning.contains("S-1-5-32-545"));
    assert!(!token_provisioning.contains("Everyone"));
    assert!(token_provisioning.contains("Test-Path -LiteralPath $serviceTokenFile"));
    assert!(token_provisioning.contains("$ownerSid, 'Read'"));
    assert!(token_provisioning.contains(
        "$systemSid.Value, $administratorsSid.Value, $networkServiceSid.Value, $ownerSid.Value"
    ));
    assert!(
        token_provisioning
            .find("Set-Acl -LiteralPath $trayTokenFile")
            .unwrap()
            < token_provisioning
                .find("[IO.File]::WriteAllText($trayTokenFile, $managementToken)")
                .unwrap()
    );
    assert!(service_setup.contains("Join-Path (Join-Path $serviceData 'logs') 'unproxy.log'"));
    assert!(service_setup.contains("$serviceData = Join-Path $serviceRoot 'data'"));
    assert!(!service_setup.contains("$env:ProgramData"));
    assert!(!service_setup.contains("$legacyServiceData"));
    let service_source = include_str!("../src/platform/windows_service.rs");
    assert!(service_source.contains("std::env::current_exe().ok()"));
    assert!(service_source.contains("service_config_path_from(executable"));
    let uninstaller = include_str!("../assets/uninstall.ps1");
    assert!(uninstaller.contains("$serviceData = Join-Path $serviceRoot 'data'"));
    assert!(uninstaller.contains("Where-Object { $_.FullName -ne $serviceData }"));
    assert!(uninstaller.contains("Remove-Item $legacyServiceData"));
    let troubleshooting = include_str!("../docs/troubleshooting.md");
    assert!(troubleshooting.contains("Service status is available to a normal user."));
    assert!(
        troubleshooting
            .contains("Run the following diagnostic from that elevated PowerShell session")
    );
    assert!(
        troubleshooting.contains("Administrators, SYSTEM, and the service account can read them.")
    );
}

#[test]
fn windows_package_scripts_never_relaunch_for_elevation() {
    for script in [
        include_str!("../assets/install.ps1"),
        include_str!("../assets/uninstall.ps1"),
    ] {
        let script = script.to_ascii_lowercase();
        assert!(!script.contains("-verb runas"));
        assert!(!script.contains("-executionpolicy bypass"));
        assert!(script.contains("-not $administrator -or $psscriptroot -notmatch $stagepattern"));
    }
}

#[test]
fn windows_service_setup_uses_an_independent_release_digest() {
    let docs = include_str!("../docs/windows-service-setup.md").replace("\r\n", "\n");
    let prose = docs.replace('\n', " ");
    let setup = docs
        .split("```powershell")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    assert!(prose.contains("over HTTPS on a trusted machine or session"));
    assert!(prose.contains("Do not use a checksum file from the same writable download directory"));
    let trusted_digest = setup.find("$expected = Read-Host").unwrap();
    let verify_archive = setup.find("Get-FileHash -LiteralPath $archive").unwrap();
    let extract_archive = setup
        .find("ExtractToDirectory($archive, $payload)")
        .unwrap();
    assert!(trusted_digest < verify_archive);
    assert!(verify_archive < extract_archive);
}

#[test]
fn installation_overview_links_to_online_only_service_commands() {
    let overview = include_str!("../docs/installation.md");
    assert!(overview.contains("https://m42e.github.io/unproxy/docs/windows-service-setup.html"));
    assert!(!overview.contains("Get-FileHash"));
    assert!(!overview.contains("-AsService"));
}

#[cfg(windows)]
#[test]
fn windows_service_setup_verifies_the_package_before_running_either_script() {
    let temp = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg("tests/windows_service_package.ps1")
        .arg("-WorkDir")
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PowerShell service package check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn windows_installer_port_probe_uses_custom_ports_and_ignores_unrelated_addresses() {
    let installer = include_str!("../assets/install.ps1");
    let functions_start = installer
        .find("function Test-ListenerAddressConflict")
        .unwrap();
    let installer_start = installer[functions_start..]
        .find("if ($AsService)")
        .map(|offset| functions_start + offset)
        .unwrap();
    let functions = &installer[functions_start..installer_start];
    let script = format!(
        r#"
{functions}
$script:queriedPorts = @()
function Get-NetTCPConnection {{
    param($LocalPort, $State, $ErrorAction)
    $script:queriedPorts += $LocalPort
    if ($LocalPort -eq 8080) {{
        @(
            [pscustomobject]@{{ LocalAddress = '127.0.0.2'; OwningProcess = 31 }},
            [pscustomobject]@{{ LocalAddress = '127.0.0.1'; OwningProcess = 32 }}
        )
    }}
}}
function Get-CimInstance {{
    param($Class, $Filter, $ErrorAction)
    [pscustomobject]@{{ Name = "process$Filter"; ExecutablePath = '' }}
}}
$specific = @(Get-ProxyPortOwners @('127.0.0.1:8080'))
if ($script:queriedPorts -notcontains 8080) {{ throw 'configured port was not queried' }}
if ($specific.Count -ne 1 -or $specific[0].ProcessId -ne 32) {{ throw 'unrelated address caused a false conflict' }}
$wildcard = @(Get-ProxyPortOwners @('0.0.0.0:8080'))
if ($wildcard.Count -ne 2) {{ throw 'wildcard listener did not detect both conflicts' }}
if (-not (Test-ListenerAddressConflict '::1' '::')) {{ throw 'IPv6 wildcard overlap was missed' }}
if (Test-ListenerAddressConflict '127.0.0.1' '127.0.0.2') {{ throw 'distinct IPv4 addresses conflicted' }}
$config = Join-Path $env:TEMP ('unproxy-config-' + [guid]::NewGuid().ToString() + '.rc')
$configContents = @'
# --listen 127.0.0.9:9000
--pac-file "C:\path with spaces\pac --listen 127.0.0.8:9001"
--listen 127.0.0.1:8081
-L="[::1]:8082"
-L [::1]:8083
--listen "127.0.0.1:8084"
'@
[System.IO.File]::WriteAllText($config, [char]0xFEFF + $configContents, [System.Text.Encoding]::UTF8)
$configuredServiceListeners = @(Get-ConfiguredServiceListeners $config)
$expectedServiceListeners = @('127.0.0.1:8081', '[::1]:8082', '[::1]:8083', '127.0.0.1:8084')
if (($configuredServiceListeners -join '|') -ne ($expectedServiceListeners -join '|')) {{ throw "service config listeners parsed incorrectly: $($configuredServiceListeners -join ', ')" }}
Remove-Item -LiteralPath $config -Force
"#
    );
    let temp = tempfile::tempdir().unwrap();
    let script_path = temp.path().join("installer-port-probe.ps1");
    std::fs::write(&script_path, script).unwrap();
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PowerShell installer probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    while Instant::now() < deadline {
        if std::fs::read_to_string(&marker).is_ok_and(|value| value == "1") {
            break;
        }
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
        release_info_url: Some("https://updates.example.test/unproxy.json".into()),
        direct_fallback: true,
        ..Preferences::default()
    };
    prefs.save(&path).unwrap();

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(saved.get("pacFile").is_some());
    assert!(saved.get("pacFiles").is_some());
    assert!(saved.get("filterLists").is_some());
    assert_eq!(
        saved["releaseInfoUrl"],
        "https://updates.example.test/unproxy.json"
    );
    assert_eq!(saved["directFallback"], true);
    assert!(saved.get("pac_file").is_none());

    let helper_json = serde_json::json!({
        "pacFile": pac_file,
        "pacFiles": [pac_file],
        "filterLists": [dir.path().join("hosts.txt"), "https://filters.example.test/hosts.txt"],
        "releaseInfoUrl": "https://updates.example.test/unproxy.json",
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
    assert_eq!(helper_preferences.release_info_url, prefs.release_info_url);

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

#[test]
fn status_page_url_tracks_the_current_primary_listener() {
    let mut preferences = Preferences::default();
    assert_eq!(preferences.status_url().unwrap(), "http://127.0.0.1:3128/");
    for (listeners, expected) in [
        (
            vec!["127.0.0.1:8080", "[::1]:8080"],
            "http://127.0.0.1:8080/",
        ),
        (vec!["[::1]:9090", "127.0.0.1:9090"], "http://[::1]:9090/"),
        (vec!["192.0.2.10:8000"], "http://192.0.2.10:8000/"),
    ] {
        preferences.listeners = Some(listeners.into_iter().map(str::to_owned).collect());
        assert_eq!(preferences.status_url().unwrap(), expected);
    }
    // Read the newly saved settings instead of remembering the address at startup.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preferences.json");
    preferences.save(&path).unwrap();
    assert_eq!(
        Preferences::load(&path).unwrap().status_url().unwrap(),
        "http://192.0.2.10:8000/"
    );
    for invalid in [
        "localhost:3128",
        "0.0.0.0:3128",
        "[::]:3128",
        "https://example.org/",
    ] {
        preferences.listeners = Some(vec![invalid.to_owned()]);
        assert!(
            preferences.status_url().is_err(),
            "invalid listener {invalid}"
        );
    }
}
