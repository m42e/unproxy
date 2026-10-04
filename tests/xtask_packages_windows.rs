#![cfg(windows)]

use std::{
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    root: tempfile::TempDir,
    tools: PathBuf,
    cargo_capture: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let tools = root.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let cargo_capture = root.path().join("cargo-arguments.txt");
        let source = root.path().join("cargo-shim.rs");
        std::fs::write(
            &source,
            r#"
use std::io::Write;

fn main() {
    let path = std::env::var_os("CARGO_SHIM_CAPTURE").expect("capture path");
    let args = std::env::args().skip(1).collect::<Vec<_>>().join("\n");
    let mut capture = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open captured cargo arguments");
    if capture.metadata().expect("read capture metadata").len() > 0 {
        writeln!(capture, "--CALL--").expect("separate captured cargo calls");
    }
    write!(capture, "{args}").expect("write captured cargo arguments");
}
"#,
        )
        .unwrap();
        let cargo = tools.join("cargo.exe");
        let output = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&cargo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rustc stdout: {}\nrustc stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        Self {
            root,
            tools,
            cargo_capture,
        }
    }

    fn binary(&self, target: &str, name: &str, bytes: &[u8]) {
        let path = self
            .root
            .path()
            .join("target")
            .join(target)
            .join("release")
            .join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn command(&self, args: &[&str]) -> Output {
        let mut paths = vec![self.tools.clone()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let path = std::env::join_paths(paths).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command
            .current_dir(self.root.path())
            .env("PATH", path)
            .env("CARGO_SHIM_CAPTURE", &self.cargo_capture)
            .env_remove("APPLE_SIGNING_IDENTITY")
            .env_remove("APPLE_INSTALLER_SIGNING_IDENTITY")
            .args(args);
        if let Some(pattern) = std::env::var_os("LLVM_PROFILE_FILE") {
            let pattern = pattern.to_string_lossy();
            let unique = if pattern.contains("%p") && pattern.contains("%m") {
                pattern.into_owned()
            } else {
                format!("{pattern}.child-%p-%m.profraw")
            };
            command.env("LLVM_PROFILE_FILE", unique);
        }
        command.output().unwrap()
    }
}

#[test]
fn xtask_build_check_coverage_and_bump_use_the_requested_cargo_commands() {
    let fixture = Fixture::new();

    let build = fixture.command(&[
        "build",
        "--target",
        "x86_64-pc-windows-msvc",
        "--no-negotiate",
    ]);
    assert!(build.status.success());
    assert_eq!(
        std::fs::read_to_string(&fixture.cargo_capture).unwrap(),
        "build\n--locked\n--bins\n--target\nx86_64-pc-windows-msvc\n--no-default-features"
    );

    let check = fixture.command(&["check"]);
    assert!(
        check.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let calls = std::fs::read_to_string(&fixture.cargo_capture).unwrap();
    assert!(calls.contains("--CALL--\nfmt\n--all\n--\n--check"));
    assert!(calls.contains("--CALL--\nclippy\n--locked\n--all-targets\n--all-features"));
    assert!(calls.contains("--CALL--\ntest\n--locked\n--all-features"));
    assert!(calls.ends_with("--CALL--\ntest\n--locked\n--no-default-features"));

    let report = fixture.command(&["coverage", "--output", "reports/coverage html"]);
    assert!(report.status.success());
    assert!(
        std::fs::read_to_string(&fixture.cargo_capture)
            .unwrap()
            .ends_with("--CALL--\nllvm-cov\n--html\n--output-dir\nreports/coverage html")
    );

    std::fs::write(
        fixture.root.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    let bump = fixture.command(&["bump", "patch"]);
    assert!(bump.status.success());
    assert!(String::from_utf8_lossy(&bump.stdout).contains("version=1.2.4"));
    assert!(
        std::fs::read_to_string(fixture.root.path().join("Cargo.toml"))
            .unwrap()
            .contains("version = \"1.2.4\"")
    );
    assert!(
        std::fs::read_to_string(&fixture.cargo_capture)
            .unwrap()
            .ends_with("--CALL--\ngenerate-lockfile")
    );
}

#[test]
fn windows_package_is_a_real_zip_with_the_staged_payload() {
    let fixture = Fixture::new();
    let target = "x86_64-pc-windows-msvc";
    fixture.binary(target, "unproxy.exe", b"fixture daemon");
    fixture.binary(target, "unproxy-tray.exe", b"fixture tray");

    let root = fixture.root.path();
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    std::fs::write(root.join("README.md"), "fixture README").unwrap();
    std::fs::write(
        assets.join("proxy.pac"),
        "function FindProxyForURL(){return 'DIRECT';}",
    )
    .unwrap();
    std::fs::write(assets.join("install.ps1"), "install script").unwrap();
    std::fs::write(assets.join("uninstall.ps1"), "uninstall script").unwrap();
    std::fs::write(assets.join("unproxy-tray.ps1"), "tray script").unwrap();

    let output = fixture.command(&[
        "package",
        "--format",
        "windows",
        "--target",
        target,
        "--output",
        "dist/windows package",
        "--no-negotiate",
    ]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.cargo_capture).unwrap(),
        format!("build\n--locked\n--bins\n--release\n--target\n{target}\n--no-default-features")
    );

    let archive = root.join(format!(
        "dist/windows package/unproxy-{}-{target}.zip",
        unproxy::VERSION
    ));
    let extracted = root.join("expanded Windows package");
    let extraction = fixture.command(&[
        "unpack",
        archive.to_str().unwrap(),
        extracted.to_str().unwrap(),
    ]);
    assert!(
        extraction.status.success(),
        "powershell stdout: {}\npowershell stderr: {}",
        String::from_utf8_lossy(&extraction.stdout),
        String::from_utf8_lossy(&extraction.stderr)
    );

    assert_eq!(
        std::fs::read(extracted.join("unproxy.exe")).unwrap(),
        b"fixture daemon"
    );
    assert_eq!(
        std::fs::read(extracted.join("UnproxyTray.exe")).unwrap(),
        b"fixture tray"
    );
    assert!(!extracted.join("unproxy-tray.exe").exists());
    assert_eq!(
        std::fs::read_to_string(extracted.join("README.md")).unwrap(),
        "fixture README"
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("proxy.pac.sample")).unwrap(),
        "function FindProxyForURL(){return 'DIRECT';}"
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("install.ps1")).unwrap(),
        "install script"
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("uninstall.ps1")).unwrap(),
        "uninstall script"
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("unproxy-tray.ps1")).unwrap(),
        "tray script"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(extracted.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["target"], target);
    assert_eq!(metadata["negotiate"], false);
    let components = metadata["components"].as_array().unwrap();
    for component in [
        "unproxy.exe",
        "UnproxyTray.exe",
        "unproxy-tray.ps1",
        "install.ps1",
        "uninstall.ps1",
        "metadata.json",
    ] {
        assert!(
            components.iter().any(|value| value == component),
            "package metadata is missing component {component}"
        );
    }
    assert!(
        root.join(format!(
            "dist/windows package/unproxy-{}-{target}.zip",
            unproxy::VERSION
        ))
        .is_file()
    );

    let native_binaries = root.join("target/release");
    std::fs::create_dir_all(&native_binaries).unwrap();
    for name in ["unproxy.exe", "unproxy-tray.exe"] {
        std::fs::write(native_binaries.join(name), format!("native fixture {name}")).unwrap();
    }
    let native = fixture.command(&["package", "--format", "native", "--output", "dist/native"]);
    assert!(
        native.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    let native_packages = std::fs::read_dir(root.join("dist/native"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "zip"))
        .collect::<Vec<_>>();
    assert_eq!(native_packages.len(), 1);
}

#[test]
fn windows_host_stages_debian_and_macos_packages_from_fixture_binaries() {
    let fixture = Fixture::new();
    let root = fixture.root.path();
    let target = root.join("target");
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    std::fs::write(root.join("README.md"), "fixture README").unwrap();
    std::fs::write(
        assets.join("proxy.pac"),
        "function FindProxyForURL(){return 'DIRECT';}",
    )
    .unwrap();
    std::fs::write(assets.join("unproxy.service"), "fixture service").unwrap();
    std::fs::write(assets.join("de.m42e.unproxy.plist"), "fixture launch agent").unwrap();
    std::fs::write(
        assets.join("app-entitlements.plist"),
        "fixture app entitlements",
    )
    .unwrap();
    std::fs::write(
        assets.join("child-entitlements.plist"),
        "fixture child entitlements",
    )
    .unwrap();
    for name in ["postinst", "prerm", "postrm"] {
        std::fs::write(assets.join(format!("debian-{name}")), "#!/bin/sh\nexit 0\n").unwrap();
    }
    for name in ["preinstall", "postinstall"] {
        std::fs::write(assets.join(format!("macos-{name}")), "#!/bin/sh\nexit 0\n").unwrap();
    }

    let debian_target = "x86_64-unknown-linux-gnu";
    let debian_binaries = target.join(debian_target).join("release");
    std::fs::create_dir_all(&debian_binaries).unwrap();
    std::fs::write(debian_binaries.join("unproxy"), "fixture linux daemon").unwrap();

    let darwin_target = "x86_64-apple-darwin";
    let darwin_binaries = target.join(darwin_target).join("release");
    std::fs::create_dir_all(&darwin_binaries).unwrap();
    for name in [
        "unproxy",
        "unproxyctl",
        "unproxy-register",
        "unproxy-system-proxy",
        "unproxy-app",
        "unproxy-login-helper",
    ] {
        std::fs::write(darwin_binaries.join(name), format!("fixture {name}")).unwrap();
    }

    let dpkg_capture = root.join("dpkg-arguments.txt");
    let dpkg_control = root.join("dpkg-control.txt");
    let dpkg_source = fixture.tools.join("dpkg-shim.rs");
    let dpkg_executable = fixture.tools.join("dpkg-deb.exe");
    let source = r#"
use std::{fs, io::Write};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut capture = fs::File::create(@CAPTURE@).unwrap();
    writeln!(capture, "{}", args.join("\n")).unwrap();
    fs::copy(
        std::path::Path::new(&args[2]).join("DEBIAN/control"),
        @CONTROL@,
    )
    .unwrap();
    fs::write(args.last().unwrap(), "fixture deb package").unwrap();
}
"#
    .replace(
        "@CAPTURE@",
        &format!("{:?}", dpkg_capture.to_string_lossy()),
    )
    .replace(
        "@CONTROL@",
        &format!("{:?}", dpkg_control.to_string_lossy()),
    );
    std::fs::write(&dpkg_source, source).unwrap();
    let compiled = Command::new("rustc")
        .arg(&dpkg_source)
        .arg("-o")
        .arg(&dpkg_executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "rustc stdout: {}\nrustc stderr: {}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );

    let deb = fixture.command(&[
        "package",
        "--format",
        "deb",
        "--target",
        debian_target,
        "--output",
        "dist/deb",
        "--no-negotiate",
    ]);
    assert!(
        deb.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&deb.stdout),
        String::from_utf8_lossy(&deb.stderr)
    );
    let deb_name = format!("unproxy-{}-{debian_target}.deb", unproxy::VERSION);
    assert!(root.join("dist/deb").join(deb_name).is_file());
    let captured = std::fs::read_to_string(&dpkg_capture).unwrap();
    assert!(captured.contains("--root-owner-group\n--build"));
    let control = std::fs::read_to_string(dpkg_control).unwrap();
    assert!(control.contains("Architecture: amd64"));
    assert!(control.contains("Depends: libc6, libssl3 | libssl3t64\n"));
    assert!(!control.contains("gssapi"));

    let macos = fixture.command(&[
        "package",
        "--format",
        "macos",
        "--target",
        darwin_target,
        "--output",
        "dist/macos",
    ]);
    assert!(
        macos.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&macos.stdout),
        String::from_utf8_lossy(&macos.stderr)
    );
    assert!(
        root.join("dist/macos")
            .join(format!(
                "unproxy-{}-{darwin_target}-staging.zip",
                unproxy::VERSION
            ))
            .is_file()
    );

    let app = fixture.command(&[
        "package",
        "--format",
        "app",
        "--target",
        darwin_target,
        "--output",
        "dist/app",
    ]);
    assert!(
        app.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&app.stdout),
        String::from_utf8_lossy(&app.stderr)
    );
    assert!(
        root.join("dist/app")
            .join(format!(
                "unproxy-{}-{darwin_target}-app.zip",
                unproxy::VERSION
            ))
            .is_file()
    );
    assert!(
        root.join("dist/app")
            .join(format!(
                "unproxy-{}-{darwin_target}-app-pkg-staging.zip",
                unproxy::VERSION
            ))
            .is_file()
    );
}
