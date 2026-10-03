#![cfg(windows)]

use std::{
    path::{Path, PathBuf},
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
fn main() {
    let path = std::env::var_os("CARGO_SHIM_CAPTURE").expect("capture path");
    let args = std::env::args().skip(1).collect::<Vec<_>>().join("\n");
    std::fs::write(path, args).expect("write captured cargo arguments");
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

fn powershell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
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
    let script = format!(
        "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
        powershell_literal(&archive),
        powershell_literal(&extracted)
    );
    let extraction = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
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
}
