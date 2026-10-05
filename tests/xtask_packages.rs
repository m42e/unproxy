#![cfg(unix)]

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    root: tempfile::TempDir,
    tools: PathBuf,
    capture: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let tools = root.path().join("tools");
        let capture = root.path().join("capture");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::create_dir_all(&capture).unwrap();
        Self {
            root,
            tools,
            capture,
        }
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.tools.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn command(&self, args: &[&str]) -> Output {
        self.command_with_staging_collision(args, None)
    }

    fn command_with_staging_collision(
        &self,
        args: &[&str],
        collision_output: Option<&str>,
    ) -> Output {
        let current_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = self.tools.as_os_str().to_owned();
        path.push(":");
        path.push(current_path);
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command
            .current_dir(self.root.path())
            .env("PATH", path)
            .env("CAPTURE_DIR", &self.capture)
            .env_remove("APPLE_SIGNING_IDENTITY")
            .env_remove("APPLE_INSTALLER_SIGNING_IDENTITY")
            .args(args);
        if let Some(output) = collision_output {
            command.env("STAGING_COLLISION_DIR", output);
        }
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

    fn asset(&self, name: &str, contents: &str) {
        let path = self.root.path().join("assets").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn binary(&self, target: Option<&str>, name: &str) {
        let mut path = self.root.path().join("target");
        if let Some(target) = target {
            path.push(target);
        }
        path.push("release");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join(name), format!("fixture {name}")).unwrap();
    }

    fn reset_capture(&self) {
        std::fs::remove_dir_all(&self.capture).unwrap();
        std::fs::create_dir_all(&self.capture).unwrap();
    }
}

fn assert_ok(output: Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seed_common(f: &Fixture) {
    f.tool(
        "cargo",
        r#"if [ -n "${STAGING_COLLISION_DIR:-}" ]; then mkdir -p "$STAGING_COLLISION_DIR/.staging-$PPID"; fi
exit 0"#,
    );
    f.tool(
        "zip",
        r#"
out=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-qr" ]; then shift; out=$1; fi
    shift
done
printf 'fixture zip' > "$out"
n=1
while [ -e "$CAPTURE_DIR/zip-$n" ]; do n=$((n + 1)); done
mkdir -p "$CAPTURE_DIR/zip-$n"
cp -R ./. "$CAPTURE_DIR/zip-$n/"
"#,
    );
    std::fs::write(f.root.path().join("README.md"), "fixture README").unwrap();
    f.asset("proxy.pac", "function FindProxyForURL(){return 'DIRECT';}");
    f.asset("install.ps1", "install");
    f.asset("uninstall.ps1", "uninstall");
    f.asset("unproxy-tray.ps1", "tray");
    f.asset("app-entitlements.plist", "app entitlements");
    f.asset("child-entitlements.plist", "child entitlements");
    for hook in ["postinst", "prerm", "postrm"] {
        f.asset(&format!("debian-{hook}"), "#!/bin/sh\nexit 0");
    }
    for hook in ["preinstall", "postinstall"] {
        f.asset(&format!("macos-{hook}"), "#!/bin/sh\nexit 0");
    }
    f.asset("de.m42e.unproxy.plist", "launch agent");
    f.asset("unproxy.service", "service");
}

#[test]
fn portable_and_windows_packages_stage_expected_files() {
    let f = Fixture::new();
    seed_common(&f);
    for name in ["unproxy", "paceval", "undns"] {
        f.binary(None, name);
    }

    let portable = f.command(&[
        "package",
        "--format",
        "portable",
        "--output",
        "dist/portable",
    ]);
    assert_ok(portable);
    let portable = f.capture.join("zip-1");
    for name in [
        "unproxy",
        "paceval",
        "undns",
        "proxy.pac.sample",
        "README.md",
    ] {
        assert!(portable.join(name).is_file(), "missing {name}");
    }
    assert!(
        std::fs::read_to_string(portable.join("metadata.json"))
            .unwrap()
            .contains("\"negotiate\": true")
    );

    f.reset_capture();
    let target = "x86_64-pc-windows-gnu";
    for name in ["unproxy.exe", "unproxy-tray.exe"] {
        f.binary(Some(target), name);
    }
    let windows = f.command(&[
        "package",
        "--format",
        "windows",
        "--target",
        target,
        "--output",
        "dist/windows",
        "--no-negotiate",
    ]);
    assert_ok(windows);
    let staged = f.capture.join("zip-1");
    assert!(staged.join("unproxy.exe").is_file());
    assert!(staged.join("UnproxyTray.exe").is_file());
    assert!(!staged.join("unproxy-tray.exe").exists());
    assert!(staged.join("install.ps1").is_file());
    assert!(staged.join("uninstall.ps1").is_file());
    assert!(
        std::fs::read_to_string(staged.join("metadata.json"))
            .unwrap()
            .contains("\"negotiate\": false")
    );
}

#[test]
fn portable_package_is_a_readable_archive_with_the_expected_payload() {
    let f = Fixture::new();
    seed_common(&f);
    // Use the host archiver here: the staging tests above use a stub so they
    // can also assert the pre-archive directory layout.
    std::fs::remove_file(f.tools.join("zip")).unwrap();
    for name in ["unproxy", "paceval", "undns"] {
        f.binary(None, name);
    }

    assert_ok(f.command(&[
        "package",
        "--format",
        "portable",
        "--output",
        "dist/portable",
    ]));
    let output_dir = f.root.path().join("dist/portable");
    let archives = std::fs::read_dir(output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "zip"))
        .collect::<Vec<_>>();
    assert_eq!(archives.len(), 1);

    let inspection = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as package:
    names = {name.removeprefix('./') for name in package.namelist() if not name.endswith('/')}
    assert names == {'README.md', 'metadata.json', 'paceval', 'proxy.pac.sample', 'undns', 'unproxy'}, names
    assert package.read('unproxy') == b'fixture unproxy'
    assert package.read('paceval') == b'fixture paceval'
    assert package.read('undns') == b'fixture undns'
    metadata = json.loads(package.read('metadata.json'))
    assert metadata['version'] == sys.argv[2], metadata
    assert metadata['negotiate'] is True, metadata
    assert metadata['components'] == ['unproxy', 'paceval', 'undns'], metadata
"#,
        ])
        .arg(&archives[0])
        .arg(unproxy::VERSION)
        .output()
        .unwrap();
    assert!(
        inspection.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&inspection.stdout),
        String::from_utf8_lossy(&inspection.stderr)
    );
}

#[test]
fn debian_package_maps_architecture_and_stages_service_and_hooks() {
    let f = Fixture::new();
    seed_common(&f);
    let target = "aarch64-unknown-linux-gnu";
    f.binary(Some(target), "unproxy");
    f.tool(
        "dpkg-deb",
        r#"
while [ "$1" != "--build" ]; do shift; done
shift
root=$1
shift
out=$1
mkdir -p "$(dirname "$out")" "$CAPTURE_DIR/deb"
printf 'fixture deb' > "$out"
cp -R "$root"/. "$CAPTURE_DIR/deb/"
"#,
    );
    assert_ok(f.command(&[
        "package", "--format", "deb", "--target", target, "--output", "dist/deb",
    ]));
    let staged = f.capture.join("deb");
    let control = std::fs::read_to_string(staged.join("DEBIAN/control")).unwrap();
    assert!(control.contains("Architecture: arm64"));
    assert!(control.contains("libgssapi-krb5-2"));
    assert!(staged.join("DEBIAN/postinst").is_file());
    assert!(staged.join("usr/bin/unproxy").is_file());
    assert!(
        staged
            .join("usr/lib/systemd/user/unproxy.service")
            .is_file()
    );
    assert!(staged.join("usr/share/doc/unproxy/README.md").is_file());
}

#[test]
fn macos_service_and_app_packages_stage_bundles_and_call_pkgbuild() {
    let f = Fixture::new();
    seed_common(&f);
    let target = "aarch64-apple-darwin";
    f.tool(
        "pkgbuild",
        r#"
printf '%s\n' "$@" > "$CAPTURE_DIR/pkgbuild.args"
root=""
hooks=""
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) shift; root=$1 ;;
        --scripts) shift; hooks=$1 ;;
    esac
    out=$1
    shift
done
n=1
while [ -e "$CAPTURE_DIR/pkgroot-$n" ]; do n=$((n + 1)); done
mkdir -p "$CAPTURE_DIR/pkgroot-$n"
cp -R "$root"/. "$CAPTURE_DIR/pkgroot-$n/"
if [ -n "$hooks" ]; then cp -R "$hooks" "$CAPTURE_DIR/hooks-$n"; fi
printf 'fixture pkg' > "$out"
"#,
    );
    for name in [
        "unproxy",
        "unproxyctl",
        "unproxy-register",
        "unproxy-system-proxy",
    ] {
        f.binary(Some(target), name);
    }
    let service = f.command(&[
        "package",
        "--format",
        "macos",
        "--target",
        target,
        "--output",
        "dist/macos",
    ]);
    assert_ok(service);
    if cfg!(target_os = "macos") {
        assert!(
            f.capture
                .join("pkgroot-1/opt/unproxy/bin/unproxy")
                .is_file()
        );
        assert!(
            f.capture
                .join("pkgroot-1/Library/LaunchAgents/de.m42e.unproxy.plist")
                .is_file()
        );
        assert!(f.capture.join("hooks-1/preinstall").is_file());
        assert!(f.capture.join("hooks-1/postinstall").is_file());
        assert!(
            std::fs::read_to_string(f.capture.join("pkgbuild.args"))
                .unwrap()
                .contains("de.m42e.unproxy")
        );
    } else {
        assert!(f.capture.join("zip-1/opt/unproxy/bin/unproxy").is_file());
    }

    f.reset_capture();
    for name in ["unproxy-app", "unproxy", "unproxy-login-helper"] {
        f.binary(Some(target), name);
    }
    let app = f.command(&[
        "package", "--format", "app", "--target", target, "--output", "dist/app",
    ]);
    assert_ok(app);
    if cfg!(target_os = "macos") {
        assert!(
            f.capture
                .join("pkgroot-1/Applications/Unproxy.app/Contents/MacOS/unproxy-app")
                .is_file()
        );
        assert!(f.capture.join("pkgroot-1/Applications/Unproxy.app/Contents/Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper").is_file());
        assert!(
            f.capture
                .join("pkgroot-1/Applications/Unproxy.app/Contents/Resources/metadata.json")
                .is_file()
        );
        assert!(
            f.capture
                .join("pkgroot-1/Applications/Unproxy.app/Contents/Info.plist")
                .is_file()
        );
    } else {
        assert!(
            f.capture
                .join("zip-1/Unproxy.app/Contents/MacOS/unproxy-app")
                .is_file()
        );
        assert!(f.capture.join("zip-1/Unproxy.app/Contents/Library/LoginItems/UnproxyLoginHelper.app/Contents/MacOS/unproxy-login-helper").is_file());
        assert!(
            f.capture
                .join("zip-2/Applications/Unproxy.app/Contents/Info.plist")
                .is_file()
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn native_package_builds_all_supported_macos_formats() {
    let f = Fixture::new();
    seed_common(&f);
    for name in [
        "unproxy",
        "paceval",
        "undns",
        "unproxyctl",
        "unproxy-register",
        "unproxy-system-proxy",
        "unproxy-app",
        "unproxy-login-helper",
    ] {
        f.binary(None, name);
    }
    f.tool(
        "pkgbuild",
        r#"
out=""
while [ "$#" -gt 0 ]; do out=$1; shift; done
printf 'fixture pkg' > "$out"
"#,
    );

    let output = f.command(&["package", "--format", "native", "--output", "dist/native"]);
    assert_ok(output);
    let versioned = format!(
        "unproxy-{}-{}-{}",
        unproxy::VERSION,
        unproxy::ARCH,
        unproxy::PLATFORM
    );
    assert!(
        f.root
            .path()
            .join(format!("dist/native/{versioned}.zip"))
            .is_file()
    );
    assert!(
        f.root
            .path()
            .join(format!("dist/native/{versioned}.pkg"))
            .is_file()
    );
    assert!(
        f.root
            .path()
            .join(format!("dist/native/{versioned}-app.pkg"))
            .is_file()
    );
    assert!(
        !f.root
            .path()
            .join(format!("dist/native/.staging-{}", std::process::id()))
            .exists()
    );
    assert!(
        !f.capture
            .join("zip-1/Unproxy.app/Contents/entitlements.plist")
            .exists()
    );
    assert!(
        !f.capture
            .join("zip-1/Unproxy.app/Contents/child-entitlements.plist")
            .exists()
    );
}

#[test]
fn build_coverage_and_check_dispatch_use_expected_cargo_arguments() {
    let f = Fixture::new();
    f.tool(
        "cargo",
        r#"
printf '<%s>\n' "$@" >> "$CAPTURE_DIR/cargo.calls"
for arg in "$@"; do
    if [ "${FAIL_CARGO_ON:-}" = "$arg" ]; then exit 7; fi
done
"#,
    );

    assert_ok(f.command(&[
        "build",
        "--release",
        "--target",
        "fixture-target",
        "--no-negotiate",
    ]));
    let build = std::fs::read_to_string(f.capture.join("cargo.calls")).unwrap();
    assert_eq!(
        build,
        "<build>\n<--locked>\n<--bins>\n<--release>\n<--target>\n<fixture-target>\n<--no-default-features>\n"
    );

    f.reset_capture();
    assert_ok(f.command(&["coverage", "--output", "coverage report"]));
    assert_eq!(
        std::fs::read_to_string(f.capture.join("cargo.calls")).unwrap(),
        "<llvm-cov>\n<--html>\n<--output-dir>\n<coverage report>\n"
    );

    f.reset_capture();
    let check = f.command(&["check"]);
    assert_ok(check);
    assert_eq!(
        std::fs::read_to_string(f.capture.join("cargo.calls")).unwrap(),
        "<fmt>\n<--all>\n<-->\n<--check>\n<clippy>\n<--locked>\n<--all-targets>\n<--all-features>\n<-->\n<-D>\n<warnings>\n<test>\n<--locked>\n<--all-features>\n<--target-dir>\n<target/xtask-tests>\n<test>\n<--locked>\n<--no-default-features>\n<--target-dir>\n<target/xtask-tests>\n"
    );

    f.reset_capture();
    f.tool(
        "cargo",
        r#"printf '<%s>\n' "$@" >> "$CAPTURE_DIR/cargo.calls"; if [ "$1" = "clippy" ]; then exit 7; fi"#,
    );
    let failed = f.command(&["check"]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("exited with"));
    let calls = std::fs::read_to_string(f.capture.join("cargo.calls")).unwrap();
    assert!(calls.contains("<clippy>"));
    assert!(!calls.contains("<--all-features>\n<test>"));
}

#[test]
fn unpack_and_bump_report_outputs_and_preserve_command_failures() {
    let f = Fixture::new();
    f.tool(
        "unzip",
        r#"
printf '<%s>\n' "$@" > "$CAPTURE_DIR/unzip.args"
while [ "$1" != "-d" ]; do shift; done
shift
printf 'expanded archive' > "$1/inside.txt"
"#,
    );
    let unpack = f.command(&["unpack", "source bundle.zip", "expanded files"]);
    assert_ok(unpack);
    assert_eq!(
        std::fs::read_to_string(f.capture.join("unzip.args")).unwrap(),
        "<-q>\n<source bundle.zip>\n<-d>\n<expanded files>\n"
    );
    assert_eq!(
        std::fs::read_to_string(f.root.path().join("expanded files/inside.txt")).unwrap(),
        "expanded archive"
    );

    std::fs::write(
        f.root.path().join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='1.2.3'\n",
    )
    .unwrap();
    f.tool(
        "cargo",
        r#"printf '<%s>\n' "$@" > "$CAPTURE_DIR/cargo.bump"; if [ "${FAIL_LOCKFILE:-}" = 1 ]; then exit 8; fi"#,
    );
    let bump = f.command(&["bump", "minor"]);
    let bump_stdout = String::from_utf8_lossy(&bump.stdout).into_owned();
    assert_ok(bump);
    assert!(bump_stdout.contains("version=1.3.0"));
    assert!(
        std::fs::read_to_string(f.root.path().join("Cargo.toml"))
            .unwrap()
            .contains("version = \"1.3.0\"")
    );
    assert_eq!(
        std::fs::read_to_string(f.capture.join("cargo.bump")).unwrap(),
        "<generate-lockfile>\n"
    );

    f.tool("cargo", "exit 8");
    let lockfile_failure = f.command(&["bump", "patch"]);
    assert!(!lockfile_failure.status.success());
    assert!(String::from_utf8_lossy(&lockfile_failure.stderr).contains("exited with"));
    assert!(
        std::fs::read_to_string(f.root.path().join("Cargo.toml"))
            .unwrap()
            .contains("version = \"1.3.1\"")
    );
}

#[test]
fn package_rejects_incompatible_targets_and_reports_missing_binaries_and_collisions() {
    let f = Fixture::new();
    f.tool("cargo", "exit 9");
    let invalid = f.command(&[
        "package",
        "--format",
        "windows",
        "--target",
        "aarch64-unknown-linux-gnu",
        "--output",
        "dist",
    ]);
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("Windows ZIPs require a Windows target")
    );
    assert!(!f.root.path().join("dist").exists());

    seed_common(&f);
    for name in ["unproxy", "paceval"] {
        f.binary(None, name);
    }
    let missing = f.command(&["package", "--format", "portable", "--output", "dist"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("copying executable"));

    f.binary(None, "undns");
    let collision = f.command_with_staging_collision(
        &["package", "--format", "portable", "--output", "dist"],
        Some("dist"),
    );
    assert!(!collision.status.success());
    assert!(
        String::from_utf8_lossy(&collision.stderr).contains("staging directory already exists")
    );
}

#[test]
fn documentation_generation_sorts_pages_and_validates_repository_names() {
    let f = Fixture::new();
    f.tool(
        "git",
        r#"
while [ "$1" != "-o" ]; do shift; done
shift
printf 'fixture archive' > "$1"
"#,
    );
    std::fs::create_dir_all(f.root.path().join("docs")).unwrap();
    std::fs::write(f.root.path().join("docs/z.md"), "# Last\n").unwrap();
    std::fs::write(f.root.path().join("docs/a.md"), "# First\n").unwrap();
    std::fs::create_dir_all(f.root.path().join("site")).unwrap();
    std::fs::write(
        f.root.path().join("site/index.html"),
        "@VERSION@ @REPOSITORY@",
    )
    .unwrap();

    assert_ok(f.command(&[
        "docs",
        "--output",
        "dist/site",
        "--repository",
        "owner/project",
    ]));
    let page = std::fs::read_to_string(f.root.path().join("dist/site/docs/a.html")).unwrap();
    assert!(page.contains("<h1>First</h1>"));
    let landing = std::fs::read_to_string(f.root.path().join("dist/site/index.html")).unwrap();
    assert!(landing.contains("owner/project"));
    assert!(f.root.path().join("dist/site/source.zip").is_file());
    let nav = std::fs::read_to_string(f.root.path().join("dist/site/docs/z.html")).unwrap();
    assert!(nav.find("a.html").unwrap() < nav.find("z.html").unwrap());

    let invalid = f.command(&[
        "docs",
        "--output",
        "bad-site",
        "--repository",
        "owner/name/extra",
    ]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("repository must be OWNER/NAME"));
}
