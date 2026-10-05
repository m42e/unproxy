//! Platform-aware development and artifact assembly entry point.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use unproxy::{
    desktop::DesktopDefaults,
    tools::{copy_tree, html_escape},
};

#[derive(Parser)]
#[command(
    about = "Build, validate, document and package Unproxy",
    long_about = "Development and release utility for the Unproxy repository. Select a subcommand to build binaries, run the project checks, generate documentation, package releases, or manage release metadata."
)]
struct Args {
    #[command(subcommand)]
    command: Task,
}
#[derive(Subcommand)]
enum Task {
    Build {
        #[arg(long)]
        release: bool,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        no_negotiate: bool,
        /// TOML file with first-run desktop preferences to embed in the build.
        #[arg(long)]
        defaults: Option<PathBuf>,
    },
    Check,
    Test,
    Docs {
        #[arg(long, default_value = "dist/site")]
        output: PathBuf,
        #[arg(long, env = "GITHUB_REPOSITORY")]
        repository: Option<String>,
    },
    Package {
        #[arg(long, value_enum)]
        format: Format,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "dist")]
        output: PathBuf,
        #[arg(long)]
        no_negotiate: bool,
        /// TOML file with first-run desktop preferences for the distributable.
        #[arg(long)]
        defaults: Option<PathBuf>,
    },
    Copy {
        source: PathBuf,
        output: PathBuf,
    },
    Unpack {
        archive: PathBuf,
        output: PathBuf,
    },
    Bump {
        #[arg(value_parser = ["patch", "minor", "major"])]
        part: String,
    },
    ReleaseNotes {
        #[arg(default_value = "CHANGELOG.md")]
        changelog: PathBuf,
    },
    Coverage {
        #[arg(long, default_value = "dist/coverage")]
        output: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Native,
    Portable,
    Windows,
    Deb,
    Macos,
    App,
}
fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("running {command:?}"))?;
    anyhow::ensure!(status.success(), "command {command:?} exited with {status}");
    Ok(())
}
fn test() -> Result<()> {
    // Keep test builds separate from the running xtask executable. Windows
    // cannot replace target/debug/xtask.exe while `cargo xtask` is executing it.
    let target_dir = "target/xtask-tests";
    run(Command::new("cargo").args([
        "test",
        "--locked",
        "--all-features",
        "--target-dir",
        target_dir,
    ]))?;
    run(Command::new("cargo").args([
        "test",
        "--locked",
        "--no-default-features",
        "--target-dir",
        target_dir,
    ]))
}
fn run_pkgbuild(command: &mut Command) -> Result<()> {
    let output = command
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {command:?}"))?
        .wait_with_output()?;

    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    for line in output.stderr.split_inclusive(|byte| *byte == b'\n') {
        let line_without_newline = line.strip_suffix(b"\n").unwrap_or(line);
        let line_without_newline = line_without_newline
            .strip_suffix(b"\r")
            .unwrap_or(line_without_newline);
        // Recent macOS pkgbuild emits this while preserving extended attributes,
        // even when the package is written successfully.
        if line_without_newline != b"write: Permission denied" {
            stderr.write_all(line)?;
        }
    }
    drop(stderr);

    anyhow::ensure!(
        output.status.success(),
        "command {command:?} exited with {}",
        output.status
    );
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Task::Build {
            release,
            target,
            no_negotiate,
            defaults,
        } => {
            let defaults = read_desktop_defaults(defaults.as_deref())?;
            validate_defaults(defaults.as_ref(), no_negotiate)?;
            build(release, target.as_deref(), no_negotiate, defaults.as_ref())
        }
        Task::Check => {
            run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))?;
            run(Command::new("cargo").args([
                "clippy",
                "--locked",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]))?;
            test()
        }
        Task::Test => test(),
        Task::Docs { output, repository } => docs(&output, repository.as_deref()),
        Task::Package {
            format,
            target,
            output,
            no_negotiate,
            defaults,
        } => package(
            format,
            target.as_deref(),
            &output,
            no_negotiate,
            defaults.as_deref(),
        ),
        Task::Copy { source, output } => {
            if source.is_dir() {
                copy_tree(&source, &output)
            } else {
                if let Some(parent) = output.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(source, output)?;
                Ok(())
            }
        }
        Task::Unpack { archive, output } => {
            std::fs::create_dir_all(&output)?;
            if cfg!(windows) {
                powershell(&format!(
                    "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
                    ps_literal(&archive),
                    ps_literal(&output)
                ))
            } else {
                run(Command::new("unzip")
                    .arg("-q")
                    .arg(archive)
                    .arg("-d")
                    .arg(output))
            }
        }
        Task::Bump { part } => {
            let version = unproxy::tools::bump_version(Path::new("Cargo.toml"), &part)?;
            println!("version={version}");
            run(Command::new("cargo").arg("generate-lockfile"))
        }
        Task::ReleaseNotes { changelog } => {
            let text = std::fs::read_to_string(changelog)?;
            let mut found = false;
            for line in text.lines() {
                if line.starts_with("## ") {
                    if found {
                        break;
                    }
                    found = true;
                }
                if found {
                    println!("{line}");
                }
            }
            anyhow::ensure!(found, "changelog contains no release section");
            Ok(())
        }
        Task::Coverage { output } => run(Command::new("cargo")
            .args(["llvm-cov", "--html", "--output-dir"])
            .arg(output)),
    }
}
fn read_desktop_defaults(path: Option<&Path>) -> Result<Option<DesktopDefaults>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading desktop defaults from {}", path.display()))?;
    let defaults: DesktopDefaults = toml::from_str(&source)
        .with_context(|| format!("parsing desktop defaults from {}", path.display()))?;
    if let Some(port) = defaults.port {
        anyhow::ensure!(
            (1024..=65534).contains(&port),
            "desktop default port must be between 1024 and 65534"
        );
    }
    if let Some(path) = &defaults.pac_file {
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "desktop default PAC path is empty"
        );
    }
    Ok(Some(defaults))
}

fn validate_defaults(defaults: Option<&DesktopDefaults>, no_negotiate: bool) -> Result<()> {
    anyhow::ensure!(
        !no_negotiate || defaults.is_none_or(|d| d.negotiate != Some(true)),
        "desktop defaults enable Negotiate, but --no-negotiate disables that build feature"
    );
    Ok(())
}

fn build(
    release: bool,
    target: Option<&str>,
    no_negotiate: bool,
    defaults: Option<&DesktopDefaults>,
) -> Result<()> {
    let mut command = Command::new("cargo");
    command.args(["build", "--locked", "--bins"]);
    if release {
        command.arg("--release");
    }
    if let Some(target) = target {
        command.args(["--target", target]);
    }
    if no_negotiate {
        command.arg("--no-default-features");
    }
    if let Some(defaults) = defaults {
        command.env(
            "UNPROXY_DESKTOP_DEFAULTS_JSON",
            serde_json::to_string(defaults)?,
        );
    } else {
        command.env_remove("UNPROXY_DESKTOP_DEFAULTS_JSON");
    }
    run(&mut command)
}
fn ps_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}
fn powershell(script: &str) -> Result<()> {
    run(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]))
}
fn zip(directory: &Path, output: &Path) -> Result<()> {
    let absolute = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    if absolute.exists() {
        std::fs::remove_file(&absolute)?;
    }
    if cfg!(windows) {
        powershell(&format!(
            "Get-ChildItem -LiteralPath {} -Force | Compress-Archive -DestinationPath {} -Force",
            ps_literal(directory),
            ps_literal(&absolute)
        ))
    } else {
        run(Command::new("zip")
            .current_dir(directory)
            .arg("-qr")
            .arg(absolute)
            .arg("."))
    }
}
fn executable(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(from, to).with_context(|| format!("copying executable {}", from.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
fn sign_macos_code(path: &Path, entitlements: Option<&Path>) -> Result<()> {
    let Ok(identity) = std::env::var("APPLE_SIGNING_IDENTITY") else {
        return Ok(());
    };
    if identity.trim().is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        cfg!(target_os = "macos"),
        "APPLE_SIGNING_IDENTITY can only be used when packaging on macOS"
    );
    let mut command = Command::new("codesign");
    command.args(["--force", "--options", "runtime", "--timestamp"]);
    if let Some(entitlements) = entitlements {
        command.arg("--entitlements").arg(entitlements);
    }
    command.args(["--sign", &identity]).arg(path);
    run(&mut command).with_context(|| format!("signing {}", path.display()))?;
    run(Command::new("codesign")
        .arg("--verify")
        .arg("--verbose=2")
        .arg(path))
    .with_context(|| format!("verifying signature for {}", path.display()))
}
fn pkgbuild_signing_args(command: &mut Command) {
    if let Ok(identity) = std::env::var("APPLE_INSTALLER_SIGNING_IDENTITY")
        && !identity.trim().is_empty()
    {
        command.arg("--sign").arg(identity);
    }
}
fn windows_desktop_defaults(defaults: Option<&DesktopDefaults>) -> serde_json::Value {
    let defaults = defaults.cloned().unwrap_or_default();
    serde_json::json!({
        "port": defaults.port.unwrap_or(3128),
        "pacFile": defaults.pac_file.map(|path| path.to_string_lossy().into_owned()).unwrap_or_else(|| "proxy.pac".into()),
        "negotiate": defaults.negotiate.unwrap_or(false),
        "proxytunnel": defaults.proxytunnel.unwrap_or(false),
        "directFallback": defaults.direct_fallback.unwrap_or(false),
        "autostart": defaults.autostart.unwrap_or(true),
    })
}
fn package(
    format: Format,
    target: Option<&str>,
    output: &Path,
    no_negotiate: bool,
    defaults_path: Option<&Path>,
) -> Result<()> {
    let formats: Vec<Format> = if matches!(format, Format::Native) {
        anyhow::ensure!(
            target.is_none(),
            "the native package set cannot be combined with --target"
        );
        if cfg!(target_os = "windows") {
            vec![Format::Windows]
        } else if cfg!(target_os = "macos") {
            vec![Format::Portable, Format::Macos, Format::App]
        } else if cfg!(target_os = "linux") {
            vec![Format::Portable, Format::Deb]
        } else {
            bail!("native packages are not configured for this operating system")
        }
    } else {
        vec![format]
    };
    let defaults = read_desktop_defaults(defaults_path)?;
    validate_defaults(defaults.as_ref(), no_negotiate)?;
    anyhow::ensure!(
        defaults.is_none()
            || formats
                .iter()
                .any(|f| matches!(f, Format::Windows | Format::App)),
        "--defaults applies to Windows tray and macOS app packages"
    );
    anyhow::ensure!(
        !matches!(format, Format::Windows)
            || target.map_or(cfg!(windows), |t| t.contains("windows")),
        "Windows ZIPs require a Windows target when packaging from another operating system"
    );
    build(true, target, no_negotiate, defaults.as_ref())?;
    std::fs::create_dir_all(output)?;
    let target_name = target
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}-{}", unproxy::ARCH, unproxy::PLATFORM));
    let windows = target_name.contains("windows") || matches!(format, Format::Windows);
    let suffix = if windows { ".exe" } else { "" };
    let binary_dir = target
        .map(|t| PathBuf::from("target").join(t).join("release"))
        .unwrap_or_else(|| PathBuf::from("target/release"));
    let staging = output.join(format!(".staging-{}", std::process::id()));
    // Fresh process-specific staging avoids merging artifacts from prior builds.
    anyhow::ensure!(
        !staging.exists(),
        "staging directory already exists: {}",
        staging.display()
    );
    std::fs::create_dir_all(&staging)?;
    let source_bin = |name: &str| binary_dir.join(format!("{name}{suffix}"));
    let package_base = format!("unproxy-{}-{target_name}", unproxy::VERSION);
    for format in formats {
        let mut package_name = package_base.clone();
        match format {
            Format::Native => unreachable!("native is expanded before packaging"),
            Format::Portable | Format::Windows => {
                let windows_package = matches!(format, Format::Windows);
                let mut bins = if windows_package {
                    vec!["unproxy", "unproxy-tray"]
                } else {
                    vec!["unproxy", "paceval", "undns"]
                };
                let mut windows_components = vec![
                    "unproxy.exe",
                    "UnproxyTray.exe",
                    "unproxy-tray.ps1",
                    "tray-icons",
                    "install.ps1",
                    "uninstall.ps1",
                    "metadata.json",
                ];
                if windows_package {
                    for name in ["unproxy-register", "unproxyctl"] {
                        if source_bin(name).is_file() {
                            bins.push(name);
                            windows_components.push(if name == "unproxy-register" {
                                "unproxy-register.exe"
                            } else {
                                "unproxyctl.exe"
                            });
                        }
                    }
                }
                for name in bins {
                    let output_name = if name == "unproxy-tray" {
                        "UnproxyTray"
                    } else {
                        name
                    };
                    executable(
                        &source_bin(name),
                        &staging.join(format!("{output_name}{suffix}")),
                    )?;
                }
                if matches!(format, Format::Windows) {
                    std::fs::copy("assets/install.ps1", staging.join("install.ps1"))?;
                    std::fs::copy("assets/uninstall.ps1", staging.join("uninstall.ps1"))?;
                    std::fs::copy("assets/unproxy-tray.ps1", staging.join("unproxy-tray.ps1"))?;
                    let icons = Path::new("assets/tray-icons");
                    if icons.is_dir() {
                        let destination = staging.join("tray-icons");
                        std::fs::create_dir_all(&destination)?;
                        for icon in std::fs::read_dir(icons)? {
                            let icon = icon?.path();
                            if icon.extension().is_some_and(|ext| ext == "ico") {
                                std::fs::copy(&icon, destination.join(icon.file_name().unwrap()))?;
                            }
                        }
                    }
                }
                std::fs::copy("README.md", staging.join("README.md"))?;
                std::fs::copy("assets/proxy.pac", staging.join("proxy.pac.sample"))?;
                let mut metadata = serde_json::json!({
                    "version": unproxy::VERSION,
                    "target": target_name,
                    "negotiate": !no_negotiate,
                    "components": if windows_package {
                        windows_components
                    } else {
                        vec!["unproxy", "paceval", "undns"]
                    },
                    "dns_version": unproxy::DNS_VERSION,
                });
                if matches!(format, Format::Windows) {
                    metadata["defaults"] = windows_desktop_defaults(defaults.as_ref());
                }
                std::fs::write(
                    staging.join("metadata.json"),
                    serde_json::to_vec_pretty(&metadata)?,
                )?;
                zip(&staging, &output.join(format!("{package_name}.zip")))?;
            }
            Format::Deb => {
                anyhow::ensure!(
                    target_name.contains("linux"),
                    "Debian packages require a Linux target"
                );
                let arch = if target_name.starts_with("x86_64") {
                    "amd64"
                } else if target_name.starts_with("aarch64") {
                    "arm64"
                } else if target_name.starts_with("i686") {
                    "i386"
                } else {
                    bail!("unsupported Debian architecture")
                };
                let control = staging.join("DEBIAN");
                std::fs::create_dir_all(&control)?;
                let depends = if no_negotiate {
                    "libc6, libssl3 | libssl3t64"
                } else {
                    "libc6, libssl3 | libssl3t64, libgssapi-krb5-2"
                };
                std::fs::write(
                    control.join("control"),
                    format!(
                        "Package: unproxy\nVersion: {}\nArchitecture: {arch}\nMaintainer: Unproxy contributors\nDepends: {depends}\nSection: net\nPriority: optional\nDescription: Local HTTP proxy with PAC routing and upstream authentication\n",
                        unproxy::VERSION
                    ),
                )?;
                for hook in ["postinst", "prerm", "postrm"] {
                    executable(
                        &PathBuf::from(format!("assets/debian-{hook}")),
                        &control.join(hook),
                    )?;
                }
                executable(&source_bin("unproxy"), &staging.join("usr/bin/unproxy"))?;
                let service_dir = staging.join("usr/lib/systemd/user");
                std::fs::create_dir_all(&service_dir)?;
                std::fs::copy(
                    "assets/unproxy.service",
                    service_dir.join("unproxy.service"),
                )?;
                let doc_dir = staging.join("usr/share/doc/unproxy");
                std::fs::create_dir_all(&doc_dir)?;
                std::fs::copy("README.md", doc_dir.join("README.md"))?;
                run(Command::new("dpkg-deb")
                    .arg("--root-owner-group")
                    .arg("--build")
                    .arg(&staging)
                    .arg(output.join(format!("{package_name}.deb"))))?;
            }
            Format::Macos => {
                anyhow::ensure!(
                    target_name.contains("darwin") || target_name.contains("macos"),
                    "macOS packages require a macOS target"
                );
                for name in [
                    "unproxy",
                    "unproxyctl",
                    "unproxy-register",
                    "unproxy-system-proxy",
                ] {
                    executable(
                        &source_bin(name),
                        &staging.join("opt/unproxy/bin").join(name),
                    )?;
                    sign_macos_code(&staging.join("opt/unproxy/bin").join(name), None)?;
                }
                let agents = staging.join("Library/LaunchAgents");
                std::fs::create_dir_all(&agents)?;
                std::fs::copy(
                    "assets/de.m42e.unproxy.plist",
                    agents.join("de.m42e.unproxy.plist"),
                )?;
                let paths = staging.join("etc/paths.d");
                std::fs::create_dir_all(&paths)?;
                std::fs::write(paths.join("unproxy"), "/opt/unproxy/bin\n")?;
                if cfg!(target_os = "macos") {
                    let hooks = output.join(format!(".hooks-{}", std::process::id()));
                    std::fs::create_dir_all(&hooks)?;
                    for hook in ["preinstall", "postinstall"] {
                        executable(
                            &PathBuf::from(format!("assets/macos-{hook}")),
                            &hooks.join(hook),
                        )?;
                    }
                    let mut command = Command::new("pkgbuild");
                    command
                        .arg("--root")
                        .arg(&staging)
                        .args([
                            "--identifier",
                            "de.m42e.unproxy",
                            "--version",
                            unproxy::VERSION.split('+').next().unwrap(),
                            "--install-location",
                            "/",
                            "--scripts",
                        ])
                        .arg(&hooks)
                        .arg(output.join(format!("{package_name}.pkg")));
                    pkgbuild_signing_args(&mut command);
                    run_pkgbuild(&mut command)?;
                    std::fs::remove_dir_all(hooks)?;
                } else {
                    package_name.push_str("-staging");
                    zip(&staging, &output.join(format!("{package_name}.zip")))?;
                    println!(
                        "Created an installer staging archive; pkgbuild on macOS is required for a native .pkg."
                    );
                }
            }
            Format::App => {
                anyhow::ensure!(
                    target_name.contains("darwin") || target_name.contains("macos"),
                    "the menu bar app requires a macOS target"
                );
                let app = staging.join("Unproxy.app/Contents");
                executable(&source_bin("unproxy-app"), &app.join("MacOS/unproxy-app"))?;
                executable(&source_bin("unproxy"), &app.join("MacOS/unproxy"))?;
                let helper = app.join("Library/LoginItems/UnproxyLoginHelper.app/Contents");
                executable(
                    &source_bin("unproxy-login-helper"),
                    &helper.join("MacOS/unproxy-login-helper"),
                )?;
                std::fs::write(
                    app.join("Info.plist"),
                    info_plist("de.m42e.unproxy.app", "unproxy-app", "11.1"),
                )?;
                std::fs::write(
                    helper.join("Info.plist"),
                    info_plist(
                        "de.m42e.unproxy.login-helper",
                        "unproxy-login-helper",
                        "10.14",
                    ),
                )?;
                std::fs::copy(
                    "assets/app-entitlements.plist",
                    app.join("entitlements.plist"),
                )?;
                std::fs::copy(
                    "assets/child-entitlements.plist",
                    app.join("child-entitlements.plist"),
                )?;
                std::fs::create_dir_all(app.join("Resources"))?;
                let tray_icons = Path::new("assets/tray-icons");
                if tray_icons.is_dir() {
                    let resources_icons = app.join("Resources/tray-icons");
                    std::fs::create_dir_all(&resources_icons)?;
                    for icon in std::fs::read_dir(tray_icons)? {
                        let icon = icon?.path();
                        if icon.extension().is_some_and(|ext| ext == "png") {
                            std::fs::copy(&icon, resources_icons.join(icon.file_name().unwrap()))?;
                        }
                    }
                }
                std::fs::write(
                    app.join("Resources/metadata.json"),
                    serde_json::to_vec_pretty(
                        &serde_json::json!({"version":unproxy::VERSION,"bundle_id":"de.m42e.unproxy.app","helper_bundle_id":"de.m42e.unproxy.login-helper","minimum_macos":"11.1"}),
                    )?,
                )?;
                sign_macos_code(&app.join("MacOS/unproxy"), None)?;
                sign_macos_code(
                    helper.parent().context("helper bundle has no parent")?,
                    Some(&app.join("child-entitlements.plist")),
                )?;
                sign_macos_code(
                    app.parent().context("app bundle has no parent")?,
                    Some(&app.join("entitlements.plist")),
                )?;
                zip(&staging, &output.join(format!("{package_name}-app.zip")))?;
                let pkg_root = staging.join("pkg-root");
                copy_tree(
                    &staging.join("Unproxy.app"),
                    &pkg_root.join("Applications/Unproxy.app"),
                )?;
                if cfg!(target_os = "macos") {
                    let mut command = Command::new("pkgbuild");
                    command
                        .arg("--root")
                        .arg(&pkg_root)
                        .args([
                            "--identifier",
                            "de.m42e.unproxy.app",
                            "--version",
                            unproxy::VERSION.split('+').next().unwrap(),
                            "--install-location",
                            "/",
                        ])
                        .arg(output.join(format!("{package_name}-app.pkg")));
                    pkgbuild_signing_args(&mut command);
                    run_pkgbuild(&mut command)?;
                } else {
                    zip(
                        &pkg_root,
                        &output.join(format!("{package_name}-app-pkg-staging.zip")),
                    )?;
                    println!(
                        "Created an app package staging archive; pkgbuild on macOS is required for the native .pkg."
                    );
                }
            }
        }
        std::fs::remove_dir_all(&staging)?;
    }
    println!("Artifacts written to {}", output.display());
    Ok(())
}
fn info_plist(id: &str, executable: &str, minimum: &str) -> String {
    let version = unproxy::VERSION.split('+').next().unwrap();
    format!(
        "<?xml version=\"1.0\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleName</key><string>Unproxy</string><key>CFBundleExecutable</key><string>{executable}</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>{version}</string><key>CFBundleShortVersionString</key><string>{version}</string><key>ProductBuildVersion</key><string>{}</string><key>LSUIElement</key><true/><key>LSMinimumSystemVersion</key><string>{minimum}</string></dict></plist>",
        html_escape(unproxy::VERSION)
    )
}
fn docs(output: &Path, repository: Option<&str>) -> Result<()> {
    let book = output.join("docs");
    std::fs::create_dir_all(&book)?;
    let mut pages = std::fs::read_dir("docs")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|s| s == "md"))
        .collect::<Vec<_>>();
    pages.sort();
    let nav = pages
        .iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy();
            format!("<a href='{name}.html'>{name}</a> ")
        })
        .collect::<String>();
    for page in pages {
        let text = std::fs::read_to_string(&page)?;
        let name = page.file_stem().unwrap().to_string_lossy();
        std::fs::write(
            book.join(format!("{name}.html")),
            format!(
                "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Unproxy {name}</title><style>body{{max-width:70em;margin:2em auto;padding:1em;font:16px system-ui}}pre{{white-space:pre-wrap}}nav a{{padding:.3em}}</style><nav>{nav}</nav><main>{}</main>",
                markdown(&text)
            ),
        )?;
    }
    std::fs::write(
        book.join("index.html"),
        "<!doctype html><meta http-equiv=refresh content='0;url=user-guide.html'><a href=user-guide.html>Use Unproxy</a>",
    )?;
    let mut landing = std::fs::read_to_string("site/index.html")?
        .replace("@VERSION@", &html_escape(unproxy::VERSION));
    let repository = repository.unwrap_or("");
    anyhow::ensure!(
        repository.is_empty()
            || (repository.split('/').count() == 2
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_/ .".contains(&b))
                && !repository.contains(' ')),
        "repository must be OWNER/NAME"
    );
    landing = landing.replace("@REPOSITORY@", &html_escape(repository));
    std::fs::write(output.join("index.html"), landing)?;
    let archive = if output.is_absolute() {
        output.join("source.zip")
    } else {
        std::env::current_dir()?.join(output).join("source.zip")
    };
    run(Command::new("git")
        .args(["archive", "--format=zip", "HEAD", "-o"])
        .arg(archive))?;
    println!(
        "Documentation and landing page written to {}",
        output.display()
    );
    Ok(())
}
fn markdown(text: &str) -> String {
    let mut output = String::new();
    let mut code = false;
    for line in text.lines() {
        if line.starts_with("```") {
            output.push_str(if code { "</code></pre>" } else { "<pre><code>" });
            code = !code;
            continue;
        }
        let escaped = html_escape(line);
        if code {
            output.push_str(&escaped);
            output.push('\n');
        } else if let Some(heading) = line.strip_prefix("# ") {
            output.push_str(&format!("<h1>{}</h1>", html_escape(heading)));
        } else if let Some(heading) = line.strip_prefix("## ") {
            output.push_str(&format!("<h2>{}</h2>", html_escape(heading)));
        } else if let Some(heading) = line.strip_prefix("### ") {
            output.push_str(&format!("<h3>{}</h3>", html_escape(heading)));
        } else if !line.is_empty() {
            output.push_str(&format!("<p>{escaped}</p>"));
        }
    }
    if code {
        output.push_str("</code></pre>");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_renders_headings_paragraphs_and_unclosed_code_blocks() {
        let html = markdown("# Title\n\n## Sub & heading\ntext <tag>\n```\n<code>");
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<h2>Sub &amp; heading</h2>"));
        assert!(html.contains("<p>text &lt;tag&gt;</p>"));
        assert!(html.ends_with("<pre><code>&lt;code&gt;\n</code></pre>"));
    }

    #[test]
    fn app_plist_escapes_version_and_includes_bundle_metadata() {
        let plist = info_plist("example.bundle", "example", "11.1");
        assert!(plist.contains("<string>example.bundle</string>"));
        assert!(plist.contains("<string>example</string>"));
        assert!(plist.contains("<string>11.1</string>"));
        assert!(plist.contains(&html_escape(unproxy::VERSION)));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_literals_escape_single_quotes() {
        assert_eq!(ps_literal(Path::new("a'b")), "'a''b'");
    }

    #[cfg(unix)]
    #[test]
    fn executable_copies_file_and_sets_executable_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("nested/target");
        std::fs::write(&source, "binary").unwrap();

        executable(&source, &target).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"binary");
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn zip_helper_writes_an_archive_that_extracts_on_the_host() {
        let temp = tempfile::tempdir().unwrap();
        let payload = temp.path().join("payload directory");
        let nested = payload.join("nested folder");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(payload.join("README.md"), b"package readme").unwrap();
        std::fs::write(nested.join("binary file"), b"fixture executable").unwrap();
        let archive = temp.path().join("package output.zip");

        zip(&payload, &archive).unwrap();

        let extracted = temp.path().join("expanded package");
        #[cfg(unix)]
        run(Command::new("unzip")
            .arg("-q")
            .arg(&archive)
            .arg("-d")
            .arg(&extracted))
        .unwrap();
        #[cfg(windows)]
        powershell(&format!(
            "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
            ps_literal(&archive),
            ps_literal(&extracted)
        ))
        .unwrap();

        assert_eq!(
            std::fs::read(extracted.join("README.md")).unwrap(),
            b"package readme"
        );
        assert_eq!(
            std::fs::read(extracted.join("nested folder/binary file")).unwrap(),
            b"fixture executable"
        );
    }
}
