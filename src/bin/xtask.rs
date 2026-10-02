//! Platform-aware development and artifact assembly entry point.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use unproxy::tools::{copy_tree, html_escape};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
#[command(about = "Build, validate, document and package Unproxy")]
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
    },
    Check,
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
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Task::Build {
            release,
            target,
            no_negotiate,
        } => build(release, target.as_deref(), no_negotiate),
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
            run(Command::new("cargo").args(["test", "--locked", "--all-features"]))?;
            run(Command::new("cargo").args(["test", "--locked", "--no-default-features"]))
        }
        Task::Docs { output, repository } => docs(&output, repository.as_deref()),
        Task::Package {
            format,
            target,
            output,
            no_negotiate,
        } => package(format, target.as_deref(), &output, no_negotiate),
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
            run(Command::new("unzip")
                .arg("-q")
                .arg(archive)
                .arg("-d")
                .arg(output))
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
fn build(release: bool, target: Option<&str>, no_negotiate: bool) -> Result<()> {
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
    run(&mut command)
}
fn zip(directory: &Path, output: &Path) -> Result<()> {
    let absolute = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    if cfg!(windows) {
        run(Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Compress-Archive -Path $args[0] -DestinationPath $args[1] -Force",
            ])
            .arg(directory.join("*"))
            .arg(absolute))
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
fn package(format: Format, target: Option<&str>, output: &Path, no_negotiate: bool) -> Result<()> {
    build(true, target, no_negotiate)?;
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
    let mut package_name = format!("unproxy-{}-{target_name}", unproxy::VERSION);
    match format {
        Format::Portable | Format::Windows => {
            let bins = if matches!(format, Format::Windows) {
                vec!["unproxy"]
            } else {
                vec!["unproxy", "paceval", "dnsdetox"]
            };
            for name in bins {
                executable(&source_bin(name), &staging.join(format!("{name}{suffix}")))?;
            }
            if windows {
                std::fs::copy("assets/install.ps1", staging.join("install.ps1"))?;
            }
            std::fs::copy("README.md", staging.join("README.md"))?;
            std::fs::copy("assets/proxy.pac", staging.join("proxy.pac.sample"))?;
            std::fs::write(
                staging.join("metadata.json"),
                serde_json::to_vec_pretty(
                    &serde_json::json!({"version":unproxy::VERSION,"target":target_name,"negotiate":!no_negotiate,"dns_version":unproxy::DNS_VERSION}),
                )?,
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
            executable(
                &source_bin("unproxy"),
                &staging.join("usr/bin/unproxy"),
            )?;
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
                run(Command::new("pkgbuild")
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
                    .arg(output.join(format!("{package_name}.pkg"))))?;
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
            executable(
                &source_bin("unproxy-app"),
                &app.join("MacOS/unproxy-app"),
            )?;
            executable(&source_bin("unproxy"), &app.join("Resources/unproxy"))?;
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
            zip(&staging, &output.join(format!("{package_name}-app.zip")))?;
        }
    }
    std::fs::remove_dir_all(staging)?;
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
    std::fs::create_dir_all("docs")?;
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let executable = PathBuf::from("target")
        .join(profile)
        .join(format!("unproxy{suffix}"));
    if !executable.exists() {
        build(profile == "release", None, false)?;
    }
    let help = Command::new(executable)
        .arg("--help")
        .env("UNPROXY_NORC", "1")
        .output()?;
    anyhow::ensure!(help.status.success(), "help generation failed");
    std::fs::write(
        "docs/cli.md",
        format!(
            "# Command-line reference\n\nGenerated with settings-file reading disabled.\n\n```text\n{}```\n",
            String::from_utf8(help.stdout)?
        ),
    )?;
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
        "<!doctype html><meta http-equiv=refresh content='0;url=introduction.html'><a href=introduction.html>Documentation</a>",
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
