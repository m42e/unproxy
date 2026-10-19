use std::process::Command;

fn xtask(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command.args(args);
    inherit_coverage_profile(&mut command);
    command.output().unwrap()
}

fn inherit_coverage_profile(command: &mut Command) {
    let Some(pattern) = std::env::var_os("LLVM_PROFILE_FILE") else {
        return;
    };
    let pattern = pattern.to_string_lossy();
    let unique = if pattern.contains("%p") && pattern.contains("%m") {
        pattern.into_owned()
    } else {
        format!("{pattern}.child-%p-%m.profraw")
    };
    command.env("LLVM_PROFILE_FILE", unique);
}

#[cfg(unix)]
fn xtask_with_tool(args: &[&str], tool_dir: &std::path::Path) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;

    let cargo = tool_dir.join("cargo");
    std::fs::write(&cargo, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = std::fs::metadata(&cargo).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&cargo, permissions).unwrap();
    let mut path = tool_dir.as_os_str().to_owned();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command.args(args).env("PATH", path);
    inherit_coverage_profile(&mut command);
    command.output().unwrap()
}

#[cfg(unix)]
#[test]
fn build_validates_and_passes_embedded_desktop_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let defaults = temp.path().join("defaults.toml");
    std::fs::write(
        &defaults,
        "port = 4242\npac_file = 'corp.pac'\nnegotiate = false\nproxytunnel = true\ndirect_fallback = true\nautostart = false\n",
    )
    .unwrap();
    let output = xtask_with_tool(
        &[
            "build",
            "--release",
            "--target",
            "aarch64-unknown-linux-gnu",
            "--defaults",
            defaults.to_str().unwrap(),
        ],
        temp.path(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let invalid_port = temp.path().join("invalid-port.toml");
    std::fs::write(&invalid_port, "port = 80\n").unwrap();
    let output = xtask(&["build", "--defaults", invalid_port.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1024 and 65534"));

    let enabled_negotiate = temp.path().join("negotiate.toml");
    std::fs::write(&enabled_negotiate, "negotiate = true\n").unwrap();
    let output = xtask(&[
        "build",
        "--no-negotiate",
        "--defaults",
        enabled_negotiate.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--no-negotiate"));

    let unknown = temp.path().join("unknown.toml");
    std::fs::write(&unknown, "unexpected = true\n").unwrap();
    let output = xtask(&["build", "--defaults", unknown.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
}

#[test]
fn copy_command_copies_files_and_nested_directories() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    let nested = input.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(input.join("root.txt"), "root").unwrap();
    std::fs::write(nested.join("child.txt"), "child").unwrap();

    let copied_file = temp.path().join("single/output.txt");
    let file = xtask(&[
        "copy",
        input.join("root.txt").to_str().unwrap(),
        copied_file.to_str().unwrap(),
    ]);
    assert!(
        file.status.success(),
        "{}",
        String::from_utf8_lossy(&file.stderr)
    );
    assert_eq!(std::fs::read_to_string(copied_file).unwrap(), "root");

    let copied_tree = temp.path().join("tree");
    let tree = xtask(&[
        "copy",
        input.to_str().unwrap(),
        copied_tree.to_str().unwrap(),
    ]);
    assert!(
        tree.status.success(),
        "{}",
        String::from_utf8_lossy(&tree.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(copied_tree.join("nested/child.txt")).unwrap(),
        "child"
    );
}

#[test]
fn release_notes_print_only_the_latest_section() {
    let temp = tempfile::tempdir().unwrap();
    let changelog = temp.path().join("CHANGELOG.md");
    std::fs::write(
        &changelog,
        "# Changelog\n\n## 1.2.3\nCurrent release\n\n## 1.2.2\nOlder release\n",
    )
    .unwrap();

    let output = xtask(&["release-notes", changelog.to_str().unwrap()]);
    assert!(output.status.success());
    let notes = String::from_utf8(output.stdout).unwrap();
    assert!(notes.contains("## 1.2.3\nCurrent release"));
    assert!(!notes.contains("Older release"));
}

#[test]
fn release_notes_reject_a_changelog_without_a_release_section() {
    let temp = tempfile::tempdir().unwrap();
    let changelog = temp.path().join("CHANGELOG.md");
    std::fs::write(&changelog, "No release headings here\n").unwrap();

    let output = xtask(&["release-notes", changelog.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("changelog contains no release section")
    );
}

#[test]
fn docs_command_generates_pages_landing_page_and_source_archive() {
    let temp = tempfile::tempdir().unwrap();
    let output_dir = temp.path().join("generated docs");
    let output = xtask(&[
        "docs",
        "--output",
        output_dir.to_str().unwrap(),
        "--repository",
        "m42e/unproxy",
    ]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let guide = std::fs::read_to_string(output_dir.join("docs/user-guide.html")).unwrap();
    assert!(guide.contains("aria-label=\"Documentation\""));
    assert!(guide.contains("aria-current=\"page\""));
    assert!(guide.contains("<table>"));
    assert!(guide.contains("unproxy doctor --url"));
    assert!(guide.contains("does not read desktop preferences automatically"));
    assert!(guide.contains("<ol>") || guide.contains("<h2"));
    assert!(guide.contains("src=\"traffic-flow.svg\""));
    assert!(!guide.contains("traffic-flow-mobile.svg"));
    assert!(guide.contains("href=\"installation.html\""));
    assert!(guide.contains("aria-label=\"On this page\""));
    assert!(guide.contains("href=\"#1-install-and-start-unproxy\""));
    assert!(guide.contains("src=\"../unproxy-icon.png\""));
    assert!(guide.contains("href=\"../unproxy-icon.png\""));
    let routing = std::fs::read_to_string(output_dir.join("docs/routing.html")).unwrap();
    assert!(routing.contains("Measured during this documentation build"));
    assert!(routing.contains("<th>Benchmark</th>"));
    assert!(routing.contains("<th>Workload</th>"));
    assert!(routing.contains("<th>Results</th>"));
    assert!(routing.contains("<td>Repeated route parser only</td>"));
    assert!(routing.contains("<td>PAC matching performance</td>"));
    assert!(!routing.contains("PAC_PERFORMANCE_RESULTS"));
    assert!(output_dir.join("unproxy-icon.png").is_file());
    let landing = std::fs::read_to_string(output_dir.join("index.html")).unwrap();
    assert!(landing.contains("href=\"unproxy-icon.png\""));
    assert!(output_dir.join("docs/index.html").is_file());
    assert!(
        std::fs::read_to_string(output_dir.join("docs/index.html"))
            .unwrap()
            .contains("../unproxy-icon.png")
    );
    for asset in ["docs.css", "docs.js"] {
        assert!(output_dir.join("docs").join(asset).is_file());
    }
    assert!(output_dir.join("docs/traffic-flow.svg").is_file());
    let install = std::fs::read_to_string(output_dir.join("docs/installation.html")).unwrap();
    assert!(install.contains("role=tablist"));
    assert_eq!(install.matches("role=tablist").count(), 2);
    for platform in ["windows", "macos", "debian-or-ubuntu"] {
        assert!(install.contains(&format!("aria-controls=\"install-{platform}\"")));
        assert!(install.contains(&format!("data-platform=\"{platform}\"")));
    }
    assert!(install.contains("id=\"windows-service\""));
    assert!(install.contains("href=\"#remove-unproxy\""));
    let removal = install.split_once("<h2 id=\"remove-unproxy\">").unwrap().1;
    for (platform, required) in [
        (
            "windows",
            vec![
                "uninstall.ps1",
                "RemoveUserData",
                "service configuration",
                "PAC",
                "preferences",
            ],
        ),
        (
            "macos",
            vec!["Start with Login", "quit Unproxy", "Applications", "Trash"],
        ),
        ("debian-or-ubuntu", vec!["apt remove unproxy"]),
    ] {
        assert!(removal.contains(&format!("aria-controls=\"remove-{platform}\"")));
        let start = format!("<section class=platform-panel id=\"remove-{platform}\"");
        let panel = removal
            .split_once(&start)
            .unwrap()
            .1
            .split_once("</section>")
            .unwrap()
            .0;
        for text in required {
            assert!(
                panel.contains(text),
                "{platform} removal instructions lack {text}"
            );
        }
        assert!(
            !panel.contains(" hidden"),
            "removal instructions must be available without JavaScript"
        );
    }
    let troubleshooting =
        std::fs::read_to_string(output_dir.join("docs/troubleshooting.html")).unwrap();
    assert!(troubleshooting.contains("role=tablist"));
    for (platform, required, excluded) in [
        (
            "windows",
            vec![
                "curl.exe --noproxy localhost",
                "Get-Content",
                "unproxyctl.exe",
                "doctor --url",
                "language-powershell",
            ],
            vec!["systemctl", "journalctl", "tail -n", "/Applications/"],
        ),
        (
            "macos",
            vec![
                "curl --noproxy",
                "tail -n",
                "/Applications/Unproxy.app/Contents/MacOS/unproxy",
                "doctor --url",
                "language-sh",
            ],
            vec!["systemctl", "journalctl", "Get-Content", "curl.exe"],
        ),
        (
            "debian-or-ubuntu",
            vec![
                "curl --noproxy",
                "systemctl --user",
                "journalctl --user",
                "paceval",
                "unproxy doctor --url",
                "language-sh",
            ],
            vec!["Get-Content", "curl.exe", "/Applications/"],
        ),
    ] {
        assert!(troubleshooting.contains(&format!("aria-controls=\"troubleshoot-{platform}\"")));
        let start = format!("<section class=platform-panel id=\"troubleshoot-{platform}\"");
        let panel = troubleshooting
            .split_once(&start)
            .unwrap()
            .1
            .split_once("</section>")
            .unwrap()
            .0;
        for command in required {
            assert!(
                panel.contains(command),
                "{platform} instructions lack {command}"
            );
        }
        for command in excluded {
            assert!(
                !panel.contains(command),
                "{platform} instructions contain {command}"
            );
        }
        assert!(
            !panel.contains(" hidden"),
            "instructions must be available without JavaScript"
        );
    }
    let shared = troubleshooting.rsplit_once("</section>").unwrap().1;
    assert!(
        !shared.contains("<pre>"),
        "OS commands must stay inside their tabs"
    );
    // Follow every internal generated link, including cross-page heading anchors.
    for entry in std::fs::read_dir(output_dir.join("docs")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "html") {
            continue;
        }
        let page = std::fs::read_to_string(&path).unwrap();
        assert!(!page.contains("@BODY@"));
        for rest in page.split("href=\"").skip(1) {
            let href = rest.split('"').next().unwrap();
            if href.contains(':') || href.starts_with("//") {
                continue;
            }
            let (file, anchor) = href.split_once('#').unwrap_or((href, ""));
            let target = if file.is_empty() {
                path.clone()
            } else {
                path.parent().unwrap().join(file)
            };
            assert!(target.is_file(), "broken link {href} in {}", path.display());
            if !anchor.is_empty() {
                let target_html = std::fs::read_to_string(&target).unwrap();
                assert!(
                    target_html.contains(&format!("id=\"{anchor}\"")),
                    "missing anchor {href} in {}",
                    path.display()
                );
            }
        }
    }
    let applications = std::fs::read_to_string(output_dir.join("docs/applications.html")).unwrap();
    assert_eq!(
        applications
            .matches("class=shell-tabs role=tablist")
            .count(),
        2
    );
    for shell in ["bash", "zsh", "fish", "powershell", "cmd"] {
        assert_eq!(
            applications
                .matches(&format!("aria-controls=\"shell-setup-{shell}\""))
                .count(),
            1
        );
        assert_eq!(
            applications
                .matches(&format!("aria-controls=\"shell-cleanup-{shell}\""))
                .count(),
            1
        );
        assert!(applications.contains(&format!("data-shell=\"{shell}\"")));
    }
    assert!(applications.contains("source &lt;(unproxy shell-setup bash)"));
    assert!(applications.contains("Remove-Item Env:http_proxy"));
    let docs_js = std::fs::read_to_string(output_dir.join("docs/docs.js")).unwrap();
    assert!(docs_js.contains("localStorage.getItem(storageKey)"));
    assert!(docs_js.contains("localStorage.setItem(storageKey, id)"));
    assert!(docs_js.contains("document.querySelectorAll('.shell-tabs')"));
    assert!(output_dir.join("docs/index.html").is_file());
    assert!(output_dir.join("source.zip").is_file());
    let landing = std::fs::read_to_string(output_dir.join("index.html")).unwrap();
    assert!(landing.contains("m42e/unproxy"));
    assert!(!landing.contains("@VERSION@"));
}
