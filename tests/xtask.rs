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
    assert!(guide.contains("<nav>"));
    assert!(output_dir.join("docs/index.html").is_file());
    assert!(output_dir.join("source.zip").is_file());
    let landing = std::fs::read_to_string(output_dir.join("index.html")).unwrap();
    assert!(landing.contains("m42e/unproxy"));
    assert!(!landing.contains("@VERSION@"));
}
