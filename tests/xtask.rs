use std::process::Command;

fn xtask(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap()
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
