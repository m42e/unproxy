use unproxy::tools::{bump_version, query_toml};
#[test]
fn nested_toml_and_errors() {
    let input = "[a]\nb = [{c = 'text'}, {c = 17}]\n";
    assert_eq!(query_toml(input, &["a".into(), "b".into(), "0".into(), "c".into()]).unwrap(), "text");
    assert_eq!(query_toml(input, &["a".into(), "b".into(), "1".into(), "c".into()]).unwrap(), "17");
    for index in ["-1", "x", "99"] { assert!(query_toml(input, &["a".into(), "b".into(), index.into()]).is_err()); }
    assert!(query_toml("broken =", &["broken".into()]).is_err());
    assert!(query_toml(input, &["missing".into()]).is_err());
}
#[test]
fn bump_preserves_comments() {
    let temp = tempfile::tempdir().unwrap(); let file = temp.path().join("Cargo.toml");
    std::fs::write(&file, "# original\n[package]\nname = 'demo'\nversion = '1.2.3'\n").unwrap();
    assert_eq!(bump_version(&file, "minor").unwrap(), "1.3.0");
    assert!(std::fs::read_to_string(&file).unwrap().starts_with("# original"));
    assert!(bump_version(&file, "other").is_err());
}
