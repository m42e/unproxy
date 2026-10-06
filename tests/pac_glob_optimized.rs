use unproxy::pac::Pac;

#[test]
fn shell_glob_matches_unicode_questions_and_character_classes() {
    let mut pac = Pac::new(Some(
        "function FindProxyForURL(){ return shExpMatch('猫','?') && shExpMatch('猫','[猫]') && shExpMatch('https://例え.test/道','https://例え.test/*') ? 'DIRECT' : 'PROXY fail.test:8080'; }",
    ))
    .unwrap();

    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}

#[test]
fn invalid_patterns_and_argument_types_keep_throwing() {
    let mut invalid = Pac::new(Some(
        "function FindProxyForURL(){ for(var i=0;i<2;i++){ try { shExpMatch('x','['); return 'PROXY fail.test:8080'; } catch(e) {} } return 'DIRECT'; }",
    ))
    .unwrap();
    assert_eq!(invalid.evaluate("x", "x").unwrap().to_string(), "DIRECT");

    for args in ["(1,'*')", "('x',1)"] {
        let source = format!(
            "function FindProxyForURL(){{ try {{ shExpMatch{args}; return 'PROXY fail.test:8080'; }} catch(e) {{ return 'DIRECT'; }} }}"
        );
        let mut pac = Pac::new(Some(&source)).unwrap();
        assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
    }
}

#[test]
fn cache_capacity_does_not_change_glob_results() {
    let mut pac = Pac::new(Some(
        "function FindProxyForURL(){ for(var i=0;i<700;i++){ var pattern='host'+i+'.example.test'; if(!shExpMatch(pattern,pattern)) return 'PROXY fail.test:8080'; } return shExpMatch('last.example.test','*.example.test') ? 'DIRECT' : 'PROXY fail.test:8080'; }",
    ))
    .unwrap();

    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}
