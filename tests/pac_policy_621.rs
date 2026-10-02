use unproxy::pac::Pac;

#[test]
fn custom_pac_construction_requires_callable_entry_point() {
    assert!(Pac::new(Some("function FindProxyForURL(){")).is_err());
    let error = Pac::new(Some("function FindProxyForURLTypo(){return 'DIRECT';}"))
        .err()
        .unwrap();
    assert!(error.to_string().contains("FindProxyForURL"));
    assert!(Pac::new(Some("var FindProxyForURL=1;")).is_err());
    assert!(Pac::new(None).unwrap().evaluate("x", "x").is_ok());
}
