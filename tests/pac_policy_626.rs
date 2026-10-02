use unproxy::pac::Pac;
#[test]
fn runaway_loop_is_bounded_and_runtime_recovers() {
    let mut pac = Pac::new(Some(
        "let n=0; function FindProxyForURL(){if(n++===0){while(true){}} return 'DIRECT';}",
    ))
    .unwrap();
    assert!(pac.evaluate("x", "x").is_err());
    assert_eq!(pac.evaluate("x", "x").unwrap().to_string(), "DIRECT");
}
