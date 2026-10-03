fn main() {
    for key in [
        "UNPROXY_VERSION",
        "UNPROXY_REVISION",
        "UNPROXY_PLATFORM",
        "UNPROXY_ARCH",
        "UNPROXY_DESKTOP_DEFAULTS_JSON",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    if let Ok(defaults) = std::env::var("UNPROXY_DESKTOP_DEFAULTS_JSON") {
        println!("cargo:rustc-env=UNPROXY_DESKTOP_DEFAULTS_JSON={defaults}");
    }
    let version = std::env::var("UNPROXY_VERSION")
        .unwrap_or_else(|_| std::env::var("CARGO_PKG_VERSION").unwrap());
    let revision = std::env::var("UNPROXY_REVISION").unwrap_or_default();
    println!(
        "cargo:rustc-env=PRODUCT_VERSION={version}{}",
        if revision.is_empty() {
            String::new()
        } else {
            format!("+{revision}")
        }
    );
    println!(
        "cargo:rustc-env=PRODUCT_PLATFORM={}",
        std::env::var("UNPROXY_PLATFORM")
            .unwrap_or_else(|_| std::env::var("CARGO_CFG_TARGET_OS").unwrap())
    );
    println!(
        "cargo:rustc-env=PRODUCT_ARCH={}",
        std::env::var("UNPROXY_ARCH")
            .unwrap_or_else(|_| std::env::var("CARGO_CFG_TARGET_ARCH").unwrap())
    );
}
