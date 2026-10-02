fn main() {
    if let Err(e) = unproxy::desktop::run_login_helper() {
        eprintln!("unproxy-login-helper: {e:#}");
        std::process::exit(1)
    }
}
