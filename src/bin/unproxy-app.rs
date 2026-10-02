fn main() {
    if let Err(e) = unproxy::desktop::run_app() {
        eprintln!("unproxy-app: {e:#}");
        std::process::exit(1)
    }
}
