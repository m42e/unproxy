use clap::Parser;

#[derive(Parser)]
#[command(
    about = "Run the Unproxy login helper",
    long_about = "Start the background login helper used by Unproxy.app to manage the proxy process at user login. This executable is normally launched by macOS as an app login item."
)]
struct Args {}

fn main() {
    let _ = Args::parse();
    if let Err(e) = unproxy::desktop::run_login_helper() {
        eprintln!("unproxy-login-helper: {e:#}");
        std::process::exit(1)
    }
}
