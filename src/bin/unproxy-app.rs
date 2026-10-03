use clap::Parser;

#[derive(Parser)]
#[command(
    about = "Launch the Unproxy menu bar application",
    long_about = "Start the Unproxy desktop application. The app provides a menu bar control for the background proxy and stores its preferences in the user's application support directory. This executable is normally launched from Unproxy.app."
)]
struct Args {}

fn main() {
    let _ = Args::parse();
    if let Err(e) = unproxy::desktop::run_app() {
        eprintln!("unproxy-app: {e:#}");
        std::process::exit(1)
    }
}
