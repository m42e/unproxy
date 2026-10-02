use clap::Parser;
#[derive(Parser)]
#[command(about = "Print product build version metadata")]
struct Args {
    #[arg(short = 'r')]
    raw: bool,
    #[arg(default_value = "unproxy")]
    package: String,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!(
        "{}{}",
        if args.raw { "" } else { "version=" },
        unproxy::tools::product_version(&args.package)?
    );
    Ok(())
}
