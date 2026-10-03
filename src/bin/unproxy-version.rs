use clap::Parser;
#[derive(Parser)]
#[command(
    about = "Print product build version metadata",
    long_about = "Print the build version recorded for a product package. With no package argument, the Unproxy version is printed. Use --raw to omit the version= prefix for scripts."
)]
struct Args {
    /// Print only the version value, without the version= prefix.
    #[arg(short = 'r')]
    raw: bool,
    /// Product package name to query.
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
