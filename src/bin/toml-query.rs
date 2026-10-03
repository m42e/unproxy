use clap::Parser;
#[derive(Parser)]
#[command(
    about = "Query a value from a TOML file",
    long_about = "Read a TOML file and select a value by walking table keys and numeric array indexes. The selected value is printed to standard output; --name can prefix it as name=value for scripts."
)]
struct Args {
    /// TOML file to read.
    #[arg(short, long)]
    file: std::path::PathBuf,
    /// Prefix the result with NAME=.
    #[arg(short, long)]
    name: Option<String>,
    /// Sequence of table keys and numeric array indexes to follow.
    #[arg(required = true)]
    path: Vec<String>,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let value = unproxy::tools::query_toml(&std::fs::read_to_string(args.file)?, &args.path)?;
    println!(
        "{}{value}",
        args.name.map(|n| format!("{n}=")).unwrap_or_default()
    );
    Ok(())
}
