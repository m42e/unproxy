use clap::Parser;
#[derive(Parser)]
#[command(about = "Query TOML table keys and numeric array indexes")]
struct Args {
    #[arg(short, long)] file: std::path::PathBuf,
    #[arg(short, long)] name: Option<String>,
    #[arg(required = true)] path: Vec<String>,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let value = unproxy::tools::query_toml(&std::fs::read_to_string(args.file)?, &args.path)?;
    println!("{}{value}", args.name.map(|n| format!("{n}=")).unwrap_or_default());
    Ok(())
}
