use clap::Parser;
use revm::primitives::Address;
use rusty_fuzz::chain::mempool::MempoolScanner;
use rusty_fuzz::config::Config;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Fuzz {
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        contract: Option<String>,
    },
    ScanMempool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::load("config.toml")?;

    match args.command {
        Command::Fuzz { chain, contract } => {
            println!(
                "Starting fuzz campaign on {:?} for contract {:?}",
                chain, contract
            );
            let fuzz_config = rusty_fuzz::engine::fuzz_engine::Config {
                rpc_url: config.rpc_url.clone(),
                fork_block: config.fork_block.unwrap_or(0),
                target_contract: config
                    .target_contract
                    .as_deref()
                    .map(Address::from_str)
                    .transpose()?,
                corpus_dir: config.corpus_dir.clone(),
                report_dir: config.report_dir.clone(),
            };
            rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign(fuzz_config).await?;
        }
        Command::ScanMempool => {
            println!("Starting mempool scanner for chain: {}", config.chain);
            let scanner = MempoolScanner::new(config.rpc_url.clone());
            scanner.scan_mempool().await?;
        }
    }

    Ok(())
}
