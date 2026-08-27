//! Thin binary entry point: parse CLI, dispatch to `cli::handlers`.
//!
//! Stage 4D: business logic lives in `cli::{commands, handlers, helpers}` so
//! it is testable without going through the parser.

mod cli;

use clap::Parser;

use cli::commands::{Args, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let command = match args.command {
        Command::Satori { command } => {
            return rusty_fuzz::satori::cli::run(command)
                .await
                .map_err(|err| anyhow::anyhow!("satori: {err}"));
        }
        other => other,
    };

    cli::handlers::run(command).await
}
