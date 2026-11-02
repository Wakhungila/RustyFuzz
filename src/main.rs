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
        Command::Ops { command } => return cli::ops_handlers::run(command).await,
        Command::Satori { command } => {
            return rusty_fuzz::satori::cli::run(command)
                .await
                .map_err(|err| anyhow::anyhow!("satori: {err}"));
        }
        other => other,
    };

    cli::handlers::run(command).await
}

/// Test-only helpers, shared with the library through the same source file.
///
/// The binary target declares its own `mod cli` instead of linking the library,
/// so it needs its own include of this module.
#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;
