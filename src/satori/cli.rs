use crate::satori::error::SatoriResult;
use crate::satori::pipeline::{
    build_report_for_existing_run, ingest_graph_packets, revalidate_existing_run, run_model_audit,
};
use crate::satori::types::SatoriConfig;
use clap::{ArgAction, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand, Debug)]
pub enum SatoriCommand {
    Ingest {
        path: PathBuf,
    },
    Graph {
        path: PathBuf,
    },
    Packets {
        path: PathBuf,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
    },
    Model {
        path: PathBuf,
        #[arg(long, default_value = "big-pickle")]
        model: String,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
    },
    Hunt {
        path: PathBuf,
        #[arg(long, default_value = "big-pickle")]
        model: String,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
        #[arg(long, default_value_t = 2)]
        max_hypotheses_per_function: usize,
        #[arg(long, default_value_t = 0.40)]
        min_confidence: f64,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
        /// Deployed contract the generated jobs target (0x-prefixed address).
        #[arg(long)]
        target_contract: Option<String>,
        /// Fork RPC endpoint. Prefer the RUSTYFUZZ_RPC_URL environment variable
        /// so provider credentials never reach the process argument list.
        #[arg(long)]
        fork_rpc_url: Option<String>,
        /// Fork block the campaign replays from.
        #[arg(long)]
        fork_block: Option<u64>,
    },
    Validate {
        run_id: String,
    },
    Audit {
        path: PathBuf,
        #[arg(long, default_value = "big-pickle")]
        model: String,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
        #[arg(long, default_value_t = 2)]
        max_hypotheses_per_function: usize,
        #[arg(long, default_value_t = 0.40)]
        min_confidence: f64,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        validate: bool,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        generate_jobs: bool,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
        /// Deployed contract the generated jobs target (0x-prefixed address).
        #[arg(long)]
        target_contract: Option<String>,
        /// Fork RPC endpoint. Prefer the RUSTYFUZZ_RPC_URL environment variable
        /// so provider credentials never reach the process argument list.
        #[arg(long)]
        fork_rpc_url: Option<String>,
        /// Fork block the campaign replays from.
        #[arg(long)]
        fork_block: Option<u64>,
    },
    Report {
        run_id: String,
    },
}

fn split_model_candidates(model: &str) -> (String, Vec<String>) {
    let candidates: Vec<String> = model
        .split(',')
        .map(|candidate| candidate.trim().to_string())
        .filter(|candidate| !candidate.is_empty())
        .collect();
    match candidates.split_first() {
        Some((first, rest)) => (first.clone(), rest.to_vec()),
        None => (
            crate::satori::reasoning::zen_client::DEFAULT_MODEL.to_string(),
            Vec::new(),
        ),
    }
}

/// Live-chain settings for a hunt: the deployed contract, the fork RPC, and
/// the fork block.
///
/// The RPC endpoint is taken from `--fork-rpc-url` or, preferably, the
/// `RUSTYFUZZ_RPC_URL` environment variable, so provider credentials stay out
/// of the process argument list and shell history.
#[derive(Debug)]
struct LiveTarget {
    target_contract: Option<String>,
    fork_rpc_url: Option<String>,
    fork_block: Option<u64>,
}

fn resolve_live_target(
    target_contract: Option<String>,
    fork_rpc_url: Option<String>,
    fork_block: Option<u64>,
) -> SatoriResult<LiveTarget> {
    let rpc = match fork_rpc_url.or_else(|| {
        std::env::var("RUSTYFUZZ_RPC_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }) {
        Some(value) => {
            rustyfuzz_evm::rpc_url::validate_rpc_url_for_process(&value)
                .map_err(anyhow::Error::msg)?;
            Some(value)
        }
        None => None,
    };

    let target_contract = match target_contract {
        Some(value) => {
            let trimmed = value.trim().to_string();
            anyhow::ensure!(
                !trimmed.is_empty(),
                "--target-contract must not be empty"
            );
            // Accept only a 0x-prefixed 20-byte address so a typo cannot
            // silently widen what the campaign touches.
            let parsed = alloy_primitives::Address::from_str(&trimmed)
                .map_err(|_| anyhow::anyhow!("--target-contract must be a 0x-prefixed 20-byte address"))?;
            Some(parsed.to_string())
        }
        None => None,
    };

    // A fork block without an RPC (or vice versa) cannot produce a live
    // campaign, so reject the partial configuration instead of silently
    // degrading to an offline run.
    anyhow::ensure!(
        rpc.is_some() == fork_block.is_some(),
        "--fork-rpc-url and --fork-block must be supplied together for a live campaign"
    );

    Ok(LiveTarget {
        target_contract,
        fork_rpc_url: rpc,
        fork_block,
    })
}

pub async fn run(command: SatoriCommand) -> SatoriResult<()> {
    match command {
        SatoriCommand::Ingest { path } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, 0)?;
            println!(
                "Satori ingest complete: run_id={}, project={}",
                artifacts.run.run_id,
                artifacts.project.root.display()
            );
        }
        SatoriCommand::Graph { path } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, 8)?;
            println!(
                "Satori graph complete: run_id={}, functions={}",
                artifacts.run.run_id,
                artifacts.analysis.functions.len()
            );
        }
        SatoriCommand::Packets {
            path,
            max_critical_functions,
        } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, max_critical_functions)?;
            println!(
                "Satori packets complete: run_id={}, max_critical_functions={}",
                artifacts.run.run_id, max_critical_functions
            );
        }
        SatoriCommand::Model { path, model, .. } => {
            require_llm_feature()?;
            let (model, fallback_models) = split_model_candidates(&model);
            let config = SatoriConfig {
                model,
                fallback_models,
                validate: false,
                generate_jobs: false,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori model run complete: run_id={}, hypotheses={}",
                report.run_id,
                report.hypotheses.len()
            );
        }
        SatoriCommand::Hunt {
            path,
            model,
            max_critical_functions,
            max_hypotheses_per_function,
            min_confidence,
            target_contract,
            fork_rpc_url,
            fork_block,
            ..
        } => {
            require_llm_feature()?;
            let (model, fallback_models) = split_model_candidates(&model);
            let live = resolve_live_target(target_contract, fork_rpc_url, fork_block)?;
            let config = SatoriConfig {
                model,
                fallback_models,
                max_critical_functions,
                max_hypotheses_per_function,
                min_confidence,
                validate: true,
                generate_jobs: true,
                target_contract: live.target_contract,
                fork_rpc_url: live.fork_rpc_url,
                fork_block: live.fork_block,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori hunt complete: run_id={}, hypotheses={}, jobs={}, verdicts={}",
                report.run_id,
                report.hypotheses.len(),
                report.jobs.len(),
                report.validation_verdicts.len()
            );
        }
        SatoriCommand::Audit {
            path,
            model,
            max_critical_functions,
            max_hypotheses_per_function,
            min_confidence,
            validate,
            generate_jobs,
            target_contract,
            fork_rpc_url,
            fork_block,
            ..
        } => {
            require_llm_feature()?;
            let (model, fallback_models) = split_model_candidates(&model);
            let live = resolve_live_target(target_contract, fork_rpc_url, fork_block)?;
            let config = SatoriConfig {
                model,
                fallback_models,
                max_critical_functions,
                max_hypotheses_per_function,
                min_confidence,
                validate,
                generate_jobs,
                target_contract: live.target_contract,
                fork_rpc_url: live.fork_rpc_url,
                fork_block: live.fork_block,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori audit complete: run_id={}, report=satori/runs/{}/report.md",
                report.run_id, report.run_id
            );
        }
        SatoriCommand::Validate { run_id } => {
            let report = revalidate_existing_run(&run_id).await?;
            println!(
                "Satori validation complete: run_id={}, verdicts={}, confirmed={}",
                report.run_id,
                report.validation_verdicts.len(),
                report
                    .validation_verdicts
                    .iter()
                    .filter(|verdict| {
                        matches!(
                            verdict.status,
                            crate::satori::types::ValidationStatus::ValidatedLocal
                                | crate::satori::types::ValidationStatus::ValidatedMinimized
                                | crate::satori::types::ValidationStatus::ValidatedEconomicImpact
                        )
                    })
                    .count()
            );
        }
        SatoriCommand::Report { run_id } => {
            let report = build_report_for_existing_run(&run_id)?;
            println!(
                "Satori report written: satori/runs/{}/report.md (hypotheses={}, verdicts={})",
                report.run_id,
                report.hypotheses.len(),
                report.validation_verdicts.len()
            );
        }
    }
    Ok(())
}

fn require_llm_feature() -> SatoriResult<()> {
    #[cfg(feature = "llm")]
    {
        Ok(())
    }
    #[cfg(not(feature = "llm"))]
    {
        Err(crate::satori::error::llm_feature_required())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_complete_live_target_is_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        let live = resolve_live_target(
            Some("0x1Cd97ee98f3423222f7B4CDdb383f2EE2907E628".to_string()),
            Some("https://arb-mainnet.g.alchemy.com/v2/example".to_string()),
            Some(519_323_411),
        )
        .expect("complete live target must be accepted");
        assert_eq!(
            live.target_contract.as_deref(),
            Some("0x1Cd97ee98f3423222f7B4CDdb383f2EE2907E628")
        );
        assert_eq!(live.fork_block, Some(519_323_411));
        assert!(live.fork_rpc_url.is_some());
    }

    #[test]
    fn an_invalid_target_address_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap();
        for candidate in ["not-an-address", "0x1234", "0xZZ97ee98f3423222f7B4CDdb383f2EE2907E628"] {
            let error = resolve_live_target(
                Some(candidate.to_string()),
                Some("https://arb-mainnet.g.alchemy.com/v2/example".to_string()),
                Some(1),
            )
            .expect_err("an invalid address must be refused");
            assert!(
                error.to_string().contains("20-byte address"),
                "{candidate}: {error}"
            );
        }
    }

    #[test]
    fn a_partial_live_configuration_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap();
        let error = resolve_live_target(
            Some("0x1Cd97ee98f3423222f7B4CDdb383f2EE2907E628".to_string()),
            Some("https://arb-mainnet.g.alchemy.com/v2/example".to_string()),
            None,
        )
        .expect_err("an RPC without a block must be refused");
        assert!(
            error.to_string().contains("must be supplied together"),
            "{error}"
        );
    }

    #[test]
    fn an_insecure_rpc_url_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap();
        let error = resolve_live_target(
            Some("0x1Cd97ee98f3423222f7B4CDdb383f2EE2907E628".to_string()),
            Some("http://arb-mainnet.g.alchemy.com/v2/example".to_string()),
            Some(1),
        )
        .expect_err("plain HTTP must be refused for a production RPC");
        assert!(error.to_string().contains("HTTPS"), "{error}");
    }

    #[test]
    fn the_rpc_url_can_come_from_the_environment() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("RUSTYFUZZ_RPC_URL");
        std::env::set_var(
            "RUSTYFUZZ_RPC_URL",
            "https://arb-mainnet.g.alchemy.com/v2/from-env",
        );
        let live = resolve_live_target(
            Some("0x1Cd97ee98f3423222f7B4CDdb383f2EE2907E628".to_string()),
            None,
            Some(519_323_411),
        )
        .expect("the environment RPC must be used");
        assert_eq!(
            live.fork_rpc_url.as_deref(),
            Some("https://arb-mainnet.g.alchemy.com/v2/from-env")
        );
        match previous {
            Some(value) => std::env::set_var("RUSTYFUZZ_RPC_URL", value),
            None => std::env::remove_var("RUSTYFUZZ_RPC_URL"),
        }
    }
}
