use alloy::providers::ProviderBuilder;
use clap::Parser;
use revm::database::CacheDB;
use revm::primitives::Address;
use rusty_fuzz::chain::mempool::MempoolScanner;
use rusty_fuzz::common::oracle::{ProtocolOraclePack, ReentrancyOracle, VulnType};
use rusty_fuzz::common::verifier::ReplayVerifier;
use rusty_fuzz::config::Config;
use rusty_fuzz::engine::benchmark::ValidationRunner;
use rusty_fuzz::engine::foundry_ingest::FoundryHarnessManifest;
use rusty_fuzz::engine::minimizer::Minimizer;
use rusty_fuzz::engine::seed_intelligence::SeedIntelligence;
use rusty_fuzz::evm::corpus::PersistentCorpus;
use rusty_fuzz::evm::executor::EvmExecutor;
use rusty_fuzz::evm::fork::create_fork_block_env;
use rusty_fuzz::evm::fork_db::ForkDb;
use rusty_fuzz::evm::seed_ingester::{
    MainnetSeed, MainnetSeedBundle, MainnetSeedConfig, SeedIngester, SeedMetadata,
};
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
        #[arg(long, default_value_t = false)]
        hardened_defi: bool,
        #[arg(long, default_value_t = false)]
        single_process: bool,
        #[arg(long, default_value_t = false)]
        deterministic: bool,
        #[arg(long)]
        rng_seed: Option<u64>,
        #[arg(long, default_value_t = false)]
        bounded_search: bool,
        #[arg(long)]
        seed_file: Option<String>,
    },
    Seed {
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value_t = 32)]
        max_seeds: usize,
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long, default_value_t = 10_000)]
        search_depth: u64,
        #[arg(long, default_value_t = false)]
        include_address_hints: bool,
    },
    SeedIngest {
        #[arg(long)]
        file: String,
        #[arg(long, default_value = "historical-json")]
        bundle_id: String,
    },
    Replay {
        #[arg(long, alias = "input_id")]
        input: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long, default_value_t = false)]
        live: bool,
    },
    Minimize {
        #[arg(long)]
        input_id: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long, default_value = "cli-minimize")]
        reason: String,
    },
    Report {
        #[arg(long)]
        input_id: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    Validate {
        #[arg(long)]
        benchmarks: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = true)]
        broker_free: bool,
    },
    ScanMempool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::load("config.toml")?;

    match args.command {
        Command::Fuzz {
            chain,
            contract,
            hardened_defi,
            single_process,
            deterministic,
            rng_seed,
            bounded_search,
            seed_file,
        } => {
            println!(
                "Starting fuzz campaign on {:?} for contract {:?}",
                chain, contract
            );
            let mut hardened_defi_config = config.hardened_defi.clone();
            if hardened_defi {
                hardened_defi_config.enabled = true;
            }
            if single_process {
                hardened_defi_config.single_process = true;
            }
            if deterministic {
                hardened_defi_config.deterministic = true;
            }
            if rng_seed.is_some() {
                hardened_defi_config.rng_seed = rng_seed;
                hardened_defi_config.deterministic = true;
            }
            if bounded_search {
                hardened_defi_config.enable_bounded_search = true;
            }
            if seed_file.is_some() {
                hardened_defi_config.historical_seed_file = seed_file;
            }
            let fuzz_config = rusty_fuzz::engine::fuzz_engine::Config {
                rpc_url: config.rpc_url.clone(),
                fork_block: config.fork_block.unwrap_or(0),
                target_contract: contract
                    .as_deref()
                    .or(config.target_contract.as_deref())
                    .map(Address::from_str)
                    .transpose()?,
                corpus_dir: config.corpus_dir.clone(),
                report_dir: config.report_dir.clone(),
                foundry_harness: config
                    .foundry_project
                    .as_deref()
                    .map(FoundryHarnessManifest::ingest)
                    .transpose()?,
                mainnet_seed_bundle: config.mainnet_seed_bundle.clone(),
                hardened_defi: hardened_defi_config,
            };
            rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign(fuzz_config).await?;
        }
        Command::Seed {
            target,
            max_seeds,
            bundle_id,
            start_block,
            search_depth,
            include_address_hints,
        } => {
            ensure_evm_chain(&config)?;
            let target = target_address(target.as_deref(), &config)?;
            let fork_block = config.fork_block.unwrap_or(0);
            let url: reqwest::Url = config.rpc_url.parse()?;
            let provider = ProviderBuilder::new().connect_http(url);
            let fork_db = ForkDb::new(config.rpc_url.clone(), fork_block);
            let ingester = SeedIngester::new(provider);
            let mut seed_config = MainnetSeedConfig::new(fork_block, target, max_seeds);
            seed_config.start_block = start_block;
            seed_config.search_depth = search_depth;
            seed_config.include_address_hints = include_address_hints;
            let bundle = ingester
                .ingest_bundle_from_target(&seed_config, &fork_db)
                .await?;
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            corpus.persist_mainnet_seed_bundle(&bundle_id, &bundle)?;
            println!(
                "Persisted seed bundle `{}`: {} seeds, {} discovered accounts",
                bundle_id,
                bundle.seeds.len(),
                bundle.discovered_accounts.len()
            );
        }
        Command::SeedIngest { file, bundle_id } => {
            ensure_evm_chain(&config)?;
            let raw = std::fs::read_to_string(&file)?;
            let intelligence = SeedIntelligence::default();
            let candidates = intelligence.parse_historical_seed_json(&raw)?;
            anyhow::ensure!(
                !candidates.is_empty(),
                "no valid historical seeds in {}",
                file
            );
            let target = candidates[0].target;
            let seeds = candidates
                .into_iter()
                .enumerate()
                .map(|(idx, candidate)| {
                    let selector = candidate.selector;
                    let caller = candidate.caller;
                    let target = candidate.target;
                    let value = candidate.value;
                    let input = candidate.into_evm_input(0);
                    MainnetSeed {
                        id: format!("historical-json-{idx:04}"),
                        metadata: SeedMetadata {
                            source_block: config.fork_block.unwrap_or(0),
                            block_offset: 0,
                            transaction_ordinal: idx,
                            caller,
                            target,
                            value,
                            selector,
                            calldata_len: input
                                .txs
                                .first()
                                .map(|tx| tx.input.len())
                                .unwrap_or_default(),
                            discovered_address_hints: Vec::new(),
                            matched_target: Some(target),
                            match_kind: Some("historical-json".to_string()),
                        },
                        input,
                    }
                })
                .collect::<Vec<_>>();
            let bundle = MainnetSeedBundle {
                fork_block: config.fork_block.unwrap_or(0),
                target,
                seeds,
                discovered_accounts: Vec::new(),
                fork_cache: ForkDb::empty().cache_snapshot(),
            };
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            corpus.persist_mainnet_seed_bundle(&bundle_id, &bundle)?;
            println!(
                "Persisted historical seed bundle `{}`: {} seeds",
                bundle_id,
                bundle.seeds.len()
            );
        }
        Command::Replay {
            input,
            fork_cache_id,
            live,
        } => {
            ensure_evm_chain(&config)?;
            let fork_cache_id = fork_cache_id.unwrap_or_else(|| input.clone());
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            let block_env = campaign_block_env(&config).await?;
            let verifier = ReplayVerifier::new(65_536);
            let execution = if live {
                let input = load_replay_input(&corpus, &input)?;
                let (execution, report) = verifier.compare_cached_vs_live(
                    corpus.load_offline_fork_db(&fork_cache_id)?,
                    ForkDb::new(config.rpc_url.clone(), config.fork_block.unwrap_or(0)),
                    &block_env,
                    &input,
                )?;
                println!("Differential replay report: {report:?}");
                anyhow::ensure!(report.equivalent, "cached-vs-live replay mismatch");
                execution
            } else {
                if std::path::Path::new(&input).exists() {
                    anyhow::ensure!(
                        fork_cache_id != input,
                        "replaying a raw JSON input path requires --fork-cache-id"
                    );
                    let input = load_json_replay_input(&input)?;
                    verifier.verify_deterministic(
                        &replay_base_state(&corpus, &fork_cache_id)?,
                        &block_env,
                        &input,
                    )?
                } else {
                    verifier.verify_persisted_input(&corpus, &input, &fork_cache_id, &block_env)?
                }
            };
            println!(
                "Replay ok: txs={}, gas={}, coverage_hash={}",
                execution.tx_results.len(),
                execution.total_gas_used,
                execution.final_coverage_hash
            );
        }
        Command::Minimize {
            input_id,
            fork_cache_id,
            reason,
        } => {
            ensure_evm_chain(&config)?;
            let fork_cache_id = fork_cache_id.unwrap_or_else(|| input_id.clone());
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            let input = corpus.load_input(&input_id)?;
            let block_env = campaign_block_env(&config).await?;
            let db = CacheDB::new(corpus.load_offline_fork_db(&fork_cache_id)?);
            let executor = EvmExecutor::new();
            let oracle = ReentrancyOracle;
            let minimizer = Minimizer::new(&executor, &oracle, db, block_env);
            let artifact = minimizer.minimize_crash_to_foundry_poc(
                &input,
                &corpus,
                std::path::Path::new(&config.report_dir),
                &VulnType::Other(reason.clone()),
                &config.rpc_url,
                config.fork_block.unwrap_or(0),
                &reason,
                |execution| {
                    !ProtocolOraclePack::default().evaluate(execution).is_empty()
                        || execution.tx_results.iter().any(|result| {
                            !matches!(
                                result.status,
                                rusty_fuzz::common::types::ExecutionStatus::Success
                            )
                        })
                },
            )?;
            println!(
                "Minimized {} -> {} txs; report={}, foundry_poc={}",
                artifact.original_tx_count,
                artifact.minimized_tx_count,
                artifact.reproduction_report.display(),
                artifact.foundry_poc.display()
            );
        }
        Command::Report {
            input_id,
            fork_cache_id,
            reason,
        } => {
            ensure_evm_chain(&config)?;
            let fork_cache_id = fork_cache_id.unwrap_or_else(|| input_id.clone());
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            let input = corpus.load_input(&input_id)?;
            let block_env = campaign_block_env(&config).await?;
            let execution = ReplayVerifier::new(65_536).verify_persisted_input(
                &corpus,
                &input_id,
                &fork_cache_id,
                &block_env,
            )?;
            let metadata = corpus.persist_execution_input(
                &input,
                &execution,
                &execution_coverage_material(&execution),
                0,
            )?;
            let crash = match reason {
                Some(reason) => Some(corpus.persist_crash(&metadata, &reason)?),
                None => None,
            };
            let report = corpus.write_reproduction_report(&input, &execution, crash.as_ref())?;
            println!("Report written: {}", report.display());
        }
        Command::Validate {
            benchmarks,
            output,
            broker_free: _,
        } => {
            let manifests = ValidationRunner::load_manifests(&benchmarks)?;
            let runner = ValidationRunner;
            let block_env = campaign_block_env(&config).await.ok();
            let report_dir = output
                .as_deref()
                .and_then(|path| std::path::Path::new(path).parent())
                .map(std::path::Path::to_path_buf)
                .or_else(|| Some(std::path::PathBuf::from(&config.report_dir)));
            let context = rusty_fuzz::engine::benchmark::ValidationContext {
                rpc_url: Some(config.rpc_url.clone()),
                fork_block: config.fork_block,
                block_env,
                report_dir,
            };
            let report = runner.run_manifests_with_context(&manifests, &context);
            let output =
                output.unwrap_or_else(|| format!("{}/validation_report.json", config.report_dir));
            runner.write_report(&report, &output)?;
            let calibration_output = std::path::Path::new(&output)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("scoring_calibration.json");
            std::fs::write(
                &calibration_output,
                serde_json::to_string_pretty(&report.calibration)?,
            )?;
            println!(
                "Validation report written: {} (benchmarks={}, executed={}, found={}, not_found={}, not_run={}); calibration={}",
                output,
                report.summary.total,
                report.summary.executed,
                report.summary.found,
                report.summary.not_found,
                report.summary.not_run,
                calibration_output.display()
            );
        }
        Command::ScanMempool => {
            println!("Starting mempool scanner for chain: {}", config.chain);
            let scanner = MempoolScanner::new(config.rpc_url.clone());
            scanner.scan_mempool().await?;
        }
    }

    Ok(())
}

fn load_replay_input(
    corpus: &PersistentCorpus,
    input: &str,
) -> anyhow::Result<rusty_fuzz::evm::fuzz::EvmInput> {
    if std::path::Path::new(input).exists() {
        load_json_replay_input(input)
    } else {
        corpus.load_input(input)
    }
}

fn load_json_replay_input(path: &str) -> anyhow::Result<rusty_fuzz::evm::fuzz::EvmInput> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn replay_base_state(
    corpus: &PersistentCorpus,
    fork_cache_id: &str,
) -> anyhow::Result<rusty_fuzz::common::types::ChainState> {
    let fork_db = corpus.load_offline_fork_db(fork_cache_id)?;
    Ok(rusty_fuzz::common::types::ChainState::Evm(
        revm::database::CacheDB::new(fork_db),
    ))
}

fn ensure_evm_chain(config: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.chain == "evm",
        "this command targets the EVM campaign path; configured chain is `{}`",
        config.chain
    );
    Ok(())
}

fn target_address(cli_target: Option<&str>, config: &Config) -> anyhow::Result<Address> {
    cli_target
        .or(config.target_contract.as_deref())
        .ok_or_else(|| anyhow::anyhow!("target contract is required"))
        .and_then(|target| Address::from_str(target).map_err(Into::into))
}

async fn campaign_block_env(config: &Config) -> anyhow::Result<revm::context::BlockEnv> {
    let Some(fork_block) = config.fork_block else {
        return Ok(Default::default());
    };
    create_fork_block_env(&config.rpc_url, fork_block)
        .await
        .or_else(|_| Ok(Default::default()))
}

fn execution_coverage_material(
    execution: &rusty_fuzz::common::types::SequenceExecutionResult,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(execution.tx_results.len() * 8);
    for result in &execution.tx_results {
        material.extend_from_slice(&result.coverage_hash.to_be_bytes());
    }
    if material.is_empty() {
        material.extend_from_slice(&execution.final_coverage_hash.to_be_bytes());
    }
    material
}
