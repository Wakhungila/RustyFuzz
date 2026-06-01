use alloy::providers::{Provider, ProviderBuilder};
use clap::Parser;
use revm::database::CacheDB;
use revm::primitives::Address;
use rusty_fuzz::chain::mempool::MempoolScanner;
use rusty_fuzz::common::oracle::{ProtocolOraclePack, ReentrancyOracle, VulnType};
use rusty_fuzz::common::verifier::ReplayVerifier;
use rusty_fuzz::config::Config;
use rusty_fuzz::engine::abi_ingest::{ingest_abi_file, write_abi_cache};
use rusty_fuzz::engine::benchmark::ValidationRunner;
use rusty_fuzz::engine::bytecode_analysis::analyze_bytecode;
use rusty_fuzz::engine::fork_setup::ForkSetupDiscoverer;
use rusty_fuzz::engine::foundry_ingest::FoundryHarnessManifest;
use rusty_fuzz::engine::invariant_manifest::TargetInvariantManifest;
use rusty_fuzz::engine::minimizer::Minimizer;
use rusty_fuzz::engine::promotion::PromotionConfig;
use rusty_fuzz::engine::seed_intelligence::SeedIntelligence;
use rusty_fuzz::evm::corpus::PersistentCorpus;
use rusty_fuzz::evm::executor::EvmExecutor;
use rusty_fuzz::evm::fork::create_fork_block_env;
use rusty_fuzz::evm::fork_db::ForkDb;
use rusty_fuzz::evm::inspector::MAP_SIZE;
use rusty_fuzz::evm::seed_ingester::{
    MainnetSeed, MainnetSeedBundle, MainnetSeedConfig, SeedIngester, SeedMetadata,
};
use rusty_fuzz::satori::cli::SatoriCommand;
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
        #[arg(long, default_value_t = false)]
        require_seed_bundle: bool,
        #[arg(long, default_value_t = false)]
        require_rpc_fork: bool,
        #[arg(long, default_value_t = false)]
        allow_synthetic_fallback: bool,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long)]
        max_execs: Option<u64>,
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long, default_value_t = false)]
        unbounded: bool,
        #[arg(long)]
        artifact_limit: Option<u64>,
        #[arg(long)]
        campaign_id: Option<String>,
        #[arg(long, default_value_t = false)]
        no_synthetic_fallback: bool,
        #[arg(long, default_value_t = 0)]
        min_finding_confidence: u64,
        #[arg(long, default_value_t = false)]
        promote_findings: bool,
        #[arg(long, default_value_t = false)]
        no_promote_findings: bool,
        #[arg(long, default_value_t = true)]
        require_replay_for_report: bool,
        #[arg(long, default_value_t = true)]
        require_poc_for_confirmed: bool,
        #[arg(long)]
        promotion_limit: Option<u64>,
    },
    AbiIngest {
        #[arg(long)]
        file: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        output: Option<String>,
    },
    BytecodeAnalyze {
        #[arg(long)]
        file: String,
        #[arg(long)]
        output: Option<String>,
    },
    Seed {
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long, default_value = "evm")]
        chain: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        abi: Option<String>,
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
        #[arg(long, default_value_t = 0.0, alias = "rate-limit-rps")]
        seed_max_blocks_per_second: f64,
        #[arg(long, default_value_t = 3)]
        seed_rpc_retry_count: usize,
        #[arg(long, default_value_t = 250)]
        seed_rpc_backoff_ms: u64,
        #[arg(long, default_value_t = false)]
        resume: bool,
        #[arg(long)]
        seed_resume_cursor: Option<String>,
        #[arg(long)]
        seed_output_manifest: Option<String>,
    },
    SeedIngest {
        #[arg(long)]
        file: String,
        #[arg(long, default_value = "historical-json")]
        bundle_id: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        chain_id: Option<u64>,
        #[arg(long)]
        fork_block: Option<u64>,
    },
    Setup {
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        abi: Option<String>,
    },
    Invariants {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        abi_report: Option<String>,
        #[arg(long)]
        setup_report: Option<String>,
        #[arg(long)]
        bytecode_report: Option<String>,
        #[arg(long)]
        satori_job: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
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
    Satori {
        #[command(subcommand)]
        command: SatoriCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
enum JobCommand {
    Run {
        file: String,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long)]
        seed_bundle: Option<String>,
        #[arg(long, default_value_t = false)]
        require_seed_bundle: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let command = args.command;
    let command = match command {
        Command::Satori { command } => return rusty_fuzz::satori::cli::run(command).await,
        other => other,
    };
    let config = Config::load("config.toml")?;

    match command {
        Command::Fuzz {
            chain,
            contract,
            hardened_defi,
            single_process,
            deterministic,
            rng_seed,
            bounded_search,
            seed_file,
            require_seed_bundle,
            require_rpc_fork,
            allow_synthetic_fallback,
            abi,
            max_execs,
            duration_secs,
            unbounded,
            artifact_limit,
            campaign_id,
            no_synthetic_fallback,
            min_finding_confidence,
            promote_findings,
            no_promote_findings,
            require_replay_for_report,
            require_poc_for_confirmed,
            promotion_limit,
        } => {
            let raw_target = match contract.as_deref() {
                Some(target) if target.trim().is_empty() => {
                    anyhow::bail!(
                        "--contract was provided but empty; export TARGET first or pass a 0x-prefixed 20-byte address"
                    );
                }
                Some(target) => Some(target.trim()),
                None => config
                    .target_contract
                    .as_deref()
                    .map(str::trim)
                    .filter(|target| !target.is_empty()),
            };
            let target_contract = raw_target
                .map(Address::from_str)
                .transpose()
                .map_err(|err| {
                    anyhow::anyhow!(
                        "invalid --contract/target_contract address; got {:?}: {err}",
                        raw_target.unwrap_or("")
                    )
                })?;
            println!(
                "Starting fuzz campaign on {:?} for contract {:?}",
                chain,
                target_contract.map(|address| address.to_string())
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
            let (max_execs, duration_secs) =
                resolve_campaign_bounds(max_execs, duration_secs, unbounded)?;
            let promotion_enabled = if no_promote_findings {
                false
            } else {
                promote_findings
                    || hardened_defi_config.single_process
                    || max_execs.is_some()
                    || duration_secs.is_some()
            };
            println!(
                "Campaign controls: mode={}, max_execs={:?}, duration_secs={:?}, single_process={}, synthetic_fallback={}, promotion={}",
                if unbounded { "unbounded" } else { "bounded" },
                max_execs,
                duration_secs,
                hardened_defi_config.single_process,
                !no_synthetic_fallback && (config.allow_synthetic_fallback || allow_synthetic_fallback),
                promotion_enabled
            );
            let sanitized_campaign_id = campaign_id.as_deref().map(sanitize_campaign_id);
            let campaign_corpus_dir = sanitized_campaign_id
                .as_ref()
                .map(|id| format!("{}/{}", config.corpus_dir, id))
                .unwrap_or_else(|| config.corpus_dir.clone());
            let campaign_report_dir = sanitized_campaign_id
                .as_ref()
                .map(|id| format!("{}/{}", config.report_dir, id))
                .unwrap_or_else(|| config.report_dir.clone());
            let fuzz_config = rusty_fuzz::engine::fuzz_engine::Config {
                rpc_url: config.rpc_url.clone(),
                fork_block: config.fork_block.unwrap_or(0),
                target_contract,
                corpus_dir: campaign_corpus_dir,
                report_dir: campaign_report_dir,
                foundry_harness: config
                    .foundry_project
                    .as_deref()
                    .map(FoundryHarnessManifest::ingest)
                    .transpose()?,
                mainnet_seed_bundle: config.mainnet_seed_bundle.clone(),
                in_memory_bytecode: None,
                require_seed_bundle: config.require_seed_bundle || require_seed_bundle,
                require_rpc_fork: config.require_rpc_fork || require_rpc_fork,
                allow_synthetic_fallback: !no_synthetic_fallback
                    && (config.allow_synthetic_fallback || allow_synthetic_fallback),
                hardened_defi: hardened_defi_config,
                target_invariant_manifest: config.target_invariant_manifest.clone(),
                abi_path: abi.or(config.target_abi.clone()),
                max_execs,
                duration_secs,
                artifact_limit,
                campaign_id: sanitized_campaign_id,
                min_finding_confidence,
                promotion: PromotionConfig {
                    enabled: promotion_enabled,
                    require_replay_for_report,
                    require_poc_for_confirmed,
                    promotion_limit,
                },
            };
            rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign(fuzz_config).await?;
        }
        Command::AbiIngest {
            file,
            target,
            bundle_id,
            output,
        } => {
            ensure_evm_chain(&config)?;
            let target = target
                .as_deref()
                .map(Address::from_str)
                .transpose()?
                .or_else(|| {
                    config
                        .target_contract
                        .as_deref()
                        .and_then(|value| Address::from_str(value).ok())
                });
            let (abi, _registry, report) = ingest_abi_file(&file, target)?;
            let (abi_path, report_path) =
                write_abi_cache(&config.abi_cache_dir, &bundle_id, &abi, &report)?;
            if let Some(output) = output {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
            }
            println!(
                "ABI loaded: function_count={}, event_count={}, classified_selectors={}, cache={}, report={}",
                report.function_count,
                report.event_count,
                report.classified_selectors,
                abi_path.display(),
                report_path.display()
            );
        }
        Command::BytecodeAnalyze { file, output } => {
            let bytecode = match std::fs::read_to_string(&file) {
                Ok(text) => {
                    let raw = text.trim();
                    if !raw.is_empty()
                        && (raw.starts_with("0x") || raw.chars().all(|ch| ch.is_ascii_hexdigit()))
                    {
                        hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?
                    } else {
                        std::fs::read(&file)?
                    }
                }
                Err(_) => std::fs::read(&file)?,
            };
            let report = analyze_bytecode(&bytecode);
            let rendered = serde_json::to_string_pretty(&report)?;
            if let Some(output) = output {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&output, rendered)?;
                println!(
                    "Bytecode analysis written: {} (push4_selectors={}, dispatch_selectors={}, proxy_patterns={}, risk_flags={}, profile={:?}, confidence={})",
                    output,
                    report.push4_selectors.len(),
                    report.dispatch_selectors.len(),
                    report.proxy_patterns.len(),
                    report.risk_flags.len(),
                    report.target_profile.protocol_types,
                    report.target_profile.confidence
                );
            } else {
                println!("{rendered}");
            }
        }
        Command::Seed {
            target,
            contract,
            rpc_url,
            chain,
            output,
            limit,
            abi,
            max_seeds,
            bundle_id,
            start_block,
            search_depth,
            include_address_hints,
            seed_max_blocks_per_second,
            seed_rpc_retry_count,
            seed_rpc_backoff_ms,
            resume,
            seed_resume_cursor,
            seed_output_manifest,
        } => {
            ensure_evm_chain(&config)?;
            if contract.is_some() || rpc_url.is_some() || output.is_some() {
                let contract = contract
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("rustyfuzz seed requires --contract"))?;
                let rpc_url = rpc_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("rustyfuzz seed requires --rpc-url"))?;
                let output = output
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("rustyfuzz seed requires --output"))?;
                let target = Address::from_str(contract)?;
                if let Some(abi_path) = abi.as_deref() {
                    let _ = ingest_abi_file(abi_path, Some(target))?;
                }

                let url: reqwest::Url = rpc_url.parse()?;
                let provider = ProviderBuilder::new().connect_http(url);
                let latest_block = provider.get_block_number().await?;
                let fork_block = config.fork_block.unwrap_or(latest_block);
                let fork_db = ForkDb::new(rpc_url.to_string(), fork_block);
                let ingester = SeedIngester::new(provider);
                let mut seed_config = MainnetSeedConfig::new(fork_block, target, limit);
                seed_config.search_depth = search_depth.max(limit as u64);
                seed_config.start_block = start_block;
                seed_config.include_address_hints = include_address_hints;
                seed_config.max_blocks_per_second = if seed_max_blocks_per_second > 0.0 {
                    Some(seed_max_blocks_per_second)
                } else {
                    None
                };
                seed_config.max_retries = seed_rpc_retry_count;
                seed_config.retry_backoff_ms = seed_rpc_backoff_ms;
                seed_config.resume_cursor = seed_resume_cursor.or_else(|| {
                    resume.then(|| format!("{output}/seed-cursor.json"))
                });
                let mut bundle = ingester
                    .ingest_bundle_from_target(&seed_config, &fork_db)
                    .await?;
                if let Some(scan) = bundle.scan.as_mut() {
                    scan.chain_id = match chain.as_str() {
                        "bsc" => Some(56),
                        "evm" => None,
                        other => anyhow::bail!("unsupported --chain `{other}`; expected evm or bsc"),
                    };
                }
                std::fs::create_dir_all(output)?;
                let manifest_path = std::path::Path::new(output).join("manifest.json");
                std::fs::write(&manifest_path, serde_json::to_vec_pretty(&bundle)?)?;
                println!(
                    "Ingested {} transactions. Wrote seed bundle to {}.",
                    bundle.seeds.len(),
                    manifest_path.display()
                );
                return Ok(());
            }

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
            seed_config.max_blocks_per_second = if seed_max_blocks_per_second > 0.0 {
                Some(seed_max_blocks_per_second)
            } else {
                None
            };
            seed_config.max_retries = seed_rpc_retry_count;
            seed_config.retry_backoff_ms = seed_rpc_backoff_ms;
            seed_config.resume_cursor = seed_resume_cursor.or_else(|| {
                resume.then(|| format!("{}/seed_cursors/{bundle_id}.json", config.corpus_dir))
            });
            seed_config.output_manifest = seed_output_manifest;
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
        Command::SeedIngest {
            file,
            bundle_id,
            target,
            chain_id,
            fork_block,
        } => {
            ensure_evm_chain(&config)?;
            let raw = std::fs::read_to_string(&file)?;
            let intelligence = SeedIntelligence::default();
            let target_hint = target
                .as_deref()
                .map(Address::from_str)
                .transpose()?
                .or_else(|| {
                    config
                        .target_contract
                        .as_deref()
                        .and_then(|value| Address::from_str(value).ok())
                });
            let candidates =
                intelligence.parse_historical_seed_json_with_target(&raw, target_hint)?;
            anyhow::ensure!(
                !candidates.is_empty(),
                "no valid historical seeds in {}",
                file
            );
            let target = target_hint.unwrap_or(candidates[0].target);
            let inputs = intelligence.historical_candidates_to_inputs(candidates.clone(), 0, 3);
            let seeds = inputs
                .into_iter()
                .enumerate()
                .map(|(idx, input)| {
                    let first_tx = input.txs.first().cloned();
                    let caller = first_tx
                        .as_ref()
                        .map(|tx| tx.caller)
                        .unwrap_or(Address::repeat_byte(0x13));
                    let seed_target = first_tx.as_ref().map(|tx| tx.to).unwrap_or(target);
                    let value = first_tx.as_ref().map(|tx| tx.value).unwrap_or_default();
                    let selector = first_tx
                        .as_ref()
                        .and_then(|tx| tx.input.get(0..4))
                        .and_then(|bytes| bytes.try_into().ok());
                    MainnetSeed {
                        id: format!("historical-json-{idx:04}"),
                        metadata: SeedMetadata {
                            source_block: fork_block.or(config.fork_block).unwrap_or(0),
                            block_offset: 0,
                            transaction_ordinal: idx,
                            caller,
                            target: seed_target,
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
                            confidence: None,
                            provenance: Some("historical-json-ingest".to_string()),
                        },
                        input,
                    }
                })
                .collect::<Vec<_>>();
            let bundle = MainnetSeedBundle {
                fork_block: fork_block.or(config.fork_block).unwrap_or(0),
                target,
                seeds,
                discovered_accounts: Vec::new(),
                fork_cache: ForkDb::empty().cache_snapshot(),
                scan: Some(rusty_fuzz::evm::seed_ingester::SeedScanManifest {
                    chain_id,
                    start_block: None,
                    end_block: None,
                    search_depth: 0,
                    include_address_hints: false,
                    max_blocks_per_second: None,
                    seed_count: candidates.len(),
                    discovered_selectors: candidates
                        .iter()
                        .filter_map(|seed| seed.selector)
                        .collect(),
                }),
            };
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            corpus.persist_mainnet_seed_bundle(&bundle_id, &bundle)?;
            println!(
                "Persisted historical seed bundle `{}`: {} seeds",
                bundle_id,
                bundle.seeds.len()
            );
        }
        Command::Setup {
            bundle_id,
            target,
            output,
            abi,
        } => {
            ensure_evm_chain(&config)?;
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            let bundle = corpus.load_mainnet_seed_bundle(&bundle_id)?;
            let target = target
                .as_deref()
                .map(Address::from_str)
                .transpose()?
                .unwrap_or(bundle.target);
            let mut report = ForkSetupDiscoverer::discover_from_seed_bundle(
                target,
                &bundle.seeds,
                &bundle.discovered_accounts,
            );
            if let Some(path) = abi.or(config.target_abi.clone()) {
                let (_abi, _registry, abi_report) = ingest_abi_file(&path, Some(target))?;
                report = ForkSetupDiscoverer::discover_with_abi_report(
                    target,
                    &bundle.seeds,
                    &bundle.discovered_accounts,
                    &abi_report,
                );
            }
            let report_json = serde_json::to_string_pretty(&report)?;
            if let Some(output) = output {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&output, report_json)?;
                println!(
                    "Wrote fork setup report `{}`: tokens={}, whales={}, holders={}, pools={}, oracles={}, collateral_assets={}, flows={}",
                    output,
                    report.tokens.len(),
                    report.whales.len(),
                    report.holders.len(),
                    report.pools.len(),
                    report.oracle_feeds.len(),
                    report.collateral_assets.len(),
                    report.recent_valid_flows.len()
                );
            } else {
                println!("{report_json}");
            }
        }
        Command::Invariants {
            target,
            abi_report,
            setup_report,
            bytecode_report,
            satori_job,
            output,
        } => {
            ensure_evm_chain(&config)?;
            let target = target
                .as_deref()
                .map(Address::from_str)
                .transpose()?
                .or_else(|| {
                    config
                        .target_contract
                        .as_deref()
                        .and_then(|value| Address::from_str(value).ok())
                });
            let abi_report = abi_report.as_deref().map(read_json_file).transpose()?;
            let setup_report = setup_report.as_deref().map(read_json_file).transpose()?;
            let bytecode_report = bytecode_report.as_deref().map(read_json_file).transpose()?;
            let satori_job = satori_job.as_deref().map(read_json_file).transpose()?;
            let mut manifest = TargetInvariantManifest::generate(
                target,
                abi_report.as_ref(),
                setup_report.as_ref(),
                satori_job.as_ref(),
            );
            if let Some(report) = bytecode_report.as_ref() {
                manifest.apply_bytecode_report(report);
            }
            let rendered = toml::to_string_pretty(&manifest)?;
            if let Some(output) = output {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&output, rendered)?;
                println!(
                    "Invariant manifest written: {} (rules={})",
                    output,
                    manifest.invariants.len()
                );
            } else {
                println!("{rendered}");
            }
        }
        Command::Job { command } => match command {
            JobCommand::Run {
                file,
                abi,
                seed_bundle,
                require_seed_bundle,
            } => {
                ensure_evm_chain(&config)?;
                let job: rusty_fuzz::satori::types::RustyFuzzJobSpec =
                    serde_json::from_str(&std::fs::read_to_string(&file)?)?;
                let target_contract = job
                    .target_contract
                    .as_deref()
                    .or(config.target_contract.as_deref())
                    .map(Address::from_str)
                    .transpose()?;
                let job_report_dir = format!("{}/jobs/{}", config.report_dir, job.job_id);
                std::fs::create_dir_all(&job_report_dir)?;
                let invariant_manifest =
                    TargetInvariantManifest::generate(target_contract, None, None, Some(&job));
                let invariant_path = format!("{job_report_dir}/invariants.toml");
                std::fs::write(
                    &invariant_path,
                    toml::to_string_pretty(&invariant_manifest)?,
                )?;
                let fuzz_config = rusty_fuzz::engine::fuzz_engine::Config {
                    rpc_url: job.fork_rpc_url.unwrap_or_else(|| config.rpc_url.clone()),
                    fork_block: job.fork_block.or(config.fork_block).unwrap_or(0),
                    target_contract,
                    corpus_dir: config.corpus_dir.clone(),
                    report_dir: job_report_dir,
                    foundry_harness: None,
                    mainnet_seed_bundle: seed_bundle.or(config.mainnet_seed_bundle.clone()),
                    in_memory_bytecode: None,
                    require_seed_bundle: config.require_seed_bundle || require_seed_bundle,
                    require_rpc_fork: true,
                    allow_synthetic_fallback: false,
                    hardened_defi: {
                        let mut hardened = config.hardened_defi.clone();
                        hardened.enabled = true;
                        hardened.max_tx_depth = job.max_depth.max(1);
                        hardened
                    },
                    target_invariant_manifest: Some(invariant_path),
                    abi_path: abi.or(config.target_abi.clone()),
                    max_execs: None,
                    duration_secs: None,
                    artifact_limit: None,
                    campaign_id: Some(job.job_id.clone()),
                    min_finding_confidence: 0,
                    promotion: PromotionConfig {
                        enabled: true,
                        require_replay_for_report: true,
                        require_poc_for_confirmed: true,
                        promotion_limit: Some(8),
                    },
                };
                rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign(fuzz_config).await?;
            }
        },
        Command::Replay {
            input,
            fork_cache_id,
            live,
        } => {
            ensure_evm_chain(&config)?;
            let fork_cache_id = fork_cache_id.unwrap_or_else(|| input.clone());
            let corpus = PersistentCorpus::new(&config.corpus_dir)?;
            let block_env = campaign_block_env(&config).await?;
            let verifier = ReplayVerifier::new(MAP_SIZE);
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
            } else if std::path::Path::new(&input).exists() {
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
            let execution = ReplayVerifier::new(MAP_SIZE).verify_persisted_input(
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
        Command::Satori { .. } => unreachable!("Satori command is dispatched before config load"),
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

fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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

fn sanitize_campaign_id(id: &str) -> String {
    let sanitized = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "campaign".to_string()
    } else {
        sanitized
    }
}

fn resolve_campaign_bounds(
    max_execs: Option<u64>,
    duration_secs: Option<u64>,
    unbounded: bool,
) -> anyhow::Result<(Option<u64>, Option<u64>)> {
    if unbounded || max_execs.is_some() || duration_secs.is_some() {
        return Ok((max_execs, duration_secs));
    }
    anyhow::bail!(
        "refusing to start an unbounded fuzz campaign without an explicit opt-in; pass --max-execs, --duration-secs, or --unbounded"
    );
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

#[cfg(test)]
mod tests {
    use super::resolve_campaign_bounds;

    #[test]
    fn fuzz_requires_bounds_unless_unbounded() {
        assert!(resolve_campaign_bounds(None, None, false).is_err());
        assert_eq!(
            resolve_campaign_bounds(Some(100), None, false).unwrap(),
            (Some(100), None)
        );
        assert_eq!(
            resolve_campaign_bounds(None, Some(60), false).unwrap(),
            (None, Some(60))
        );
        assert_eq!(
            resolve_campaign_bounds(None, None, true).unwrap(),
            (None, None)
        );
    }
}
