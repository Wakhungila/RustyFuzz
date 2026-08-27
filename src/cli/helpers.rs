#![allow(clippy::too_many_lines)]

use alloy::primitives::keccak256;
use alloy::providers::{Provider, ProviderBuilder};
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use rusty_fuzz::config::Config;
use rusty_fuzz::engine::abi_ingest::ingest_abi_file;
use rusty_fuzz::engine::fork_setup::ForkSetupDiscoverer;
use rusty_fuzz::engine::invariant_manifest::TargetInvariantManifest;
use rusty_fuzz::engine::promotion::{PromotionCampaignSummary, PromotionConfig};
use rusty_fuzz::evm::corpus::PersistentCorpus;
use rusty_fuzz::evm::etherscan_abi_fetcher::EtherscanAbiFetcher;
use rusty_fuzz::evm::fork::create_fork_block_env;
use rusty_fuzz::evm::seed_ingester::{
    seed_abi_functions, MainnetSeedConfig, SeedIngester, SeedScanMode,
};
use rustyfuzz_evm::fork_db::ForkDb;
use std::io::Write;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

pub fn load_replay_input(
    corpus: &PersistentCorpus,
    input: &str,
) -> anyhow::Result<rusty_fuzz::evm::fuzz::EvmInput> {
    if std::path::Path::new(input).exists() {
        load_json_replay_input(input)
    } else {
        corpus.load_input(input)
    }
}

pub fn load_json_replay_input(path: &str) -> anyhow::Result<rusty_fuzz::evm::fuzz::EvmInput> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

pub fn replay_base_state(
    corpus: &PersistentCorpus,
    fork_cache_id: &str,
) -> anyhow::Result<rusty_fuzz::common::types::ChainState> {
    let fork_db = corpus.load_offline_fork_db(fork_cache_id)?;
    Ok(rusty_fuzz::common::types::ChainState::Evm(
        revm::database::CacheDB::new(fork_db),
    ))
}

pub fn ensure_evm_chain(config: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.chain == "evm",
        "this command targets the EVM campaign path; configured chain is `{}`",
        config.chain
    );
    Ok(())
}

pub fn sanitize_campaign_id(id: &str) -> String {
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

pub fn resolve_campaign_bounds(
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

pub fn install_campaign_watchdog(
    wall_timeout_secs: Option<u64>,
    max_execs: Option<u64>,
    duration_secs: Option<u64>,
    unbounded: bool,
) -> Option<Arc<AtomicBool>> {
    let timeout_secs = wall_timeout_secs.or_else(|| {
        if unbounded {
            None
        } else if let Some(duration_secs) = duration_secs {
            Some(duration_secs.saturating_add(60).max(90))
        } else {
            max_execs.map(|execs| {
                let execution_scaled = execs.saturating_div(100).saturating_mul(2);
                execution_scaled.clamp(90, 3600)
            })
        }
    })?;
    if timeout_secs == 0 {
        return None;
    }

    let done = Arc::new(AtomicBool::new(false));
    let watchdog_done = Arc::clone(&done);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        if !watchdog_done.load(Ordering::SeqCst) {
            eprintln!(
                "fuzz campaign exceeded wall-clock timeout of {timeout_secs}s; exiting with code 124"
            );
            let _ = std::io::stderr().flush();
            std::process::exit(124);
        }
    });
    Some(done)
}

pub fn target_address(cli_target: Option<&str>, config: &Config) -> anyhow::Result<Address> {
    cli_target
        .or(config.target_contract.as_deref())
        .ok_or_else(|| anyhow::anyhow!("target contract is required"))
        .and_then(|target| Address::from_str(target).map_err(Into::into))
}

pub fn parse_seed_scan_mode(value: &str) -> anyhow::Result<SeedScanMode> {
    match value {
        "block-scan" | "block_scan" | "blocks" => Ok(SeedScanMode::BlockScan),
        "logs" | "eth-getlogs" | "eth_getlogs" => Ok(SeedScanMode::Logs),
        "debug-trace" | "debug_trace" | "debug-trace-block" => Ok(SeedScanMode::DebugTrace),
        other => anyhow::bail!(
            "unsupported --seed-mode `{other}`; expected block-scan, logs, or debug-trace"
        ),
    }
}

pub struct ProveLiveOptions {
    pub target: String,
    pub chain: String,
    pub block: Option<u64>,
    pub rpc_url: Option<String>,
    pub abi: Option<String>,
    pub abi_key: Option<String>,
    pub explorer_url: Option<String>,
    pub campaign_id: Option<String>,
    pub duration_secs: u64,
    pub max_execs: Option<u64>,
    pub wall_timeout_secs: Option<u64>,
    pub max_seeds: usize,
    pub search_depth: u64,
    pub seed_mode: String,
    pub include_address_hints: bool,
    pub seed_max_blocks_per_second: f64,
    pub skip_seed_discovery: bool,
    pub artifact_limit: u64,
    pub promotion_limit: u64,
    pub min_finding_confidence: u64,
    pub strict_proof: bool,
    pub no_synthetic_proof: bool,
    pub require_foundry_poc: bool,
    pub require_minimized: bool,
    pub reject_heuristics: bool,
    pub max_finding_noise: Option<u64>,
    pub poc_out: Option<String>,
    pub deterministic: bool,
    pub rng_seed: Option<u64>,
}

pub async fn run_prove_live(config: &Config, options: ProveLiveOptions) -> anyhow::Result<()> {
    ensure_evm_chain(config)?;
    anyhow::ensure!(
        matches!(options.chain.as_str(), "evm" | "eth" | "ethereum" | "bsc"),
        "unsupported --chain `{}`; expected evm, eth, ethereum, or bsc",
        options.chain
    );

    let target = Address::from_str(options.target.trim())?;
    let rpc_url = options.rpc_url.unwrap_or_else(|| config.rpc_url.clone());
    let url: reqwest::Url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let latest_block = provider.get_block_number().await?;
    let fork_block = options.block.or(config.fork_block).unwrap_or(latest_block);
    let campaign_id = options.campaign_id.unwrap_or_else(|| {
        format!(
            "prove-live-{}-{fork_block}",
            target
                .to_string()
                .trim_start_matches("0x")
                .chars()
                .take(8)
                .collect::<String>()
        )
    });
    let campaign_id = sanitize_campaign_id(&campaign_id);
    let campaign_corpus_dir = format!("{}/prove-live/{}", config.corpus_dir, campaign_id);
    let campaign_report_dir = format!("{}/prove-live/{}", config.report_dir, campaign_id);
    std::fs::create_dir_all(&campaign_report_dir)?;

    print_prove_live_banner(&campaign_id, target, fork_block, options.duration_secs);

    let abi_fetcher = options
        .abi_key
        .clone()
        .or_else(|| std::env::var("ETHERSCAN_API_KEY").ok())
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .map(|api_key| {
            let explorer_url = options
                .explorer_url
                .clone()
                .unwrap_or_else(|| default_explorer_api_url(&options.chain).to_string());
            EtherscanAbiFetcher::new(api_key, explorer_url)
        });

    let fetched_abi_path = if options.abi.is_none() {
        if let Some(fetcher) = abi_fetcher.as_ref() {
            fetch_explorer_abi_to_report(fetcher, target, "target", &campaign_report_dir).await?
        } else {
            println!(
                "\x1b[33m[abi]\x1b[0m no ABI supplied and ETHERSCAN_API_KEY is empty; continuing with selector heuristics"
            );
            None
        }
    } else {
        None
    };

    let mut resolved_abi_path = options
        .abi
        .clone()
        .or(fetched_abi_path.clone())
        .or(config.target_abi.clone());
    let mut abi_report = None;
    if let Some(abi_path) = resolved_abi_path.as_deref() {
        let (_abi, _registry, report) = ingest_abi_file(abi_path, Some(target))?;
        let output = std::path::Path::new(&campaign_report_dir).join("abi_report.json");
        std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
        println!(
            "\x1b[36m[abi]\x1b[0m loaded {} functions, {} events -> {}",
            report.function_count,
            report.event_count,
            output.display()
        );
        abi_report = Some(report);
    }

    if abi_report
        .as_ref()
        .is_some_and(|report| report.function_count == 0)
        && options.abi.is_none()
    {
        if let Some(fetcher) = abi_fetcher.as_ref() {
            let fork_db = ForkDb::new(rpc_url.clone(), fork_block);
            match discover_eip1967_implementation(&fork_db, target) {
                Ok(Some(implementation)) => {
                    println!(
                        "\x1b[36m[abi]\x1b[0m target ABI has no functions; discovered EIP-1967 implementation {}",
                        implementation
                    );
                    if let Some(path) = fetch_explorer_abi_to_report(
                        fetcher,
                        implementation,
                        "implementation",
                        &campaign_report_dir,
                    )
                    .await?
                    {
                        let (_abi, _registry, report) = ingest_abi_file(&path, Some(target))?;
                        let output = std::path::Path::new(&campaign_report_dir)
                            .join("implementation_abi_report.json");
                        std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
                        println!(
                            "\x1b[36m[abi]\x1b[0m loaded implementation ABI {} functions, {} events -> {}",
                            report.function_count,
                            report.event_count,
                            output.display()
                        );
                        resolved_abi_path = Some(path);
                        abi_report = Some(report);
                    }
                }
                Ok(None) => {
                    println!(
                        "\x1b[33m[abi]\x1b[0m target ABI has no functions and no EIP-1967 implementation slot was populated"
                    );
                }
                Err(error) => {
                    println!(
                        "\x1b[33m[abi]\x1b[0m target ABI has no functions; EIP-1967 implementation lookup failed ({error})"
                    );
                }
            }
        }
    }

    let seed_bundle_id = if options.skip_seed_discovery || options.max_seeds == 0 {
        println!("\x1b[33m[seed]\x1b[0m skipped seed discovery");
        None
    } else {
        let bundle_id = format!("{campaign_id}-seeds");
        let fork_db = ForkDb::new(rpc_url.clone(), fork_block);
        let ingester = SeedIngester::new(provider);
        let mut seed_config = MainnetSeedConfig::new(fork_block, target, options.max_seeds);
        seed_config.search_depth = options.search_depth.max(options.max_seeds as u64);
        seed_config.include_address_hints = options.include_address_hints;
        seed_config.max_blocks_per_second = if options.seed_max_blocks_per_second > 0.0 {
            Some(options.seed_max_blocks_per_second)
        } else {
            None
        };
        seed_config.scan_mode = parse_seed_scan_mode(&options.seed_mode)?;
        if let Some(report) = abi_report.as_ref() {
            seed_config.abi_functions = seed_abi_functions(report.functions.clone());
        }
        let bundle = ingester
            .ingest_bundle_from_target(&seed_config, &fork_db)
            .await?;
        let manifest_output = std::path::Path::new(&campaign_report_dir).join("seed_bundle.json");
        std::fs::write(&manifest_output, serde_json::to_vec_pretty(&bundle)?)?;
        let corpus = PersistentCorpus::new(&campaign_corpus_dir)?;
        corpus.persist_mainnet_seed_bundle(&bundle_id, &bundle)?;
        println!(
            "\x1b[36m[seed]\x1b[0m persisted `{}`: {} seeds, {} discovered accounts -> {}",
            bundle_id,
            bundle.seeds.len(),
            bundle.discovered_accounts.len(),
            manifest_output.display()
        );

        let setup_report = if let Some(report) = abi_report.as_ref() {
            ForkSetupDiscoverer::discover_with_abi_report(
                target,
                &bundle.seeds,
                &bundle.discovered_accounts,
                report,
            )
        } else {
            ForkSetupDiscoverer::discover_from_seed_bundle(
                target,
                &bundle.seeds,
                &bundle.discovered_accounts,
            )
        };
        let setup_output = std::path::Path::new(&campaign_report_dir).join("setup_report.json");
        std::fs::write(&setup_output, serde_json::to_vec_pretty(&setup_report)?)?;
        println!(
            "\x1b[36m[setup]\x1b[0m tokens={}, whales={}, pools={}, oracles={} -> {}",
            setup_report.tokens.len(),
            setup_report.whales.len(),
            setup_report.pools.len(),
            setup_report.oracle_feeds.len(),
            setup_output.display()
        );

        let invariant_manifest = TargetInvariantManifest::generate(
            Some(target),
            abi_report.as_ref(),
            Some(&setup_report),
            None,
        );
        let invariant_output = std::path::Path::new(&campaign_report_dir).join("invariants.toml");
        std::fs::write(
            &invariant_output,
            toml::to_string_pretty(&invariant_manifest)?,
        )?;
        println!(
            "\x1b[36m[invariants]\x1b[0m rules={} -> {}",
            invariant_manifest.invariants.len(),
            invariant_output.display()
        );
        Some(bundle_id)
    };

    let target_invariant_manifest = {
        let path = std::path::Path::new(&campaign_report_dir).join("invariants.toml");
        if path.exists() {
            Some(path.to_string_lossy().to_string())
        } else {
            let invariant_manifest =
                TargetInvariantManifest::generate(Some(target), abi_report.as_ref(), None, None);
            std::fs::write(&path, toml::to_string_pretty(&invariant_manifest)?)?;
            Some(path.to_string_lossy().to_string())
        }
    };

    let mut hardened = config.hardened_defi.clone();
    hardened.enabled = true;
    hardened.single_process = true;
    hardened.enable_bounded_search = true;
    if options.deterministic || options.rng_seed.is_some() {
        hardened.deterministic = true;
        hardened.rng_seed = options.rng_seed;
    }

    println!(
        "\x1b[35m[fuzz]\x1b[0m fail-closed fork campaign: rpc={}, target={}, duration={}s, max_execs={:?}",
        sanitize_rpc_for_display(&rpc_url),
        target,
        options.duration_secs,
        options.max_execs
    );
    apply_prove_live_runtime_defaults(options.duration_secs);
    let fuzz_config = rusty_fuzz::engine::fuzz_engine::Config {
        rpc_url,
        fork_block,
        target_contract: Some(target),
        corpus_dir: campaign_corpus_dir,
        report_dir: campaign_report_dir.clone(),
        foundry_harness: None,
        mainnet_seed_bundle: seed_bundle_id,
        in_memory_bytecode: None,
        cores: None,
        require_seed_bundle: false,
        require_rpc_fork: true,
        allow_synthetic_fallback: false,
        hardened_defi: hardened,
        target_invariant_manifest,
        abi_path: resolved_abi_path,
        max_execs: options.max_execs,
        duration_secs: Some(options.duration_secs),
        artifact_limit: Some(options.artifact_limit),
        campaign_id: Some(campaign_id.clone()),
        min_finding_confidence: options.min_finding_confidence,
        promotion: PromotionConfig {
            enabled: true,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            strict_proof: options.strict_proof,
            no_synthetic_proof: options.no_synthetic_proof,
            require_foundry_poc: options.require_foundry_poc,
            require_minimized: options.require_minimized,
            reject_heuristics: options.reject_heuristics,
            max_finding_noise: options.max_finding_noise,
            poc_out: options.poc_out,
            promotion_limit: Some(options.promotion_limit),
        },
    };
    let watchdog_done = install_campaign_watchdog(
        options.wall_timeout_secs,
        options.max_execs,
        Some(options.duration_secs),
        false,
    );
    let result = rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign(fuzz_config).await;
    if let Some(done) = watchdog_done {
        done.store(true, Ordering::SeqCst);
    }
    result?;
    println!(
        "\x1b[32m[done]\x1b[0m proof campaign `{}` finished. Reports: {}",
        campaign_id, campaign_report_dir
    );
    if let Some(exit_code) = prove_live_exit_code(&campaign_report_dir)? {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub fn prove_live_exit_code(report_dir: &str) -> anyhow::Result<Option<i32>> {
    let summary_path = std::path::Path::new(report_dir).join("campaign_summary.json");
    if !summary_path.exists() {
        return Ok(None);
    }
    let summary: PromotionCampaignSummary = serde_json::from_slice(&std::fs::read(&summary_path)?)?;
    if summary.confirmed_findings > 0 {
        Ok(Some(10))
    } else if summary.replay_failure_count > 0
        || summary.missing_poc_for_promoted > 0
        || summary.rejected_candidates > 0
    {
        Ok(Some(20))
    } else if summary.candidate_findings > 0 || summary.unproven_candidates > 0 {
        Ok(Some(11))
    } else {
        Ok(Some(0))
    }
}

fn apply_prove_live_runtime_defaults(duration_secs: u64) {
    let default_exec_timeout = duration_secs.clamp(5, 15);
    if std::env::var("RUSTYFUZZ_EXEC_TIMEOUT_SECS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        std::env::set_var(
            "RUSTYFUZZ_EXEC_TIMEOUT_SECS",
            default_exec_timeout.to_string(),
        );
        println!(
            "\x1b[36m[runtime]\x1b[0m default per-input timeout={}s (override with RUSTYFUZZ_EXEC_TIMEOUT_SECS)",
            default_exec_timeout
        );
    }
    if std::env::var("RUSTYFUZZ_EXEC_RPC_BUDGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        std::env::set_var("RUSTYFUZZ_EXEC_RPC_BUDGET", "4");
        println!(
            "\x1b[36m[runtime]\x1b[0m default per-input RPC budget=4 (override with RUSTYFUZZ_EXEC_RPC_BUDGET)"
        );
    }
}

async fn fetch_explorer_abi_to_report(
    fetcher: &EtherscanAbiFetcher,
    address: Address,
    label: &str,
    campaign_report_dir: &str,
) -> anyhow::Result<Option<String>> {
    match fetcher.fetch_abi(address).await {
        Ok(abi) => {
            let filename = match label {
                "implementation" => "fetched_implementation_abi.json",
                _ => "fetched_abi.json",
            };
            let output = std::path::Path::new(campaign_report_dir).join(filename);
            std::fs::write(&output, serde_json::to_vec_pretty(&abi)?)?;
            println!(
                "\x1b[36m[abi]\x1b[0m fetched {} ABI for {} -> {}",
                label,
                address,
                output.display()
            );
            Ok(Some(output.to_string_lossy().to_string()))
        }
        Err(error) => {
            println!(
                "\x1b[33m[abi]\x1b[0m explorer {} ABI lookup failed for {} ({error}); continuing with selector heuristics",
                label, address
            );
            Ok(None)
        }
    }
}

fn discover_eip1967_implementation(
    fork_db: &ForkDb,
    proxy: Address,
) -> anyhow::Result<Option<Address>> {
    let slot = eip1967_slot("eip1967.proxy.implementation");
    let value = fork_db.storage_ref(proxy, slot)?;
    Ok(address_from_storage_word(value))
}

fn eip1967_slot(label: &str) -> U256 {
    U256::from_be_bytes(keccak256(label.as_bytes()).0).saturating_sub(U256::from(1))
}

fn address_from_storage_word(value: U256) -> Option<Address> {
    if value.is_zero() {
        return None;
    }
    let bytes = value.to_be_bytes::<32>();
    let address = Address::from_slice(&bytes[12..]);
    (address != Address::ZERO).then_some(address)
}

fn print_prove_live_banner(
    campaign_id: &str,
    target: Address,
    fork_block: u64,
    duration_secs: u64,
) {
    println!(
        "\x1b[38;5;209m
  :::====  :::  === :::===  :::==== ::: === :::===== :::  === :::===== :::=====
:::  === :::  === :::     :::==== ::: === :::      :::  ===      ===      ===
=======  ===  ===  =====    ===    =====  ======   ===  ===    ===      ===  
=== ===  ===  ===     ===   ===     ===   ===      ===  ===  ===      ===    
===  ===  ======  ======    ===     ===   ===       ======  ======== ========/     
\x1b[0m"
    );
    println!(
        "🦐 RustyFuzz prove-live | campaign={} | target={} | fork_block={} | duration={}s",
        campaign_id, target, fork_block, duration_secs
    );
    println!("mode=fail-closed rpc-fork synthetic-fallback=off replay-and-poc=required");
}

fn sanitize_rpc_for_display(raw: &str) -> String {
    match reqwest::Url::parse(raw) {
        Ok(url) => {
            let host = url.host_str().unwrap_or("rpc");
            format!("{}://{}", url.scheme(), host)
        }
        Err(_) => "<invalid-rpc-url>".to_string(),
    }
}

fn default_explorer_api_url(chain: &str) -> &'static str {
    match chain {
        "bsc" => "https://api.etherscan.io/v2/api?chainid=56",
        _ => "https://api.etherscan.io/v2/api?chainid=1",
    }
}

pub async fn campaign_block_env(config: &Config) -> anyhow::Result<revm::context::BlockEnv> {
    let Some(fork_block) = config.fork_block else {
        return Ok(Default::default());
    };
    create_fork_block_env(&config.rpc_url, fork_block)
        .await
        .or_else(|_| Ok(Default::default()))
}

pub fn execution_coverage_material(
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

/// Deterministic fingerprint of the effective configuration for run manifests.
///
/// Hashes the serialized shape of non-secret config fields; secrets (the RPC
/// URL credentials) are excluded by hashing the sanitized endpoint instead.
pub fn config_fingerprint(config: &rusty_fuzz::config::Config) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rustyfuzz_artifacts::sanitize_rpc_endpoint(&config.rpc_url).hash(&mut hasher);
    config.chain.hash(&mut hasher);
    config.target_contract.hash(&mut hasher);
    config.fork_block.hash(&mut hasher);
    config.mainnet_seed_bundle.hash(&mut hasher);
    config.target_abi.hash(&mut hasher);
    config.target_invariant_manifest.hash(&mut hasher);
    config.require_seed_bundle.hash(&mut hasher);
    config.require_rpc_fork.hash(&mut hasher);
    config.allow_synthetic_fallback.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        address_from_storage_word, apply_prove_live_runtime_defaults,
        discover_eip1967_implementation, eip1967_slot, prove_live_exit_code,
        resolve_campaign_bounds,
    };
    use revm::primitives::{Address, U256};
    use rusty_fuzz::engine::promotion::PromotionCampaignSummary;
    use rustyfuzz_evm::fork_db::ForkDb;

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

    #[test]
    fn eip1967_implementation_slot_decodes_storage_word_address() {
        let proxy = Address::repeat_byte(0x11);
        let implementation = Address::repeat_byte(0x42);
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(implementation.as_slice());
        let value = U256::from_be_bytes(padded);

        assert_eq!(address_from_storage_word(value), Some(implementation));

        let fork_db = ForkDb::new_offline("0x1");
        fork_db.cache_storage(proxy, eip1967_slot("eip1967.proxy.implementation"), value);
        assert_eq!(
            discover_eip1967_implementation(&fork_db, proxy).unwrap(),
            Some(implementation)
        );
    }

    #[test]
    fn prove_live_runtime_defaults_are_overrideable() {
        std::env::remove_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS");
        std::env::remove_var("RUSTYFUZZ_EXEC_RPC_BUDGET");
        apply_prove_live_runtime_defaults(300);
        assert_eq!(std::env::var("RUSTYFUZZ_EXEC_TIMEOUT_SECS").unwrap(), "15");
        assert_eq!(std::env::var("RUSTYFUZZ_EXEC_RPC_BUDGET").unwrap(), "4");

        std::env::set_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS", "9");
        std::env::set_var("RUSTYFUZZ_EXEC_RPC_BUDGET", "8");
        apply_prove_live_runtime_defaults(300);
        assert_eq!(std::env::var("RUSTYFUZZ_EXEC_TIMEOUT_SECS").unwrap(), "9");
        assert_eq!(std::env::var("RUSTYFUZZ_EXEC_RPC_BUDGET").unwrap(), "8");

        std::env::remove_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS");
        std::env::remove_var("RUSTYFUZZ_EXEC_RPC_BUDGET");
    }

    #[test]
    fn prove_live_exit_codes_distinguish_findings_leads_and_failures() {
        fn write_summary(dir: &std::path::Path, summary: PromotionCampaignSummary) {
            std::fs::create_dir_all(dir).expect("dir");
            std::fs::write(
                dir.join("campaign_summary.json"),
                serde_json::to_vec_pretty(&summary).expect("json"),
            )
            .expect("summary");
        }
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-prove-live-exit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let summary = PromotionCampaignSummary {
            confirmed_findings: 1,
            ..Default::default()
        };
        write_summary(&base, summary);
        assert_eq!(
            prove_live_exit_code(base.to_str().unwrap()).unwrap(),
            Some(10)
        );

        let summary = PromotionCampaignSummary {
            candidate_findings: 1,
            rejected_candidates: 0,
            ..Default::default()
        };
        write_summary(&base, summary);
        assert_eq!(
            prove_live_exit_code(base.to_str().unwrap()).unwrap(),
            Some(11)
        );

        let summary = PromotionCampaignSummary {
            rejected_candidates: 1,
            ..Default::default()
        };
        write_summary(&base, summary);
        assert_eq!(
            prove_live_exit_code(base.to_str().unwrap()).unwrap(),
            Some(20)
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
