use crate::common::oracle::ProtocolOraclePack;
use crate::common::types::{
    ChainState, EvmInput, ExecutionStatus, SequenceExecutionResult, SingletonTx,
};
use crate::config::HardenedDefiConfig;
use crate::engine::abi_ingest::{ingest_abi_file, merge_abi_registry, AbiIngestReport};
use crate::engine::actors::{ActorModel, ActorModelConfig, ActorSet};
use crate::engine::bounded_search::{
    BoundedSearchBounds, BoundedSearchEngine, BoundedSearchRequest,
};
use crate::engine::bytecode_analysis::{analyze_bytecode, BytecodeAnalysisReport};
use crate::engine::concolic::{ConcolicHint, ConcolicHintStats, ConcolicSolver, ConcolicStrategy};
use crate::engine::dependency::generate_flow_template_inputs;
use crate::engine::economic_delta::{EconomicDeltaEngine, EconomicDeltaReport};
use crate::engine::exploit_path::ExploitPathBuilder;
use crate::engine::foundry_ingest::FoundryHarnessManifest;
use crate::engine::invariant_manifest::TargetInvariantManifest;
use crate::engine::promotion::{
    promote_finding_artifact, write_campaign_status, write_campaign_summary,
    PromotionCampaignStats, PromotionCampaignSummary, PromotionConfig, PromotionRequest,
};
use crate::engine::protocol_model::CounterexampleSearchEngine;
use crate::engine::scheduler::RustyFuzzScheduler;
use crate::engine::scoring::{CampaignScore, CampaignScorer};
use crate::engine::seed_intelligence::{SeedCandidate, SeedIntelligence, SeedIntelligenceConfig};
use crate::engine::target_profile::{ProtocolType, TargetProfile, TargetProfiler};
use crate::evm::corpus::{
    CampaignArtifactRequest, PersistentCorpus, SeedBundleStatus, SnapshotCorpus,
};
use crate::evm::feedback::{EvmCoverageFeedback, EvmStateNoveltyFeedback, StateNoveltyReport};
use crate::evm::fuzz::{AbiRegistry, EvmMutator, EvmTestcaseMetadataStore, MutationProvenance};
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::seed_ingester::{validate_mainnet_seed_bundle, MainnetSeedBundle};
use crate::evm::snapshot::new_evm_snapshot;
use rustyfuzz_evm::dataflow::DataflowRegistry;
use rustyfuzz_evm::executor::EvmExecutor;
use rustyfuzz_evm::fork_db::{execution_rpc_budget, ForkCacheProvenance, ForkDb};
use rustyfuzz_evm::inspector::MAP_SIZE;

use libafl::corpus::{Corpus, Testcase};
use libafl::events::{
    llmp::LlmpRestartingEventManager, EventRestarter, NopEventManager, SendExiting,
};
use libafl::state::HasCorpus;
use parking_lot::{Mutex, RwLock};
use revm::database::CacheDB;
use revm::primitives::{Address, U256};
use revm::state::AccountInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const DEFAULT_MUTATIONAL_STAGE_MAX_ITERATIONS: usize = 128;
const MAX_SNAPSHOT_CORPUS_SIZE: usize = 4096;
const REQUIRED_SEED_PROVENANCE_PREFIX: &str = "rustyfuzz:required-seed";

fn required_seed_inputs(bundle: &MainnetSeedBundle) -> anyhow::Result<Vec<EvmInput>> {
    let inputs = bundle
        .seeds
        .iter()
        .filter(|seed| {
            seed.metadata
                .provenance
                .as_deref()
                .is_some_and(|provenance| provenance.starts_with(REQUIRED_SEED_PROVENANCE_PREFIX))
        })
        .map(|seed| seed.input.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        inputs.len() <= 1,
        "a seed bundle may contain at most one required pre-fuzz sequence"
    );
    Ok(inputs)
}

fn ensure_campaign_directory(path: &str) -> anyhow::Result<()> {
    rustyfuzz_artifacts::fsutil::write_atomic(
        Path::new(path).join(".rustyfuzz-campaign"),
        b"ready\n",
    )?;
    Ok(())
}

fn write_required_seed_replay_marker(
    report_dir: &str,
    input: &EvmInput,
    execution_admitted: bool,
) -> anyhow::Result<()> {
    let marker_path = Path::new(report_dir).join("required_seed_replay.json");
    if !execution_admitted {
        if let Err(error) = fs::remove_file(&marker_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
        return Ok(());
    }
    let marker = serde_json::json!({
        "completed": true,
        "sequence_hash": input.semantic_input_hash(),
    });
    rustyfuzz_artifacts::fsutil::write_atomic(marker_path, serde_json::to_vec(&marker)?)?;
    Ok(())
}

fn campaign_rng_seed(config: &Config, core_id: usize) -> u64 {
    if config.hardened_defi.deterministic {
        return config
            .hardened_defi
            .rng_seed
            .unwrap_or(0)
            .wrapping_add(core_id as u64);
    }
    config
        .hardened_defi
        .rng_seed
        .map(|seed| seed.wrapping_add(core_id as u64))
        .unwrap_or(core_id as u64)
}

fn valid_fork_provenance(provenance: &ForkCacheProvenance, expected_block: u64) -> bool {
    !provenance.provider_sanitized.is_empty()
        && provenance.chain_id.is_some()
        && provenance.block_number == Some(expected_block)
        && provenance.block_hash.is_some()
        && provenance.cache_id.is_some()
}
fn execution_provenance_fields(
    config: &Config,
    core_id: usize,
    synthetic_fork_mode: bool,
    from_checkpoint: bool,
    db: &CacheDB<ForkDb>,
) -> (
    super::provenance::RpcProvenance,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u64>,
) {
    let source = if from_checkpoint {
        "cache_replay"
    } else if synthetic_fork_mode {
        "synthetic_fallback"
    } else {
        "live_rpc"
    };
    let fork_prov = db.db.provenance();
    let provider = if fork_prov.provider_sanitized.is_empty() {
        None
    } else {
        Some(fork_prov.provider_sanitized.clone())
    };
    let rpc_provenance = super::provenance::RpcProvenance {
        provider_sanitized: provider,
        chain_id: fork_prov.chain_id,
        fork_block: fork_prov.block_number.or(Some(config.fork_block)),
        fork_block_hash: fork_prov.block_hash.clone(),
        fetched_at_unix: fork_prov.fetched_at_unix,
        fork_cache_id: fork_prov.cache_id.clone(),
        source: Some(source.to_string()),
    };

    let bytecode_hash = config.target_contract.and_then(|target| {
        let info = db.cache.accounts.get(&target)?.info()?;
        let code = info.code?;
        let mut hasher = Sha256::new();
        hasher.update(code.original_byte_slice());
        Some(format!("0x{}", hex::encode(hasher.finalize())))
    });

    let config_payload = format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        rustyfuzz_artifacts::sanitize_rpc_endpoint(&config.rpc_url),
        config.fork_block,
        config.target_contract,
        config.require_rpc_fork,
        config.allow_synthetic_fallback,
        config.mainnet_seed_bundle,
        config.target_invariant_manifest,
        config.abi_path,
        config.max_execs,
        config.duration_secs,
        config.artifact_limit,
        config.hardened_defi,
        config.promotion,
    );
    let config_hash = Some(format!(
        "0x{}",
        hex::encode(Sha256::digest(config_payload.as_bytes()))
    ));

    let tool_revision = Some(env!("CARGO_PKG_VERSION").to_string());
    let rng_seed = if config.hardened_defi.deterministic || config.hardened_defi.rng_seed.is_some()
    {
        Some(campaign_rng_seed(config, core_id))
    } else {
        None
    };

    (
        rpc_provenance,
        bytecode_hash,
        config_hash,
        tool_revision,
        rng_seed,
    )
}

fn mutational_stage_iterations(config: &Config) -> NonZeroUsize {
    if config.max_execs.is_some() || config.duration_secs.is_some() {
        NonZeroUsize::new(1).expect("one is non-zero")
    } else {
        NonZeroUsize::new(DEFAULT_MUTATIONAL_STAGE_MAX_ITERATIONS).expect("default is non-zero")
    }
}

use rustyfuzz_engine::campaign::budget::CampaignBudget;
use rustyfuzz_engine::campaign::telemetry::{
    CampaignTelemetry, ExecutionTelemetryRecord, CAMPAIGN_TELEMETRY_INTERVAL,
};
use rustyfuzz_engine::events::{CampaignEvent, EventSink};

// LibAFL 0.15.4 imports.
use libafl::events::ClientDescription;
use libafl::prelude::{
    EventConfig, ExitKind, Fuzzer, InMemoryCorpus, InProcessExecutor, Launcher, SimpleMonitor,
    StdFuzzer, StdMapObserver, StdMutationalStage, StdState,
};
use libafl::{HasFeedback, HasScheduler};
use libafl_bolts::ownedref::OwnedMutSlice;
use libafl_bolts::prelude::*;
use libafl_bolts::shmem::{ShMemProvider, StdShMem, StdShMemProvider};
use libafl_bolts::tuples::tuple_list;

pub(crate) type EvmCampaignState =
    StdState<InMemoryCorpus<EvmInput>, EvmInput, StdRand, InMemoryCorpus<EvmInput>>;
type EvmLauncherManager =
    LlmpRestartingEventManager<(), EvmInput, EvmCampaignState, StdShMem, StdShMemProvider>;

const STATE_NOVELTY_MAP_SLOTS: usize = 2_048;
const CAMPAIGN_SCORE_MAP_SLOTS: usize = 1_024;
const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(60);

fn log_bounded_campaign_progress(
    label: &str,
    last_report: &mut Instant,
    budget: &CampaignBudget,
    telemetry: &CampaignTelemetry,
    report_dir: &str,
    worker_id: Option<usize>,
) {
    if last_report.elapsed() < CAMPAIGN_TELEMETRY_INTERVAL {
        return;
    }
    log::info!(
        "Hard-bounded campaign progress: mode={}, reserved_execs={}, completed_execs={}, mutated_inputs={}, seed_replays={}, max_execs={:?}, artifacts={}, coverage_edges={}",
        label,
        budget.reserved(),
        telemetry.executions(),
        telemetry.mutated_inputs(),
        telemetry.seed_replays(),
        budget.max_execs,
        telemetry.artifacts(),
        telemetry.coverage_edges()
    );
    let status = serde_json::json!({
        "schema_version": 1,
        "mode": label,
        "reserved_executions": budget.reserved(),
        "completed_executions": telemetry.executions(),
        "mutated_inputs": telemetry.mutated_inputs(),
        "seed_replays": telemetry.seed_replays(),
        "max_executions": budget.max_execs,
        "artifacts": telemetry.artifacts(),
        "coverage_edges": telemetry.coverage_edges(),
        "updated_at_unix": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
    });
    if let Some(worker_id) = worker_id {
        let heartbeat_dir = std::path::Path::new(report_dir).join("worker_heartbeat");
        if let Err(error) = rustyfuzz_artifacts::fsutil::write_json_atomic(
            &heartbeat_dir.join(format!("{worker_id}.json")),
            &status,
        ) {
            log::error!("worker heartbeat write failed: {error:#}");
        }
    } else if let Err(error) = write_campaign_status(std::path::Path::new(report_dir), &status) {
        log::error!("campaign heartbeat write failed: {error:#}");
    }
    *last_report = Instant::now();
}

#[derive(Clone, Debug)]
pub struct Config {
    pub rpc_url: String,
    pub fork_block: u64,
    pub target_contract: Option<Address>,
    pub corpus_dir: String,
    pub report_dir: String,
    pub foundry_harness: Option<FoundryHarnessManifest>,
    pub mainnet_seed_bundle: Option<String>,
    pub in_memory_bytecode: Option<Vec<u8>>,
    pub cores: Option<Cores>,
    pub require_seed_bundle: bool,
    pub require_rpc_fork: bool,
    pub allow_synthetic_fallback: bool,
    pub hardened_defi: HardenedDefiConfig,
    pub target_invariant_manifest: Option<String>,
    pub abi_path: Option<String>,
    pub max_execs: Option<u64>,
    pub duration_secs: Option<u64>,
    pub artifact_limit: Option<u64>,
    pub campaign_id: Option<String>,
    pub paths_are_isolated: bool,
    pub min_finding_confidence: u64,

    pub promotion: PromotionConfig,
}

impl Config {
    fn isolation_suffix(&self) -> String {
        self.campaign_id
            .as_ref()
            .map(|id| {
                let sanitized = id
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                            character
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>();
                let mut sanitized = if sanitized.is_empty() {
                    "campaign".to_string()
                } else {
                    sanitized
                };
                sanitized.truncate(48);
                if sanitized == id.as_str() {
                    return format!("_{sanitized}");
                }
                let digest = Sha256::digest(id.as_bytes());
                let digest = digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                format!("_{}-{}", sanitized, &digest[..16])
            })
            .unwrap_or_default()
    }

    fn isolated_path(path: &str, suffix: &str) -> String {
        format!("{path}{suffix}")
    }

    pub fn with_isolated_paths(mut self) -> Self {
        let generated_campaign = self.campaign_id.is_none();
        if generated_campaign {
            self.campaign_id = Some(format!("run-{}", Uuid::new_v4()));
        }
        if generated_campaign || !self.paths_are_isolated {
            let suffix = self.isolation_suffix();
            self.corpus_dir = Self::isolated_path(&self.corpus_dir, &suffix);
            self.report_dir = Self::isolated_path(&self.report_dir, &suffix);
            self.paths_are_isolated = true;
        }
        self
    }

    pub fn ensure_state_isolation(&self) -> anyhow::Result<()> {
        ensure_campaign_directory(&self.corpus_dir)?;
        ensure_campaign_directory(&self.report_dir)?;
        Ok(())
    }

    pub fn isolated_corpus_dir(&self) -> String {
        if self.paths_are_isolated {
            self.corpus_dir.clone()
        } else {
            Self::isolated_path(&self.corpus_dir, &self.isolation_suffix())
        }
    }

    pub fn isolated_report_dir(&self) -> String {
        if self.paths_are_isolated {
            self.report_dir.clone()
        } else {
            Self::isolated_path(&self.report_dir, &self.isolation_suffix())
        }
    }
}

pub fn run_fuzz_campaign_blocking(config: Config) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_fuzz_campaign(config))
}

pub async fn run_fuzz_campaign(config: Config) -> anyhow::Result<()> {
    run_fuzz_campaign_with_cancellation(config, None).await
}

pub async fn run_fuzz_campaign_with_cancellation(
    config: Config,
    cancellation: Option<Arc<AtomicBool>>,
) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = config.with_isolated_paths();
    config.ensure_state_isolation()?;
    let run_nonce = Uuid::new_v4().to_string();
    let checkpoint_session = super::checkpoint::CheckpointSession::open(&config)?;
    let start_time = Instant::now();

    let monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });

    let shmem_provider = StdShMemProvider::new()?;

    log::info!("Initializing RustyFuzz v0.15.4 Campaign...");

    let (mut initial_db, initial_env, synthetic_fork_mode) = if let Some(saved) = checkpoint_session
        .as_ref()
        .and_then(|session| session.saved.as_ref())
    {
        let restored_db = saved.snapshots.initial_db()?;
        let restored_provenance = restored_db.db.provenance();
        let restored_is_synthetic = !valid_fork_provenance(&restored_provenance, config.fork_block);
        (restored_db, saved.block_env.clone(), restored_is_synthetic)
    } else if let Some(bytecode) = config.in_memory_bytecode.as_ref() {
        let target = config
            .target_contract
            .ok_or_else(|| anyhow::anyhow!("in-memory fuzz campaigns require a target contract"))?;
        (
            crate::evm::fork::create_in_memory_fork_db(target, bytecode.clone()),
            crate::evm::fork::create_offline_fallback_block_env(config.fork_block),
            true,
        )
    } else {
        let mut synthetic_fork_mode = false;
        let require_rpc_fork = config.require_rpc_fork || campaign_requires_rpc_fork();
        let startup_timeout = startup_rpc_timeout();
        let db_attempt = match tokio::time::timeout(
            startup_timeout,
            crate::evm::fork::create_fork_db(
                &config.rpc_url,
                config.fork_block,
                config.target_contract,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "RPC fork DB setup timed out after {}s",
                startup_timeout.as_secs()
            )),
        };
        let db = match db_attempt {
            Ok(db) => db,
            Err(err) => {
                if require_rpc_fork || !config.allow_synthetic_fallback {
                    anyhow::bail!(
                        "RPC-backed fork DB unavailable for chain=evm target={:?} fork_block={} rpc_host={}; synthetic fallback is disabled: {}",
                        config.target_contract,
                        config.fork_block,
                        sanitize_rpc_host(&config.rpc_url),
                        err
                    );
                }
                log::warn!(
                    "RPC-backed fork DB unavailable for target {:?}; falling back to offline synthetic fork: {}",
                    config.target_contract,
                    err
                );
                synthetic_fork_mode = true;
                crate::evm::fork::create_offline_fallback_fork_db(config.target_contract)
            }
        };

        let env_attempt = match tokio::time::timeout(
            startup_timeout,
            crate::evm::fork::create_fork_block_env(&config.rpc_url, config.fork_block),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "RPC fork block env setup timed out after {}s",
                startup_timeout.as_secs()
            )),
        };
        let env = match env_attempt {
            Ok(env) => env,
            Err(err) => {
                if require_rpc_fork || !config.allow_synthetic_fallback {
                    anyhow::bail!(
                        "RPC-backed fork block env unavailable for chain=evm fork_block={} rpc_host={}; synthetic fallback is disabled: {}",
                        config.fork_block,
                        sanitize_rpc_host(&config.rpc_url),
                        err
                    );
                }
                log::warn!(
                    "RPC-backed fork block env unavailable for block {}; falling back to offline synthetic env: {}",
                    config.fork_block,
                    err
                );
                crate::evm::fork::create_offline_fallback_block_env(config.fork_block)
            }
        };

        (db, env, synthetic_fork_mode)
    };

    let fuzzer_address = Address::repeat_byte(0x13);
    initial_db.insert_account_info(
        fuzzer_address,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );

    let hardened_actor_set =
        if config.hardened_defi.enabled && config.hardened_defi.enable_actor_model {
            let actor_set = ActorModel::new(ActorModelConfig {
                fuzzer_address,
                ..ActorModelConfig::default()
            })
            .generate([]);
            actor_set.fund_synthetic_actors(&mut initial_db);
            log::info!(
                "Hardened DeFi actor model active: {} actors funded",
                actor_set.actors.len()
            );
            Some(actor_set)
        } else {
            None
        };

    let campaign_from_checkpoint = checkpoint_session
        .as_ref()
        .is_some_and(|session| session.saved.is_some());
    let launcher_fallback_config = config.clone();
    let launcher_fallback_db = initial_db.clone();
    let launcher_fallback_env = initial_env.clone();
    let launcher_fallback_actor_set = hardened_actor_set.clone();
    let launcher_fallback_synthetic_fork_mode = synthetic_fork_mode;
    let bytecode_analysis = discover_target_bytecode_analysis(&initial_db, config.target_contract);
    let bytecode_selectors = bytecode_analysis
        .as_ref()
        .map(|analysis| {
            if analysis.dispatch_selectors.is_empty() {
                analysis.push4_selectors.clone()
            } else {
                analysis.dispatch_selectors.clone()
            }
        })
        .unwrap_or_default();
    if !bytecode_selectors.is_empty() {
        log::info!(
            "Bytecode analysis: code_len={}, push4_selectors={}, dispatch_selectors={}, known_selectors={}, proxy_patterns={}, risk_flags={}, profile={:?}, confidence={}",
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.code_len)
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.push4_selectors.len())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.dispatch_selectors.len())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.known_selectors.len())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.proxy_patterns.len())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.risk_flags.len())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.target_profile.protocol_types.clone())
                .unwrap_or_default(),
            bytecode_analysis
                .as_ref()
                .map(|analysis| analysis.target_profile.confidence)
                .unwrap_or_default()
        );
    }
    let launcher_fallback_bytecode_selectors = bytecode_selectors.clone();
    let launcher_fallback_bytecode_analysis = bytecode_analysis.clone();

    let cores = campaign_cores(config.cores.as_ref())?;
    let broker_worker_count = cores.ids.len().max(1);
    let use_launcher = !config.hardened_defi.single_process && cores.ids.len() > 1;
    if use_launcher && cancellation.is_some() {
        let report_dir = Path::new(&config.report_dir);
        write_campaign_status(
            report_dir,
            &serde_json::json!({
                "schema_version": 1,
                "state": "cancelled",
                "terminal": true,
                "campaign_id": config.campaign_id.as_deref().expect("campaign identity is initialized before use"),
                "run_nonce": run_nonce,
                "reason": "multi-worker watchdog cancellation is not shared across launcher processes",
            }),
        )?;
        anyhow::bail!("multi-worker watchdog cancellation is unsupported; use single-process mode for cancellable campaigns");
    }
    if !use_launcher {
        let result = run_single_process_campaign(
            launcher_fallback_config,
            launcher_fallback_db,
            launcher_fallback_env,
            launcher_fallback_actor_set,
            launcher_fallback_synthetic_fork_mode,
            InitialBytecode {
                selectors: launcher_fallback_bytecode_selectors,
                analysis: launcher_fallback_bytecode_analysis,
            },
            CampaignResume {
                session: checkpoint_session,
                from_checkpoint: campaign_from_checkpoint,
                cancellation: cancellation.clone(),
            },
        )
        .await;
        result?;
        if cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            anyhow::bail!("fuzz campaign cancelled by watchdog after finalization");
        }
        return Ok(());
    }

    let execution_timeout = campaign_execution_timeout();
    log::info!(
        "Launching brokered fuzz campaign on cores `{}` with per-input timeout {:?}",
        cores.cmdline,
        execution_timeout
    );

    let launcher_result = Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .configuration(EventConfig::AlwaysUnique)
        .run_client(
            |state: Option<EvmCampaignState>,
             mut manager: EvmLauncherManager,
             description: ClientDescription| {
                let mut initial_registry = GlobalAccountRegistry::default();
                initial_registry.discover_from_state(&ChainState::Evm(initial_db.clone()));

                let target_contract =
                    choose_target_contract(config.target_contract, &initial_registry).ok_or_else(
                        || {
                            libafl::Error::unknown(
                                "cannot start EVM campaign without a target contract",
                            )
                        },
                    )?;

                let mut initial_snapshot_corpus = SnapshotCorpus::new();
                initial_snapshot_corpus
                    .add_snapshot(0, 0, new_evm_snapshot(0, initial_db.clone()))
                    .map_err(|err| {
                        libafl::Error::unknown(format!(
                            "failed to initialize root snapshot: {err}"
                        ))
                    })?;
                let snapshot_corpus = Arc::new(RwLock::new(initial_snapshot_corpus));

                let persistent_corpus =
                    Arc::new(PersistentCorpus::new(&config.corpus_dir).map_err(|err| {
                        libafl::Error::unknown(format!(
                            "failed to initialize persistent corpus `{}`: {err:#}",
                            config.corpus_dir
                        ))
                    })?);

                let dataflow_registry = Arc::new(RwLock::new(DataflowRegistry::new()));
                let state_novelty_feedback =
                    Arc::new(RwLock::new(EvmStateNoveltyFeedback::new()));
                let telemetry = Arc::new(CampaignTelemetry::new());
                 let promotion_stats = Arc::new(PromotionCampaignStats::default());
                 let promotion_outbox = Arc::new(Mutex::new(VecDeque::new()));
                 let campaign_cancellation = cancellation.clone();
                 let pending_campaign_score = Arc::new(RwLock::new(None));
                 let worker_run_nonce = run_nonce.clone();
                let testcase_metadata_store = EvmTestcaseMetadataStore::default();
                let (event_sink, _event_receiver) =
                    EventSink::bounded(rustyfuzz_engine::events::DEFAULT_EVENT_SINK_CAPACITY);
                let event_sink = Arc::new(event_sink);
                let campaign_scorer = Arc::new(CampaignScorer::default());
                let protocol_oracles = Arc::new(ProtocolOraclePack::default());
                let evm_executor = Arc::new(EvmExecutor::new());
                let account_registry = Arc::new(RwLock::new(initial_registry));

                let mut initial_abi = AbiRegistry::default();
                account_registry.read().auto_populate_abi(&mut initial_abi);
                for selector in &bytecode_selectors {
                    initial_abi.functions.entry(*selector).or_default();
                }
                let mut abi_loaded = false;
                let mut abi_report = None;
                if let Some(path) = &config.abi_path {
                    match ingest_abi_file(path, config.target_contract) {
                        Ok((_abi, abi_registry, report)) => {
                            merge_abi_registry(&mut initial_abi, &abi_registry);
                            abi_loaded = true;
                            log::info!(
                                "ABI loaded: function_count={}, event_count={}, classified_selectors={}",
                                report.function_count,
                                report.event_count,
                                report.classified_selectors
                            );
                            abi_report = Some(report);
                        }
                        Err(err) => {
                            return Err(libafl::Error::unknown(format!(
                                "failed to load required ABI `{path}`: {err:#}"
                            )));
                        }
                    }
                }

                if let Some(harness) = &config.foundry_harness {
                    log::info!(
                        "Loaded Foundry harness: {} files, {} invariants, {} target selectors, {} handlers",
                        harness.files_scanned.len(),
                        harness.invariant_functions.len(),
                        harness.target_selectors.len(),
                        harness.handler_contracts.len()
                    );

                    populate_abi_from_foundry_harness(harness, &mut initial_abi);
                }

                let seed_intelligence = SeedIntelligence::new(SeedIntelligenceConfig {
                    max_candidates: config.hardened_defi.max_template_sequences.max(64),
                    include_low_confidence_fallbacks: false,
                    conservative_startup_only: false,
                });
                let has_trusted_abi_source =
                    config.foundry_harness.is_some() || abi_loaded || !bytecode_selectors.is_empty();
                let mut hardened_seed_candidates = Vec::<SeedCandidate>::new();
                if has_trusted_abi_source {
                    hardened_seed_candidates.extend(seed_intelligence.generate_candidates(
                        target_contract,
                        fuzzer_address,
                        &initial_abi,
                        config.foundry_harness.as_ref(),
                    ));
                    if let Some(analysis) = bytecode_analysis.as_ref() {
                        let bytecode_candidates = seed_intelligence.generate_bytecode_candidates(
                            target_contract,
                            fuzzer_address,
                            &analysis.function_summaries,
                        );
                        if !bytecode_candidates.is_empty() {
                            log::info!(
                                "Generated {} bytecode function-slice seed candidates",
                                bytecode_candidates.len()
                            );
                            hardened_seed_candidates.extend(bytecode_candidates);
                        }
                    }
                }
                if config.hardened_defi.enabled {
                    if let Some(seed_file) = &config.hardened_defi.historical_seed_file {
                        match fs::read_to_string(seed_file)
                            .map_err(anyhow::Error::from)
                            .and_then(|raw| seed_intelligence.parse_historical_seed_json(&raw))
                        {
                            Ok(candidates) => {
                                let total_candidates = candidates.len();
                                let target_candidates = candidates
                                    .into_iter()
                                    .filter(|candidate| candidate.target == target_contract)
                                    .collect::<Vec<_>>();
                                log::info!(
                                    "Loaded {} historical Hardened DeFi seed candidates from {} ({} matched target)",
                                    total_candidates,
                                    seed_file,
                                    target_candidates.len()
                                );
                                hardened_seed_candidates.extend(target_candidates);
                            }
                            Err(err) => log::warn!(
                                "Failed to load Hardened DeFi historical seed file `{}`: {err:#}",
                                seed_file
                            ),
                        }
                    }
                }
                let hardened_profile_has_evidence = has_trusted_abi_source || !hardened_seed_candidates.is_empty();
                let target_profile = if config.hardened_defi.enabled {
                    let profile = if hardened_profile_has_evidence {
                        TargetProfiler.profile(
                            &initial_abi,
                            config.foundry_harness.as_ref(),
                            &hardened_seed_candidates,
                        )
                    } else {
                        TargetProfiler::profile_from_selectors([])
                    };
                    let profile =
                        merge_bytecode_profile(profile, bytecode_analysis.as_ref(), abi_loaded);
                    log::info!(
                        "Hardened DeFi target profile: types={:?}, confidence={}, risky_selectors={}, templates={:?}",
                        profile.protocol_types,
                        profile.confidence,
                        profile.risky_selectors.len(),
                        profile.recommended_seed_templates
                    );
                    Some(Arc::new(profile))
                } else {
                    None
                };

                let abi_registry = Arc::new(initial_abi);
                let target_invariant_manifest = build_runtime_invariant_manifest(
                    &config,
                    abi_report.as_ref(),
                    bytecode_analysis.as_ref(),
                );

                let core_id = description.core_id();

                 let mut feedback = EvmCoverageFeedback::new();
                 let mut objective = ();
                 let mut required_replay_inputs = Vec::new();

                 let mut state = state.unwrap_or_else(|| {

                    StdState::new(
                        StdRand::with_seed(campaign_rng_seed(&config, core_id.0)),
                        InMemoryCorpus::<EvmInput>::new(),
                        InMemoryCorpus::<EvmInput>::new(),
                        &mut feedback,
                        &mut objective,
                    )
                    .expect("Failed to initialize State")
                });

                if state.corpus().count() == 0 {
                    let mut inserted_seed_count = 0usize;
                    if let Some(bundle_id) = &config.mainnet_seed_bundle {
                        let status = persistent_corpus
                            .inspect_mainnet_seed_bundle(Some(bundle_id), target_contract);
                        log_seed_bundle_status(
                            &status,
                            config.require_seed_bundle,
                            config.allow_synthetic_fallback,
                        )
                            .map_err(|err| libafl::Error::unknown(err.to_string()))?;
                        if let SeedBundleStatus::Loaded { .. } = status {
                             let bundle = persistent_corpus
                                 .load_mainnet_seed_bundle(bundle_id)
                                 .map_err(|err| libafl::Error::unknown(err.to_string()))?;
                             validate_mainnet_seed_bundle(
                                 &bundle,
                                 target_contract,
                                 config.fork_block,
                                 &initial_db.db.provenance(),
                             )
                             .map_err(|err| libafl::Error::unknown(err.to_string()))?;
                             required_replay_inputs.extend(
                                 required_seed_inputs(&bundle)
                                     .map_err(|err| libafl::Error::unknown(err.to_string()))?,
                             );
                             {

                                for seed in bundle.seeds {
                                    state.corpus_mut().add(Testcase::new(seed.input))?;
                                    inserted_seed_count += 1;
                                }
                                log::info!(
                                    "Loaded mainnet seed bundle `{}` into campaign corpus: {} seeds",
                                    bundle_id,
                                    inserted_seed_count
                                );
                            }
                        }
                    }

                    if !hardened_seed_candidates.is_empty() {
                        for seed in hardened_seed_candidates.clone() {
                            let (input, metadata) = seed.into_parts(0);
                            testcase_metadata_store.insert(&input, metadata);
                            state.corpus_mut().add(Testcase::new(input))?;
                            inserted_seed_count += 1;
                        }
                        log::info!(
                            "Initialized campaign corpus with {} Hardened DeFi/trusted seed candidates",
                            hardened_seed_candidates.len()
                        );
                    }

                    if config.hardened_defi.enabled
                        && config.hardened_defi.enable_exploit_templates
                        && hardened_profile_has_evidence
                    {
                        if let Some(profile) = target_profile.as_ref() {
                            if profile.confidence >= 35 && profile.protocol_types != vec![ProtocolType::Unknown] {
                                let mut template_inputs = generate_flow_template_inputs(
                                    target_contract,
                                    fuzzer_address,
                                    abi_registry.as_ref(),
                                );
                                template_inputs.truncate(config.hardened_defi.max_template_sequences);
                                for (mut template, template_metadata) in template_inputs {
                                    if let Some(actor_set) = hardened_actor_set.as_ref() {
                                        actor_set.apply_roles_to_sequence(&mut template.txs);
                                    }
                                    testcase_metadata_store.insert(&template, template_metadata);
                                    state.corpus_mut().add(Testcase::new(template))?;
                                    inserted_seed_count += 1;
                                }
                                log::info!(
                                    "Added Hardened DeFi exploit template seeds for profile {:?}",
                                    profile.protocol_types
                                );
                            }
                        }
                    }

                    if inserted_seed_count == 0 && config.foundry_harness.is_some() {
                        let seed_intelligence =
                            SeedIntelligence::new(SeedIntelligenceConfig::default());
                        let intelligent_seeds = seed_intelligence.generate_candidates(
                            target_contract,
                            fuzzer_address,
                            abi_registry.as_ref(),
                            config.foundry_harness.as_ref(),
                        );
                        for seed in intelligent_seeds {
                            let (input, metadata) = seed.into_parts(0);
                            testcase_metadata_store.insert(&input, metadata);
                            state
                                .corpus_mut()
                                .add(Testcase::new(input))?;
                            inserted_seed_count += 1;
                        }
                        if inserted_seed_count > 0 {
                            log::info!(
                                "Initialized campaign corpus with {} seed inputs including trusted ABI/Foundry seed intelligence",
                                inserted_seed_count
                            );
                        }
                    } else if config.allow_synthetic_fallback {
                        log::info!(
                            "No trusted ABI/Foundry seed source configured; starting from synthetic seed and preserving generic ABI registry for mutations"
                        );
                    }

                    if inserted_seed_count == 0 {
                        if config.allow_synthetic_fallback {
                            log::info!(
                                "Seed startup mode: synthetic-seed-start (fallback_allowed=true, inserted_seed_count=0)"
                            );
                            state
                                .corpus_mut()
                                .add(Testcase::new(seed_input(target_contract, fuzzer_address)))?;
                        } else {
                            return Err(libafl::Error::unknown(
                                "no trusted seed inputs available and synthetic fallback is disabled; ingest a non-empty mainnet seed bundle, provide --abi/Foundry seeds, or pass --allow-synthetic-fallback for smoke testing"
                                    .to_string(),
                            ));
                        }
                    }
                }
                log_worker_corpus_sync(
                    core_id.0,
                    state.corpus().count(),
                    &config.corpus_dir,
                    "brokered",
                );

                let concolic_hints = Arc::new(Mutex::new(Vec::new()));
                let mutator = EvmMutator::with_concolic_hints_and_stats(
                    abi_registry,
                    account_registry.clone(),
                    concolic_hints.clone(),
                    telemetry.concolic_hint_stats.clone(),
                    testcase_metadata_store.clone(),
                );
                let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
                    mutator,
                    mutational_stage_iterations(&config),
                ),);

                let mut fuzzer = StdFuzzer::new(
                    RustyFuzzScheduler::with_pending_score(pending_campaign_score.clone()),
                    feedback,
                    objective,
                );

                let mut shmem_provider = StdShMemProvider::new()?;
                let mut shmem = shmem_provider.new_shmem(MAP_SIZE)?;
                let coverage_map_ptr = shmem.as_mut_ptr();
                 // SAFETY: `shmem` owns a writable allocation of `MAP_SIZE` bytes and its raw pointer remains valid for the observer lifetime.
                 let observer = StdMapObserver::from_mut_slice(
                     "edges",
                     unsafe { OwnedMutSlice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE) },
                 );
                let worker_index = cores.ids.iter().position(|id| *id == description.core_id())
                    .ok_or_else(|| libafl::Error::unknown("worker core is absent from campaign topology"))?;
                let budget = Arc::new(CampaignBudget::for_worker(
                    config.max_execs,
                    config.duration_secs,
                    broker_worker_count,
                    worker_index,
                ).ok_or_else(|| libafl::Error::unknown("invalid campaign worker topology"))?);

                let (
                    rpc_provenance,
                    bytecode_hash,
                    config_hash,
                    tool_revision,
                    rng_seed,
                ) = execution_provenance_fields(
                    &config,
                    core_id.0,
                    synthetic_fork_mode,
                    campaign_from_checkpoint,
                    &initial_db,
                );

                let mut harness = |input: &EvmInput| {
                    if !budget.reserve_execution() {
                        return ExitKind::Ok;
                    }
                    let snap_id = input.base_snapshot_id;
                    let snapshot_corpus_guard = snapshot_corpus.read();

                    let Some(base_snap_arc) = snapshot_corpus_guard.get_snapshot(snap_id) else {
                        log::error!("Input references missing snapshot id {}", snap_id);
                        return ExitKind::Crash;
                    };

                    let mut current_state = base_snap_arc.read().state.read().clone();
                    drop(snapshot_corpus_guard);

                    let base_fork_state = match &current_state {
                        ChainState::Evm(db) => db.clone(),
                    };

                    let mut current_env = initial_env.clone();
                    let mut tx_results = Vec::with_capacity(input.txs.len());

                    for (tx_idx, tx) in input.txs.iter().enumerate() {
                        let mut waypoints = Vec::new();
                        let mut df = dataflow_registry.write();

                        let exec_result = ForkDb::with_thread_rpc_budget(
                            Some(execution_rpc_budget()),
                            // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
                            || unsafe {
                                let map_slice =
                                    std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                                evm_executor.execute_with_result(
                                    &mut current_state,
                                    &mut current_env,
                                    tx,
                                    map_slice,
                                    &mut df,
                                    &mut waypoints,
                                    tx_idx,
                                )
                            },
                        );

                        let result = match exec_result {
                            Ok(result) => result,
                            Err(err) => {
                                if err.to_string().contains("fork RPC budget exhausted") {
                                    if synthetic_fork_mode {
                                        log::warn!(
                                            "Skipping input after fork RPC budget exhaustion at tx {}; increase RUSTYFUZZ_EXEC_RPC_BUDGET for deeper live-fork exploration",
                                            tx_idx
                                        );
                                        return ExitKind::Ok;
                                    }
                                    log::error!(
                                        "Fork RPC budget exhausted at tx {} under live RPC (fail-closed); increase RUSTYFUZZ_EXEC_RPC_BUDGET",
                                        tx_idx
                                    );
                                    return ExitKind::Crash;
                                }
                                log::error!("EVM execution failed for tx {}: {err:#}", tx_idx);
                                return ExitKind::Crash;
                            }
                        };
                        enqueue_concolic_hints(
                            &concolic_hints,
                            telemetry.concolic_hint_stats.as_ref(),
                            tx_idx,
                            &waypoints,
                        );

                        tx_results.push(result);
                    }

                    let execution = sequence_result_from_tx_results(tx_results);

                    let report = state_novelty_feedback
                        .write()
                        .observe_execution(&execution);
                    // SAFETY: the shared-memory allocation is readable and exactly `MAP_SIZE` bytes for the harness lifetime.
                    unsafe {
                        let map_slice = std::slice::from_raw_parts(coverage_map_ptr, MAP_SIZE);
                        if let Some(snapshot_id) = snapshot_corpus.write().maybe_add_post_execution_snapshot(
                            snap_id,
                            input,
                            current_state.clone(),
                            map_slice,
                            &execution,
                            MAX_SNAPSHOT_CORPUS_SIZE,
                        ) {
                            log::debug!(
                                "Inserted post-execution snapshot id={} parent={} txs={} state_novelty={}",
                                snapshot_id,
                                snap_id,
                                input.txs.len(),
                                report.novelty_score()
                            );
                            event_sink.emit(CampaignEvent::NewSnapshot {
                                id: snapshot_id,
                                parent: snap_id,
                            });
                        }
                    }

                    let mut findings = protocol_oracles.evaluate(&execution);
                    let economic_delta = (config.hardened_defi.enabled
                        && config.hardened_defi.enable_economic_delta)
                        .then(|| EconomicDeltaEngine::from_execution(input, &execution));
                    findings.extend(evaluate_runtime_invariants(
                        &config,
                        target_invariant_manifest.as_ref(),
                        economic_delta.as_ref(),
                    ));
                    apply_min_finding_confidence(&mut findings, config.min_finding_confidence);

                    let testcase_provenance = testcase_metadata_store
                        .get_or_default(input)
                        .mutation_provenance;
                    let mut campaign_score = campaign_scorer.score(
                        input,
                        &execution,
                        &report,
                        &findings,
                        &testcase_provenance,
                    );
                    if let Some(economic_delta) = economic_delta {
                        let delta_score = EconomicDeltaEngine::score(&economic_delta);
                        if delta_score > 0 {
                            campaign_score.economic_pressure = campaign_score
                                .economic_pressure
                                .saturating_add(delta_score);
                            campaign_score.total = campaign_score.total.saturating_add(delta_score).min(10_000);
                            campaign_score.explanation.push(format!(
                                "hardened_defi_economic_delta: score={}, confidence={}, suspicious_extraction={}, accounting_anomaly={}",
                                delta_score,
                                economic_delta.confidence,
                                economic_delta.suspicious_value_extraction,
                                economic_delta.accounting_anomaly
                            ));
                        }
                    }
                    let mut counterexample_exploit_candidate = None;
                    if config.hardened_defi.enabled {
                        let counterexample_search = CounterexampleSearchEngine {
                            max_candidates: config.hardened_defi.max_template_sequences.max(1),
                        };
                        let search_result = counterexample_search.search(
                            input,
                            &execution,
                            &findings,
                            target_profile.as_ref().map(|profile| profile.as_ref()),
                            hardened_actor_set.as_ref(),
                        );
                        let counterexample_pressure = search_result.model.counterexample_pressure();
                        if counterexample_pressure > 0 {
                            campaign_score.counterexample_pressure = campaign_score
                                .counterexample_pressure
                                .saturating_add(counterexample_pressure);
                            campaign_score.total = campaign_score
                                .total
                                .saturating_add(counterexample_pressure)
                                .min(10_000);
                            campaign_score.explanation.push(format!(
                                "counterexample_model: pressure={}, confidence={}, hypotheses={}, protocols={:?}",
                                counterexample_pressure,
                                search_result.model.confidence,
                                search_result.model.invariant_hypotheses.len(),
                                search_result.model.inferred_protocol_types
                            ));
                        }
                        if let Some(candidate) = search_result.candidate {
                            let confidence = candidate.confidence;
                            let violated_invariant = candidate.violated_invariant.clone();
                            let replayability_status = candidate.replayability_status.clone();
                            let minimized_sequence_status =
                                candidate.minimized_sequence_status.clone();
                            counterexample_exploit_candidate =
                                Some(candidate.into_exploit_path_candidate());
                            if confidence >= 80 {
                                campaign_score.explanation.push(format!(
                                    "counterexample_search: confidence={}, invariant={:?}, replay={:?}, minimized={:?}",
                                    confidence,
                                    violated_invariant,
                                    replayability_status,
                                    minimized_sequence_status
                                ));
                            }
                        }
                    }
                    let exploit_candidate = counterexample_exploit_candidate.or_else(|| {
                        ExploitPathBuilder::from_execution(
                        input,
                        &execution,
                        &findings,
                        &campaign_score,
                    )
                    });

                    account_registry.write().observe_execution(&execution);
                    let mutation_strategies = mutation_strategies(&testcase_provenance);
                    record_successful_concolic_mutation(
                        telemetry.concolic_hint_stats.as_ref(),
                        &mutation_strategies,
                        findings.len(),
                        report.interesting,
                        campaign_score.total,
                    );
                    let coverage_edges = execution
                        .tx_results
                        .iter()
                        .map(|result| result.coverage_edges)
                        .sum();
                    telemetry.record_execution(ExecutionTelemetryRecord {
                        core_id: core_id.0,
                        tx_count: input.txs.len(),
                        findings: findings.len(),
                        campaign_score: campaign_score.total,
                        corpus_size: 0,
                        coverage_edges,
                        state_novelty_score: report.novelty_score(),
                        mutation_strategies: &mutation_strategies,
                    });
                    if let Err(error) = super::provenance::persist(
                        config.corpus_dir.as_ref(),
                        super::provenance::PersistRequest {
                            execution_index: telemetry.execution_count(),
                            budget_consumed: budget.reserved(),
                            input,
                            execution: &execution,
                            coverage_edges,
                            state_novelty_score: report.novelty_score(),
                            campaign_score: &campaign_score,
                            findings: &findings,
                            mutation_strategies: &mutation_strategies,
                            rpc_provenance: rpc_provenance.clone(),
                            bytecode_hash: bytecode_hash.clone(),
                            config_hash: config_hash.clone(),
                            tool_revision: tool_revision.clone(),
                            rng_seed,
                        },
                    ) {
                        log::error!("execution provenance persistence failed: {error:#}");
                        return ExitKind::Crash;
                    }

                    if report.interesting {
                        // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
                        unsafe {
                            let map_slice =
                                std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                            reward_state_novelty(map_slice, &report);
                        }

                        log::debug!(
                            "State novelty: score={}, transitions={}, slots={}, reads={}, call_edges={}, contracts={}",
                            report.novelty_score(),
                            report.new_transition_hashes.len(),
                            report.new_slot_hashes.len(),
                            report.new_read_hashes.len(),
                            report.new_call_edge_hashes.len(),
                            report.new_contracts.len()
                        );
                    }

                    if campaign_score.is_interesting() {
                        // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
                        unsafe {
                            let map_slice =
                                std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                            reward_campaign_score(map_slice, &campaign_score);
                        }

                        log::debug!(
                            "Campaign score: total={}, economic={}, invariant={}, counterexample={}, oracle={}, state={}, exploration={}, reasons={}",
                            campaign_score.total,
                            campaign_score.economic_pressure,
                            campaign_score.invariant_pressure,
                            campaign_score.counterexample_pressure,
                            campaign_score.oracle_pressure,
                            campaign_score.state_pressure,
                            campaign_score.exploration_pressure,
                            campaign_score.explanation.join("; ")
                        );
                    }

                    if let Some(candidate) = &exploit_candidate {
                        if candidate.confidence >= 80 {
                            log::debug!(
                                "Exploit path candidate: confidence={}, target={:?}, invariant={:?}, replay={:?}, minimize={:?}",
                                candidate.confidence,
                                candidate.target,
                                candidate.violated_invariant,
                                candidate.replayability_status,
                                candidate.minimized_sequence_status
                            );
                        }
                    }

                    if artifact_limit_reached(&telemetry, config.artifact_limit) {
                        log::debug!(
                            "Artifact limit reached; skipping persistence (limit={:?})",
                            config.artifact_limit
                        );
                    } else if let Some(reason) = campaign_artifact_reason(
                        synthetic_fork_mode,
                        &execution,
                        &report,
                        &campaign_score,
                        &findings,
                        exploit_candidate.as_ref(),
                    ) {
                        // SAFETY: the shared-memory allocation is readable and exactly `MAP_SIZE` bytes for the harness lifetime.
                        let persisted = unsafe {
                            let map_slice =
                                std::slice::from_raw_parts(coverage_map_ptr, MAP_SIZE);

                            persistent_corpus.persist_campaign_artifact(CampaignArtifactRequest {
                                input,
                                execution: &execution,
                                coverage: map_slice,
                                state_novelty_score: report.novelty_score(),
                                base_fork_state: &base_fork_state,
                                score: &campaign_score,
                                findings: &findings,
                                exploit_candidate: exploit_candidate.as_ref(),
                                block_number: config.fork_block,
                                target: Some(target_contract),
                                reason,
                            })
                        };

                        match persisted {
                            Ok(outcome) => {
                                if outcome.created_new {
                                    telemetry.record_artifact();
                                    event_sink.emit(CampaignEvent::CandidateFinding {
                                        input_id: outcome.record.input_id.clone(),
                                    });
                                    log::info!(
                                        "Persisted campaign artifact: input_id={}, fork_cache_id={}, reason={}, score={}, findings={}",
                                        outcome.record.input_id,
                                        outcome.record.fork_cache_id,
                                        outcome.record.reason,
                                        outcome.record.score.total,
                                        outcome.record.findings.len()
                                    );
                                     enqueue_promotion_artifact(
                                         &config,
                                         &promotion_outbox,
                                         &outcome.record,
                                         synthetic_fork_mode,
                                         &promotion_stats,
                                     );


                                } else {
                                    log::debug!(
                                        "Reused campaign artifact: input_id={}, fork_cache_id={}, reason={}, score={}, findings={}",
                                        outcome.record.input_id,
                                        outcome.record.fork_cache_id,
                                        outcome.record.reason,
                                        outcome.record.score.total,
                                        outcome.record.findings.len()
                                    );
                                }
                            }
                            Err(err) => log::error!(
                                "Failed to persist campaign artifact for target {}: {err:#}",
                                target_contract
                            ),
                        }
                    }

                    *pending_campaign_score.write() = Some(campaign_score);

                     ExitKind::Ok
                 };

                 for input in &required_replay_inputs {
                     let reserved_before = budget.reserved();
                     if !matches!(harness(input), ExitKind::Ok) {
                         return Err(libafl::Error::unknown(
                             "required pre-fuzz sequence execution failed",
                         ));
                     }
                     write_required_seed_replay_marker(
                         &config.report_dir,
                         input,
                         budget.reserved() > reserved_before,
                     )
                     .map_err(|error| libafl::Error::unknown(error.to_string()))?;
                 }

                 let mut executor = InProcessExecutor::with_timeout::<()>(

                    &mut harness,
                    tuple_list!(observer),
                    &mut fuzzer,
                    &mut state,
                    &mut manager,
                    execution_timeout,
                )?;

                if config.max_execs.is_some() || config.duration_secs.is_some() {
                    log::info!(
                        "Running hard-bounded brokered campaign: max_execs={:?}, duration_secs={:?}, worker_budget={:?}",
                        config.max_execs,
                        config.duration_secs,
                        budget.max_execs
                    );
                    let mut bounded_progress_report = Instant::now();
                     while !budget.exhausted()
                         && !campaign_cancellation
                             .as_ref()
                             .is_some_and(|flag| flag.load(Ordering::Relaxed))
                     {
                         let _ =
                             fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
                        log_bounded_campaign_progress(
                            "brokered",
                            &mut bounded_progress_report,
                             &budget,
                             &telemetry,
                            &config.report_dir,
                            Some(core_id.0),
                        );

                    }
                    manager.on_restart(&mut state)?;
                    manager.on_shutdown()?;
                 } else {
                     while !campaign_cancellation
                         .as_ref()
                         .is_some_and(|flag| flag.load(Ordering::Relaxed))
                     {
                         let _ = fuzzer.fuzz_one(
                             &mut stages,
                             &mut executor,
                             &mut state,
                             &mut manager,
                         )?;
                     }
                 }

                  let worker_state = if campaign_cancellation
                      .as_ref()
                      .is_some_and(|flag| flag.load(Ordering::Relaxed))
                  {
                      "cancelled"
                  } else {
                      "completed"
                  };
                   write_worker_terminal_artifact(
                       &config,
                       &worker_run_nonce,
                       core_id.0,
                       worker_state,
                       &promotion_stats,
                       &telemetry,
                   )
                  .map_err(|error| libafl::Error::unknown(error.to_string()))?;
                  Ok(())
            },
        )
        .cores(&cores)
        .build()
        .launch();

    let worker_ids: Vec<usize> = cores.ids.iter().map(|worker_id| worker_id.0).collect();
    let result = match launcher_result {
        Ok(_) => finalize_brokered_campaign(
            &config,
            &run_nonce,
            &launcher_fallback_env,
            launcher_fallback_synthetic_fork_mode,
            &worker_ids,
            cancellation.as_ref(),
        ),
        Err(err) => {
            if cancellation
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
            {
                anyhow::bail!("brokered fuzz launcher stopped after watchdog cancellation");
            }
            if broker_launcher_error_was_shutdown(&err.to_string()) {
                log::info!("Brokered fuzz launcher shut down cleanly");
                finalize_brokered_campaign(
                    &config,
                    &run_nonce,
                    &launcher_fallback_env,
                    launcher_fallback_synthetic_fork_mode,
                    &worker_ids,
                    cancellation.as_ref(),
                )
            } else if broker_launcher_error_can_fallback(&err.to_string()) {
                log::warn!(
                    "brokered fuzz launcher unavailable; falling back to broker-free single-process mode: {}",
                    err
                );
                run_single_process_campaign(
                    launcher_fallback_config,
                    launcher_fallback_db,
                    launcher_fallback_env,
                    launcher_fallback_actor_set,
                    launcher_fallback_synthetic_fork_mode,
                    InitialBytecode {
                        selectors: launcher_fallback_bytecode_selectors,
                        analysis: launcher_fallback_bytecode_analysis,
                    },
                    CampaignResume {
                        session: None,
                        from_checkpoint: campaign_from_checkpoint,
                        cancellation: cancellation.clone(),
                    },
                )
                .await
            } else {
                return Err(err.into());
            }
        }
    };
    result?;
    if cancellation
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
    {
        anyhow::bail!("fuzz campaign cancelled by watchdog after finalization");
    }
    Ok(())
}

struct InitialBytecode {
    selectors: Vec<[u8; 4]>,
    analysis: Option<BytecodeAnalysisReport>,
}

struct CampaignResume {
    session: Option<super::checkpoint::CheckpointSession>,
    from_checkpoint: bool,
    cancellation: Option<Arc<AtomicBool>>,
}

async fn run_single_process_campaign(
    config: Config,
    initial_db: CacheDB<ForkDb>,
    initial_env: revm::context::BlockEnv,
    hardened_actor_set: Option<ActorSet>,
    synthetic_fork_mode: bool,
    bytecode: InitialBytecode,
    resume: CampaignResume,
) -> anyhow::Result<()> {
    let CampaignResume {
        session: mut checkpoint_session,
        from_checkpoint: campaign_from_checkpoint,
        cancellation,
    } = resume;
    let InitialBytecode {
        selectors: bytecode_selectors,
        analysis: bytecode_analysis,
    } = bytecode;
    anyhow::ensure!(checkpoint_session.is_none() || synthetic_fork_mode,
        "live-RPC checkpointing is not implemented; refusing to checkpoint an online fork as offline");
    let start_time = Instant::now();
    let execution_timeout = campaign_execution_timeout();
    log::info!(
        "Launching broker-free single-process fuzz campaign with per-input timeout {:?}",
        execution_timeout
    );
    let _monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });
    let mut manager = NopEventManager::new();

    let mut initial_registry = GlobalAccountRegistry::default();
    initial_registry.discover_from_state(&ChainState::Evm(initial_db.clone()));

    let target_contract = choose_target_contract(config.target_contract, &initial_registry)
        .ok_or_else(|| anyhow::anyhow!("cannot start EVM campaign without a target contract"))?;

    let mut initial_snapshot_corpus = SnapshotCorpus::new();
    initial_snapshot_corpus.add_snapshot(0, 0, new_evm_snapshot(0, initial_db.clone()))?;
    let snapshot_corpus = Arc::new(RwLock::new(initial_snapshot_corpus));

    let persistent_corpus = Arc::new(PersistentCorpus::new(&config.corpus_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed to initialize persistent corpus `{}`: {err:#}",
            config.corpus_dir
        )
    })?);

    let dataflow_registry = Arc::new(RwLock::new(DataflowRegistry::new()));
    let state_novelty_feedback = Arc::new(RwLock::new(EvmStateNoveltyFeedback::new()));
    let telemetry = Arc::new(CampaignTelemetry::new());
    let promotion_stats = Arc::new(PromotionCampaignStats::default());
    let promotion_outbox = Arc::new(Mutex::new(VecDeque::new()));
    let pending_campaign_score = Arc::new(RwLock::new(None));
    let testcase_metadata_store = EvmTestcaseMetadataStore::default();
    let (event_sink, _event_receiver) =
        EventSink::bounded(rustyfuzz_engine::events::DEFAULT_EVENT_SINK_CAPACITY);
    let event_sink = Arc::new(event_sink);
    let campaign_scorer = Arc::new(CampaignScorer::default());
    let protocol_oracles = Arc::new(ProtocolOraclePack::default());
    let evm_executor = Arc::new(EvmExecutor::new());
    let account_registry = Arc::new(RwLock::new(initial_registry));

    let mut initial_abi = AbiRegistry::default();
    account_registry.read().auto_populate_abi(&mut initial_abi);
    for selector in &bytecode_selectors {
        initial_abi.functions.entry(*selector).or_default();
    }
    let mut abi_loaded = false;
    let mut abi_report = None;
    if let Some(path) = &config.abi_path {
        match ingest_abi_file(path, config.target_contract) {
            Ok((_abi, abi_registry, report)) => {
                merge_abi_registry(&mut initial_abi, &abi_registry);
                abi_loaded = true;
                log::info!(
                    "ABI loaded: function_count={}, event_count={}, classified_selectors={}",
                    report.function_count,
                    report.event_count,
                    report.classified_selectors
                );
                abi_report = Some(report);
            }
            Err(err) => anyhow::bail!("failed to load required ABI `{}`: {err:#}", path),
        }
    }

    if let Some(harness) = &config.foundry_harness {
        log::info!(
            "Loaded Foundry harness: {} files, {} invariants, {} target selectors, {} handlers",
            harness.files_scanned.len(),
            harness.invariant_functions.len(),
            harness.target_selectors.len(),
            harness.handler_contracts.len()
        );
        populate_abi_from_foundry_harness(harness, &mut initial_abi);
    }

    let seed_intelligence = SeedIntelligence::new(SeedIntelligenceConfig {
        max_candidates: config.hardened_defi.max_template_sequences.max(64),
        include_low_confidence_fallbacks: false,
        conservative_startup_only: false,
    });
    let has_trusted_abi_source =
        config.foundry_harness.is_some() || abi_loaded || !bytecode_selectors.is_empty();
    let mut hardened_seed_candidates = Vec::<SeedCandidate>::new();
    if has_trusted_abi_source {
        hardened_seed_candidates.extend(seed_intelligence.generate_candidates(
            target_contract,
            Address::repeat_byte(0x13),
            &initial_abi,
            config.foundry_harness.as_ref(),
        ));
        if let Some(analysis) = bytecode_analysis.as_ref() {
            let bytecode_candidates = seed_intelligence.generate_bytecode_candidates(
                target_contract,
                Address::repeat_byte(0x13),
                &analysis.function_summaries,
            );
            if !bytecode_candidates.is_empty() {
                log::info!(
                    "Generated {} bytecode function-slice seed candidates",
                    bytecode_candidates.len()
                );
                hardened_seed_candidates.extend(bytecode_candidates);
            }
        }
    }
    if config.hardened_defi.enabled {
        if let Some(seed_file) = &config.hardened_defi.historical_seed_file {
            match fs::read_to_string(seed_file)
                .map_err(anyhow::Error::from)
                .and_then(|raw| seed_intelligence.parse_historical_seed_json(&raw))
            {
                Ok(candidates) => {
                    let total_candidates = candidates.len();
                    let target_candidates = candidates
                        .into_iter()
                        .filter(|candidate| candidate.target == target_contract)
                        .collect::<Vec<_>>();
                    log::info!(
                        "Loaded {} historical Hardened DeFi seed candidates from {} ({} matched target)",
                        total_candidates,
                        seed_file,
                        target_candidates.len()
                    );
                    hardened_seed_candidates.extend(target_candidates);
                }
                Err(err) => log::warn!(
                    "Failed to load Hardened DeFi historical seed file `{}`: {err:#}",
                    seed_file
                ),
            }
        }
    }
    let hardened_profile_has_evidence =
        has_trusted_abi_source || !hardened_seed_candidates.is_empty();
    let target_profile = if config.hardened_defi.enabled {
        let profile = if hardened_profile_has_evidence {
            TargetProfiler.profile(
                &initial_abi,
                config.foundry_harness.as_ref(),
                &hardened_seed_candidates,
            )
        } else {
            TargetProfiler::profile_from_selectors([])
        };
        let profile = merge_bytecode_profile(profile, bytecode_analysis.as_ref(), abi_loaded);
        log::info!(
            "Hardened DeFi target profile: types={:?}, confidence={}, risky_selectors={}, templates={:?}",
            profile.protocol_types,
            profile.confidence,
            profile.risky_selectors.len(),
            profile.recommended_seed_templates
        );
        Some(Arc::new(profile))
    } else {
        None
    };

    let abi_registry = Arc::new(initial_abi);
    let target_invariant_manifest =
        build_runtime_invariant_manifest(&config, abi_report.as_ref(), bytecode_analysis.as_ref());
    let core_id = 0usize;
    let mut feedback = EvmCoverageFeedback::new();
    let mut objective = ();
    let mut state = StdState::new(
        StdRand::with_seed(campaign_rng_seed(&config, core_id)),
        InMemoryCorpus::<EvmInput>::new(),
        InMemoryCorpus::<EvmInput>::new(),
        &mut feedback,
        &mut objective,
    )?;

    let mut restored_checkpoint = checkpoint_session
        .as_mut()
        .and_then(|session| session.saved.take());
    if let Some(saved) = &restored_checkpoint {
        state = postcard::from_bytes(&saved.state)
            .map_err(|err| anyhow::anyhow!("restore LibAFL state: {err}"))?;
        feedback = saved.feedback.clone();
    }
    let resumed = restored_checkpoint.is_some();
    let mut direct_seed_inputs = Vec::new();
    let mut required_replay_inputs = Vec::new();
    if state.corpus().count() == 0 {
        let mut inserted_seed_count = 0usize;
        if let Some(bundle_id) = &config.mainnet_seed_bundle {
            let status =
                persistent_corpus.inspect_mainnet_seed_bundle(Some(bundle_id), target_contract);
            log_seed_bundle_status(
                &status,
                config.require_seed_bundle,
                config.allow_synthetic_fallback,
            )?;
            if let SeedBundleStatus::Loaded { .. } = status {
                let bundle = persistent_corpus.load_mainnet_seed_bundle(bundle_id)?;
                validate_mainnet_seed_bundle(
                    &bundle,
                    target_contract,
                    config.fork_block,
                    &initial_db.db.provenance(),
                )?;
                required_replay_inputs.extend(required_seed_inputs(&bundle)?);
                {
                    for seed in bundle.seeds {
                        let input = seed.input;
                        direct_seed_inputs.push(input.clone());
                        state.corpus_mut().add(Testcase::new(input))?;
                        inserted_seed_count += 1;
                    }
                    log::info!(
                        "Loaded mainnet seed bundle `{}` into campaign corpus: {} seeds",
                        bundle_id,
                        inserted_seed_count
                    );
                }
            }
        }

        if !hardened_seed_candidates.is_empty() {
            for seed in hardened_seed_candidates.clone() {
                let (input, metadata) = seed.into_parts(0);
                testcase_metadata_store.insert(&input, metadata);
                direct_seed_inputs.push(input.clone());
                state.corpus_mut().add(Testcase::new(input))?;
                inserted_seed_count += 1;
            }
            log::info!(
                "Initialized campaign corpus with {} Hardened DeFi/trusted seed candidates",
                hardened_seed_candidates.len()
            );
        }

        if config.hardened_defi.enable_bounded_search && config.hardened_defi.enabled {
            if let Some(profile) = target_profile.as_ref() {
                let bounded_result = BoundedSearchEngine.search(BoundedSearchRequest {
                    target: target_contract,
                    target_profile: profile.as_ref(),
                    abi_registry: abi_registry.as_ref(),
                    actor_set: hardened_actor_set.as_ref(),
                    seed_candidates: &hardened_seed_candidates,
                    base_input: None,
                    bounds: BoundedSearchBounds {
                        max_tx_depth: config.hardened_defi.max_tx_depth,
                        max_actor_roles: config.hardened_defi.max_actor_roles,
                        max_template_sequences: config.hardened_defi.max_template_sequences,
                    },
                });
                log::info!(
                    "Bounded search enumerated {} candidates (exhaustive={}, modeled_space={})",
                    bounded_result.enumerated_candidates,
                    bounded_result.exhaustive,
                    bounded_result.modeled_space_size
                );
                for outcome in bounded_result.candidates.into_iter() {
                    testcase_metadata_store
                        .insert(&outcome.candidate.input, outcome.metadata.clone());
                    direct_seed_inputs.push(outcome.candidate.input.clone());
                    state
                        .corpus_mut()
                        .add(Testcase::new(outcome.candidate.input))?;
                    inserted_seed_count += 1;
                }
            }
        } else if config.hardened_defi.enabled
            && config.hardened_defi.enable_exploit_templates
            && hardened_profile_has_evidence
        {
            if let Some(profile) = target_profile.as_ref() {
                if profile.confidence >= 35 && profile.protocol_types != vec![ProtocolType::Unknown]
                {
                    let mut template_inputs = generate_flow_template_inputs(
                        target_contract,
                        Address::repeat_byte(0x13),
                        abi_registry.as_ref(),
                    );
                    template_inputs.truncate(config.hardened_defi.max_template_sequences);
                    for (mut template, template_metadata) in template_inputs {
                        if let Some(actor_set) = hardened_actor_set.as_ref() {
                            actor_set.apply_roles_to_sequence(&mut template.txs);
                        }
                        testcase_metadata_store.insert(&template, template_metadata);
                        direct_seed_inputs.push(template.clone());
                        state.corpus_mut().add(Testcase::new(template))?;
                        inserted_seed_count += 1;
                    }
                    log::info!(
                        "Added Hardened DeFi exploit template seeds for profile {:?}",
                        profile.protocol_types
                    );
                }
            }
        }

        if inserted_seed_count == 0 && config.foundry_harness.is_some() {
            let seed_intelligence = SeedIntelligence::new(SeedIntelligenceConfig::default());
            let intelligent_seeds = seed_intelligence.generate_candidates(
                target_contract,
                Address::repeat_byte(0x13),
                abi_registry.as_ref(),
                config.foundry_harness.as_ref(),
            );
            for seed in intelligent_seeds {
                let (input, metadata) = seed.into_parts(0);
                testcase_metadata_store.insert(&input, metadata);
                direct_seed_inputs.push(input.clone());
                state.corpus_mut().add(Testcase::new(input))?;
                inserted_seed_count += 1;
            }
            if inserted_seed_count > 0 {
                log::info!(
                    "Initialized campaign corpus with {} seed inputs including trusted ABI/Foundry seed intelligence",
                    inserted_seed_count
                );
            }
        } else if config.allow_synthetic_fallback {
            log::info!(
                "No trusted ABI/Foundry seed source configured; starting from synthetic seed and preserving generic ABI registry for mutations"
            );
        }

        if inserted_seed_count == 0 {
            if config.allow_synthetic_fallback {
                log::info!(
                    "Seed startup mode: synthetic-seed-start (fallback_allowed=true, inserted_seed_count=0)"
                );
                let input = seed_input(target_contract, Address::repeat_byte(0x13));
                direct_seed_inputs.push(input.clone());
                state.corpus_mut().add(Testcase::new(input))?;
            } else {
                anyhow::bail!(
                    "no trusted seed inputs available and synthetic fallback is disabled; ingest a non-empty mainnet seed bundle, provide --abi/Foundry seeds, or pass --allow-synthetic-fallback for smoke testing"
                );
            }
        }
    }
    log_worker_corpus_sync(
        core_id,
        state.corpus().count(),
        &config.corpus_dir,
        "single",
    );

    let concolic_hints = Arc::new(Mutex::new(Vec::new()));
    let mut scheduler = RustyFuzzScheduler::with_pending_score(pending_campaign_score.clone());
    let mut restored_map = None;
    let mut restored_strategies = None;
    let budget = if let Some(saved) = restored_checkpoint.take() {
        *snapshot_corpus.write() = saved.snapshots.restore()?;
        *state_novelty_feedback.write() = saved.novelty;
        *dataflow_registry.write() = saved.dataflow;
        *account_registry.write() = saved.accounts;
        testcase_metadata_store.restore(saved.metadata);
        *concolic_hints.lock() = saved.hints;
        scheduler.restore(saved.scheduler);
        *pending_campaign_score.write() = saved.pending_score;
        restored_strategies = Some(saved.strategies);
        telemetry.restore(saved.telemetry);
        restored_map = Some(saved.raw_coverage);
        CampaignBudget::restore(saved.budget).map_err(anyhow::Error::msg)?
    } else {
        CampaignBudget::new(config.max_execs, config.duration_secs, 1)
    };
    let budget = Arc::new(budget);
    let mutator = EvmMutator::with_concolic_hints_and_stats(
        abi_registry,
        account_registry.clone(),
        concolic_hints.clone(),
        telemetry.concolic_hint_stats.clone(),
        testcase_metadata_store.clone(),
    );
    let strategy_counters = mutator.strategy_counters.clone();
    if let Some(saved) = restored_strategies {
        strategy_counters.restore(saved);
    }
    let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
        mutator,
        mutational_stage_iterations(&config),
    ),);
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut shmem_provider = StdShMemProvider::new()?;
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE)?;
    let coverage_map_ptr = shmem.as_mut_ptr();
    if let Some(map) = restored_map {
        // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes, and `map` has the same bounded length.
        unsafe {
            std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE).copy_from_slice(&map);
        }
    }
    // SAFETY: `shmem` owns a writable allocation of `MAP_SIZE` bytes and its raw pointer remains valid for the observer lifetime.
    let observer = StdMapObserver::from_mut_slice("edges", unsafe {
        OwnedMutSlice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE)
    });

    let (rpc_provenance, bytecode_hash, config_hash, tool_revision, rng_seed) =
        execution_provenance_fields(
            &config,
            core_id,
            synthetic_fork_mode,
            campaign_from_checkpoint || resumed,
            &initial_db,
        );

    let mut harness = |input: &EvmInput| {
        if !budget.reserve_execution() {
            return ExitKind::Ok;
        }
        let snap_id = input.base_snapshot_id;
        let snapshot_corpus_guard = snapshot_corpus.read();
        let Some(base_snap_arc) = snapshot_corpus_guard.get_snapshot(snap_id) else {
            log::error!("Input references missing snapshot id {}", snap_id);
            return ExitKind::Crash;
        };

        let mut current_state = base_snap_arc.read().state.read().clone();
        drop(snapshot_corpus_guard);
        let base_fork_state = match &current_state {
            ChainState::Evm(db) => db.clone(),
        };
        let mut current_env = initial_env.clone();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            let mut waypoints = Vec::new();
            let mut df = dataflow_registry.write();
            let exec_result = ForkDb::with_thread_rpc_budget(
                Some(execution_rpc_budget()),
                // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
                || unsafe {
                    let map_slice = std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                    evm_executor.execute_with_result(
                        &mut current_state,
                        &mut current_env,
                        tx,
                        map_slice,
                        &mut df,
                        &mut waypoints,
                        tx_idx,
                    )
                },
            );

            let result = match exec_result {
                Ok(result) => result,
                Err(err) => {
                    if err.to_string().contains("fork RPC budget exhausted") {
                        if synthetic_fork_mode {
                            log::warn!(
                                "Skipping input after fork RPC budget exhaustion at tx {}; increase RUSTYFUZZ_EXEC_RPC_BUDGET for deeper live-fork exploration",
                                tx_idx
                            );
                            return ExitKind::Ok;
                        }
                        log::error!(
                            "Fork RPC budget exhausted at tx {} under live RPC (fail-closed); increase RUSTYFUZZ_EXEC_RPC_BUDGET",
                            tx_idx
                        );
                        return ExitKind::Crash;
                    }
                    log::error!("EVM execution failed for tx {}: {err:#}", tx_idx);
                    return ExitKind::Crash;
                }
            };
            enqueue_concolic_hints(
                &concolic_hints,
                telemetry.concolic_hint_stats.as_ref(),
                tx_idx,
                &waypoints,
            );
            tx_results.push(result);
        }

        let execution = sequence_result_from_tx_results(tx_results);
        let report = state_novelty_feedback.write().observe_execution(&execution);
        // SAFETY: the shared-memory allocation is readable and exactly `MAP_SIZE` bytes for the harness lifetime.
        unsafe {
            let map_slice = std::slice::from_raw_parts(coverage_map_ptr, MAP_SIZE);
            if let Some(snapshot_id) = snapshot_corpus.write().maybe_add_post_execution_snapshot(
                snap_id,
                input,
                current_state.clone(),
                map_slice,
                &execution,
                MAX_SNAPSHOT_CORPUS_SIZE,
            ) {
                log::debug!(
                    "Inserted post-execution snapshot id={} parent={} txs={} state_novelty={}",
                    snapshot_id,
                    snap_id,
                    input.txs.len(),
                    report.novelty_score()
                );
                event_sink.emit(CampaignEvent::NewSnapshot {
                    id: snapshot_id,
                    parent: snap_id,
                });
            }
        }
        let mut findings = protocol_oracles.evaluate(&execution);
        let economic_delta = (config.hardened_defi.enabled
            && config.hardened_defi.enable_economic_delta)
            .then(|| EconomicDeltaEngine::from_execution(input, &execution));
        findings.extend(evaluate_runtime_invariants(
            &config,
            target_invariant_manifest.as_ref(),
            economic_delta.as_ref(),
        ));
        apply_min_finding_confidence(&mut findings, config.min_finding_confidence);

        let testcase_provenance = testcase_metadata_store
            .get_or_default(input)
            .mutation_provenance;
        let mut campaign_score =
            campaign_scorer.score(input, &execution, &report, &findings, &testcase_provenance);
        if let Some(economic_delta) = economic_delta {
            let delta_score = EconomicDeltaEngine::score(&economic_delta);
            if delta_score > 0 {
                campaign_score.economic_pressure =
                    campaign_score.economic_pressure.saturating_add(delta_score);
                campaign_score.total = campaign_score.total.saturating_add(delta_score).min(10_000);
                campaign_score.explanation.push(format!(
                    "hardened_defi_economic_delta: score={}, confidence={}, suspicious_extraction={}, accounting_anomaly={}",
                    delta_score,
                    economic_delta.confidence,
                    economic_delta.suspicious_value_extraction,
                    economic_delta.accounting_anomaly
                ));
            }
        }

        let mut counterexample_exploit_candidate = None;
        if config.hardened_defi.enabled {
            let counterexample_search = CounterexampleSearchEngine {
                max_candidates: config.hardened_defi.max_template_sequences.max(1),
            };
            let search_result = counterexample_search.search(
                input,
                &execution,
                &findings,
                target_profile.as_ref().map(|profile| profile.as_ref()),
                hardened_actor_set.as_ref(),
            );
            let counterexample_pressure = search_result.model.counterexample_pressure();
            if counterexample_pressure > 0 {
                campaign_score.counterexample_pressure = campaign_score
                    .counterexample_pressure
                    .saturating_add(counterexample_pressure);
                campaign_score.total = campaign_score
                    .total
                    .saturating_add(counterexample_pressure)
                    .min(10_000);
                campaign_score.explanation.push(format!(
                    "counterexample_model: pressure={}, confidence={}, hypotheses={}, protocols={:?}",
                    counterexample_pressure,
                    search_result.model.confidence,
                    search_result.model.invariant_hypotheses.len(),
                    search_result.model.inferred_protocol_types
                ));
            }
            if let Some(candidate) = search_result.candidate {
                let confidence = candidate.confidence;
                let violated_invariant = candidate.violated_invariant.clone();
                let replayability_status = candidate.replayability_status.clone();
                let minimized_sequence_status = candidate.minimized_sequence_status.clone();
                counterexample_exploit_candidate = Some(candidate.into_exploit_path_candidate());
                if confidence >= 80 {
                    campaign_score.explanation.push(format!(
                        "counterexample_search: confidence={}, invariant={:?}, replay={:?}, minimized={:?}",
                        confidence,
                        violated_invariant,
                        replayability_status,
                        minimized_sequence_status
                    ));
                }
            }
        }

        let exploit_candidate = counterexample_exploit_candidate.or_else(|| {
            ExploitPathBuilder::from_execution(input, &execution, &findings, &campaign_score)
        });

        account_registry.write().observe_execution(&execution);
        let mutation_strategies = mutation_strategies(&testcase_provenance);
        record_successful_concolic_mutation(
            telemetry.concolic_hint_stats.as_ref(),
            &mutation_strategies,
            findings.len(),
            report.interesting,
            campaign_score.total,
        );
        let coverage_edges = execution
            .tx_results
            .iter()
            .map(|result| result.coverage_edges)
            .sum();
        telemetry.record_execution(ExecutionTelemetryRecord {
            core_id,
            tx_count: input.txs.len(),
            findings: findings.len(),
            campaign_score: campaign_score.total,
            corpus_size: 0,
            coverage_edges,
            state_novelty_score: report.novelty_score(),
            mutation_strategies: &mutation_strategies,
        });
        if let Err(error) = super::provenance::persist(
            config.corpus_dir.as_ref(),
            super::provenance::PersistRequest {
                execution_index: telemetry.execution_count(),
                budget_consumed: budget.reserved(),
                input,
                execution: &execution,
                coverage_edges,
                state_novelty_score: report.novelty_score(),
                campaign_score: &campaign_score,
                findings: &findings,
                mutation_strategies: &mutation_strategies,
                rpc_provenance: rpc_provenance.clone(),
                bytecode_hash: bytecode_hash.clone(),
                config_hash: config_hash.clone(),
                tool_revision: tool_revision.clone(),
                rng_seed,
            },
        ) {
            log::error!("execution provenance persistence failed: {error:#}");
            return ExitKind::Crash;
        }

        if report.interesting {
            // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
            unsafe {
                let map_slice = std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                reward_state_novelty(map_slice, &report);
            }
        }

        if campaign_score.is_interesting() {
            // SAFETY: the shared-memory allocation is writable and exactly `MAP_SIZE` bytes for the harness lifetime.
            unsafe {
                let map_slice = std::slice::from_raw_parts_mut(coverage_map_ptr, MAP_SIZE);
                reward_campaign_score(map_slice, &campaign_score);
            }
        }

        if artifact_limit_reached(&telemetry, config.artifact_limit) {
            log::debug!(
                "Artifact limit reached; skipping persistence (limit={:?})",
                config.artifact_limit
            );
        } else if let Some(reason) = campaign_artifact_reason(
            synthetic_fork_mode,
            &execution,
            &report,
            &campaign_score,
            &findings,
            exploit_candidate.as_ref(),
        ) {
            // SAFETY: the shared-memory allocation is readable and exactly `MAP_SIZE` bytes for the harness lifetime.
            let persisted = unsafe {
                let map_slice = std::slice::from_raw_parts(coverage_map_ptr, MAP_SIZE);
                persistent_corpus.persist_campaign_artifact(CampaignArtifactRequest {
                    input,
                    execution: &execution,
                    coverage: map_slice,
                    state_novelty_score: report.novelty_score(),
                    base_fork_state: &base_fork_state,
                    score: &campaign_score,
                    findings: &findings,
                    exploit_candidate: exploit_candidate.as_ref(),
                    block_number: config.fork_block,
                    target: Some(target_contract),
                    reason,
                })
            };

            match persisted {
                Ok(outcome) => {
                    if outcome.created_new {
                        telemetry.record_artifact();
                        event_sink.emit(CampaignEvent::CandidateFinding {
                            input_id: outcome.record.input_id.clone(),
                        });
                        log::info!(
                            "Persisted campaign artifact: input_id={}, fork_cache_id={}, reason={}, score={}, findings={}",
                            outcome.record.input_id,
                            outcome.record.fork_cache_id,
                            outcome.record.reason,
                            outcome.record.score.total,
                            outcome.record.findings.len()
                        );
                        enqueue_promotion_artifact(
                            &config,
                            &promotion_outbox,
                            &outcome.record,
                            synthetic_fork_mode,
                            &promotion_stats,
                        );
                    }
                }
                Err(err) => log::error!(
                    "Failed to persist campaign artifact for target {}: {err:#}",
                    target_contract
                ),
            }
        }

        *pending_campaign_score.write() = Some(campaign_score);

        ExitKind::Ok
    };

    for input in &required_replay_inputs {
        let reserved_before = budget.reserved();
        if !matches!(harness(input), ExitKind::Ok) {
            anyhow::bail!("required pre-fuzz sequence execution failed");
        }
        write_required_seed_replay_marker(
            &config.report_dir,
            input,
            budget.reserved() > reserved_before,
        )?;
    }

    let capture = |state: &EvmCampaignState,

                   feedback: &EvmCoverageFeedback,
                   scheduler: &RustyFuzzScheduler|
     -> anyhow::Result<_> {
        let saved = super::checkpoint::Checkpoint {
            state: postcard::to_stdvec(state)?,
            feedback: feedback.clone(),
            // SAFETY: the shared-memory allocation is readable and exactly `MAP_SIZE` bytes for the harness lifetime.
            raw_coverage: unsafe {
                std::slice::from_raw_parts(coverage_map_ptr, MAP_SIZE).to_vec()
            },
            snapshots: super::checkpoint::SavedSnapshots::capture(&snapshot_corpus.read()),
            novelty: state_novelty_feedback.read().clone(),
            dataflow: dataflow_registry.read().clone(),
            accounts: account_registry.read().clone(),
            metadata: testcase_metadata_store.checkpoint(),
            hints: concolic_hints.lock().clone(),
            scheduler: scheduler.checkpoint(),
            budget: budget.checkpoint(),
            pending_score: pending_campaign_score.read().clone(),
            strategies: strategy_counters.snapshot(),
            telemetry: telemetry.checkpoint(),
            block_env: initial_env.clone(),
        };
        let mut corpus_ids = Vec::new();
        for id in state.corpus().ids() {
            let testcase = state.corpus().get(id)?.borrow();
            let input = testcase
                .input()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("checkpoint corpus input not loaded"))?;
            anyhow::ensure!(
                snapshot_corpus
                    .read()
                    .snapshots
                    .contains_key(&input.base_snapshot_id),
                "checkpoint corpus references missing snapshot"
            );
            corpus_ids.push(input.semantic_input_hash());
        }
        Ok((saved, corpus_ids, feedback.checkpoint_coverage().to_vec()))
    };
    if let Some(session) = checkpoint_session.as_mut() {
        let (saved, ids, coverage) = capture(
            &state,
            fuzzer.feedback(),
            HasScheduler::<EvmInput, EvmCampaignState>::scheduler(&fuzzer),
        )?;
        session.publish(&saved, ids, coverage, resumed)?;
    }

    if config.max_execs.is_some() || config.duration_secs.is_some() {
        log::info!(
            "Running mutational hard-bounded single-process campaign: max_execs={:?}, duration_secs={:?}, seed_pool={}, corpus_size={}",
            config.max_execs,
            config.duration_secs,
            direct_seed_inputs.len(),
            state.corpus().count()
        );
        let mut executor = InProcessExecutor::with_timeout::<()>(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut manager,
            execution_timeout,
        )?;
        let mut bounded_progress_report = Instant::now();
        while !budget.exhausted()
            && !cancellation
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            let _ = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
            if let Some(session) = checkpoint_session.as_mut() {
                if session.due(budget.reserved()) || budget.exhausted() {
                    let (saved, ids, coverage) = capture(
                        &state,
                        fuzzer.feedback(),
                        HasScheduler::<EvmInput, EvmCampaignState>::scheduler(&fuzzer),
                    )?;
                    session.publish(&saved, ids, coverage, false)?;
                }
            }
            log_bounded_campaign_progress(
                "single-mutational",
                &mut bounded_progress_report,
                &budget,
                &telemetry,
                &config.report_dir,
                None,
            );
        }
        if let Some(session) = checkpoint_session.as_mut() {
            let (saved, ids, coverage) = capture(
                &state,
                fuzzer.feedback(),
                HasScheduler::<EvmInput, EvmCampaignState>::scheduler(&fuzzer),
            )?;
            session.publish(&saved, ids, coverage, resumed)?;
        }

        let cancelled = cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed));
        if !cancelled {
            promote_outbox(
                &config,
                persistent_corpus.as_ref(),
                &initial_env,
                synthetic_fork_mode,
                &promotion_outbox,
                &promotion_stats,
            );
        }
        let state = if cancelled {
            "cancelled"
        } else if promotion_stats.promotion_failure_count() > 0
            || promotion_stats.promotion_pending_count() > 0
        {
            "partial"
        } else {
            "finalized"
        };
        write_final_campaign_summary(&config, &promotion_stats, &telemetry, state)?;
        if cancelled {
            anyhow::bail!("fuzz campaign cancelled by watchdog");
        }
        if promotion_stats.promotion_failure_count() > 0
            || promotion_stats.promotion_pending_count() > 0
        {
            anyhow::bail!("campaign completed with promotion failures or pending work");
        }
        return Ok(());
    }

    let mut executor = InProcessExecutor::with_timeout::<()>(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut manager,
        execution_timeout,
    )?;

    if let Some(session) = checkpoint_session.as_mut() {
        loop {
            if cancellation
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
            {
                break;
            }
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
            if session.due(budget.reserved()) {
                let (saved, ids, coverage) = capture(
                    &state,
                    fuzzer.feedback(),
                    HasScheduler::<EvmInput, EvmCampaignState>::scheduler(&fuzzer),
                )?;
                session.publish(&saved, ids, coverage, false)?;
            }
        }
    } else {
        while !cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
        }
    }

    let cancelled = cancellation
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed));
    if !cancelled {
        promote_outbox(
            &config,
            persistent_corpus.as_ref(),
            &initial_env,
            synthetic_fork_mode,
            &promotion_outbox,
            &promotion_stats,
        );
    }
    let state = if cancelled {
        "cancelled"
    } else if promotion_stats.promotion_failure_count() > 0
        || promotion_stats.promotion_pending_count() > 0
    {
        "partial"
    } else {
        "finalized"
    };
    write_final_campaign_summary(&config, &promotion_stats, &telemetry, state)?;
    if cancelled {
        anyhow::bail!("fuzz campaign cancelled by watchdog");
    }
    if promotion_stats.promotion_failure_count() > 0
        || promotion_stats.promotion_pending_count() > 0
    {
        anyhow::bail!("campaign completed with promotion failures or pending work");
    }
    Ok(())
}

fn broker_launcher_error_was_shutdown(message: &str) -> bool {
    message.contains("Shutting down")
}

fn broker_launcher_error_can_fallback(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    let fatal_markers = [
        "worker",
        "runtime",
        "promotion",
        "panic",
        "required pre-fuzz",
        "failed to execute",
        "execution failed",
        "checkpoint",
    ];
    if fatal_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return false;
    }
    let startup_markers = [
        "failed to bind to port",
        "address already in use",
        "no available port",
        "connection refused",
        "failed to start broker",
        "failed to launch broker",
        "failed to connect to broker",
        "could not connect to broker",
        "broker unavailable",
    ];
    startup_markers
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn campaign_cores(configured: Option<&Cores>) -> anyhow::Result<Cores> {
    if let Some(cores) = configured {
        return Ok(cores.clone());
    }
    let requested = std::env::var("RUSTYFUZZ_CORES")
        .ok()
        .or_else(|| std::env::var("LIBAFL_CORES").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "0".to_string());
    Cores::from_cmdline(&requested)
        .map_err(|err| anyhow::anyhow!("invalid core selection `{requested}`: {err}"))
}

fn campaign_execution_timeout() -> Duration {
    std::env::var("RUSTYFUZZ_EXEC_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_EXECUTION_TIMEOUT)
}

fn startup_rpc_timeout() -> Duration {
    std::env::var("RUSTYFUZZ_STARTUP_RPC_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

fn campaign_requires_rpc_fork() -> bool {
    std::env::var("RUSTYFUZZ_REQUIRE_RPC_FORK")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn sanitize_rpc_host(rpc_url: &str) -> String {
    url::Url::parse(rpc_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "<invalid-rpc-url>".to_string())
}

fn discover_target_bytecode_analysis(
    db: &CacheDB<ForkDb>,
    target: Option<Address>,
) -> Option<BytecodeAnalysisReport> {
    let target = target?;
    let account = db
        .cache
        .accounts
        .get(&target)
        .and_then(|account| account.info());
    let account = account?;
    let code = account.code?;
    Some(analyze_bytecode(code.original_byte_slice()))
}

fn log_seed_bundle_status(
    status: &SeedBundleStatus,
    required: bool,
    allow_synthetic_fallback: bool,
) -> anyhow::Result<()> {
    match status {
        SeedBundleStatus::Disabled => {
            if allow_synthetic_fallback {
                log::info!(
                    "Mainnet seed bundle: disabled; seed startup may use synthetic fallback"
                );
            } else {
                log::info!(
                    "Mainnet seed bundle: disabled; synthetic fallback is disabled, so another trusted seed source is required"
                );
            }
        }
        SeedBundleStatus::Loaded {
            bundle_id,
            path,
            seed_count,
            account_count,
        } => {
            log::info!(
                "Mainnet seed bundle `{}` loaded from `{}`: seeds={}, discovered_accounts={}",
                bundle_id,
                path.display(),
                seed_count,
                account_count
            );
        }
        SeedBundleStatus::Missing { bundle_id, path } => {
            let msg = format!(
                "mainnet seed bundle `{}` missing at `{}`",
                bundle_id,
                path.display()
            );
            if required {
                anyhow::bail!("{msg}; require_seed_bundle=true");
            }
            if allow_synthetic_fallback {
                log::warn!(
                    "{msg}; continuing with synthetic-seed-start because require_seed_bundle=false"
                );
            } else {
                log::warn!(
                    "{msg}; synthetic fallback is disabled, so another trusted seed source is required"
                );
            }
        }
        SeedBundleStatus::Empty {
            bundle_id,
            path,
            account_count,
        } => {
            let msg = format!(
                "mainnet seed bundle `{}` at `{}` is empty (discovered_accounts={})",
                bundle_id,
                path.display(),
                account_count
            );
            if required {
                anyhow::bail!("{msg}; require_seed_bundle=true");
            }
            if allow_synthetic_fallback {
                log::warn!(
                    "{msg}; continuing with synthetic-seed-start because require_seed_bundle=false"
                );
            } else {
                log::warn!(
                    "{msg}; synthetic fallback is disabled, so another trusted seed source is required"
                );
            }
        }
        SeedBundleStatus::TargetMismatch {
            bundle_id,
            path,
            bundle_target,
            campaign_target,
            seed_count,
        } => {
            let msg = format!(
                "mainnet seed bundle `{}` at `{}` targets {}, but campaign target is {} (seeds={})",
                bundle_id,
                path.display(),
                bundle_target,
                campaign_target,
                seed_count
            );
            if required {
                anyhow::bail!("{msg}; require_seed_bundle=true");
            }
            log::warn!("{msg}; ignoring bundle");
        }
        SeedBundleStatus::Invalid {
            bundle_id,
            path,
            error,
        } => {
            let msg = format!(
                "mainnet seed bundle `{}` at `{}` is invalid: {}",
                bundle_id,
                path.display(),
                error
            );
            if required {
                anyhow::bail!("{msg}; require_seed_bundle=true");
            }
            if allow_synthetic_fallback {
                log::warn!(
                    "{msg}; continuing with synthetic-seed-start because require_seed_bundle=false"
                );
            } else {
                log::warn!(
                    "{msg}; synthetic fallback is disabled, so another trusted seed source is required"
                );
            }
        }
    }
    Ok(())
}

fn campaign_artifact_reason(
    synthetic_fork_mode: bool,
    execution: &SequenceExecutionResult,
    state_report: &StateNoveltyReport,
    campaign_score: &CampaignScore,
    findings: &[crate::common::oracle::ProtocolFinding],
    exploit_candidate: Option<&crate::engine::exploit_path::ExploitPathCandidate>,
) -> Option<&'static str> {
    if synthetic_fork_mode {
        let _ = (findings, campaign_score);
        return None;
    }

    const MIN_NON_SUCCESS_ARTIFACT_SCORE: u64 = 500;
    const MIN_ECONOMIC_OR_INVARIANT_SCORE: u64 = 250;
    const MIN_STATE_NOVELTY_ARTIFACT_SCORE: u64 = 150;

    if exploit_candidate.is_some_and(|candidate| {
        candidate
            .proof
            .as_ref()
            .is_some_and(|proof| proof.confidence_is_confirmed())
    }) {
        return Some("replayable-minimized-path");
    }

    // Confirmed oracle evidence is always worth persisting, even if the
    // sequence includes a revert/halt before or after the meaningful action.
    if !findings.is_empty() {
        return Some("protocol-oracle-finding");
    }

    if campaign_score
        .explanation
        .iter()
        .any(|reason| reason.contains("exploit-directed"))
        && campaign_score.total >= MIN_ECONOMIC_OR_INVARIANT_SCORE
    {
        return Some("exploit-path-candidate");
    }

    let has_non_success_tx = execution
        .tx_results
        .iter()
        .any(|result| !matches!(result.status, ExecutionStatus::Success));

    // Reverts and halts are normal fuzzing outcomes. Persist only high-signal
    // non-success paths; otherwise the corpus gets flooded with low-value files.
    if has_non_success_tx {
        return (campaign_score.total >= MIN_NON_SUCCESS_ARTIFACT_SCORE)
            .then_some("high-score-non-success-status");
    }

    // Economic/invariant pressure is useful, but low-score pressure is usually
    // weak signal. Persist only when the full campaign score is meaningful.
    if (campaign_score.economic_pressure > 0 || campaign_score.invariant_pressure > 0)
        && campaign_score.total >= MIN_ECONOMIC_OR_INVARIANT_SCORE
    {
        return Some("economic-or-invariant-pressure");
    }

    // State novelty should be persisted only when backed by a non-trivial
    // campaign score. Otherwise minor storage/call deltas create artifact noise.
    if state_report.interesting && campaign_score.total >= MIN_STATE_NOVELTY_ARTIFACT_SCORE {
        return Some("state-novelty");
    }

    None
}

fn mutation_strategies(provenance: &[MutationProvenance]) -> Vec<String> {
    if provenance.is_empty() {
        return vec!["seed_or_imported".to_string()];
    }
    provenance
        .iter()
        .map(|mutation| mutation.strategy.clone())
        .collect()
}

fn log_worker_corpus_sync(core_id: usize, corpus_count: usize, corpus_dir: &str, mode: &str) {
    log::info!(
        "Worker corpus sync sanity: mode={}, core={}, local_corpus_count={}, shared_coverage_map_bytes={}, persistent_corpus_dir={}",
        mode,
        core_id,
        corpus_count,
        MAP_SIZE,
        corpus_dir
    );
}

fn record_successful_concolic_mutation(
    stats: &ConcolicHintStats,
    mutation_strategies: &[String],
    findings: usize,
    state_interesting: bool,
    campaign_score: u64,
) {
    if !mutation_strategies
        .iter()
        .any(|strategy| strategy.starts_with("concolic"))
    {
        return;
    }
    if findings > 0 || state_interesting || campaign_score > 0 {
        stats.record_successful();
    }
}

fn enqueue_concolic_hints(
    hint_queue: &Arc<Mutex<Vec<ConcolicHint>>>,
    stats: &ConcolicHintStats,
    tx_idx: usize,
    waypoints: &[crate::common::types::Waypoint],
) {
    const MAX_PENDING_CONCOLIC_HINTS: usize = 1024;

    let solver = ConcolicSolver::new();
    let mut new_hints = waypoints
        .iter()
        .filter_map(|waypoint| solver.solve_hint(tx_idx, waypoint))
        .collect::<Vec<_>>();
    if new_hints.is_empty() {
        return;
    }
    stats.record_generated(new_hints.len() as u64);
    new_hints.sort_by_key(|hint| concolic_hint_priority(hint, waypoints));

    let mut queue = hint_queue.lock();
    queue.extend(new_hints);
    queue.sort_by_key(|hint| concolic_hint_priority(hint, waypoints));
    let before_dedup = queue.len();
    let mut seen = HashSet::new();
    queue.retain(|hint| seen.insert((hint.tx_index, hint.calldata_offset, hint.word)));
    let deduplicated = before_dedup.saturating_sub(queue.len());
    if queue.len() > MAX_PENDING_CONCOLIC_HINTS {
        queue.truncate(MAX_PENDING_CONCOLIC_HINTS);
    }
    if deduplicated > 0 {
        stats.record_deduplicated(deduplicated as u64);
    }
}

fn concolic_hint_priority(
    hint: &ConcolicHint,
    waypoints: &[crate::common::types::Waypoint],
) -> (u64, usize, usize, usize) {
    let mut priority: u64 = match &hint.strategy {
        ConcolicStrategy::FlipBranch { .. } => 0,
        ConcolicStrategy::FlipComparison { .. } => 1_000,
        ConcolicStrategy::ArithmeticBoundary { .. } => 2_000,
    };
    priority = priority.saturating_add(branch_distance_priority(hint.pc, waypoints));
    if oracle_adjacent_pc(hint.pc, waypoints) {
        priority = priority.saturating_sub(500);
    }
    (priority, hint.tx_index, hint.calldata_offset, hint.pc)
}

fn branch_distance_priority(pc: usize, waypoints: &[crate::common::types::Waypoint]) -> u64 {
    waypoints
        .iter()
        .filter_map(|waypoint| match waypoint {
            crate::common::types::Waypoint::Comparison {
                pc: cmp_pc,
                branch_distance,
                ..
            } if *cmp_pc == pc => branch_distance.map(|distance| distance.saturating_to::<u64>()),
            crate::common::types::Waypoint::BranchPath {
                pc: branch_pc,
                constraint,
                ..
            } if *branch_pc == pc => {
                if let crate::common::types::Waypoint::Comparison {
                    branch_distance, ..
                } = constraint.as_ref()
                {
                    branch_distance.map(|distance| distance.saturating_to::<u64>())
                } else {
                    None
                }
            }
            _ => None,
        })
        .min()
        .unwrap_or(0)
        .min(10_000)
}

fn oracle_adjacent_pc(pc: usize, waypoints: &[crate::common::types::Waypoint]) -> bool {
    waypoints.iter().any(|waypoint| {
        let candidate = match waypoint {
            crate::common::types::Waypoint::StorageRead { pc, .. }
            | crate::common::types::Waypoint::StorageWrite { pc, .. }
            | crate::common::types::Waypoint::TransientStorageRead { pc, .. }
            | crate::common::types::Waypoint::TransientStorageWrite { pc, .. } => Some(*pc),
            crate::common::types::Waypoint::Dataflow {
                influenced: true, ..
            } => Some(pc),
            _ => None,
        };
        candidate.is_some_and(|other_pc| pc.abs_diff(other_pc) <= 16)
    })
}

fn apply_min_finding_confidence(
    findings: &mut Vec<crate::common::oracle::ProtocolFinding>,
    min_confidence: u64,
) {
    if min_confidence == 0 {
        return;
    }
    findings.retain(|finding| protocol_finding_confidence(finding) >= min_confidence);
}

fn protocol_finding_confidence(finding: &crate::common::oracle::ProtocolFinding) -> u64 {
    use crate::common::oracle::ProtocolSeverity;
    match &finding.severity {
        ProtocolSeverity::Info => 20,
        ProtocolSeverity::Low => 35,
        ProtocolSeverity::Medium => 55,
        ProtocolSeverity::High => 75,
        ProtocolSeverity::Critical => 90,
    }
}

fn artifact_limit_reached(telemetry: &CampaignTelemetry, artifact_limit: Option<u64>) -> bool {
    artifact_limit.is_some_and(|limit| telemetry.artifacts.load(Ordering::Relaxed) >= limit)
}

fn merge_bytecode_profile(
    mut profile: TargetProfile,
    bytecode_analysis: Option<&BytecodeAnalysisReport>,
    abi_loaded: bool,
) -> TargetProfile {
    let Some(analysis) = bytecode_analysis else {
        return profile;
    };
    let bytecode_profile = &analysis.target_profile;
    let has_strong_bytecode_protocol = bytecode_profile.protocol_types.iter().any(|protocol| {
        matches!(
            protocol,
            ProtocolType::ProxyUpgradeable
                | ProtocolType::AccessControlHeavy
                | ProtocolType::AccountingHeavy
                | ProtocolType::LendingBorrowing
                | ProtocolType::AmmDexPool
                | ProtocolType::OraclePriceFeed
                | ProtocolType::GovernanceTimelock
        )
    });
    if !abi_loaded
        && has_strong_bytecode_protocol
        && profile.protocol_types.len() == 1
        && profile.protocol_types.contains(&ProtocolType::Erc20Token)
    {
        profile.protocol_types.clear();
        profile
            .explanation
            .push("bytecode evidence overrode weak ERC20-only seed classification".to_string());
    }
    for protocol in &bytecode_profile.protocol_types {
        if *protocol != ProtocolType::Unknown && !profile.protocol_types.contains(protocol) {
            profile.protocol_types.push(protocol.clone());
        }
    }
    if profile.protocol_types.len() > 1 {
        profile
            .protocol_types
            .retain(|p| *p != ProtocolType::Unknown);
    }
    profile.confidence = profile.confidence.max(bytecode_profile.confidence);
    extend_unique(
        &mut profile.relevant_selectors,
        &bytecode_profile.relevant_selectors,
    );
    extend_unique(
        &mut profile.risky_selectors,
        &bytecode_profile.risky_selectors,
    );
    extend_unique(
        &mut profile.state_changing_functions,
        &bytecode_profile.state_changing_functions,
    );
    extend_unique(
        &mut profile.role_sensitive_functions,
        &bytecode_profile.role_sensitive_functions,
    );
    extend_unique(
        &mut profile.value_sensitive_functions,
        &bytecode_profile.value_sensitive_functions,
    );
    extend_unique_strings(
        &mut profile.recommended_seed_templates,
        &bytecode_profile.recommended_seed_templates,
    );
    extend_unique_strings(
        &mut profile.recommended_invariant_families,
        &bytecode_profile.recommended_invariant_families,
    );
    if analysis.proxy_patterns.iter().any(|pattern| {
        matches!(
            pattern,
            crate::engine::bytecode_analysis::ProxyPattern::Eip1967AdminSlot
                | crate::engine::bytecode_analysis::ProxyPattern::Eip1967ImplementationSlot
                | crate::engine::bytecode_analysis::ProxyPattern::DelegateCallDispatch
        )
    }) {
        push_unique_string(
            &mut profile.recommended_invariant_families,
            "access-control",
        );
        push_unique_string(
            &mut profile.recommended_seed_templates,
            "access-control-sensitive-call",
        );
    }
    if analysis.risk_flags.iter().any(|flag| {
        matches!(
            flag,
            crate::engine::bytecode_analysis::BytecodeRiskFlag::HasSstore
        )
    }) {
        push_unique_string(
            &mut profile.recommended_invariant_families,
            "generic-accounting",
        );
    }
    profile.protocol_types.sort();
    profile.protocol_types.dedup();
    profile.recommended_seed_templates.sort();
    profile.recommended_seed_templates.dedup();
    profile.recommended_invariant_families.sort();
    profile.recommended_invariant_families.dedup();
    profile
}

fn build_runtime_invariant_manifest(
    config: &Config,
    abi_report: Option<&AbiIngestReport>,
    bytecode_analysis: Option<&BytecodeAnalysisReport>,
) -> Option<TargetInvariantManifest> {
    if let Some(path) = config.target_invariant_manifest.as_deref() {
        match TargetInvariantManifest::load(path) {
            Ok(manifest) => {
                log::info!(
                    "Loaded target invariant manifest `{}` with {} rules",
                    path,
                    manifest.invariants.len()
                );
                return Some(manifest);
            }
            Err(err) => log::warn!("Failed to load target invariant manifest `{path}`: {err:#}"),
        }
    }
    if abi_report.is_none() && bytecode_analysis.is_none() {
        return None;
    }
    let mut manifest =
        TargetInvariantManifest::generate(config.target_contract, abi_report, None, None);
    if let Some(report) = bytecode_analysis {
        manifest.apply_bytecode_report(report);
    }
    log::info!(
        "Generated runtime invariant manifest from ABI/bytecode evidence: rules={}",
        manifest.invariants.len()
    );
    Some(manifest)
}

fn evaluate_runtime_invariants(
    config: &Config,
    manifest: Option<&TargetInvariantManifest>,
    delta: Option<&EconomicDeltaReport>,
) -> Vec<crate::common::oracle::ProtocolFinding> {
    let Some(delta) = delta else {
        return Vec::new();
    };
    if let Some(path) = config.target_invariant_manifest.as_deref() {
        match TargetInvariantManifest::load(path) {
            Ok(manifest) => return manifest.evaluate(delta),
            Err(err) => log::warn!("Failed to load target invariant manifest `{path}`: {err:#}"),
        }
    }
    manifest
        .map(|manifest| manifest.evaluate(delta))
        .unwrap_or_default()
}

fn extend_unique<T: Clone + Ord>(dst: &mut Vec<T>, src: &[T]) {
    dst.extend_from_slice(src);
    dst.sort();
    dst.dedup();
}

fn extend_unique_strings(dst: &mut Vec<String>, src: &[String]) {
    dst.extend(src.iter().cloned());
    dst.sort();
    dst.dedup();
}

fn push_unique_string(dst: &mut Vec<String>, value: &str) {
    if !dst.iter().any(|candidate| candidate == value) {
        dst.push(value.to_string());
    }
}

fn promotion_allowed(config: &PromotionConfig, high_confidence: bool) -> bool {
    !config.no_promotion && (config.enabled || high_confidence)
}

fn enqueue_promotion_artifact(
    config: &Config,
    outbox: &Mutex<VecDeque<crate::evm::corpus::CampaignArtifactRecord>>,
    artifact: &crate::evm::corpus::CampaignArtifactRecord,
    synthetic_fork_mode: bool,
    promotion_stats: &PromotionCampaignStats,
) {
    if config.promotion.no_promotion {
        log::debug!("Skipping promotion enqueue because no-promotion mode is active");
        return;
    }
    if artifact.findings.is_empty() {
        log::debug!(
            "Skipping promotion for score-only artifact input_id={} reason={} score={}; no oracle/protocol finding evidence",
            artifact.input_id,
            artifact.reason,
            artifact.score.total
        );
        return;
    }
    if synthetic_fork_mode {
        log::debug!(
            "Skipping promotion for synthetic fallback artifact input_id={} reason={}; synthetic executions are smoke evidence only",
            artifact.input_id,
            artifact.reason
        );
        return;
    }
    let high_confidence = artifact
        .findings
        .iter()
        .map(protocol_finding_confidence)
        .max()
        .unwrap_or_default()
        >= 80;
    if !promotion_allowed(&config.promotion, high_confidence) {
        return;
    }
    let queued = outbox.lock().len() as u64;
    let campaign_id = config
        .campaign_id
        .as_deref()
        .expect("campaign identity is initialized before use");
    let promotion_id = format!("{campaign_id}-{}", artifact.input_id);
    if config
        .promotion
        .promotion_limit
        .is_some_and(|limit| promotion_stats.promoted_count().saturating_add(queued) >= limit)
    {
        promotion_stats.record_capped(&promotion_id);
        log::debug!(
            "Promotion limit reached; skipping artifact promotion (limit={:?})",
            config.promotion.promotion_limit
        );
        return;
    }
    if !promotion_stats.reserve_promotion(&promotion_id) {
        log::debug!(
            "Skipping duplicate promotion for artifact input_id={}",
            artifact.input_id
        );
        return;
    }
    outbox.lock().push_back(artifact.clone());
}

fn promote_outbox(
    config: &Config,
    corpus: &PersistentCorpus,
    block_env: &revm::context::BlockEnv,
    synthetic_fork_mode: bool,
    outbox: &Mutex<VecDeque<crate::evm::corpus::CampaignArtifactRecord>>,
    promotion_stats: &PromotionCampaignStats,
) {
    let queued = std::mem::take(&mut *outbox.lock());
    if synthetic_fork_mode {
        return;
    }
    if config.promotion.no_promotion {
        log::debug!("Skipping final persisted-artifact rescan because no-promotion mode is active");
        return;
    }
    let campaign_id = config
        .campaign_id
        .as_deref()
        .expect("campaign identity is initialized before use");
    let queued_ids = queued
        .iter()
        .map(|artifact| format!("{campaign_id}-{}", artifact.input_id))
        .collect::<HashSet<_>>();
    let mut artifacts = queued;
    match corpus.list_campaign_artifacts() {
        Ok(persisted) => {
            for artifact in persisted {
                if !queued_ids.contains(&format!("{campaign_id}-{}", artifact.input_id)) {
                    artifacts.push_back(artifact);
                }
            }
        }
        Err(error) => {
            promotion_stats.record_failure(true);
            log::error!("failed to rescan persisted campaign artifacts: {error:#}");
            return;
        }
    }
    for artifact in artifacts {
        if artifact.findings.is_empty() {
            continue;
        }
        let high_confidence = artifact
            .findings
            .iter()
            .map(protocol_finding_confidence)
            .max()
            .unwrap_or_default()
            >= 80;
        if !promotion_allowed(&config.promotion, high_confidence) {
            continue;
        }
        let finding_id = format!("{campaign_id}-{}", artifact.input_id);
        if config
            .promotion
            .promotion_limit
            .is_some_and(|limit| promotion_stats.promoted_count() >= limit)
        {
            promotion_stats.record_capped(&finding_id);
            continue;
        }
        let already_reserved = queued_ids.contains(&finding_id);
        if !already_reserved && !promotion_stats.reserve_promotion(&finding_id) {
            continue;
        }
        let report_dir = std::path::Path::new(&config.report_dir);
        match promote_finding_artifact(PromotionRequest {
            corpus,
            artifact: &artifact,
            block_env,
            report_dir,
            campaign_id,
            fork_block: config.fork_block,
            rpc_url: &config.rpc_url,
            synthetic_mode: false,
            config: &config.promotion,
        }) {
            Ok(record) => promotion_stats.record(&record),
            Err(error) => {
                promotion_stats.release_promotion(&finding_id);
                promotion_stats.record_failure(true);
                log::warn!(
                    "Failed to promote persisted campaign artifact input_id={}: {error:#}",
                    artifact.input_id
                );
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WorkerTerminalArtifact {
    schema_version: u32,
    campaign_id: String,
    run_nonce: String,
    worker_id: String,
    state: String,
    summary: PromotionCampaignSummary,
}

fn worker_terminal_path(report_dir: &Path, worker_id: impl ToString) -> PathBuf {
    report_dir
        .join("worker_terminal")
        .join(format!("{}.json", worker_id.to_string()))
}

fn write_worker_terminal_artifact(
    config: &Config,
    run_nonce: &str,
    worker_id: impl ToString,
    state: &str,
    promotion_stats: &PromotionCampaignStats,
    telemetry: &CampaignTelemetry,
) -> anyhow::Result<()> {
    let report_dir = Path::new(&config.report_dir);
    let campaign_id = config
        .campaign_id
        .as_deref()
        .expect("campaign identity is initialized before use");
    let summary = promotion_stats.summary(
        campaign_id,
        telemetry.execution_count(),
        telemetry.mutated_inputs(),
        telemetry.seed_replays(),
        telemetry.artifact_count(),
        telemetry.coverage_edges(),
    );
    let worker_id = worker_id.to_string();
    rustyfuzz_artifacts::fsutil::write_json_atomic(
        &worker_terminal_path(report_dir, &worker_id),
        &WorkerTerminalArtifact {
            schema_version: 2,
            campaign_id: campaign_id.to_string(),
            run_nonce: run_nonce.to_string(),
            worker_id,
            state: state.to_string(),
            summary,
        },
    )?;
    Ok(())
}

fn write_final_campaign_summary(
    config: &Config,
    promotion_stats: &PromotionCampaignStats,
    telemetry: &CampaignTelemetry,
    state: &str,
) -> anyhow::Result<()> {
    let campaign_id = config
        .campaign_id
        .as_deref()
        .expect("campaign identity is initialized before use");
    let summary = promotion_stats.summary(
        campaign_id,
        telemetry.execution_count(),
        telemetry.mutated_inputs(),
        telemetry.seed_replays(),
        telemetry.artifact_count(),
        telemetry.coverage_edges(),
    );
    let report_dir = Path::new(&config.report_dir);
    write_campaign_summary(report_dir, &summary)?;
    write_campaign_status(
        report_dir,
        &serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": state,
            "campaign_id": campaign_id,
            "summary": summary,
        }),
    )
}

fn merge_worker_summaries(
    campaign_id: &str,
    workers: &[WorkerTerminalArtifact],
) -> PromotionCampaignSummary {
    let mut summary = PromotionCampaignSummary {
        campaign_id: campaign_id.to_string(),
        ..Default::default()
    };
    for worker in workers {
        summary.total_executions = summary
            .total_executions
            .saturating_add(worker.summary.total_executions);
        summary.mutated_inputs = summary
            .mutated_inputs
            .saturating_add(worker.summary.mutated_inputs);
        summary.seed_replays = summary
            .seed_replays
            .saturating_add(worker.summary.seed_replays);
        summary.total_artifacts = summary
            .total_artifacts
            .saturating_add(worker.summary.total_artifacts);
        summary.coverage_edges = summary
            .coverage_edges
            .saturating_add(worker.summary.coverage_edges);
        summary.interesting_candidates = summary
            .interesting_candidates
            .saturating_add(worker.summary.interesting_candidates);
        summary.candidate_findings = summary
            .candidate_findings
            .saturating_add(worker.summary.candidate_findings);
        summary.unproven_candidates = summary
            .unproven_candidates
            .saturating_add(worker.summary.unproven_candidates);
        summary.highest_confidence = summary
            .highest_confidence
            .max(worker.summary.highest_confidence);
        summary.promotion_capped = summary
            .promotion_capped
            .saturating_add(worker.summary.promotion_capped);
    }
    summary
}

fn write_broker_failure_status(config: &Config, reason: &str) -> anyhow::Result<()> {
    write_campaign_status(
        Path::new(&config.report_dir),
        &serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": "failed",
            "campaign_id": config.campaign_id.as_deref().expect("campaign identity is initialized before use"),
            "reason": reason,
        }),
    )
}

fn finalize_brokered_campaign(
    config: &Config,
    run_nonce: &str,
    block_env: &revm::context::BlockEnv,
    synthetic_fork_mode: bool,
    worker_ids: &[usize],
    cancellation: Option<&Arc<AtomicBool>>,
) -> anyhow::Result<()> {
    let report_dir = Path::new(&config.report_dir);
    let expected_campaign_id = config
        .campaign_id
        .as_deref()
        .expect("campaign identity is initialized before use");
    let mut workers = Vec::with_capacity(worker_ids.len());
    for worker_id in worker_ids {
        let path = worker_terminal_path(report_dir, *worker_id);
        let artifact = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<WorkerTerminalArtifact>(&bytes) {
                Ok(artifact) => artifact,
                Err(error) => {
                    let reason = format!(
                        "brokered campaign worker {worker_id} has malformed terminal artifact: {error}"
                    );
                    write_broker_failure_status(config, &reason)?;
                    anyhow::bail!(reason);
                }
            },
            Err(error) => {
                let reason = format!(
                    "brokered campaign worker {worker_id} has no readable terminal artifact: {error}"
                );
                write_broker_failure_status(config, &reason)?;
                anyhow::bail!(reason);
            }
        };
        let validation_error = if artifact.schema_version != 2 {
            Some("terminal artifact schema version is not current".to_string())
        } else if artifact.campaign_id != expected_campaign_id {
            Some("terminal artifact campaign identity is stale or mismatched".to_string())
        } else if artifact.run_nonce != run_nonce {
            Some("terminal artifact run nonce is stale or mismatched".to_string())
        } else if artifact.worker_id != worker_id.to_string() {
            Some("terminal artifact worker identity is mismatched".to_string())
        } else if !matches!(artifact.state.as_str(), "completed" | "cancelled") {
            Some("terminal artifact has an invalid worker state".to_string())
        } else if artifact.summary.campaign_id != expected_campaign_id {
            Some("terminal artifact summary campaign identity is mismatched".to_string())
        } else {
            None
        };
        if let Some(reason) = validation_error {
            let reason = format!("brokered campaign worker {worker_id}: {reason}");
            write_broker_failure_status(config, &reason)?;
            anyhow::bail!(reason);
        }
        workers.push(artifact);
    }

    let cancelled = cancellation
        .and_then(|flag| flag.load(Ordering::Relaxed).then_some(()))
        .is_some()
        || workers.iter().any(|worker| worker.state == "cancelled");
    let mut summary = merge_worker_summaries(
        config
            .campaign_id
            .as_deref()
            .expect("campaign identity is initialized before use"),
        &workers,
    );
    let promotion_stats = PromotionCampaignStats::default();
    if !cancelled && !synthetic_fork_mode {
        let corpus = PersistentCorpus::new(&config.corpus_dir)?;
        promote_outbox(
            config,
            &corpus,
            block_env,
            false,
            &Mutex::new(VecDeque::new()),
            &promotion_stats,
        );
        let promotion_summary = promotion_stats.summary(
            config
                .campaign_id
                .as_deref()
                .expect("campaign identity is initialized before use"),
            summary.total_executions,
            summary.mutated_inputs,
            summary.seed_replays,
            summary.total_artifacts,
            summary.coverage_edges,
        );
        summary.promoted_findings = promotion_summary.promoted_findings;
        summary.confirmed_findings = promotion_summary.confirmed_findings;
        summary.rejected_candidates = promotion_summary.rejected_candidates;
        summary.synthetic_non_production_findings =
            promotion_summary.synthetic_non_production_findings;
        summary.highest_confidence = summary
            .highest_confidence
            .max(promotion_summary.highest_confidence);
        summary.poc_count = promotion_summary.poc_count;
        summary.missing_poc_for_promoted = promotion_summary.missing_poc_for_promoted;
        summary.replay_failure_count = promotion_summary.replay_failure_count;
        summary.minimization_attempts = promotion_summary.minimization_attempts;
        summary.minimization_reduced = promotion_summary.minimization_reduced;
        summary.minimization_not_reducible = promotion_summary.minimization_not_reducible;
        summary.promotion_failures = promotion_summary.promotion_failures;
        summary.promotion_pending = promotion_summary.promotion_pending;
        summary.promotion_capped = promotion_summary.promotion_capped;
    }
    let state = if cancelled {
        "cancelled"
    } else if summary.promotion_failures > 0 || summary.promotion_pending > 0 {
        "partial"
    } else {
        "finalized"
    };
    write_campaign_summary(report_dir, &summary)?;
    write_campaign_status(
        report_dir,
        &serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": state,
            "campaign_id": expected_campaign_id,
            "run_nonce": run_nonce,
            "summary": summary,
        }),
    )?;
    if cancelled {
        anyhow::bail!("fuzz campaign cancelled before final promotion");
    }
    if summary.promotion_failures > 0 || summary.promotion_pending > 0 {
        anyhow::bail!("brokered campaign completed with promotion failures or pending work");
    }
    Ok(())
}

fn sequence_result_from_tx_results(
    tx_results: Vec<crate::common::types::TxExecutionResult>,
) -> SequenceExecutionResult {
    let total_gas_used = tx_results.iter().map(|result| result.gas_used).sum();

    let final_coverage_hash = tx_results
        .last()
        .map(|result| result.coverage_hash)
        .unwrap_or_default();

    SequenceExecutionResult {
        total_gas_used,
        final_coverage_hash,
        storage_reads: tx_results
            .iter()
            .flat_map(|result| result.storage_reads.clone())
            .collect(),
        storage_writes: tx_results
            .iter()
            .flat_map(|result| result.storage_writes.clone())
            .collect(),
        storage_diffs: tx_results
            .iter()
            .flat_map(|result| result.storage_diffs.clone())
            .collect(),
        call_trace: tx_results
            .iter()
            .flat_map(|result| result.call_trace.clone())
            .collect(),
        oracle_observations: Vec::new(),
        tx_results,
    }
}

fn reward_state_novelty(coverage: &mut [u8], report: &StateNoveltyReport) {
    if coverage.is_empty() {
        return;
    }

    let novelty_slots = STATE_NOVELTY_MAP_SLOTS.min(coverage.len());
    let offset = coverage.len() - novelty_slots;

    for hash in report
        .new_transition_hashes
        .iter()
        .chain(report.new_slot_hashes.iter())
        .chain(report.new_read_hashes.iter())
        .chain(report.new_call_edge_hashes.iter())
    {
        let idx = offset + ((*hash as usize) % novelty_slots);
        coverage[idx] = coverage[idx].saturating_add(1);
    }

    for contract in &report.new_contracts {
        let mut material = [0u8; 8];
        material.copy_from_slice(&contract.as_slice()[..8]);

        let idx = offset + ((u64::from_be_bytes(material) as usize) % novelty_slots);
        coverage[idx] = coverage[idx].saturating_add(1);
    }
}

fn reward_campaign_score(coverage: &mut [u8], score: &CampaignScore) {
    if coverage.is_empty() || score.total == 0 {
        return;
    }

    let score_slots = CAMPAIGN_SCORE_MAP_SLOTS.min(coverage.len());
    let offset = coverage.len() - score_slots;

    let components = [
        score.total,
        score.economic_pressure,
        score.invariant_pressure,
        score.counterexample_pressure,
        score.oracle_pressure,
        score.state_pressure,
        score.exploration_pressure,
    ];

    for (component_idx, value) in components.into_iter().enumerate() {
        if value == 0 {
            continue;
        }

        let bucket = value.next_power_of_two().min(128) as u8;
        let idx = offset + ((component_idx * 131 + value as usize) % score_slots);

        coverage[idx] = coverage[idx].saturating_add(bucket.max(1));
    }
}

fn choose_target_contract(
    configured: Option<Address>,
    registry: &GlobalAccountRegistry,
) -> Option<Address> {
    configured.or_else(|| {
        let mut contracts: Vec<_> = registry.contracts.iter().copied().collect();
        contracts.sort_by_key(|address| *address);
        contracts.into_iter().next()
    })
}

fn populate_abi_from_foundry_harness(
    harness: &FoundryHarnessManifest,
    abi_registry: &mut AbiRegistry,
) {
    for target in &harness.target_selectors {
        for selector in &target.selectors {
            if let Some(selector_hex) = selector.selector_hex {
                abi_registry.functions.entry(selector_hex).or_default();
            }
        }
    }
}

fn seed_input(target_contract: Address, fuzzer_address: Address) -> EvmInput {
    EvmInput::new(
        vec![SingletonTx {
            input: Vec::new(),
            caller: fuzzer_address,
            to: target_contract,
            value: U256::ZERO,
            is_victim: false,
        }],
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_promotion_mode_blocks_high_confidence_promotion() {
        let config = PromotionConfig {
            enabled: false,
            no_promotion: true,
            ..PromotionConfig::default()
        };
        assert!(!promotion_allowed(&config, false));
        assert!(!promotion_allowed(&config, true));
    }

    #[test]
    fn promotion_limit_counts_capped_candidates_without_pending_or_failure() {
        use crate::common::oracle::{ProtocolOraclePackKind, ProtocolSeverity, VulnType};
        use crate::evm::corpus::CorpusEntryMetadata;

        let config = Config {
            rpc_url: "https://rpc.example.com".to_string(),
            fork_block: 1,
            target_contract: None,
            corpus_dir: "corpus".to_string(),
            report_dir: "reports".to_string(),
            foundry_harness: None,
            mainnet_seed_bundle: None,
            in_memory_bytecode: None,
            cores: None,
            require_seed_bundle: false,
            require_rpc_fork: false,
            allow_synthetic_fallback: true,
            hardened_defi: HardenedDefiConfig::default(),
            target_invariant_manifest: None,
            abi_path: None,
            max_execs: Some(1),
            duration_secs: Some(1),
            artifact_limit: None,
            campaign_id: Some("bounded-promotion".to_string()),
            paths_are_isolated: true,
            min_finding_confidence: 0,
            promotion: PromotionConfig {
                enabled: true,
                promotion_limit: Some(2),
                ..PromotionConfig::default()
            },
        };
        let outbox = Mutex::new(VecDeque::new());
        let stats = PromotionCampaignStats::default();

        for index in 0..5 {
            let input_id = format!("candidate-{index}");
            let artifact = crate::evm::corpus::CampaignArtifactRecord {
                input_id: input_id.clone(),
                fork_cache_id: "fork".to_string(),
                artifact_key: String::new(),
                block_number: 1,
                target: None,
                reason: "promotable".to_string(),
                score: CampaignScore {
                    total: 100,
                    ..CampaignScore::default()
                },
                findings: vec![crate::common::oracle::ProtocolFinding {
                    pack: ProtocolOraclePackKind::RuntimePanic,
                    vuln: VulnType::Reentrancy,
                    severity: ProtocolSeverity::Critical,
                    tx_index: Some(0),
                    target: None,
                    evidence: "test evidence".to_string(),
                }],
                proof: None,
                metadata: CorpusEntryMetadata {
                    id: input_id.clone(),
                    input_hash: input_id,
                    path_hash: index as u64,
                    state_hash: 0,
                    state_novelty_score: 0,
                    coverage_edges: 0,
                    gas_used: 0,
                    crash_fingerprint: None,
                    frontier: Default::default(),
                },
                triage: Default::default(),
            };
            enqueue_promotion_artifact(&config, &outbox, &artifact, false, &stats);
        }

        let summary = stats.summary("bounded-promotion", 0, 0, 0, 5, 0);
        assert_eq!(outbox.lock().len(), 2);
        assert_eq!(summary.promoted_findings, 0);
        assert_eq!(summary.promotion_capped, 3);
        assert_eq!(summary.promotion_pending, 0);
        assert_eq!(summary.promotion_failures, 0);
    }

    #[test]
    fn campaign_path_resolution_preserves_campaign_suffix() {
        assert_eq!(
            Config::isolated_path("/tmp/reports_a", "_b"),
            "/tmp/reports_a_b"
        );
    }

    #[test]
    fn missing_campaign_identity_generates_isolated_paths() {
        let make_config = || Config {
            rpc_url: "https://rpc.example.com".to_string(),
            fork_block: 1,
            target_contract: None,
            corpus_dir: "corpus".to_string(),
            report_dir: "reports".to_string(),
            foundry_harness: None,
            mainnet_seed_bundle: None,
            in_memory_bytecode: None,
            cores: None,
            require_seed_bundle: false,
            require_rpc_fork: false,
            allow_synthetic_fallback: true,
            hardened_defi: HardenedDefiConfig::default(),
            target_invariant_manifest: None,
            abi_path: None,
            max_execs: Some(1),
            duration_secs: Some(1),
            artifact_limit: None,
            campaign_id: None,
            paths_are_isolated: true,
            min_finding_confidence: 0,
            promotion: PromotionConfig::default(),
        };
        let first = make_config().with_isolated_paths();
        let second = make_config().with_isolated_paths();
        assert_ne!(first.campaign_id, second.campaign_id);
        assert_ne!(first.corpus_dir, second.corpus_dir);
        assert_ne!(first.report_dir, second.report_dir);
        assert!(first.paths_are_isolated && second.paths_are_isolated);
    }

    #[test]
    fn state_novelty_projection_rewards_reserved_coverage_slots() {
        let mut coverage = vec![0u8; 64];

        let report = StateNoveltyReport {
            interesting: true,
            new_transition_hashes: vec![1, 65],
            new_slot_hashes: vec![2],
            new_read_hashes: vec![3],
            new_call_edge_hashes: vec![4],
            new_contracts: vec![Address::repeat_byte(0x99)],
            state_hash: 10,
            write_set_hash: 11,
            read_set_hash: 12,
            call_graph_hash: 13,
        };

        reward_state_novelty(&mut coverage, &report);

        assert!(coverage.iter().any(|hit| *hit > 0));
        assert_eq!(coverage.iter().filter(|hit| **hit > 0).count(), 5);
    }

    #[test]
    fn campaign_score_projection_rewards_reserved_coverage_slots() {
        let mut coverage = vec![0u8; 128];

        let score = CampaignScore {
            total: 1000,
            economic_pressure: 600,
            invariant_pressure: 0,
            counterexample_pressure: 0,
            oracle_pressure: 350,
            state_pressure: 20,
            exploration_pressure: 30,
            explanation: vec!["test".to_string()],
        };

        reward_campaign_score(&mut coverage, &score);

        assert!(coverage.iter().any(|hit| *hit > 0));
        assert!(coverage.iter().filter(|hit| **hit > 0).count() >= 4);
    }

    #[test]
    fn telemetry_distinguishes_mutations_from_seed_replays() {
        let telemetry = CampaignTelemetry::new();
        telemetry.record_execution(ExecutionTelemetryRecord {
            core_id: 0,
            tx_count: 1,
            findings: 0,
            campaign_score: 0,
            corpus_size: 1,
            coverage_edges: 0,
            state_novelty_score: 0,
            mutation_strategies: &["seed_or_imported".to_string()],
        });
        telemetry.record_execution(ExecutionTelemetryRecord {
            core_id: 0,
            tx_count: 1,
            findings: 0,
            campaign_score: 0,
            corpus_size: 1,
            coverage_edges: 0,
            state_novelty_score: 0,
            mutation_strategies: &["abi_word_mutation".to_string()],
        });

        assert_eq!(telemetry.executions(), 2);
        assert_eq!(telemetry.seed_replays(), 1);
        assert_eq!(telemetry.mutated_inputs(), 1);
    }

    #[test]
    fn campaign_cores_respects_libafl_env_alias() {
        std::env::set_var("LIBAFL_CORES", "0-1");
        std::env::remove_var("RUSTYFUZZ_CORES");
        let cores = campaign_cores(None).unwrap();
        assert_eq!(cores.cmdline, "0-1");
        assert_eq!(cores.ids.len(), 2);
        std::env::remove_var("LIBAFL_CORES");
    }

    #[test]
    fn execution_timeout_uses_safe_default_and_env_override() {
        std::env::remove_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS");
        assert_eq!(campaign_execution_timeout(), DEFAULT_EXECUTION_TIMEOUT);
        std::env::set_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS", "7");
        assert_eq!(campaign_execution_timeout(), Duration::from_secs(7));
        std::env::remove_var("RUSTYFUZZ_EXEC_TIMEOUT_SECS");
    }

    #[test]
    fn required_seed_marker_requires_an_admitted_execution() {
        let report_dir =
            std::env::temp_dir().join(format!("rustyfuzz-required-marker-{}", std::process::id()));
        let _ = fs::remove_dir_all(&report_dir);
        fs::create_dir_all(&report_dir).unwrap();
        let budget = CampaignBudget::new(Some(0), Some(1), 1);
        assert!(budget.exhausted());
        let input = EvmInput::new(
            vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                is_victim: false,
            }],
            0,
        );
        write_required_seed_replay_marker(report_dir.to_str().unwrap(), &input, false).unwrap();
        assert!(!Path::new(&report_dir)
            .join("required_seed_replay.json")
            .exists());
        write_required_seed_replay_marker(report_dir.to_str().unwrap(), &input, true).unwrap();
        assert!(Path::new(&report_dir)
            .join("required_seed_replay.json")
            .is_file());
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[cfg(unix)]
    #[test]
    fn campaign_paths_reject_symlinked_parents() {
        use std::os::unix::fs::symlink;

        let temp = std::env::temp_dir().join(format!(
            "rustyfuzz-campaign-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&temp).unwrap();
        let outside = temp.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, temp.join("linked")).unwrap();
        let linked = temp.join("linked");
        let config = Config {
            rpc_url: "https://rpc.example.com".to_string(),
            fork_block: 1,
            target_contract: None,
            corpus_dir: linked.join("corpus").to_string_lossy().into_owned(),
            report_dir: linked.join("reports").to_string_lossy().into_owned(),
            foundry_harness: None,
            mainnet_seed_bundle: None,
            in_memory_bytecode: None,
            cores: None,
            require_seed_bundle: false,
            require_rpc_fork: false,
            allow_synthetic_fallback: true,
            hardened_defi: HardenedDefiConfig::default(),
            target_invariant_manifest: None,
            abi_path: None,
            max_execs: Some(1),
            duration_secs: Some(1),
            artifact_limit: None,
            campaign_id: Some("test".to_string()),
            paths_are_isolated: true,
            min_finding_confidence: 0,
            promotion: PromotionConfig::default(),
        };
        assert!(config.ensure_state_isolation().is_err());
        assert!(!outside.join("corpus").exists());
        assert!(!outside.join("reports").exists());

        let input = EvmInput::new(
            vec![SingletonTx {
                input: vec![0xde, 0xad],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                is_victim: false,
            }],
            0,
        );
        assert!(write_required_seed_replay_marker(
            linked.join("campaign").to_str().unwrap(),
            &input,
            true,
        )
        .is_err());
        assert!(!outside.join("campaign/required_seed_replay.json").exists());
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn campaign_budget_reserves_shutdown_grace_for_duration_runs() {
        std::env::set_var("RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS", "2");
        let budget = CampaignBudget::new(None, Some(1), 1);
        assert!(budget.exhausted());
        std::env::remove_var("RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS");
    }

    #[test]
    fn broker_fallback_is_limited_to_startup_unavailability() {
        assert!(broker_launcher_error_was_shutdown("Shutting down!"));
        assert!(!broker_launcher_error_can_fallback("Shutting down!"));
        assert!(broker_launcher_error_can_fallback(
            "Failed to bind to port 1337: address already in use"
        ));
        assert!(broker_launcher_error_can_fallback(
            "could not connect to broker: connection refused"
        ));
        for message in [
            "worker runtime panicked",
            "promotion failed while worker was running",
            "required pre-fuzz sequence execution failed",
            "unknown launcher failure",
        ] {
            assert!(!broker_launcher_error_can_fallback(message), "{message}");
        }
    }

    #[test]
    fn rpc_fork_requirement_is_opt_in() {
        std::env::remove_var("RUSTYFUZZ_REQUIRE_RPC_FORK");
        assert!(!campaign_requires_rpc_fork());
        std::env::set_var("RUSTYFUZZ_REQUIRE_RPC_FORK", "1");
        assert!(campaign_requires_rpc_fork());
        std::env::set_var("RUSTYFUZZ_REQUIRE_RPC_FORK", "false");
        assert!(!campaign_requires_rpc_fork());
        std::env::remove_var("RUSTYFUZZ_REQUIRE_RPC_FORK");
    }

    #[test]
    fn rpc_url_sanitization_removes_credentials_and_path() {
        assert_eq!(
            sanitize_rpc_host("https://user:secret@example.com/path?token=hidden"),
            "example.com"
        );
        assert_eq!(sanitize_rpc_host("not a url"), "<invalid-rpc-url>");
    }

    #[test]
    fn required_seed_bundle_status_aborts_missing_bundle() {
        let status = SeedBundleStatus::Missing {
            bundle_id: "bundle".to_string(),
            path: std::path::PathBuf::from("corpus/mainnet_seeds/bundle/manifest.json"),
        };

        assert!(log_seed_bundle_status(&status, false, true).is_ok());
        assert!(log_seed_bundle_status(&status, false, false).is_ok());
        assert!(log_seed_bundle_status(&status, true, false).is_err());
    }

    #[test]
    fn bytecode_profile_overrides_weak_erc20_seed_profile_without_abi() {
        use crate::engine::bytecode_analysis::{
            BytecodeRiskFlag, FunctionSliceSummary, ProxyPattern, SymbolicBytecodeSummary,
        };
        use std::collections::BTreeMap;

        let seed_profile = TargetProfile {
            protocol_types: vec![ProtocolType::Erc20Token],
            confidence: 95,
            ..Default::default()
        };

        let bytecode_profile = TargetProfile {
            protocol_types: vec![
                ProtocolType::ProxyUpgradeable,
                ProtocolType::AccessControlHeavy,
                ProtocolType::AccountingHeavy,
            ],
            confidence: 88,
            recommended_invariant_families: vec![
                "access-control".to_string(),
                "generic-accounting".to_string(),
            ],
            ..Default::default()
        };

        let report = BytecodeAnalysisReport {
            code_len: 32,
            push4_selectors: Vec::new(),
            dispatch_selectors: Vec::new(),
            function_summaries: Vec::<FunctionSliceSummary>::new(),
            known_selectors: Vec::new(),
            proxy_patterns: vec![ProxyPattern::Eip1967ImplementationSlot],
            risk_flags: vec![BytecodeRiskFlag::HasSstore],
            storage_slots: Vec::new(),
            symbolic_summary: SymbolicBytecodeSummary::default(),
            opcode_counts: BTreeMap::new(),
            target_profile: bytecode_profile,
            explanation: Vec::new(),
        };

        let merged = merge_bytecode_profile(seed_profile, Some(&report), false);
        assert!(!merged.protocol_types.contains(&ProtocolType::Erc20Token));
        assert!(merged
            .protocol_types
            .contains(&ProtocolType::ProxyUpgradeable));
        assert!(merged
            .protocol_types
            .contains(&ProtocolType::AccessControlHeavy));
        assert!(merged
            .recommended_invariant_families
            .contains(&"access-control".to_string()));
    }
}
