use crate::common::oracle::ProtocolOraclePack;
use crate::common::types::{
    ChainState, EvmInput, ExecutionStatus, SequenceExecutionResult, SingletonTx,
};
use crate::config::HardenedDefiConfig;
use crate::engine::actors::{ActorModel, ActorModelConfig, ActorSet};
use crate::engine::bounded_search::{
    BoundedSearchBounds, BoundedSearchEngine, BoundedSearchRequest,
};
use crate::engine::dependency::generate_flow_template_inputs;
use crate::engine::economic_delta::EconomicDeltaEngine;
use crate::engine::exploit_path::ExploitPathBuilder;
use crate::engine::foundry_ingest::FoundryHarnessManifest;
use crate::engine::protocol_model::CounterexampleSearchEngine;
use crate::engine::scheduler::RustyFuzzScheduler;
use crate::engine::scoring::{CampaignScore, CampaignScorer};
use crate::engine::seed_intelligence::{SeedCandidate, SeedIntelligence, SeedIntelligenceConfig};
use crate::engine::target_profile::{ProtocolType, TargetProfiler};
use crate::evm::corpus::{CampaignArtifactRequest, PersistentCorpus, SnapshotCorpus};
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::executor::EvmExecutor;
use crate::evm::feedback::{EvmCoverageFeedback, EvmStateNoveltyFeedback, StateNoveltyReport};
use crate::evm::fork_db::ForkDb;
use crate::evm::fuzz::{AbiRegistry, EvmMutator};
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::snapshot::new_evm_snapshot;

use libafl::corpus::{Corpus, Testcase};
use libafl::events::NopEventManager;
use libafl::state::HasCorpus;
use parking_lot::{Mutex, RwLock};
use revm::database::CacheDB;
use revm::primitives::{Address, U256};
use revm::state::AccountInfo;
use std::cell::UnsafeCell;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

// Sync wrapper for UnsafeCell to allow thread-safe static usage.
struct SyncUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T: Send> Sync for SyncUnsafeCell<T> {}

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

struct CampaignTelemetry {
    start: Instant,
    executions: AtomicU64,
    artifacts: AtomicU64,
    oracle_findings: AtomicU64,
    last_report: Mutex<(Instant, u64)>,
}

impl CampaignTelemetry {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            executions: AtomicU64::new(0),
            artifacts: AtomicU64::new(0),
            oracle_findings: AtomicU64::new(0),
            last_report: Mutex::new((now, 0)),
        }
    }

    fn record_execution(
        &self,
        core_id: usize,
        tx_count: usize,
        findings: usize,
        campaign_score: u64,
    ) {
        let total = self.executions.fetch_add(1, Ordering::Relaxed) + 1;
        if findings > 0 {
            self.oracle_findings
                .fetch_add(findings as u64, Ordering::Relaxed);
        }

        let now = Instant::now();
        let mut last = self.last_report.lock();
        let elapsed = now.duration_since(last.0);
        if elapsed < CAMPAIGN_TELEMETRY_INTERVAL {
            return;
        }

        let delta_execs = total.saturating_sub(last.1);
        let interval_execs_per_sec = delta_execs as f64 / elapsed.as_secs_f64().max(0.001);
        let total_execs_per_sec =
            total as f64 / now.duration_since(self.start).as_secs_f64().max(0.001);
        log::info!(
            "RustyFuzz telemetry: core={}, execs={}, exec_sec_30s={:.3}, exec_sec_avg={:.3}, artifacts={}, oracle_findings={}, txs_last={}, score_last={}",
            core_id,
            total,
            interval_execs_per_sec,
            total_execs_per_sec,
            self.artifacts.load(Ordering::Relaxed),
            self.oracle_findings.load(Ordering::Relaxed),
            tx_count,
            campaign_score
        );
        *last = (now, total);
    }

    fn record_artifact(&self) {
        self.artifacts.fetch_add(1, Ordering::Relaxed);
    }
}

// LibAFL 0.15.4 imports.
use libafl::events::ClientDescription;
use libafl::prelude::{
    EventConfig, ExitKind, Fuzzer, InMemoryCorpus, InProcessExecutor, Launcher, SimpleMonitor,
    StdFuzzer, StdMapObserver, StdMutationalStage, StdState,
};
use libafl_bolts::prelude::*;
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl_bolts::tuples::tuple_list;

const MAP_SIZE: usize = 65_536;
const STATE_NOVELTY_MAP_SLOTS: usize = 2_048;
const CAMPAIGN_SCORE_MAP_SLOTS: usize = 1_024;
const CAMPAIGN_TELEMETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Config {
    pub rpc_url: String,
    pub fork_block: u64,
    pub target_contract: Option<Address>,
    pub corpus_dir: String,
    pub report_dir: String,
    pub foundry_harness: Option<FoundryHarnessManifest>,
    pub mainnet_seed_bundle: Option<String>,
    pub hardened_defi: HardenedDefiConfig,
}

pub async fn run_fuzz_campaign(config: Config) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let start_time = Instant::now();

    let monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });

    let shmem_provider = StdShMemProvider::new()?;

    log::info!("Initializing RustyFuzz v0.15.4 Campaign...");

    let (mut initial_db, initial_env) = {
        let db = match crate::evm::fork::create_fork_db(
            &config.rpc_url,
            config.fork_block,
            config.target_contract,
        )
        .await
        {
            Ok(db) => db,
            Err(err) => {
                log::warn!(
                    "RPC-backed fork DB unavailable for target {:?}; falling back to offline synthetic fork: {}",
                    config.target_contract,
                    err
                );
                crate::evm::fork::create_offline_fallback_fork_db(config.target_contract)
            }
        };

        let env = match crate::evm::fork::create_fork_block_env(&config.rpc_url, config.fork_block)
            .await
        {
            Ok(env) => env,
            Err(err) => {
                log::warn!(
                    "RPC-backed fork block env unavailable for block {}; falling back to offline synthetic env: {}",
                    config.fork_block,
                    err
                );
                crate::evm::fork::create_offline_fallback_block_env(config.fork_block)
            }
        };

        (db, env)
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

    let launcher_fallback_config = config.clone();
    let launcher_fallback_db = initial_db.clone();
    let launcher_fallback_env = initial_env.clone();
    let launcher_fallback_actor_set = hardened_actor_set.clone();

    if config.hardened_defi.single_process {
        return run_single_process_campaign(
            launcher_fallback_config,
            launcher_fallback_db,
            launcher_fallback_env,
            launcher_fallback_actor_set,
        )
        .await;
    }

    let launcher_result = Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .configuration(EventConfig::AlwaysUnique)
        .run_client(
            |state: Option<StdState<_, _, _, _>>, mut manager, description: ClientDescription| {
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
                initial_snapshot_corpus.add_snapshot(0, 0, new_evm_snapshot(0, initial_db.clone()));
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
                let pending_campaign_score = Arc::new(RwLock::new(None));
                let campaign_scorer = Arc::new(CampaignScorer::default());
                let protocol_oracles = Arc::new(ProtocolOraclePack::default());
                let evm_executor = Arc::new(EvmExecutor::new());
                let account_registry = Arc::new(RwLock::new(initial_registry));

                let mut initial_abi = AbiRegistry::default();
                account_registry.read().auto_populate_abi(&mut initial_abi);

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
                let has_trusted_abi_source = config.foundry_harness.is_some();
                let mut hardened_seed_candidates = Vec::<SeedCandidate>::new();
                if has_trusted_abi_source {
                    hardened_seed_candidates.extend(seed_intelligence.generate_candidates(
                        target_contract,
                        fuzzer_address,
                        &initial_abi,
                        config.foundry_harness.as_ref(),
                    ));
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

                let core_id = description.core_id();

                let mut feedback = EvmCoverageFeedback::new();
                let mut objective = ();

                let mut state = state.unwrap_or_else(|| {
                    StdState::new(
                        StdRand::with_seed(campaign_rng_seed(&config, core_id.0 as usize)),
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
                        match persistent_corpus.load_mainnet_seed_bundle(bundle_id) {
                            Ok(bundle) if bundle.target == target_contract => {
                                for seed in bundle.seeds {
                                    state.corpus_mut().add(Testcase::new(seed.input))?;
                                    inserted_seed_count += 1;
                                }
                                if inserted_seed_count == 0 {
                                    log::warn!(
                                        "Mainnet seed bundle `{}` matched target {} but contained no seeds; using synthetic seed",
                                        bundle_id,
                                        target_contract
                                    );
                                } else {
                                    log::info!(
                                        "Loaded mainnet seed bundle `{}` into campaign corpus: {} seeds",
                                        bundle_id,
                                        inserted_seed_count
                                    );
                                }
                            }
                            Ok(bundle) => {
                                log::warn!(
                                    "Ignoring mainnet seed bundle `{}` for target {}; campaign target is {}",
                                    bundle_id,
                                    bundle.target,
                                    target_contract
                                );
                            }
                            Err(err) => {
                                log::warn!(
                                    "Failed to load mainnet seed bundle `{}` from `{}`: {err:#}",
                                    bundle_id,
                                    config.corpus_dir
                                );
                            }
                        }
                    }

                    if !hardened_seed_candidates.is_empty() {
                        for seed in hardened_seed_candidates.clone() {
                            state.corpus_mut().add(Testcase::new(seed.into_evm_input(0)))?;
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
                                for mut template in template_inputs {
                                    if let Some(actor_set) = hardened_actor_set.as_ref() {
                                        actor_set.apply_roles_to_sequence(&mut template.txs);
                                    }
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
                            state
                                .corpus_mut()
                                .add(Testcase::new(seed.into_evm_input(0)))?;
                            inserted_seed_count += 1;
                        }
                        if inserted_seed_count > 0 {
                            log::info!(
                                "Initialized campaign corpus with {} seed inputs including trusted ABI/Foundry seed intelligence",
                                inserted_seed_count
                            );
                        }
                    } else {
                        log::info!(
                            "No trusted ABI/Foundry seed source configured; starting from synthetic seed and preserving generic ABI registry for mutations"
                        );
                    }

                    if inserted_seed_count == 0 {
                        state
                            .corpus_mut()
                            .add(Testcase::new(seed_input(target_contract, fuzzer_address)))?;
                    }
                }

                let mutator = EvmMutator::new(abi_registry, account_registry.clone());
                let mut stages = tuple_list!(StdMutationalStage::new(mutator),);

                let mut fuzzer = StdFuzzer::new(
                    RustyFuzzScheduler::with_pending_score(pending_campaign_score.clone()),
                    feedback,
                    objective,
                );

                static COVERAGE_MAP: SyncUnsafeCell<[u8; MAP_SIZE]> =
                    SyncUnsafeCell(UnsafeCell::new([0u8; MAP_SIZE]));

                let observer = unsafe {
                    StdMapObserver::from_mut_ptr(
                        "edges",
                        (COVERAGE_MAP.0).get() as *mut u8,
                        MAP_SIZE,
                    )
                };

                let mut harness = |input: &EvmInput| {
                    let snap_id = input.base_snapshot_id;
                    let snapshot_corpus_guard = snapshot_corpus.read();

                    let Some(base_snap_arc) = snapshot_corpus_guard.get_snapshot(snap_id) else {
                        log::error!("Input references missing snapshot id {}", snap_id);
                        return ExitKind::Crash;
                    };

                    let mut current_state = base_snap_arc.read().state.read().clone();

                    let base_fork_state = match &current_state {
                        ChainState::Evm(db) => db.clone(),
                    };

                    let mut current_env = initial_env.clone();
                    let mut tx_results = Vec::with_capacity(input.txs.len());

                    for (tx_idx, tx) in input.txs.iter().enumerate() {
                        let mut waypoints = Vec::new();
                        let mut df = dataflow_registry.write();

                        let exec_result = unsafe {
                            let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                            let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);

                            evm_executor.execute_with_result(
                                &mut current_state,
                                &mut current_env,
                                tx,
                                map_slice,
                                &mut df,
                                &mut waypoints,
                                tx_idx,
                            )
                        };

                        let result = match exec_result {
                            Ok(result) => result,
                            Err(err) => {
                                log::error!("EVM execution failed for tx {}: {err:#}", tx_idx);
                                return ExitKind::Crash;
                            }
                        };

                        tx_results.push(result);
                    }

                    let execution = sequence_result_from_tx_results(tx_results);

                    let report = state_novelty_feedback
                        .write()
                        .observe_execution(&execution);

                    let findings = protocol_oracles.evaluate(&execution);

                    let mut campaign_score =
                        campaign_scorer.score(input, &execution, &report, &findings);
                    if config.hardened_defi.enabled && config.hardened_defi.enable_economic_delta {
                        let economic_delta = EconomicDeltaEngine::from_execution(input, &execution);
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
                    telemetry.record_execution(
                        core_id.0,
                        input.txs.len(),
                        findings.len(),
                        campaign_score.total,
                    );

                    if report.interesting {
                        unsafe {
                            let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                            let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
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
                        unsafe {
                            let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                            let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
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

                    if let Some(reason) =
                        campaign_artifact_reason(
                            &execution,
                            &report,
                            &campaign_score,
                            &findings,
                            exploit_candidate.as_ref(),
                        )
                    {
                        let persisted = unsafe {
                            let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                            let map_slice = std::slice::from_raw_parts(map_ptr, MAP_SIZE);

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
                                    log::info!(
                                        "Persisted campaign artifact: input_id={}, fork_cache_id={}, reason={}, score={}, findings={}",
                                        outcome.record.input_id,
                                        outcome.record.fork_cache_id,
                                        outcome.record.reason,
                                        outcome.record.score.total,
                                        outcome.record.findings.len()
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

                let mut executor = InProcessExecutor::new(
                    &mut harness,
                    tuple_list!(observer),
                    &mut fuzzer,
                    &mut state,
                    &mut manager,
                )?;

                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;

                Ok(())
            },
        )
        .cores(&Cores::from_cmdline("all")?)
        .build()
        .launch();

    match launcher_result {
        Ok(_) => Ok(()),
        Err(err) => {
            log::warn!(
                "brokered fuzz launcher unavailable; falling back to broker-free single-process mode: {}",
                err
            );
            run_single_process_campaign(
                launcher_fallback_config,
                launcher_fallback_db,
                launcher_fallback_env,
                launcher_fallback_actor_set,
            )
            .await
        }
    }
}

async fn run_single_process_campaign(
    config: Config,
    initial_db: CacheDB<ForkDb>,
    initial_env: revm::context::BlockEnv,
    hardened_actor_set: Option<ActorSet>,
) -> anyhow::Result<()> {
    let start_time = Instant::now();
    let _monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });
    let mut manager = NopEventManager::new();

    let mut initial_registry = GlobalAccountRegistry::default();
    initial_registry.discover_from_state(&ChainState::Evm(initial_db.clone()));

    let target_contract = choose_target_contract(config.target_contract, &initial_registry)
        .ok_or_else(|| anyhow::anyhow!("cannot start EVM campaign without a target contract"))?;

    let mut initial_snapshot_corpus = SnapshotCorpus::new();
    initial_snapshot_corpus.add_snapshot(0, 0, new_evm_snapshot(0, initial_db.clone()));
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
    let pending_campaign_score = Arc::new(RwLock::new(None));
    let campaign_scorer = Arc::new(CampaignScorer::default());
    let protocol_oracles = Arc::new(ProtocolOraclePack::default());
    let evm_executor = Arc::new(EvmExecutor::new());
    let account_registry = Arc::new(RwLock::new(initial_registry));

    let mut initial_abi = AbiRegistry::default();
    account_registry.read().auto_populate_abi(&mut initial_abi);

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
    let has_trusted_abi_source = config.foundry_harness.is_some();
    let mut hardened_seed_candidates = Vec::<SeedCandidate>::new();
    if has_trusted_abi_source {
        hardened_seed_candidates.extend(seed_intelligence.generate_candidates(
            target_contract,
            Address::repeat_byte(0x13),
            &initial_abi,
            config.foundry_harness.as_ref(),
        ));
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

    if state.corpus().count() == 0 {
        let mut inserted_seed_count = 0usize;
        if let Some(bundle_id) = &config.mainnet_seed_bundle {
            match persistent_corpus.load_mainnet_seed_bundle(bundle_id) {
                Ok(bundle) if bundle.target == target_contract => {
                    for seed in bundle.seeds {
                        state.corpus_mut().add(Testcase::new(seed.input))?;
                        inserted_seed_count += 1;
                    }
                    if inserted_seed_count == 0 {
                        log::warn!(
                            "Mainnet seed bundle `{}` matched target {} but contained no seeds; using synthetic seed",
                            bundle_id,
                            target_contract
                        );
                    } else {
                        log::info!(
                            "Loaded mainnet seed bundle `{}` into campaign corpus: {} seeds",
                            bundle_id,
                            inserted_seed_count
                        );
                    }
                }
                Ok(bundle) => {
                    log::warn!(
                        "Ignoring mainnet seed bundle `{}` for target {}; campaign target is {}",
                        bundle_id,
                        bundle.target,
                        target_contract
                    );
                }
                Err(err) => {
                    log::warn!(
                        "Failed to load mainnet seed bundle `{}` from `{}`: {err:#}",
                        bundle_id,
                        config.corpus_dir
                    );
                }
            }
        }

        if !hardened_seed_candidates.is_empty() {
            for seed in hardened_seed_candidates.clone() {
                state
                    .corpus_mut()
                    .add(Testcase::new(seed.into_evm_input(0)))?;
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
                    for mut template in template_inputs {
                        if let Some(actor_set) = hardened_actor_set.as_ref() {
                            actor_set.apply_roles_to_sequence(&mut template.txs);
                        }
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
                state
                    .corpus_mut()
                    .add(Testcase::new(seed.into_evm_input(0)))?;
                inserted_seed_count += 1;
            }
            if inserted_seed_count > 0 {
                log::info!(
                    "Initialized campaign corpus with {} seed inputs including trusted ABI/Foundry seed intelligence",
                    inserted_seed_count
                );
            }
        } else {
            log::info!(
                "No trusted ABI/Foundry seed source configured; starting from synthetic seed and preserving generic ABI registry for mutations"
            );
        }

        if inserted_seed_count == 0 {
            state.corpus_mut().add(Testcase::new(seed_input(
                target_contract,
                Address::repeat_byte(0x13),
            )))?;
        }
    }

    let mutator = EvmMutator::new(abi_registry, account_registry.clone());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator),);
    let mut fuzzer = StdFuzzer::new(
        RustyFuzzScheduler::with_pending_score(pending_campaign_score.clone()),
        feedback,
        objective,
    );

    static COVERAGE_MAP: SyncUnsafeCell<[u8; MAP_SIZE]> =
        SyncUnsafeCell(UnsafeCell::new([0u8; MAP_SIZE]));
    let observer = unsafe {
        StdMapObserver::from_mut_ptr("edges", (COVERAGE_MAP.0).get() as *mut u8, MAP_SIZE)
    };

    let mut harness = |input: &EvmInput| {
        let snap_id = input.base_snapshot_id;
        let snapshot_corpus_guard = snapshot_corpus.read();
        let Some(base_snap_arc) = snapshot_corpus_guard.get_snapshot(snap_id) else {
            log::error!("Input references missing snapshot id {}", snap_id);
            return ExitKind::Crash;
        };

        let mut current_state = base_snap_arc.read().state.read().clone();
        let base_fork_state = match &current_state {
            ChainState::Evm(db) => db.clone(),
        };
        let mut current_env = initial_env.clone();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            let mut waypoints = Vec::new();
            let mut df = dataflow_registry.write();
            let exec_result = unsafe {
                let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
                evm_executor.execute_with_result(
                    &mut current_state,
                    &mut current_env,
                    tx,
                    map_slice,
                    &mut df,
                    &mut waypoints,
                    tx_idx,
                )
            };

            let result = match exec_result {
                Ok(result) => result,
                Err(err) => {
                    log::error!("EVM execution failed for tx {}: {err:#}", tx_idx);
                    return ExitKind::Crash;
                }
            };
            tx_results.push(result);
        }

        let execution = sequence_result_from_tx_results(tx_results);
        let report = state_novelty_feedback.write().observe_execution(&execution);
        let findings = protocol_oracles.evaluate(&execution);

        let mut campaign_score = campaign_scorer.score(input, &execution, &report, &findings);
        if config.hardened_defi.enabled && config.hardened_defi.enable_economic_delta {
            let economic_delta = EconomicDeltaEngine::from_execution(input, &execution);
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
        telemetry.record_execution(
            core_id,
            input.txs.len(),
            findings.len(),
            campaign_score.total,
        );

        if report.interesting {
            unsafe {
                let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
                reward_state_novelty(map_slice, &report);
            }
        }

        if campaign_score.is_interesting() {
            unsafe {
                let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
                reward_campaign_score(map_slice, &campaign_score);
            }
        }

        if let Some(reason) = campaign_artifact_reason(
            &execution,
            &report,
            &campaign_score,
            &findings,
            exploit_candidate.as_ref(),
        ) {
            let persisted = unsafe {
                let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                let map_slice = std::slice::from_raw_parts(map_ptr, MAP_SIZE);
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
                        log::info!(
                            "Persisted campaign artifact: input_id={}, fork_cache_id={}, reason={}, score={}, findings={}",
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

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut manager,
    )?;

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;

    Ok(())
}

fn campaign_artifact_reason(
    execution: &SequenceExecutionResult,
    state_report: &StateNoveltyReport,
    campaign_score: &CampaignScore,
    findings: &[crate::common::oracle::ProtocolFinding],
    exploit_candidate: Option<&crate::engine::exploit_path::ExploitPathCandidate>,
) -> Option<&'static str> {
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
    EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller: fuzzer_address,
            to: target_contract,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
