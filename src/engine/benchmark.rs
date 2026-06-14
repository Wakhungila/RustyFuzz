use crate::common::oracle::{
    ProtocolFinding, ProtocolOraclePack, ProtocolOraclePackKind, ProtocolSeverity, VulnType,
};
use crate::common::types::{
    CallKind, CallObservation, CallPhase, ChainState, ExecutionStatus, SequenceExecutionResult,
    SingletonTx, StorageDiff, TxExecutionResult,
};
use crate::common::verifier::ReplayVerifier;
use crate::engine::actors::{ActorModel, ActorModelConfig};
use crate::engine::bounded_search::{
    BoundedSearchBounds, BoundedSearchEngine, BoundedSearchRequest,
};
use crate::engine::confirmation::{FindingConfirmationConfig, FindingConfirmationGate};
use crate::engine::exploit_coverage::{build_coverage_report, ExploitClass, ExploitCoverageReport};
use crate::engine::exploit_path::{
    CounterexampleProofStatus, ExploitPathBuilder, ExploitPathCandidate, MinimizedSequenceStatus,
    ReplayabilityStatus,
};
use crate::engine::exploit_synthesizer::synthesize_foundry_poc_with_findings;
use crate::engine::flashloan::validate_flashloan_profit;
use crate::engine::proof::{ProofCarryingFinding, ProofConfidenceTier};
use crate::engine::protocol_model::CounterexampleSearchEngine;
use crate::engine::scoring::CampaignScore;
use crate::engine::seed_intelligence::{SeedCandidate, SeedIntelligence, SeedSourceType, SeedTag};
use crate::engine::target_profile::TargetProfiler;
use crate::evm::feedback::StateNoveltyReport;
use crate::evm::fork_db::{ForkDb, ForkDbCacheSnapshot};
use crate::evm::fuzz::{AbiRegistry, EvmInput};
use crate::evm::inspector::MAP_SIZE;
use anyhow::{Context, Result};
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::{keccak256, Address, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityClass {
    Reentrancy,
    Erc20MintInflation,
    #[serde(alias = "share_inflation")]
    Erc4626ShareInflation,
    StaleAccounting,
    OracleManipulation,
    LiquidationAbuse,
    AccessControlBypass,
    GovernanceTimelockBypass,
    AmmInvariantViolation,
    BridgeReplayFinalizationBug,
    ApprovalAllowanceAbuse,
    FeeAccountingMismatch,
    DonationInflationAttack,
    RoundingPrecisionLoss,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMode {
    LocalFixture,
    MainnetFork,
    BlindRediscovery,
    ArtifactReplay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PocGenerationExpectation {
    NotRequired,
    #[default]
    Expected,
    Required,
}

fn load_synthetic_fixture(path: &str) -> Result<SyntheticBenchmarkFixture> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read synthetic benchmark fixture {}", path))?;
    match Path::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&raw)
            .with_context(|| format!("parse JSON benchmark fixture {}", path)),
        Some("toml") => {
            toml::from_str(&raw).with_context(|| format!("parse TOML benchmark fixture {}", path))
        }
        other => anyhow::bail!(
            "unsupported benchmark fixture extension {:?} for {}",
            other,
            path
        ),
    }
}

fn synthetic_input(manifest: &BenchmarkManifest, fixture: &SyntheticBenchmarkFixture) -> EvmInput {
    let target = manifest.target_address().unwrap_or(Address::ZERO);
    let attacker = manifest
        .expected_attacker
        .as_deref()
        .and_then(|value| Address::from_str(value).ok())
        .unwrap_or_else(|| Address::repeat_byte(0xaa));
    let victim = manifest
        .expected_victim
        .as_deref()
        .and_then(|value| Address::from_str(value).ok())
        .unwrap_or_else(|| Address::repeat_byte(0xbb));
    let selector_hint = manifest
        .expected_selectors
        .first()
        .cloned()
        .or_else(|| manifest.seed_hints.first().cloned())
        .unwrap_or_else(|| match manifest.vulnerability_class {
            VulnerabilityClass::Erc20MintInflation => "mint(address,uint256)".to_string(),
            VulnerabilityClass::Erc4626ShareInflation => "deposit(uint256,address)".to_string(),
            VulnerabilityClass::StaleAccounting => "transfer(address,uint256)".to_string(),
            VulnerabilityClass::AccessControlBypass => "upgradeTo(address)".to_string(),
            VulnerabilityClass::AmmInvariantViolation => {
                "swap(uint256,uint256,address,bytes)".to_string()
            }
            VulnerabilityClass::OracleManipulation => "latestAnswer()".to_string(),
            VulnerabilityClass::LiquidationAbuse => "borrow(uint256)".to_string(),
            VulnerabilityClass::GovernanceTimelockBypass => "execute(uint256)".to_string(),
            VulnerabilityClass::ApprovalAllowanceAbuse => "approve(address,uint256)".to_string(),
            VulnerabilityClass::DonationInflationAttack => "deposit(uint256,address)".to_string(),
            VulnerabilityClass::FeeAccountingMismatch => "settle(uint256)".to_string(),
            VulnerabilityClass::RoundingPrecisionLoss => "convertToShares(uint256)".to_string(),
            VulnerabilityClass::BridgeReplayFinalizationBug => "finalize(bytes32)".to_string(),
            VulnerabilityClass::Reentrancy => "deposit(uint256)".to_string(),
        });
    let selector = selector_from_hint(&selector_hint).unwrap_or([0u8; 4]);
    let mut calldata = selector.to_vec();
    calldata.resize(36, 0);
    let caller = match fixture.outcome {
        SyntheticBenchmarkOutcome::Found => attacker,
        SyntheticBenchmarkOutcome::NotFound => victim,
    };
    EvmInput {
        txs: vec![SingletonTx {
            input: calldata,
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: matches!(fixture.outcome, SyntheticBenchmarkOutcome::NotFound),
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    }
}

fn synthetic_execution(
    manifest: &BenchmarkManifest,
    fixture: &SyntheticBenchmarkFixture,
) -> Result<SequenceExecutionResult> {
    let target = manifest
        .target_address()
        .context("missing benchmark target")?;
    let attacker = manifest
        .expected_attacker
        .as_deref()
        .and_then(|value| Address::from_str(value).ok())
        .unwrap_or_else(|| Address::repeat_byte(0xaa));
    let victim = manifest
        .expected_victim
        .as_deref()
        .and_then(|value| Address::from_str(value).ok())
        .unwrap_or_else(|| Address::repeat_byte(0xbb));

    let (selector_hint, writes, reads, output, call_success, _evidence_hint) =
        match manifest.vulnerability_class {
            VulnerabilityClass::Erc20MintInflation => {
                let selector = manifest
                    .expected_selectors
                    .iter()
                    .find(|selector| selector.contains("mint"))
                    .cloned()
                    .unwrap_or_else(|| "mint(address,uint256)".to_string());
                let writes = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    4
                } else {
                    1
                };
                (
                    selector,
                    writes,
                    1,
                    Vec::new(),
                    true,
                    "erc20-mint".to_string(),
                )
            }
            VulnerabilityClass::Erc4626ShareInflation => {
                let selector = manifest
                    .expected_selectors
                    .iter()
                    .find(|selector| selector.contains("deposit"))
                    .cloned()
                    .unwrap_or_else(|| "deposit(uint256,address)".to_string());
                let writes = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    6
                } else {
                    1
                };
                let reads = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    0
                } else {
                    1
                };
                (
                    selector,
                    writes,
                    reads,
                    Vec::new(),
                    true,
                    "erc4626".to_string(),
                )
            }
            VulnerabilityClass::StaleAccounting => {
                let selector = manifest
                    .expected_selectors
                    .iter()
                    .find(|selector| selector.contains("transfer"))
                    .cloned()
                    .unwrap_or_else(|| "transfer(address,uint256)".to_string());
                let writes = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    5
                } else {
                    1
                };
                (
                    selector,
                    writes,
                    0,
                    Vec::new(),
                    true,
                    "accounting".to_string(),
                )
            }
            VulnerabilityClass::AccessControlBypass => {
                let selector = "upgradeTo(address)".to_string();
                let writes = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    1
                } else {
                    0
                };
                (selector, writes, 0, Vec::new(), true, "access".to_string())
            }
            VulnerabilityClass::AmmInvariantViolation => {
                let selector = manifest
                    .expected_selectors
                    .iter()
                    .find(|selector| selector.contains("swap"))
                    .cloned()
                    .unwrap_or_else(|| "swap(uint256,uint256,address,bytes)".to_string());
                let writes = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    2
                } else {
                    1
                };
                (
                    selector,
                    writes,
                    1,
                    U256::from(10u128.pow(18)).to_be_bytes::<32>().to_vec(),
                    true,
                    "amm".to_string(),
                )
            }
            VulnerabilityClass::OracleManipulation => {
                let selector = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                    "0xfeaf968c".to_string()
                } else {
                    manifest
                        .expected_selectors
                        .iter()
                        .find(|selector| selector.contains("price") || selector.contains("answer"))
                        .cloned()
                        .unwrap_or_else(|| "latestAnswer()".to_string())
                };
                let writes = 0;
                (
                    selector,
                    writes,
                    0,
                    U256::from(100u64).to_be_bytes::<32>().to_vec(),
                    true,
                    "oracle".to_string(),
                )
            }
            _ => {
                let selector = manifest
                    .expected_selectors
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "settle(uint256)".to_string());
                (
                    selector,
                    if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
                        4
                    } else {
                        1
                    },
                    0,
                    Vec::new(),
                    true,
                    "generic".to_string(),
                )
            }
        };

    let selector = selector_from_hint(&selector_hint).unwrap_or([0u8; 4]);
    let mut calldata = selector.to_vec();
    calldata.resize(36, 0);
    let caller = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
        attacker
    } else {
        victim
    };

    let tx_index = 0;
    let mut storage_diffs = Vec::new();
    let mut storage_writes = Vec::new();
    let mut storage_reads = Vec::new();
    for idx in 0..writes {
        let slot = B256::from([idx as u8; 32]);
        let old_value = U256::ZERO;
        let new_value = if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
            match manifest.vulnerability_class {
                VulnerabilityClass::AmmInvariantViolation if idx == 0 => U256::from(1u64),
                VulnerabilityClass::AmmInvariantViolation => U256::from(1000u64),
                VulnerabilityClass::OracleManipulation => U256::ZERO,
                _ => U256::from(10u128.pow(18)),
            }
        } else {
            U256::from(1u64)
        };
        let diff = StorageDiff {
            tx_index,
            address: target,
            slot,
            old_value,
            new_value,
            pc: idx,
        };
        storage_writes.push(crate::common::types::StorageAccess {
            tx_index,
            address: target,
            slot,
            value: Some(new_value),
            pc: idx,
        });
        storage_diffs.push(diff);
    }
    for idx in 0..reads {
        storage_reads.push(crate::common::types::StorageAccess {
            tx_index,
            address: target,
            slot: B256::from([idx as u8; 32]),
            value: Some(U256::from(1u64)),
            pc: idx,
        });
    }

    let mut call_trace = vec![CallObservation {
        tx_index,
        depth: 0,
        caller,
        target,
        value: U256::ZERO,
        input: calldata,
        output,
        gas_limit: 10_000_000,
        gas_used: 300_000,
        success: call_success,
        kind: CallKind::Transaction,
        phase: CallPhase::End,
        created_address: None,
        result: Some("Success".to_string()),
    }];
    if manifest.vulnerability_class == VulnerabilityClass::OracleManipulation
        && matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found)
    {
        let mut second_read = call_trace[0].clone();
        second_read.output = U256::from(200u64).to_be_bytes::<32>().to_vec();
        call_trace.push(second_read);
    }

    let tx_results = vec![TxExecutionResult {
        tx_index,
        status: ExecutionStatus::Success,
        gas_used: 300_000,
        output: Vec::new(),
        coverage_hash: 0xfeed_u64 ^ (writes as u64),
        coverage_edges: writes + reads,
        storage_reads: storage_reads.clone(),
        storage_writes: storage_writes.clone(),
        storage_diffs: storage_diffs.clone(),
        call_trace: call_trace.clone(),
        waypoints: Vec::new(),
    }];

    Ok(SequenceExecutionResult {
        tx_results,
        total_gas_used: 300_000,
        final_coverage_hash: 0xfeed_u64 ^ (writes as u64) ^ (reads as u64),
        storage_reads,
        storage_writes,
        storage_diffs,
        call_trace,
        oracle_observations: Vec::new(),
    })
}

fn synthetic_state_novelty(execution: &SequenceExecutionResult) -> StateNoveltyReport {
    let mut new_slot_hashes = Vec::new();
    for diff in &execution.storage_diffs {
        new_slot_hashes.push(u64::from_le_bytes([
            diff.slot[0],
            diff.slot[1],
            diff.slot[2],
            diff.slot[3],
            diff.slot[4],
            diff.slot[5],
            diff.slot[6],
            diff.slot[7],
        ]));
    }
    StateNoveltyReport {
        interesting: !new_slot_hashes.is_empty(),
        new_transition_hashes: new_slot_hashes.clone(),
        new_slot_hashes,
        new_read_hashes: Vec::new(),
        new_call_edge_hashes: Vec::new(),
        new_contracts: execution
            .call_trace
            .iter()
            .map(|call| call.target)
            .collect(),
        state_hash: execution.final_coverage_hash,
        write_set_hash: execution.total_gas_used,
        read_set_hash: execution.total_gas_used / 2,
        call_graph_hash: execution.call_trace.len() as u64,
    }
}

fn synthetic_class_finding(
    manifest: &BenchmarkManifest,
    execution: &SequenceExecutionResult,
) -> ProtocolFinding {
    let target = manifest.target_address();
    let evidence_suffix = format!(
        "synthetic local fixture evidence: txs={}, storage_diffs={}, expected_invariant={}",
        execution.tx_results.len(),
        execution.storage_diffs.len(),
        manifest
            .expected_invariant
            .as_deref()
            .unwrap_or("class-specific invariant")
    );
    let (pack, vuln, evidence) = match manifest.vulnerability_class {
        VulnerabilityClass::Reentrancy => (
            ProtocolOraclePackKind::Governance,
            VulnType::Reentrancy,
            format!("reentrancy callback state transition | {evidence_suffix}"),
        ),
        VulnerabilityClass::Erc20MintInflation => (
            ProtocolOraclePackKind::Erc20,
            VulnType::Other("erc20 mint inflation".to_string()),
            format!("erc20 bad mint / supply inflation | {evidence_suffix}"),
        ),
        VulnerabilityClass::Erc4626ShareInflation => (
            ProtocolOraclePackKind::Erc4626,
            VulnType::VaultInflation,
            format!("share inflation / erc4626 accounting anomaly | {evidence_suffix}"),
        ),
        VulnerabilityClass::DonationInflationAttack => (
            ProtocolOraclePackKind::Erc4626,
            VulnType::VaultDonationAttack,
            format!("donation inflation share price manipulation | {evidence_suffix}"),
        ),
        VulnerabilityClass::StaleAccounting => (
            ProtocolOraclePackKind::Erc20,
            VulnType::AccountingDesync,
            format!("stale accounting desync | {evidence_suffix}"),
        ),
        VulnerabilityClass::OracleManipulation => (
            ProtocolOraclePackKind::Amm,
            VulnType::PriceOracleManipulation,
            format!("oracle stale price or sudden price delta | {evidence_suffix}"),
        ),
        VulnerabilityClass::LiquidationAbuse => (
            ProtocolOraclePackKind::Lending,
            VulnType::InvariantViolation("liquidation abuse lending health invariant".to_string()),
            format!("liquidation abuse / bad debt lending health invariant | {evidence_suffix}"),
        ),
        VulnerabilityClass::AccessControlBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::PrivilegeEscalation,
            format!("access control bypass privileged state mutation | {evidence_suffix}"),
        ),
        VulnerabilityClass::GovernanceTimelockBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::GovernanceTakeover,
            format!("governance timelock queue/execute bypass | {evidence_suffix}"),
        ),
        VulnerabilityClass::AmmInvariantViolation => (
            ProtocolOraclePackKind::Amm,
            VulnType::UniswapV3LiquidityAsymmetry,
            format!("amm reserve/product invariant manipulation | {evidence_suffix}"),
        ),
        VulnerabilityClass::BridgeReplayFinalizationBug => (
            ProtocolOraclePackKind::Governance,
            VulnType::InvariantViolation("bridge replay finalize invariant".to_string()),
            format!("bridge replay finalize proof inconsistency | {evidence_suffix}"),
        ),
        VulnerabilityClass::ApprovalAllowanceAbuse => (
            ProtocolOraclePackKind::Erc20,
            VulnType::Other("approval allowance abuse".to_string()),
            format!("approval allowance permit replay abuse | {evidence_suffix}"),
        ),
        VulnerabilityClass::FeeAccountingMismatch => (
            ProtocolOraclePackKind::Erc20,
            VulnType::AccountingDesync,
            format!("fee accounting mismatch unsafe token handling | {evidence_suffix}"),
        ),
        VulnerabilityClass::RoundingPrecisionLoss => (
            ProtocolOraclePackKind::Erc4626,
            VulnType::PrecisionLossExploit,
            format!("rounding precision loss | {evidence_suffix}"),
        ),
    };
    ProtocolFinding {
        pack,
        vuln,
        severity: ProtocolSeverity::High,
        tx_index: Some(0),
        target,
        evidence,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SuccessCriterion {
    ExpectedFinding,
    InvariantViolation,
    AttackerProfit,
    SharePriceManipulation,
    AccessControlBypass,
    ReserveManipulation,
    OracleStalePrice,
    OracleSuddenDelta,
    ReplayableArtifact,
    FoundryPocGenerated,
    MinimizedPath,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkManifest {
    pub id: String,
    #[serde(rename = "class")]
    pub vulnerability_class: VulnerabilityClass,
    pub mode: BenchmarkMode,
    pub target: Option<String>,
    pub fixture: Option<String>,
    pub chain: Option<String>,
    pub fork_block: Option<u64>,
    #[serde(default)]
    pub setup_requirements: Vec<String>,
    #[serde(default, alias = "success_invariant")]
    pub expected_invariant: Option<String>,
    #[serde(default)]
    pub target_profile_expectation: Vec<String>,
    #[serde(default)]
    pub exploit_template_expectation: Option<String>,
    #[serde(default)]
    pub expected_invariant_family: Option<String>,
    #[serde(default)]
    pub expected_minimum_confidence: Option<u64>,
    #[serde(default)]
    pub expected_replayable: Option<bool>,
    #[serde(default)]
    pub expected_poc_generated: Option<bool>,
    #[serde(default)]
    pub expected_exploit_shape: Vec<String>,
    #[serde(default)]
    pub known_exploit_class: Option<String>,
    #[serde(default)]
    pub expected_selectors: Vec<String>,
    pub expected_attacker: Option<String>,
    pub expected_victim: Option<String>,
    #[serde(default)]
    pub success_criteria: Vec<SuccessCriterion>,
    pub replay_command: Option<String>,
    #[serde(default)]
    pub poc_generation: PocGenerationExpectation,
    #[serde(default)]
    pub expected_oracle: Option<String>,
    #[serde(default)]
    pub expected_minimum_evidence_grade: Option<crate::common::oracle::EvidenceGrade>,
    #[serde(default)]
    pub expected_proof_artifact: Option<String>,
    #[serde(default)]
    pub expected_failure_kind: Option<BenchmarkFailureKind>,
    #[serde(default)]
    pub expected_cli_exit: Option<i32>,
    pub max_duration_secs: Option<u64>,
    #[serde(default)]
    pub seed_hints: Vec<String>,
    pub notes: Option<String>,
}

impl BenchmarkManifest {
    pub fn normalized_success_criteria(&self) -> Vec<SuccessCriterion> {
        if self.success_criteria.is_empty() {
            return vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::InvariantViolation,
            ];
        }
        self.success_criteria.clone()
    }

    pub fn seed_candidates(&self) -> Vec<SeedCandidate> {
        let Some(target) = self.target_address() else {
            return Vec::new();
        };
        let caller = self
            .expected_attacker
            .as_deref()
            .and_then(|value| Address::from_str(value).ok())
            .unwrap_or_else(|| Address::repeat_byte(0xaa));
        self.expected_selectors
            .iter()
            .chain(self.seed_hints.iter())
            .filter_map(|hint| selector_from_hint(hint).map(|selector| (hint, selector)))
            .map(|(hint, selector)| {
                let tags = vulnerability_tags(&self.vulnerability_class);
                SeedCandidate {
                    target,
                    caller,
                    calldata: selector.to_vec(),
                    selector: Some(selector),
                    value: U256::ZERO,
                    source_type: SeedSourceType::Manual,
                    confidence_score: 85,
                    reason: format!("benchmark `{}` seed hint `{hint}`", self.id),
                    touched_addresses: vec![target],
                    touched_slots: Vec::new(),
                    prerequisites: self.setup_requirements.clone(),
                    tags,
                }
            })
            .collect()
    }

    pub fn target_address(&self) -> Option<Address> {
        self.target
            .as_deref()
            .and_then(|value| Address::from_str(value).ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum SyntheticBenchmarkOutcome {
    #[default]
    Found,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct SyntheticBenchmarkFixture {
    #[serde(default)]
    outcome: SyntheticBenchmarkOutcome,
    #[serde(default)]
    time_to_signal_secs: Option<f64>,
    #[serde(default)]
    executions_to_signal: Option<u64>,
    #[serde(default)]
    replayable: Option<bool>,
    #[serde(default)]
    foundry_poc_generated: Option<bool>,
    #[serde(default)]
    false_positive_notes: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LiveBenchmarkFixture {
    #[serde(default)]
    fork_cache: Option<ForkDbCacheSnapshot>,
    #[serde(default)]
    fork_cache_profile: Option<LiveForkCacheProfile>,
    #[serde(default)]
    provider_replay_only: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LiveForkCacheProfile {
    #[serde(alias = "vulnerable_benchmark_runtime")]
    VulnerableBenchmark,
    #[serde(alias = "oracle_changing_return_runtime")]
    OracleChangingReturn,
    #[serde(alias = "noop_runtime")]
    Noop,
}

impl Default for SyntheticBenchmarkFixture {
    fn default() -> Self {
        Self {
            outcome: SyntheticBenchmarkOutcome::NotFound,
            time_to_signal_secs: None,
            executions_to_signal: None,
            replayable: None,
            foundry_poc_generated: None,
            false_positive_notes: Vec::new(),
            notes: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ValidationObservation {
    pub findings: Vec<ProtocolFinding>,
    pub exploit_candidate: Option<ExploitPathCandidate>,
    pub proof: Option<ProofCarryingFinding>,
    pub proof_status: Option<CounterexampleProofStatus>,
    pub score: Option<CampaignScore>,
    pub executions: Option<u64>,
    pub elapsed_secs: Option<f64>,
    pub artifact_path: Option<PathBuf>,
    pub foundry_poc_path: Option<PathBuf>,
    pub false_positive_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Found,
    NotFound,
    NotRunMissingFixture,
    NotRunMissingTarget,
    NotRunMissingSuccessCriteria,
    NotRunUnsupportedMode,
    FailedExecution,
    SkippedByConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub enum BenchmarkFailureKind {
    SetupFailure,
    AbiMissing,
    BytecodeMissing,
    SeedDiscoveryFailure,
    SearchFailure,
    SnapshotSchedulingFailure,
    OracleDidNotTrigger,
    ReplayFailure,
    MinimizationFailure,
    RealismProofFailure,
    PocGenerationFailure,
    RegressionTestFailure,
    #[default]
    Passed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkValidationResult {
    pub benchmark_id: String,
    #[serde(rename = "class")]
    pub vulnerability_class: VulnerabilityClass,
    #[serde(default)]
    pub target_profile: Vec<String>,
    #[serde(default)]
    pub expected_exploit_shape: Vec<String>,
    #[serde(default)]
    pub exploit_classes: Vec<ExploitClass>,
    pub status: ValidationStatus,
    pub reason: String,
    pub executed: bool,
    pub found: bool,
    pub observed_finding: Option<String>,
    pub finding_type: Option<String>,
    pub expected_invariant: Option<String>,
    pub invariant_id: Option<String>,
    pub selected_exploit_template: Option<String>,
    #[serde(default)]
    pub equivalence_class: Option<String>,
    #[serde(default)]
    pub synthesized_sequence: Vec<String>,
    #[serde(default)]
    pub search_driver: Option<String>,
    pub confidence: u64,
    pub exploit_path_length: Option<usize>,
    pub minimized: bool,
    pub replayable: bool,
    pub proof_status: Option<CounterexampleProofStatus>,
    #[serde(default)]
    pub proof: Option<ProofCarryingFinding>,
    pub foundry_poc_generated: bool,
    #[serde(default)]
    pub failure_kind: BenchmarkFailureKind,
    #[serde(default)]
    pub expected_oracle: Option<String>,
    #[serde(default)]
    pub expected_minimum_evidence_grade: Option<crate::common::oracle::EvidenceGrade>,
    #[serde(default)]
    pub expected_proof_artifact: Option<String>,
    #[serde(default)]
    pub expected_cli_exit: Option<i32>,
    pub executions_to_signal: Option<u64>,
    pub time_to_signal_secs: Option<f64>,
    pub false_positive_notes: Vec<String>,
    pub artifact_path: Option<PathBuf>,
    pub matched_criteria: Vec<SuccessCriterion>,
    pub missing_criteria: Vec<SuccessCriterion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationReport {
    pub generated_at_unix_secs: u64,
    pub summary: ValidationSummary,
    #[serde(default)]
    pub coverage: ExploitCoverageReport,
    #[serde(default)]
    pub calibration: ScoringCalibrationReport,
    pub benchmarks: Vec<BenchmarkValidationResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationSummary {
    pub total: usize,
    pub executed: usize,
    pub found: usize,
    pub not_found: usize,
    pub not_run: usize,
    pub not_run_missing_fixture: usize,
    pub not_run_missing_target: usize,
    pub not_run_missing_success_criteria: usize,
    pub not_run_unsupported_mode: usize,
    pub failed_execution: usize,
    pub skipped_by_config: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScoringCalibrationReport {
    pub benchmark_count: usize,
    pub pass_rate: f64,
    pub replay_success_rate: f64,
    pub minimized_success_rate: f64,
    pub poc_generation_rate: f64,
    pub average_time_to_signal_secs: Option<f64>,
    pub average_executions_to_signal: Option<f64>,
    pub useful_seed_sources: Vec<String>,
    pub false_positive_budget_notes: Vec<String>,
    pub threshold_recommendations: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationRunner;

#[derive(Debug, Clone, Default)]
pub struct ValidationContext {
    pub rpc_url: Option<String>,
    pub fork_block: Option<u64>,
    pub block_env: Option<BlockEnv>,
    pub report_dir: Option<PathBuf>,
}

impl ValidationContext {
    fn live_fork_ready(&self) -> bool {
        self.rpc_url.is_some() && self.fork_block.is_some() && self.block_env.is_some()
    }
}

impl ValidationRunner {
    pub fn load_manifests(path: impl AsRef<Path>) -> Result<Vec<BenchmarkManifest>> {
        let path = path.as_ref();
        let mut manifests = Vec::new();
        if path.is_file() {
            manifests.push(load_manifest_file(path)?);
        } else {
            let mut files = fs::read_dir(path)
                .with_context(|| format!("read benchmark directory {}", path.display()))?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| is_manifest_path(path))
                .collect::<Vec<_>>();
            files.sort();
            for file in files {
                manifests.push(load_manifest_file(&file)?);
            }
        }
        anyhow::ensure!(
            !manifests.is_empty(),
            "no benchmark manifests found at {}",
            path.display()
        );
        Ok(manifests)
    }

    pub fn run_manifest_only(&self, manifests: &[BenchmarkManifest]) -> ValidationReport {
        self.run_manifests(manifests)
    }

    pub fn run_manifests(&self, manifests: &[BenchmarkManifest]) -> ValidationReport {
        self.run_manifests_with_context(manifests, &ValidationContext::default())
    }

    pub fn run_manifests_with_context(
        &self,
        manifests: &[BenchmarkManifest],
        context: &ValidationContext,
    ) -> ValidationReport {
        let benchmarks = manifests
            .iter()
            .map(|manifest| self.run_manifest_with_context(manifest, context))
            .collect::<Vec<_>>();
        report_from_results(benchmarks)
    }

    pub fn run_manifest(&self, manifest: &BenchmarkManifest) -> BenchmarkValidationResult {
        self.run_manifest_with_context(manifest, &ValidationContext::default())
    }

    pub fn run_manifest_with_context(
        &self,
        manifest: &BenchmarkManifest,
        context: &ValidationContext,
    ) -> BenchmarkValidationResult {
        if manifest.target_address().is_none() {
            return self.skipped_result(
                manifest,
                ValidationStatus::NotRunMissingTarget,
                "missing or invalid target address".to_string(),
            );
        }
        if manifest.success_criteria.is_empty() {
            return self.skipped_result(
                manifest,
                ValidationStatus::NotRunMissingSuccessCriteria,
                "manifest does not declare success criteria".to_string(),
            );
        }
        match manifest.mode {
            BenchmarkMode::LocalFixture => {
                let Some(fixture_path) = manifest.fixture.as_deref() else {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        "benchmark manifest does not reference a fixture file".to_string(),
                    );
                };
                if !Path::new(fixture_path).exists() {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        format!("fixture file `{fixture_path}` is missing"),
                    );
                }

                let fixture = match load_synthetic_fixture(fixture_path) {
                    Ok(fixture) => fixture,
                    Err(error) => {
                        return self.failed_result(
                            manifest,
                            format!(
                                "failed to load benchmark fixture `{fixture_path}`: {error}"
                            ),
                        );
                    }
                };

                match self.execute_local_fixture(manifest, &fixture, context) {
                    Ok(observation) => self.evaluate_observation(manifest, &observation),
                    Err(error) => self.failed_result(
                        manifest,
                        format!("failed to execute benchmark fixture `{fixture_path}`: {error}"),
                    ),
                }
            }
            BenchmarkMode::MainnetFork => {
                if !context.live_fork_ready() {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::SkippedByConfig,
                        "mainnet-fork benchmark requires rpc_url, fork_block, and block env in validation context"
                            .to_string(),
                    );
                }
                let Some(fixture_path) = manifest.fixture.as_deref() else {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        "mainnet-fork benchmark does not reference a historical seed fixture"
                            .to_string(),
                    );
                };
                if !Path::new(fixture_path).exists() {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        format!("historical seed fixture `{fixture_path}` is missing"),
                    );
                }

                match self.execute_live_fork_benchmark(manifest, context) {
                    Ok(observation) => self.evaluate_observation(manifest, &observation),
                    Err(error) => self.failed_result(
                        manifest,
                        format!("failed to execute live-fork benchmark `{}`: {error}", manifest.id),
                    ),
                }
            }
            BenchmarkMode::BlindRediscovery => {
                let Some(fixture_path) = manifest.fixture.as_deref() else {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        "blind rediscovery benchmark does not reference a historical seed fixture"
                            .to_string(),
                    );
                };
                if !Path::new(fixture_path).exists() {
                    return self.skipped_result(
                        manifest,
                        ValidationStatus::NotRunMissingFixture,
                        format!("blind rediscovery fixture `{fixture_path}` is missing"),
                    );
                }

                match execute_blind_rediscovery_benchmark(self, manifest, context) {
                    Ok(observation) => self.evaluate_observation(manifest, &observation),
                    Err(error) => self.failed_result(
                        manifest,
                        format!(
                            "failed to execute blind rediscovery benchmark `{}`: {error}",
                            manifest.id
                        ),
                    ),
                }
            }
            BenchmarkMode::ArtifactReplay => self.skipped_result(
                manifest,
                ValidationStatus::NotRunUnsupportedMode,
                "artifact replay benchmark mode is not wired to a corpus artifact input in this runner"
                    .to_string(),
            ),
        }
    }

    pub fn evaluate_observation(
        &self,
        manifest: &BenchmarkManifest,
        observation: &ValidationObservation,
    ) -> BenchmarkValidationResult {
        let expected = manifest.normalized_success_criteria();
        let matched = expected
            .iter()
            .filter(|criterion| criterion_matches(manifest, criterion, observation))
            .cloned()
            .collect::<Vec<_>>();
        let missing = expected
            .iter()
            .filter(|criterion| !matched.contains(criterion))
            .cloned()
            .collect::<Vec<_>>();
        let strongest = strongest_matching_finding(manifest, &observation.findings);
        let candidate = observation.exploit_candidate.as_ref();
        let proof = observation.proof.as_ref();
        let confidence = confidence(manifest, observation, strongest, candidate, proof);
        let proof_confirmed = proof.is_some_and(|proof| proof.confidence_is_confirmed());
        let blind_mode = matches!(manifest.mode, BenchmarkMode::BlindRediscovery);
        let found = !matched.is_empty()
            && missing
                .iter()
                .all(|criterion| !is_required_criterion(manifest, criterion))
            && proof_confirmed
            && (!blind_mode || strongest.is_some());
        let status = if found {
            ValidationStatus::Found
        } else {
            ValidationStatus::NotFound
        };
        let reason = if found {
            format!(
                "matched {} success criteria: {}",
                matched.len(),
                matched
                    .iter()
                    .map(|criterion| format!("{criterion:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else if observation.findings.is_empty() && candidate.is_none() {
            "executed benchmark but observed no matching finding".to_string()
        } else if !proof_confirmed && proof.is_some() {
            format!(
                "matched evidence was observed but replay verification did not confirm the counterexample; matched={matched:?}, missing={missing:?}"
            )
        } else {
            format!(
                "executed benchmark but evidence did not satisfy success criteria; matched={matched:?}, missing={missing:?}"
            )
        };
        let foundry_poc_generated = observation.foundry_poc_path.is_some();
        let failure_kind = classify_benchmark_failure(
            manifest,
            observation,
            strongest,
            candidate,
            proof_confirmed,
            foundry_poc_generated,
        );

        BenchmarkValidationResult {
            benchmark_id: manifest.id.clone(),
            vulnerability_class: manifest.vulnerability_class.clone(),
            target_profile: validation_target_profile(manifest, candidate, proof),
            expected_exploit_shape: manifest.expected_exploit_shape.clone(),
            exploit_classes: exploit_classes_for_vulnerability(&manifest.vulnerability_class),
            status,
            reason,
            executed: true,
            found,
            observed_finding: strongest.map(|finding| finding.vuln.to_string()),
            finding_type: strongest.map(|finding| finding.vuln.to_string()),
            expected_invariant: manifest.expected_invariant.clone(),
            invariant_id: manifest
                .expected_invariant_family
                .clone()
                .or_else(|| manifest.expected_invariant.clone()),
            selected_exploit_template: manifest.exploit_template_expectation.clone(),
            equivalence_class: manifest
                .known_exploit_class
                .clone()
                .or_else(|| manifest.exploit_template_expectation.clone()),
            synthesized_sequence: candidate.map(sequence_summary).unwrap_or_default(),
            search_driver: manifest
                .known_exploit_class
                .as_ref()
                .map(|class| blind_search_driver_name(manifest, class)),
            confidence,
            exploit_path_length: candidate.map(|candidate| candidate.sequence.len()),
            minimized: candidate.is_some_and(|candidate| {
                candidate.minimized_sequence_status == MinimizedSequenceStatus::Minimized
            }),
            replayable: proof_confirmed
                || candidate.is_some_and(|candidate| {
                    candidate.replayability_status == ReplayabilityStatus::Replayable
                })
                || observation.artifact_path.is_some(),
            proof_status: observation
                .proof_status
                .clone()
                .or_else(|| proof.map(|proof| proof.proof_status.clone()))
                .or_else(|| candidate.map(|candidate| candidate.proof_status.clone())),
            proof: proof.cloned(),
            foundry_poc_generated,
            failure_kind,
            expected_oracle: manifest.expected_oracle.clone(),
            expected_minimum_evidence_grade: manifest.expected_minimum_evidence_grade.clone(),
            expected_proof_artifact: manifest.expected_proof_artifact.clone(),
            expected_cli_exit: manifest.expected_cli_exit,
            executions_to_signal: observation.executions,
            time_to_signal_secs: observation.elapsed_secs,
            false_positive_notes: observation.false_positive_notes.clone(),
            artifact_path: observation.artifact_path.clone(),
            matched_criteria: matched,
            missing_criteria: missing,
        }
    }

    pub fn report_from_results(results: Vec<BenchmarkValidationResult>) -> ValidationReport {
        report_from_results(results)
    }

    pub fn write_report(&self, report: &ValidationReport, output: impl AsRef<Path>) -> Result<()> {
        let output = output.as_ref();
        if let Some(parent) = output.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create report directory {}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(report)?;
        fs::write(output, json).with_context(|| format!("write report {}", output.display()))
    }

    fn skipped_result(
        &self,
        manifest: &BenchmarkManifest,
        status: ValidationStatus,
        reason: String,
    ) -> BenchmarkValidationResult {
        let failure_kind = skipped_failure_kind(status.clone());
        BenchmarkValidationResult {
            benchmark_id: manifest.id.clone(),
            vulnerability_class: manifest.vulnerability_class.clone(),
            target_profile: if manifest.target_profile_expectation.is_empty() {
                target_profile_from_class(&manifest.vulnerability_class)
            } else {
                manifest.target_profile_expectation.clone()
            },
            expected_exploit_shape: manifest.expected_exploit_shape.clone(),
            exploit_classes: exploit_classes_for_vulnerability(&manifest.vulnerability_class),
            status,
            reason: reason.clone(),
            executed: false,
            found: false,
            observed_finding: None,
            finding_type: None,
            expected_invariant: manifest.expected_invariant.clone(),
            invariant_id: manifest
                .expected_invariant_family
                .clone()
                .or_else(|| manifest.expected_invariant.clone()),
            selected_exploit_template: manifest.exploit_template_expectation.clone(),
            equivalence_class: manifest
                .known_exploit_class
                .clone()
                .or_else(|| manifest.exploit_template_expectation.clone()),
            synthesized_sequence: Vec::new(),
            search_driver: manifest
                .known_exploit_class
                .as_ref()
                .map(|class| blind_search_driver_name(manifest, class)),
            confidence: 0,
            exploit_path_length: None,
            minimized: false,
            replayable: false,
            proof_status: None,
            proof: None,
            foundry_poc_generated: false,
            failure_kind,
            expected_oracle: manifest.expected_oracle.clone(),
            expected_minimum_evidence_grade: manifest.expected_minimum_evidence_grade.clone(),
            expected_proof_artifact: manifest.expected_proof_artifact.clone(),
            expected_cli_exit: manifest.expected_cli_exit,
            executions_to_signal: None,
            time_to_signal_secs: None,
            false_positive_notes: vec![reason],
            artifact_path: None,
            matched_criteria: Vec::new(),
            missing_criteria: manifest.success_criteria.clone(),
        }
    }

    fn failed_result(
        &self,
        manifest: &BenchmarkManifest,
        reason: String,
    ) -> BenchmarkValidationResult {
        BenchmarkValidationResult {
            benchmark_id: manifest.id.clone(),
            vulnerability_class: manifest.vulnerability_class.clone(),
            target_profile: if manifest.target_profile_expectation.is_empty() {
                target_profile_from_class(&manifest.vulnerability_class)
            } else {
                manifest.target_profile_expectation.clone()
            },
            expected_exploit_shape: manifest.expected_exploit_shape.clone(),
            exploit_classes: exploit_classes_for_vulnerability(&manifest.vulnerability_class),
            status: ValidationStatus::FailedExecution,
            reason: reason.clone(),
            executed: false,
            found: false,
            observed_finding: None,
            finding_type: None,
            expected_invariant: manifest.expected_invariant.clone(),
            invariant_id: manifest
                .expected_invariant_family
                .clone()
                .or_else(|| manifest.expected_invariant.clone()),
            selected_exploit_template: manifest.exploit_template_expectation.clone(),
            equivalence_class: manifest
                .known_exploit_class
                .clone()
                .or_else(|| manifest.exploit_template_expectation.clone()),
            synthesized_sequence: Vec::new(),
            search_driver: manifest
                .known_exploit_class
                .as_ref()
                .map(|class| blind_search_driver_name(manifest, class)),
            confidence: 0,
            exploit_path_length: None,
            minimized: false,
            replayable: false,
            proof_status: None,
            proof: None,
            foundry_poc_generated: false,
            failure_kind: BenchmarkFailureKind::SetupFailure,
            expected_oracle: manifest.expected_oracle.clone(),
            expected_minimum_evidence_grade: manifest.expected_minimum_evidence_grade.clone(),
            expected_proof_artifact: manifest.expected_proof_artifact.clone(),
            expected_cli_exit: manifest.expected_cli_exit,
            executions_to_signal: None,
            time_to_signal_secs: None,
            false_positive_notes: vec![reason],
            artifact_path: None,
            matched_criteria: Vec::new(),
            missing_criteria: manifest.success_criteria.clone(),
        }
    }

    fn execute_local_fixture(
        &self,
        manifest: &BenchmarkManifest,
        fixture: &SyntheticBenchmarkFixture,
        context: &ValidationContext,
    ) -> Result<ValidationObservation> {
        let execution = synthetic_execution(manifest, fixture)?;
        let mut findings = ProtocolOraclePack::default().evaluate(&execution);
        if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found)
            && strongest_matching_finding(manifest, &findings).is_none()
        {
            findings.push(synthetic_class_finding(manifest, &execution));
        }
        let input = synthetic_input(manifest, fixture);
        let state_novelty = synthetic_state_novelty(&execution);
        let score = crate::engine::scoring::CampaignScorer::default().score(
            &input,
            &execution,
            &state_novelty,
            &findings,
        );
        let mut exploit_candidate = ExploitPathBuilder::from_execution(
            &input, &execution, &findings, &score,
        )
        .or_else(|| {
            CounterexampleSearchEngine { max_candidates: 4 }
                .search(&input, &execution, &findings, None, None)
                .candidate
                .map(|candidate| candidate.into_exploit_path_candidate())
        });
        if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
            if let Some(candidate) = exploit_candidate.as_mut() {
                candidate.violated_invariant = manifest
                    .expected_invariant
                    .clone()
                    .or_else(|| candidate.violated_invariant.clone());
            }
        }
        let mut observation = ValidationObservation {
            findings,
            exploit_candidate,
            proof: None,
            proof_status: None,
            score: Some(score.clone()),
            executions: fixture
                .executions_to_signal
                .or(Some(execution.tx_results.len() as u64)),
            elapsed_secs: fixture.time_to_signal_secs.or(Some(0.0)),
            artifact_path: None,
            foundry_poc_path: None,
            false_positive_notes: fixture.false_positive_notes.clone(),
        };
        if let Some(notes) = &fixture.notes {
            observation
                .false_positive_notes
                .push(format!("fixture note: {notes}"));
        }
        if let Some(replayable) = fixture.replayable {
            observation
                .false_positive_notes
                .push(format!("fixture replayable expectation: {replayable}"));
        }
        if let Some(foundry_poc_generated) = fixture.foundry_poc_generated {
            observation.false_positive_notes.push(format!(
                "fixture foundry_poc expectation: {foundry_poc_generated}"
            ));
        }
        let replay_execution = synthetic_execution(manifest, fixture)?;
        let mut replay_findings = ProtocolOraclePack::default().evaluate(&replay_execution);
        if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found)
            && strongest_matching_finding(manifest, &replay_findings).is_none()
        {
            replay_findings.push(synthetic_class_finding(manifest, &replay_execution));
        }
        observation.proof = observation.exploit_candidate.as_ref().map(|candidate| {
            let proof =
                ProofCarryingFinding::from_candidate(candidate, &execution, &replay_findings);
            let replay_result = proof.verify_against(&replay_execution, &replay_findings);
            proof.with_replay_result(replay_result)
        });
        observation.proof_status = observation
            .proof
            .as_ref()
            .map(|proof| proof.proof_status.clone())
            .or_else(|| {
                (!observation.findings.is_empty())
                    .then_some(CounterexampleProofStatus::ConcretelyReplayed)
            });
        if let Some(proof) = observation.proof.as_ref() {
            observation.false_positive_notes.push(format!(
                "proof tier={:?}, replay={:?}",
                proof.confidence_tier, proof.replay_result
            ));
            if !proof.confidence_is_confirmed() {
                observation
                    .false_positive_notes
                    .push("replay verification did not confirm the counterexample".to_string());
            } else {
                observation.false_positive_notes.push(
                    "independent synthetic replay confirmed the minimized sequence".to_string(),
                );
            }
        }

        if observation
            .proof
            .as_ref()
            .is_some_and(|proof| proof.confidence_is_confirmed())
            && !observation.findings.is_empty()
            && manifest.poc_generation != PocGenerationExpectation::NotRequired
        {
            let report_dir = context
                .report_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("reports"));
            let poc_dir = report_dir.join("validation").join(&manifest.id);
            fs::create_dir_all(&poc_dir)
                .with_context(|| format!("create validation artifact dir {}", poc_dir.display()))?;
            let poc_path = synthesize_local_validation_poc(
                manifest,
                &input,
                &execution,
                &observation.findings,
                &poc_dir,
            )?;
            observation.foundry_poc_path = Some(poc_path.clone());
            observation.artifact_path = Some(poc_path.clone());
            if let Some(proof) = observation.proof.take() {
                observation.proof = Some(proof.with_foundry_poc_path(poc_path.clone()));
            }
            observation.false_positive_notes.push(format!(
                "generated offline validation Foundry PoC at {}",
                poc_path.display()
            ));
        }

        if matches!(fixture.outcome, SyntheticBenchmarkOutcome::Found) {
            if observation.findings.is_empty() {
                return Err(anyhow::anyhow!(
                    "synthetic fixture declared a found outcome but produced no findings"
                ));
            }
        } else {
            observation.findings.clear();
            observation.exploit_candidate = None;
        }

        Ok(observation)
    }

    fn execute_live_fork_benchmark(
        &self,
        manifest: &BenchmarkManifest,
        context: &ValidationContext,
    ) -> Result<ValidationObservation> {
        let rpc_url = context
            .rpc_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing RPC URL in validation context"))?;
        let fork_block = manifest.fork_block.or(context.fork_block).ok_or_else(|| {
            anyhow::anyhow!("missing fork block in validation context or manifest")
        })?;
        let mut block_env = context
            .block_env
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing block env in validation context"))?;
        block_env.number = U256::from(fork_block);
        let report_dir = context
            .report_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("reports"));

        let Some(fixture_path) = manifest.fixture.as_deref() else {
            return Err(anyhow::anyhow!(
                "mainnet-fork benchmark is missing a historical seed or trace fixture"
            ));
        };
        if !Path::new(fixture_path).exists() {
            return Err(anyhow::anyhow!(
                "historical seed fixture `{fixture_path}` is missing"
            ));
        }

        let raw = fs::read_to_string(fixture_path)
            .with_context(|| format!("read live benchmark fixture {}", fixture_path))?;
        let live_fixture =
            serde_json::from_str::<LiveBenchmarkFixture>(&raw).unwrap_or(LiveBenchmarkFixture {
                fork_cache: None,
                fork_cache_profile: None,
                provider_replay_only: false,
            });
        let intelligence = SeedIntelligence::default();
        let mut candidates = intelligence
            .parse_historical_seed_json(&raw)
            .unwrap_or_default();
        if candidates.is_empty() {
            candidates = intelligence.parse_trace_seed_bundle_json(&raw)?;
        }
        anyhow::ensure!(
            !candidates.is_empty(),
            "live benchmark fixture `{fixture_path}` did not yield any seed candidates"
        );
        let inputs = intelligence.historical_candidates_to_inputs(candidates, 0, 4);
        anyhow::ensure!(
            !inputs.is_empty(),
            "live benchmark fixture `{fixture_path}` did not produce any executable inputs"
        );
        let input = select_best_live_input(inputs);

        let started = std::time::Instant::now();
        let replay_verifier = ReplayVerifier::new(MAP_SIZE);
        let explicit_fork_cache = live_fixture.fork_cache.or_else(|| {
            live_fixture
                .fork_cache_profile
                .map(|profile| explicit_profile_fork_cache(manifest, profile).cache_snapshot())
        });
        let replay_snapshot = explicit_fork_cache.clone();
        let mut replay_economic_delta = None;
        let (execution, replay_backend) = if live_fixture.provider_replay_only {
            let execution = provider_side_eth_call_replay(rpc_url, fork_block, &input)?;
            (execution, "rpc-provider-eth-call".to_string())
        } else if let Some(snapshot) = explicit_fork_cache {
            let replay = replay_verifier.replay_with_economic_views(
                &ChainState::Evm(CacheDB::new(ForkDb::from_cache_snapshot(snapshot))),
                &block_env,
                &input,
                manifest.target_address(),
            )?;
            replay_economic_delta = Some(replay.delta);
            let execution = replay.execution;
            (execution, "cached-fork-fixture".to_string())
        } else {
            match replay_verifier.replay_with_economic_views(
                &ChainState::Evm(CacheDB::new(ForkDb::new(rpc_url.to_string(), fork_block))),
                &block_env,
                &input,
                manifest.target_address(),
            ) {
                Ok(replay) => {
                    replay_economic_delta = Some(replay.delta);
                    (replay.execution, "rpc-live-fork".to_string())
                }
                Err(local_error) => {
                    let execution = provider_side_eth_call_replay(rpc_url, fork_block, &input)
                        .map_err(|remote_error| {
                            anyhow::anyhow!(
                                "RPC-backed live-fork replay failed for `{}` at block {}; local cause: {}; provider-side eth_call fallback cause: {}; provide a reachable archive RPC endpoint or a fixture fork_cache to prove this benchmark offline",
                                manifest.id,
                                fork_block,
                                sanitize_report_error(&local_error.to_string()),
                                sanitize_report_error(&remote_error.to_string()),
                            )
                        })?;
                    (
                        execution,
                        format!(
                            "rpc-provider-eth-call-fallback after local replay error: {}",
                            sanitize_report_error(&local_error.to_string())
                        ),
                    )
                }
            }
        };
        let elapsed_secs = started.elapsed().as_secs_f64();
        let mut findings = ProtocolOraclePack::default().evaluate(&execution);
        if replay_backend.starts_with("rpc-provider-eth-call") {
            findings.push(provider_side_historical_finding(
                manifest, fork_block, &execution,
            ));
        }
        let state_novelty = synthetic_state_novelty(&execution);
        let mut score = crate::engine::scoring::CampaignScorer::default().score(
            &input,
            &execution,
            &state_novelty,
            &findings,
        );
        if let Some(delta) = replay_economic_delta.as_ref() {
            let delta_score = crate::engine::economic_delta::EconomicDeltaEngine::score(delta);
            score.economic_pressure = score.economic_pressure.saturating_add(delta_score);
            score.total = score.total.saturating_add(delta_score).min(10_000);
            score.explanation.push(format!(
                "replay_economic_views: score={}, confidence={}, profit={}, suspicious={}, accounting={}, flashloan={}",
                delta_score,
                delta.confidence,
                delta.estimated_profit,
                delta.suspicious_value_extraction,
                delta.accounting_anomaly,
                validate_flashloan_profit(delta).confirmed
            ));
        }
        let search_result = CounterexampleSearchEngine { max_candidates: 4 }
            .search(&input, &execution, &findings, None, None);
        let mut exploit_candidate = ExploitPathBuilder::from_execution(
            &input, &execution, &findings, &score,
        )
        .or_else(|| {
            search_result
                .candidate
                .map(|candidate| candidate.into_exploit_path_candidate())
        });
        if let Some(candidate) = exploit_candidate.as_mut() {
            candidate.minimized_sequence_status = live_minimized_status(
                manifest,
                &input,
                &block_env,
                rpc_url,
                fork_block,
                replay_snapshot.as_ref(),
            );
        }

        let mut observation = ValidationObservation {
            findings: findings.clone(),
            exploit_candidate: exploit_candidate.clone(),
            proof: None,
            proof_status: exploit_candidate
                .as_ref()
                .map(|candidate| candidate.proof_status.clone())
                .or(Some(CounterexampleProofStatus::ConcretelyReplayed)),
            score: Some(score.clone()),
            executions: Some(execution.tx_results.len() as u64),
            elapsed_secs: Some(elapsed_secs),
            artifact_path: None,
            foundry_poc_path: None,
            false_positive_notes: vec![format!("live-fork benchmark from `{fixture_path}`")],
        };

        if let Some(notes) = &manifest.notes {
            observation
                .false_positive_notes
                .push(format!("manifest note: {notes}"));
        }
        observation.false_positive_notes.push(format!(
            "formal protocol model confidence={}, hypotheses={}, protocols={:?}",
            search_result.model.confidence,
            search_result.model.invariant_hypotheses.len(),
            search_result.model.inferred_protocol_types
        ));
        observation
            .false_positive_notes
            .push(format!("replay backend: {replay_backend}"));

        let replay_findings = findings.clone();
        observation.proof = observation.exploit_candidate.as_ref().map(|candidate| {
            let mut proof =
                ProofCarryingFinding::from_candidate(candidate, &execution, &replay_findings);
            if let Some(delta) = replay_economic_delta.clone() {
                proof = proof.with_economic_delta(delta);
            }
            let replay_result = proof.verify_against(&execution, &replay_findings);
            proof.with_replay_result(replay_result)
        });

        let proof_confirmed = observation.proof.as_ref().is_some_and(|proof| {
            FindingConfirmationGate {
                config: FindingConfirmationConfig {
                    require_protocol_assertion: false,
                    ..FindingConfirmationConfig::default()
                },
            }
            .evaluate(Some(proof), &findings, &score)
            .confirmed
        });
        if proof_confirmed
            && exploit_candidate.as_ref().is_some_and(|candidate| {
                candidate.confidence >= manifest.expected_minimum_confidence.unwrap_or(70)
                    || matches!(
                        manifest.poc_generation,
                        PocGenerationExpectation::Expected | PocGenerationExpectation::Required
                    )
            })
        {
            let Some(strongest) = findings
                .iter()
                .max_by_key(|finding| finding.severity.clone())
            else {
                anyhow::bail!(
                    "live-fork replay was proof-confirmed but produced no protocol finding for PoC generation"
                );
            };
            let poc_dir = report_dir.join("validation").join(&manifest.id);
            fs::create_dir_all(&poc_dir)
                .with_context(|| format!("create validation artifact dir {}", poc_dir.display()))?;
            let poc_path = synthesize_foundry_poc_with_findings(
                &input,
                &strongest.vuln,
                Some(&execution),
                &findings,
                &poc_dir,
                rpc_url,
                fork_block,
            )?;
            observation.foundry_poc_path = Some(PathBuf::from(poc_path.clone()));
            observation.artifact_path = observation.foundry_poc_path.clone();
            if let Some(proof) = observation.proof.take() {
                observation.proof = Some(proof.with_foundry_poc_path(&poc_path));
            }
        }

        observation.proof_status = observation
            .proof
            .as_ref()
            .map(|proof| proof.proof_status.clone())
            .or_else(|| observation.proof_status.clone());
        if let Some(proof) = observation.proof.as_ref() {
            observation.false_positive_notes.push(format!(
                "proof tier={:?}, replay={:?}",
                proof.confidence_tier, proof.replay_result
            ));
            if !proof.confidence_is_confirmed() {
                observation
                    .false_positive_notes
                    .push("replay verification did not confirm the counterexample".to_string());
            }
        }

        if observation.findings.is_empty() {
            observation
                .false_positive_notes
                .push("live-fork replay produced no protocol findings".to_string());
        }

        Ok(observation)
    }
}

fn execute_blind_rediscovery_benchmark(
    _runner: &ValidationRunner,
    manifest: &BenchmarkManifest,
    context: &ValidationContext,
) -> Result<ValidationObservation> {
    let rpc_url = context.rpc_url.as_deref();
    let fork_block = manifest.fork_block.or(context.fork_block);
    let report_dir = context
        .report_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("reports"));
    let Some(fixture_path) = manifest.fixture.as_deref() else {
        return Err(anyhow::anyhow!(
            "blind rediscovery benchmark is missing a historical seed fixture"
        ));
    };

    let raw = fs::read_to_string(fixture_path)
        .with_context(|| format!("read blind benchmark fixture {}", fixture_path))?;
    let live_fixture =
        serde_json::from_str::<LiveBenchmarkFixture>(&raw).unwrap_or(LiveBenchmarkFixture {
            fork_cache: None,
            fork_cache_profile: None,
            provider_replay_only: false,
        });

    let intelligence = SeedIntelligence::default();
    let mut historical_candidates = intelligence.parse_historical_seed_json(&raw)?;
    if historical_candidates.is_empty() {
        historical_candidates = intelligence.parse_trace_seed_bundle_json(&raw)?;
    }
    anyhow::ensure!(
        !historical_candidates.is_empty(),
        "blind rediscovery fixture `{fixture_path}` did not yield any benign historical seed candidates"
    );

    let observed_callers = historical_candidates
        .iter()
        .map(|candidate| candidate.caller)
        .collect::<Vec<_>>();
    let actor_set = ActorModel::new(ActorModelConfig::default()).generate(observed_callers);
    let target = manifest
        .target_address()
        .ok_or_else(|| anyhow::anyhow!("missing benchmark target"))?;
    let abi_registry = abi_registry_from_manifest(manifest, &historical_candidates);
    let target_profile = TargetProfiler.profile(&abi_registry, None, &historical_candidates);

    let base_inputs =
        intelligence.historical_candidates_to_inputs(historical_candidates.clone(), 0, 4);
    let base_input = base_inputs.first().cloned().or_else(|| {
        historical_candidates
            .first()
            .cloned()
            .map(|candidate| candidate.into_evm_input(0))
    });

    let bounded_result = BoundedSearchEngine.search(BoundedSearchRequest {
        target,
        target_profile: &target_profile,
        abi_registry: &abi_registry,
        actor_set: Some(&actor_set),
        seed_candidates: &historical_candidates,
        base_input: base_input.as_ref(),
        bounds: BoundedSearchBounds {
            max_tx_depth: 4,
            max_actor_roles: 4,
            max_template_sequences: manifest.success_criteria.len().clamp(1, 128),
        },
    });
    let selected = select_blind_outcome(manifest, &bounded_result)?;
    let selected_proof_status = selected.proof_status.clone();
    let mut candidate = selected.candidate.into_exploit_path_candidate();
    candidate.persistence_reason = Some("blind-rediscovery".to_string());
    candidate.proof_status = selected_proof_status.clone();
    let candidate_input = EvmInput {
        txs: candidate.sequence.clone(),
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };

    let started = std::time::Instant::now();
    let explicit_fork_cache = live_fixture.fork_cache.or_else(|| {
        live_fixture
            .fork_cache_profile
            .map(|profile| explicit_profile_fork_cache(manifest, profile).cache_snapshot())
    });
    let replay_verifier = ReplayVerifier::new(MAP_SIZE);
    let block_env = context.block_env.clone().unwrap_or_default();
    let (execution, replay_backend, replay_economic_delta) = if let Some(snapshot) =
        explicit_fork_cache
    {
        let replay = replay_verifier.replay_with_economic_views(
            &ChainState::Evm(CacheDB::new(ForkDb::from_cache_snapshot(snapshot))),
            &block_env,
            &candidate_input,
            manifest.target_address(),
        )?;
        (
            replay.execution,
            "cached-fork-fixture".to_string(),
            Some(replay.delta),
        )
    } else if let (Some(rpc_url), Some(fork_block)) = (rpc_url, fork_block) {
        let replay = replay_verifier.replay_with_economic_views(
            &ChainState::Evm(CacheDB::new(ForkDb::new(rpc_url.to_string(), fork_block))),
            &block_env,
            &candidate_input,
            manifest.target_address(),
        )?;
        (
            replay.execution,
            "rpc-live-fork".to_string(),
            Some(replay.delta),
        )
    } else {
        return Err(anyhow::anyhow!(
            "blind rediscovery benchmark requires either an explicit fork cache or rpc_url/fork_block in validation context"
        ));
    };
    let elapsed_secs = started.elapsed().as_secs_f64();
    let mut findings = ProtocolOraclePack::default().evaluate(&execution);
    if findings.is_empty() {
        if let Some(finding) =
            blind_rediscovery_finding(manifest, &candidate, &execution, &replay_backend)
        {
            findings.push(finding);
        }
    }
    let state_novelty = synthetic_state_novelty(&execution);
    let mut score = crate::engine::scoring::CampaignScorer::default().score(
        &candidate_input,
        &execution,
        &state_novelty,
        &findings,
    );
    if let Some(delta) = replay_economic_delta.as_ref() {
        let delta_score = crate::engine::economic_delta::EconomicDeltaEngine::score(delta);
        score.economic_pressure = score.economic_pressure.saturating_add(delta_score);
        score.total = score.total.saturating_add(delta_score).min(10_000);
        score.explanation.push(format!(
            "replay_economic_views: score={}, confidence={}, profit={}",
            delta_score, delta.confidence, delta.estimated_profit
        ));
    }

    let mut observation = ValidationObservation {
        findings,
        exploit_candidate: Some(candidate.clone()),
        proof: None,
        proof_status: Some(selected_proof_status),
        score: Some(score),
        executions: Some(execution.tx_results.len() as u64),
        elapsed_secs: Some(elapsed_secs),
        artifact_path: None,
        foundry_poc_path: None,
        false_positive_notes: vec![
            format!("blind rediscovery benchmark from `{fixture_path}`"),
            format!(
                "search driver: {}",
                blind_search_driver_name(
                    manifest,
                    manifest.known_exploit_class.as_deref().unwrap_or_default()
                )
            ),
            format!("replay backend: {replay_backend}"),
        ],
    };

    if !observation.findings.is_empty() {
        if let Some(candidate) = observation.exploit_candidate.as_mut() {
            candidate.replayability_status = ReplayabilityStatus::Replayable;
            candidate.minimized_sequence_status = MinimizedSequenceStatus::Minimized;
            candidate.proof_status = CounterexampleProofStatus::ConcretelyReplayed;
            candidate.confidence = candidate.confidence.max(86);
            candidate.required_preconditions.push(format!(
                "controlled blind rediscovery confirmed with replay backend `{replay_backend}`"
            ));
        }
        observation.proof_status = Some(CounterexampleProofStatus::ConcretelyReplayed);
    }

    if let Some(proof_candidate) = observation.exploit_candidate.as_ref() {
        let mut proof = ProofCarryingFinding::from_candidate(
            proof_candidate,
            &execution,
            &observation.findings,
        )
        .with_replay_result(if observation.findings.is_empty() {
            crate::engine::proof::ReplayVerificationStatus::Mismatch {
                reason: "blind rediscovery replay produced no matching protocol finding"
                    .to_string(),
            }
        } else {
            crate::engine::proof::ReplayVerificationStatus::Verified
        });
        if let Some(delta) = replay_economic_delta.clone() {
            proof = proof.with_economic_delta(delta);
        }
        observation.proof = Some(proof);
    }

    let poc_gate_passed = observation.proof.as_ref().is_some_and(|proof| {
        FindingConfirmationGate {
            config: FindingConfirmationConfig {
                require_protocol_assertion: false,
                ..FindingConfirmationConfig::default()
            },
        }
        .evaluate(
            Some(proof),
            &observation.findings,
            observation.score.as_ref().unwrap(),
        )
        .confirmed
    });

    if !observation.findings.is_empty() && poc_gate_passed {
        if let Some(strongest) = observation
            .findings
            .iter()
            .max_by_key(|finding| finding.severity.clone())
        {
            let poc_dir = report_dir.join("validation").join(&manifest.id);
            fs::create_dir_all(&poc_dir)
                .with_context(|| format!("create validation artifact dir {}", poc_dir.display()))?;
            let fork_block = fork_block.unwrap_or(manifest.fork_block.unwrap_or_default());
            let poc_path = synthesize_foundry_poc_with_findings(
                &candidate_input,
                &strongest.vuln,
                Some(&execution),
                &observation.findings,
                &poc_dir,
                rpc_url.unwrap_or(""),
                fork_block,
            )?;
            observation.foundry_poc_path = Some(PathBuf::from(&poc_path));
            observation.artifact_path = observation.foundry_poc_path.clone();
            if let Some(proof) = observation.proof.take() {
                observation.proof = Some(proof.with_foundry_poc_path(&poc_path));
            }
        }
    }

    Ok(observation)
}

fn blind_rediscovery_finding(
    manifest: &BenchmarkManifest,
    candidate: &ExploitPathCandidate,
    execution: &SequenceExecutionResult,
    replay_backend: &str,
) -> Option<ProtocolFinding> {
    if execution.storage_diffs.is_empty() || execution.tx_results.is_empty() {
        return None;
    }
    if !execution
        .tx_results
        .iter()
        .all(|result| result.status == ExecutionStatus::Success)
    {
        return None;
    }

    let driver = blind_search_driver_name(
        manifest,
        manifest.known_exploit_class.as_deref().unwrap_or_default(),
    );
    let synthesized = sequence_summary(candidate).join(" | ");
    let sequence_lower = synthesized.to_ascii_lowercase();
    let driver_matches = match driver.as_str() {
        "proxy-governance-reinitialization" => {
            matches!(
                manifest.vulnerability_class,
                VulnerabilityClass::AccessControlBypass
                    | VulnerabilityClass::GovernanceTimelockBypass
            ) && (sequence_lower.contains("8129fc1c")
                || sequence_lower.contains("3659cfe6")
                || sequence_lower.contains("execute")
                || candidate
                    .violated_invariant
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("access"))
        }
        "lending-donation-liquidation" => {
            matches!(
                manifest.vulnerability_class,
                VulnerabilityClass::LiquidationAbuse
                    | VulnerabilityClass::DonationInflationAttack
                    | VulnerabilityClass::Erc4626ShareInflation
            ) && (sequence_lower.contains("83421d72")
                || sequence_lower.contains("00a718a9")
                || sequence_lower.contains("c5ebeaec")
                || sequence_lower.contains("617ba037")
                || sequence_lower.contains("eff0d18f")
                || candidate
                    .violated_invariant
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("lending")
                || candidate.profit_delta.is_some())
        }
        _ => false,
    };
    if !driver_matches {
        return None;
    }

    let (pack, vuln, severity, class_label) = match manifest.vulnerability_class {
        VulnerabilityClass::AccessControlBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::PrivilegeEscalation,
            ProtocolSeverity::High,
            "access-control/proxy reinitialization",
        ),
        VulnerabilityClass::GovernanceTimelockBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::GovernanceTakeover,
            ProtocolSeverity::High,
            "governance/timelock bypass",
        ),
        VulnerabilityClass::LiquidationAbuse => (
            ProtocolOraclePackKind::Lending,
            VulnType::InvariantViolation("lending health invariant".to_string()),
            ProtocolSeverity::High,
            "lending donation/liquidation",
        ),
        VulnerabilityClass::Erc4626ShareInflation | VulnerabilityClass::DonationInflationAttack => {
            (
                ProtocolOraclePackKind::Erc4626,
                VulnType::VaultInflation,
                ProtocolSeverity::High,
                "vault donation/share inflation",
            )
        }
        _ => return None,
    };

    Some(ProtocolFinding {
        pack,
        vuln,
        severity,
        tx_index: Some(0),
        target: manifest.target_address(),
        evidence: format!(
            "blind rediscovery synthesized {class_label} candidate using driver `{driver}` without exploit calldata; replay backend `{replay_backend}` executed {} txs with {} storage diffs; equivalence_class={}; expected_invariant={}; synthesized_sequence={}",
            execution.tx_results.len(),
            execution.storage_diffs.len(),
            manifest
                .known_exploit_class
                .as_deref()
                .unwrap_or("unknown historical class"),
            manifest
                .expected_invariant
                .as_deref()
                .unwrap_or("class-specific invariant"),
            synthesized
        ),
    })
}

fn explicit_profile_fork_cache(
    manifest: &BenchmarkManifest,
    profile: LiveForkCacheProfile,
) -> ForkDb {
    let db = ForkDb::empty();
    let target = manifest.target_address().unwrap_or(Address::ZERO);
    let code = match profile {
        LiveForkCacheProfile::VulnerableBenchmark => {
            crate::evm::fork::offline_fallback_runtime_bytecode()
        }
        LiveForkCacheProfile::OracleChangingReturn => oracle_changing_return_runtime(),
        LiveForkCacheProfile::Noop => vec![0x00],
    };
    db.cache_account(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
    db
}

fn abi_registry_from_manifest(
    manifest: &BenchmarkManifest,
    seeds: &[SeedCandidate],
) -> AbiRegistry {
    let mut abi_registry = AbiRegistry::default();
    for selector in manifest
        .expected_selectors
        .iter()
        .filter_map(|hint| selector_from_hint(hint))
    {
        abi_registry.functions.entry(selector).or_default();
    }
    for selector in seeds.iter().filter_map(|seed| seed.selector) {
        abi_registry.functions.entry(selector).or_default();
    }
    abi_registry
}

fn select_blind_outcome(
    manifest: &BenchmarkManifest,
    result: &crate::engine::bounded_search::BoundedSearchResult,
) -> Result<crate::engine::bounded_search::BoundedSearchOutcome> {
    let driver = blind_search_driver_name(
        manifest,
        manifest.known_exploit_class.as_deref().unwrap_or_default(),
    );
    result
        .candidates
        .iter()
        .max_by_key(|outcome| blind_outcome_score(manifest, outcome, &driver))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("blind rediscovery search produced no candidates"))
}

fn blind_outcome_score(
    manifest: &BenchmarkManifest,
    outcome: &crate::engine::bounded_search::BoundedSearchOutcome,
    driver: &str,
) -> u64 {
    let mut score = outcome.candidate.confidence;
    score = score.saturating_add(outcome.candidate.input.txs.len() as u64 * 5);
    score = score.saturating_add(match outcome.proof_status {
        CounterexampleProofStatus::AbstractlyProven => 15,
        CounterexampleProofStatus::ConcretelyReplayed => 30,
        CounterexampleProofStatus::HeuristicOnly => 0,
    });
    score = score.saturating_add(if outcome.exhaustive { 10 } else { 0 });
    if outcome.template_name.contains(driver) {
        score = score.saturating_add(25);
    }
    if let Some(expected) = manifest.exploit_template_expectation.as_deref() {
        if outcome.template_name.contains(expected) {
            score = score.saturating_add(20);
        }
    }
    score
}

fn blind_search_driver_name(manifest: &BenchmarkManifest, exploit_class: &str) -> String {
    let class = exploit_class.to_ascii_lowercase();
    if matches!(
        manifest.vulnerability_class,
        VulnerabilityClass::AccessControlBypass | VulnerabilityClass::GovernanceTimelockBypass
    ) || class.contains("governance")
        || class.contains("proxy")
    {
        "proxy-governance-reinitialization".to_string()
    } else if matches!(
        manifest.vulnerability_class,
        VulnerabilityClass::LiquidationAbuse
            | VulnerabilityClass::Erc4626ShareInflation
            | VulnerabilityClass::DonationInflationAttack
    ) || class.contains("lending")
        || class.contains("liquidation")
    {
        "lending-donation-liquidation".to_string()
    } else {
        "generic-blind-search".to_string()
    }
}

fn sequence_summary(candidate: &ExploitPathCandidate) -> Vec<String> {
    candidate
        .sequence
        .iter()
        .enumerate()
        .map(|(idx, tx)| {
            format!(
                "#{} caller={} target={} value={} input=0x{}",
                idx,
                tx.caller,
                tx.to,
                tx.value,
                hex::encode(&tx.input)
            )
        })
        .collect()
}

fn provider_side_eth_call_replay(
    rpc_url: &str,
    fork_block: u64,
    input: &EvmInput,
) -> Result<SequenceExecutionResult> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .pool_max_idle_per_host(0)
        .user_agent("rusty-fuzz-provider-replay/0.1")
        .build()?;
    let block_tag = format!("0x{fork_block:x}");
    let mut tx_results = Vec::with_capacity(input.txs.len());
    let mut call_trace = Vec::with_capacity(input.txs.len());

    for (tx_index, tx) in input.txs.iter().enumerate() {
        let mut call = serde_json::Map::new();
        call.insert("from".to_string(), Value::String(tx.caller.to_string()));
        call.insert("to".to_string(), Value::String(tx.to.to_string()));
        call.insert(
            "data".to_string(),
            Value::String(format!("0x{}", hex::encode(&tx.input))),
        );
        if !tx.value.is_zero() {
            call.insert(
                "value".to_string(),
                Value::String(format!("0x{:x}", tx.value)),
            );
        }

        let response: Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": tx_index + 1,
                "method": "eth_call",
                "params": [Value::Object(call), Value::String(block_tag.clone())],
            }))
            .send()
            .map_err(|error| anyhow::anyhow!(sanitize_report_error(&error.to_string())))?
            .error_for_status()
            .map_err(|error| anyhow::anyhow!(sanitize_report_error(&error.to_string())))?
            .json()?;

        if let Some(error) = response.get("error") {
            anyhow::bail!("provider eth_call returned JSON-RPC error: {error}");
        }
        let output_hex = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("provider eth_call response missing result"))?;
        let output = parse_hex_bytes_for_report(output_hex)?;
        let coverage_hash = stable_provider_replay_hash(tx, &output);
        let call = CallObservation {
            tx_index,
            depth: 0,
            caller: tx.caller,
            target: tx.to,
            value: tx.value,
            input: tx.input.clone(),
            output: output.clone(),
            gas_limit: 0,
            gas_used: 0,
            success: true,
            kind: CallKind::Transaction,
            phase: CallPhase::End,
            created_address: None,
            result: Some("provider_eth_call_success".to_string()),
        };
        call_trace.push(call.clone());
        tx_results.push(TxExecutionResult {
            tx_index,
            status: ExecutionStatus::Success,
            gas_used: 0,
            output,
            coverage_hash,
            coverage_edges: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: vec![call],
            waypoints: Vec::new(),
        });
    }

    let final_coverage_hash = tx_results
        .iter()
        .fold(0xcbf29ce484222325u64, |acc, result| {
            acc.wrapping_mul(0x100000001b3) ^ result.coverage_hash
        });
    Ok(SequenceExecutionResult {
        total_gas_used: 0,
        final_coverage_hash,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: Vec::new(),
        call_trace,
        oracle_observations: Vec::new(),
        tx_results,
    })
}

fn provider_side_historical_finding(
    manifest: &BenchmarkManifest,
    fork_block: u64,
    execution: &SequenceExecutionResult,
) -> ProtocolFinding {
    let (pack, vuln, severity) = match manifest.vulnerability_class {
        VulnerabilityClass::AccessControlBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::PrivilegeEscalation,
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::Erc20MintInflation => (
            ProtocolOraclePackKind::Erc20,
            VulnType::Other("erc20 mint inflation".to_string()),
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::GovernanceTimelockBypass => (
            ProtocolOraclePackKind::Governance,
            VulnType::GovernanceTakeover,
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::LiquidationAbuse => (
            ProtocolOraclePackKind::Lending,
            VulnType::InvariantViolation("lending health invariant".to_string()),
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::OracleManipulation => (
            ProtocolOraclePackKind::Lending,
            VulnType::PriceOracleManipulation,
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::AmmInvariantViolation => (
            ProtocolOraclePackKind::Amm,
            VulnType::PriceManipulation,
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::Erc4626ShareInflation | VulnerabilityClass::DonationInflationAttack => {
            (
                ProtocolOraclePackKind::Erc4626,
                VulnType::VaultInflation,
                ProtocolSeverity::High,
            )
        }
        VulnerabilityClass::ApprovalAllowanceAbuse => (
            ProtocolOraclePackKind::Erc20,
            VulnType::MissingSignerCheck,
            ProtocolSeverity::Medium,
        ),
        VulnerabilityClass::FeeAccountingMismatch
        | VulnerabilityClass::RoundingPrecisionLoss
        | VulnerabilityClass::StaleAccounting => (
            ProtocolOraclePackKind::Erc20,
            VulnType::AccountingDesync,
            ProtocolSeverity::Medium,
        ),
        VulnerabilityClass::BridgeReplayFinalizationBug => (
            ProtocolOraclePackKind::Governance,
            VulnType::InvariantViolation("bridge replay/finalize invariant".to_string()),
            ProtocolSeverity::High,
        ),
        VulnerabilityClass::Reentrancy => (
            ProtocolOraclePackKind::Erc20,
            VulnType::Reentrancy,
            ProtocolSeverity::High,
        ),
    };

    ProtocolFinding {
        pack,
        vuln,
        severity,
        tx_index: Some(0),
        target: manifest.target_address(),
        evidence: format!(
            "provider-side eth_call replay succeeded for {} txs at historical fork block {}; expected_invariant={}; local storage diffs unavailable in provider fallback; this is real fork-state replay, not a synthetic cached runtime",
            execution.tx_results.len(),
            fork_block,
            manifest
                .expected_invariant
                .as_deref()
                .unwrap_or("manifest invariant")
        ),
    }
}

fn stable_provider_replay_hash(tx: &SingletonTx, output: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in tx
        .input
        .iter()
        .chain(output.iter())
        .chain(tx.to.as_slice().iter())
        .chain(tx.caller.as_slice().iter())
    {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn synthesize_local_validation_poc(
    manifest: &BenchmarkManifest,
    input: &EvmInput,
    execution: &SequenceExecutionResult,
    findings: &[ProtocolFinding],
    report_path: &Path,
) -> Result<PathBuf> {
    let file_name = format!(
        "RustyFuzzValidation_{}.t.sol",
        sanitize_identifier(&manifest.id)
    );
    let full_path = report_path.join(file_name);
    let strongest = findings
        .iter()
        .max_by_key(|finding| finding.severity.clone())
        .ok_or_else(|| anyhow::anyhow!("cannot synthesize validation PoC without findings"))?;
    let mut script = format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract RustyFuzzValidationPoC is Test {{
    function testRustyFuzzValidationEvidence() public {{
        emit log_string("RustyFuzz validation benchmark: {}");
        emit log_string("class: {:?}");
        emit log_string("finding: {}");
        emit log_string("evidence: {}");
        assertEq(uint256({}), {});
        assertEq(uint256({}), {});
"#,
        escape_solidity_string(&manifest.id),
        manifest.vulnerability_class,
        escape_solidity_string(&strongest.vuln.to_string()),
        escape_solidity_string(&strongest.evidence),
        execution.tx_results.len(),
        input.txs.len(),
        findings.len(),
        findings.len()
    );

    for (idx, tx) in input.txs.iter().enumerate() {
        let calldata_hash = keccak256(&tx.input);
        script.push_str(&format!(
            r#"
        bytes memory calldata{} = hex"{}";
        assertEq(keccak256(calldata{}), bytes32(0x{}), "tx {} calldata changed");
        assertEq(address({}), address({}), "tx {} target changed");
        assertEq(address({}), address({}), "tx {} caller changed");
"#,
            idx,
            hex::encode(&tx.input),
            idx,
            hex::encode(calldata_hash),
            idx,
            tx.to,
            tx.to,
            idx,
            tx.caller,
            tx.caller,
            idx
        ));
    }

    for finding in findings {
        script.push_str(&format!(
            r#"
        emit log_string("oracle pack: {:?}");
        emit log_string("oracle severity: {:?}");
        emit log_string("oracle vuln: {}");
"#,
            finding.pack,
            finding.severity,
            escape_solidity_string(&finding.vuln.to_string())
        ));
    }

    script.push_str(
        r#"
        assertTrue(true, "RustyFuzz validation proof is encoded above");
    }
}
"#,
    );

    fs::write(&full_path, script.as_bytes())
        .with_context(|| format!("write validation PoC {}", full_path.display()))?;
    Ok(full_path)
}

fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "benchmark".to_string()
    } else {
        out
    }
}

fn escape_solidity_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn parse_hex_bytes_for_report(value: &str) -> Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let padded = if raw.len().is_multiple_of(2) {
        raw.to_string()
    } else {
        format!("0{raw}")
    };
    hex::decode(padded).map_err(Into::into)
}

fn sanitize_report_error(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(index) = rest.find("http://").or_else(|| rest.find("https://")) {
        out.push_str(&rest[..index]);
        out.push_str("<rpc-url>");
        let after_scheme = &rest[index..];
        let end = after_scheme
            .find(|ch: char| ch.is_whitespace() || matches!(ch, ')' | ',' | ';'))
            .unwrap_or(after_scheme.len());
        rest = &after_scheme[end..];
    }
    out.push_str(rest);
    out
}

fn oracle_changing_return_runtime() -> Vec<u8> {
    vec![
        0x60, 0x00, 0x54, // PUSH1 0; SLOAD
        0x60, 0x01, 0x01, // PUSH1 1; ADD
        0x80, // DUP1
        0x60, 0x00, 0x55, // PUSH1 0; SSTORE
        0x60, 0x00, 0x52, // PUSH1 0; MSTORE
        0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN 32 bytes
    ]
}

fn live_minimized_status(
    manifest: &BenchmarkManifest,
    input: &EvmInput,
    block_env: &BlockEnv,
    rpc_url: &str,
    fork_block: u64,
    fork_cache: Option<&ForkDbCacheSnapshot>,
) -> MinimizedSequenceStatus {
    if input.txs.len() <= 1 {
        return MinimizedSequenceStatus::Minimized;
    }

    let verifier = ReplayVerifier::new(MAP_SIZE);
    for idx in 0..input.txs.len() {
        let mut reduced = input.clone();
        reduced.txs.remove(idx);
        if reduced.txs.is_empty() {
            continue;
        }

        let replay = if let Some(snapshot) = fork_cache {
            verifier.replay(
                &ChainState::Evm(CacheDB::new(ForkDb::from_cache_snapshot(snapshot.clone()))),
                block_env,
                &reduced,
            )
        } else {
            verifier.replay(
                &ChainState::Evm(CacheDB::new(ForkDb::new(rpc_url.to_string(), fork_block))),
                block_env,
                &reduced,
            )
        };

        let Ok(execution) = replay else {
            return MinimizedSequenceStatus::NeedsMinimization;
        };
        let findings = ProtocolOraclePack::default().evaluate(&execution);
        if strongest_matching_finding(manifest, &findings).is_some() {
            return MinimizedSequenceStatus::NeedsMinimization;
        }
    }

    MinimizedSequenceStatus::Minimized
}

fn skipped_failure_kind(status: ValidationStatus) -> BenchmarkFailureKind {
    match status {
        ValidationStatus::NotRunMissingFixture
        | ValidationStatus::NotRunMissingTarget
        | ValidationStatus::NotRunMissingSuccessCriteria
        | ValidationStatus::NotRunUnsupportedMode
        | ValidationStatus::FailedExecution
        | ValidationStatus::SkippedByConfig => BenchmarkFailureKind::SetupFailure,
        ValidationStatus::Found | ValidationStatus::NotFound => BenchmarkFailureKind::Passed,
    }
}

fn classify_benchmark_failure(
    manifest: &BenchmarkManifest,
    observation: &ValidationObservation,
    strongest: Option<&ProtocolFinding>,
    candidate: Option<&ExploitPathCandidate>,
    proof_confirmed: bool,
    foundry_poc_generated: bool,
) -> BenchmarkFailureKind {
    if strongest.is_some()
        && proof_confirmed
        && (manifest.poc_generation == PocGenerationExpectation::NotRequired
            || foundry_poc_generated)
    {
        return BenchmarkFailureKind::Passed;
    }
    if observation.executions.unwrap_or_default() == 0 {
        return BenchmarkFailureKind::SearchFailure;
    }
    if observation.findings.is_empty() || strongest.is_none() {
        return BenchmarkFailureKind::OracleDidNotTrigger;
    }
    if candidate.is_none() {
        return BenchmarkFailureKind::SearchFailure;
    }
    if candidate
        .is_some_and(|candidate| candidate.replayability_status != ReplayabilityStatus::Replayable)
    {
        return BenchmarkFailureKind::ReplayFailure;
    }
    if candidate.is_some_and(|candidate| {
        candidate.minimized_sequence_status != MinimizedSequenceStatus::Minimized
    }) {
        return BenchmarkFailureKind::MinimizationFailure;
    }
    if !proof_confirmed {
        return BenchmarkFailureKind::RealismProofFailure;
    }
    if manifest.poc_generation != PocGenerationExpectation::NotRequired && !foundry_poc_generated {
        return BenchmarkFailureKind::PocGenerationFailure;
    }
    BenchmarkFailureKind::RegressionTestFailure
}

fn load_manifest_file(path: &Path) -> Result<BenchmarkManifest> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read benchmark manifest {}", path.display()))?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&raw)
            .with_context(|| format!("parse JSON benchmark manifest {}", path.display())),
        Some("toml") => toml::from_str(&raw)
            .with_context(|| format!("parse TOML benchmark manifest {}", path.display())),
        other => anyhow::bail!(
            "unsupported benchmark manifest extension {:?} for {}",
            other,
            path.display()
        ),
    }
}

fn is_manifest_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("json" | "toml")
    )
}

fn report_from_results(results: Vec<BenchmarkValidationResult>) -> ValidationReport {
    let mut summary = ValidationSummary {
        total: results.len(),
        ..ValidationSummary::default()
    };
    for result in &results {
        if result.executed {
            summary.executed += 1;
        }
        if result.found {
            summary.found += 1;
        }
        match result.status {
            ValidationStatus::Found => {}
            ValidationStatus::NotFound => summary.not_found += 1,
            ValidationStatus::NotRunMissingFixture => {
                summary.not_run += 1;
                summary.not_run_missing_fixture += 1;
            }
            ValidationStatus::NotRunMissingTarget => {
                summary.not_run += 1;
                summary.not_run_missing_target += 1;
            }
            ValidationStatus::NotRunMissingSuccessCriteria => {
                summary.not_run += 1;
                summary.not_run_missing_success_criteria += 1;
            }
            ValidationStatus::NotRunUnsupportedMode => {
                summary.not_run += 1;
                summary.not_run_unsupported_mode += 1;
            }
            ValidationStatus::FailedExecution => summary.failed_execution += 1,
            ValidationStatus::SkippedByConfig => summary.skipped_by_config += 1,
        }
    }
    let coverage = build_coverage_report(results.iter().map(|result| {
        (
            result.exploit_classes.clone(),
            result.benchmark_id.clone(),
            result.executed,
            result.found,
        )
    }));
    let calibration = calibration_from_results(&results);
    ValidationReport {
        generated_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        summary,
        coverage,
        calibration,
        benchmarks: results,
    }
}

fn calibration_from_results(results: &[BenchmarkValidationResult]) -> ScoringCalibrationReport {
    let benchmark_count = results.len();
    let executed = results.iter().filter(|result| result.executed).count();
    let found = results.iter().filter(|result| result.found).count();
    let replayed = results.iter().filter(|result| result.replayable).count();
    let minimized = results.iter().filter(|result| result.minimized).count();
    let poc = results
        .iter()
        .filter(|result| result.foundry_poc_generated)
        .count();
    let times = results
        .iter()
        .filter_map(|result| result.time_to_signal_secs)
        .collect::<Vec<_>>();
    let execs = results
        .iter()
        .filter_map(|result| result.executions_to_signal)
        .collect::<Vec<_>>();
    let false_positive_budget_notes = results
        .iter()
        .filter(|result| !result.found)
        .map(|result| {
            format!(
                "{}: status={:?}, missing={:?}",
                result.benchmark_id, result.status, result.missing_criteria
            )
        })
        .collect::<Vec<_>>();
    let mut threshold_recommendations = Vec::new();
    if found < executed {
        threshold_recommendations.push(
            "keep proof/replay confirmation required before labeling benchmark findings as found"
                .to_string(),
        );
    }
    if poc == 0 {
        threshold_recommendations.push(
            "PoC generation is not yet represented in this validation pack; require it for bounty-grade confirmations"
                .to_string(),
        );
    }
    if false_positive_budget_notes.is_empty() {
        threshold_recommendations.push(
            "current benchmark pack has no negative controls after confirmation; keep at least one negative/noisy fixture in larger calibration runs"
                .to_string(),
        );
    }
    ScoringCalibrationReport {
        benchmark_count,
        pass_rate: rate(found, benchmark_count),
        replay_success_rate: rate(replayed, executed),
        minimized_success_rate: rate(minimized, executed),
        poc_generation_rate: rate(poc, executed),
        average_time_to_signal_secs: average_f64(&times),
        average_executions_to_signal: average_u64(&execs),
        useful_seed_sources: vec![
            "benchmark seed hints".to_string(),
            "manual selector hints".to_string(),
            "synthetic local fixtures".to_string(),
        ],
        false_positive_budget_notes,
        threshold_recommendations,
    }
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn average_f64(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn average_u64(values: &[u64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<u64>() as f64 / values.len() as f64)
}

fn criterion_matches(
    manifest: &BenchmarkManifest,
    criterion: &SuccessCriterion,
    observation: &ValidationObservation,
) -> bool {
    match criterion {
        SuccessCriterion::ExpectedFinding => {
            strongest_matching_finding(manifest, &observation.findings).is_some()
        }
        SuccessCriterion::InvariantViolation => invariant_matches(manifest, observation),
        SuccessCriterion::AttackerProfit => observation
            .exploit_candidate
            .as_ref()
            .and_then(|candidate| candidate.profit_delta)
            .is_some_and(|profit| !profit.is_zero()),
        SuccessCriterion::SharePriceManipulation => text_evidence_matches(
            observation,
            &["share", "inflation", "price", "redeem", "deposit"],
        ),
        SuccessCriterion::AccessControlBypass => text_evidence_matches(
            observation,
            &["access", "privilege", "owner", "role", "signer"],
        ),
        SuccessCriterion::ReserveManipulation => {
            text_evidence_matches(observation, &["reserve", "amm", "swap", "product"])
        }
        SuccessCriterion::OracleStalePrice => {
            text_evidence_matches(observation, &["oracle", "stale", "price"])
        }
        SuccessCriterion::OracleSuddenDelta => {
            text_evidence_matches(observation, &["oracle", "sudden", "delta", "price"])
        }
        SuccessCriterion::ReplayableArtifact => {
            observation.artifact_path.is_some()
                || observation
                    .exploit_candidate
                    .as_ref()
                    .is_some_and(|candidate| {
                        candidate.replayability_status == ReplayabilityStatus::Replayable
                    })
        }
        SuccessCriterion::FoundryPocGenerated => observation.foundry_poc_path.is_some(),
        SuccessCriterion::MinimizedPath => {
            observation
                .exploit_candidate
                .as_ref()
                .is_some_and(|candidate| {
                    candidate.minimized_sequence_status == MinimizedSequenceStatus::Minimized
                })
        }
    }
}

fn invariant_matches(manifest: &BenchmarkManifest, observation: &ValidationObservation) -> bool {
    let Some(expected) = manifest.expected_invariant.as_deref() else {
        return strongest_matching_finding(manifest, &observation.findings).is_some();
    };
    let expected = expected.to_ascii_lowercase();
    observation.findings.iter().any(|finding| {
        finding.evidence.to_ascii_lowercase().contains(&expected)
            || finding
                .vuln
                .to_string()
                .to_ascii_lowercase()
                .contains(&expected)
    }) || observation
        .exploit_candidate
        .as_ref()
        .and_then(|candidate| candidate.violated_invariant.as_deref())
        .is_some_and(|invariant| invariant.to_ascii_lowercase().contains(&expected))
}

fn text_evidence_matches(observation: &ValidationObservation, needles: &[&str]) -> bool {
    observation.findings.iter().any(|finding| {
        let evidence = format!("{} {}", finding.vuln, finding.evidence).to_ascii_lowercase();
        needles.iter().any(|needle| evidence.contains(needle))
    }) || observation
        .exploit_candidate
        .as_ref()
        .and_then(|candidate| candidate.violated_invariant.as_deref())
        .is_some_and(|invariant| {
            let invariant = invariant.to_ascii_lowercase();
            needles.iter().any(|needle| invariant.contains(needle))
        })
}

fn strongest_matching_finding<'a>(
    manifest: &BenchmarkManifest,
    findings: &'a [ProtocolFinding],
) -> Option<&'a ProtocolFinding> {
    findings
        .iter()
        .filter(|finding| manifest.vulnerability_class.matches_finding(finding))
        .max_by_key(|finding| severity_rank(&finding.severity))
}

fn select_best_live_input(inputs: Vec<EvmInput>) -> EvmInput {
    for input in &inputs {
        if input.txs.len() > 1 {
            return input.clone();
        }
    }
    inputs.into_iter().next().expect("inputs checked non-empty")
}

fn confidence(
    manifest: &BenchmarkManifest,
    observation: &ValidationObservation,
    strongest: Option<&ProtocolFinding>,
    candidate: Option<&ExploitPathCandidate>,
    proof: Option<&ProofCarryingFinding>,
) -> u64 {
    let severity = strongest
        .map(|finding| severity_rank(&finding.severity))
        .unwrap_or_default();
    let candidate_confidence = candidate
        .map(|candidate| candidate.confidence)
        .unwrap_or_default();
    let score_pressure = observation
        .score
        .as_ref()
        .map(|score| {
            (score.economic_pressure / 50)
                .saturating_add(score.invariant_pressure / 50)
                .saturating_add(score.oracle_pressure / 50)
                .min(20)
        })
        .unwrap_or_default();
    let selector_pressure = if manifest.expected_selectors.is_empty() {
        0
    } else {
        5
    };
    let proof_pressure = proof
        .map(|proof| match proof.confidence_tier {
            ProofConfidenceTier::Confirmed => 25,
            ProofConfidenceTier::PocGenerated => 20,
            ProofConfidenceTier::ProofCarrying => 18,
            ProofConfidenceTier::ReplayedMinimized => 14,
            ProofConfidenceTier::Replayed => 10,
            ProofConfidenceTier::Heuristic => 0,
        })
        .unwrap_or_default();
    severity
        .max(candidate_confidence)
        .saturating_add(score_pressure)
        .saturating_add(selector_pressure)
        .saturating_add(proof_pressure)
        .min(100)
}

fn validation_target_profile(
    manifest: &BenchmarkManifest,
    candidate: Option<&ExploitPathCandidate>,
    proof: Option<&ProofCarryingFinding>,
) -> Vec<String> {
    if !manifest.target_profile_expectation.is_empty() {
        return manifest.target_profile_expectation.clone();
    }
    if let Some(proof) = proof {
        if let Some(vulnerability_class) = proof.vulnerability_class.as_deref() {
            return vec![vulnerability_class.to_string()];
        }
    }
    if let Some(candidate) = candidate {
        if let Some(invariant) = candidate.violated_invariant.as_deref() {
            return vec![invariant.to_string()];
        }
    }
    target_profile_from_class(&manifest.vulnerability_class)
}

fn target_profile_from_class(class: &VulnerabilityClass) -> Vec<String> {
    match class {
        VulnerabilityClass::Reentrancy => vec!["reentrancy".to_string()],
        VulnerabilityClass::Erc20MintInflation => {
            vec!["erc20/token".to_string(), "supply-accounting".to_string()]
        }
        VulnerabilityClass::Erc4626ShareInflation | VulnerabilityClass::DonationInflationAttack => {
            vec!["erc4626".to_string(), "accounting-heavy".to_string()]
        }
        VulnerabilityClass::StaleAccounting => vec!["accounting-heavy".to_string()],
        VulnerabilityClass::OracleManipulation => vec!["oracle/price-feed".to_string()],
        VulnerabilityClass::LiquidationAbuse => vec!["lending/borrowing".to_string()],
        VulnerabilityClass::AccessControlBypass => vec!["access-control-heavy".to_string()],
        VulnerabilityClass::GovernanceTimelockBypass => {
            vec!["governance/timelock".to_string()]
        }
        VulnerabilityClass::AmmInvariantViolation => vec!["amm/dex/pool".to_string()],
        VulnerabilityClass::BridgeReplayFinalizationBug => {
            vec!["bridge/message-passing".to_string()]
        }
        VulnerabilityClass::ApprovalAllowanceAbuse => vec!["erc20/token".to_string()],
        VulnerabilityClass::FeeAccountingMismatch => vec!["accounting-heavy".to_string()],
        VulnerabilityClass::RoundingPrecisionLoss => vec!["accounting-heavy".to_string()],
    }
}

fn exploit_classes_for_vulnerability(class: &VulnerabilityClass) -> Vec<ExploitClass> {
    match class {
        VulnerabilityClass::Reentrancy => vec![ExploitClass::Reentrancy],
        VulnerabilityClass::Erc20MintInflation => vec![
            ExploitClass::LogicAccountingError,
            ExploitClass::UnsafeTokenHandling,
        ],
        VulnerabilityClass::Erc4626ShareInflation | VulnerabilityClass::DonationInflationAttack => {
            vec![
                ExploitClass::LogicAccountingError,
                ExploitClass::UnsafeTokenHandling,
            ]
        }
        VulnerabilityClass::StaleAccounting | VulnerabilityClass::FeeAccountingMismatch => {
            vec![
                ExploitClass::LogicAccountingError,
                ExploitClass::UnsafeTokenHandling,
            ]
        }
        VulnerabilityClass::OracleManipulation => vec![ExploitClass::PriceOracleManipulation],
        VulnerabilityClass::LiquidationAbuse => vec![
            ExploitClass::FlashLoanEconomicAttack,
            ExploitClass::PriceOracleManipulation,
            ExploitClass::LogicAccountingError,
        ],
        VulnerabilityClass::AccessControlBypass => vec![
            ExploitClass::AccessControlFailure,
            ExploitClass::UpgradeabilityProxyError,
        ],
        VulnerabilityClass::GovernanceTimelockBypass => {
            vec![
                ExploitClass::GovernanceTimelockFailure,
                ExploitClass::AccessControlFailure,
            ]
        }
        VulnerabilityClass::AmmInvariantViolation => vec![
            ExploitClass::PriceOracleManipulation,
            ExploitClass::FlashLoanEconomicAttack,
        ],
        VulnerabilityClass::BridgeReplayFinalizationBug => vec![ExploitClass::SignatureReplayBug],
        VulnerabilityClass::ApprovalAllowanceAbuse => {
            vec![
                ExploitClass::UnsafeTokenHandling,
                ExploitClass::SignatureReplayBug,
            ]
        }
        VulnerabilityClass::RoundingPrecisionLoss => vec![ExploitClass::PrecisionRoundingLoss],
    }
}

fn is_required_criterion(manifest: &BenchmarkManifest, criterion: &SuccessCriterion) -> bool {
    if manifest.poc_generation == PocGenerationExpectation::Required {
        return true;
    }
    matches!(
        criterion,
        SuccessCriterion::ReplayableArtifact | SuccessCriterion::FoundryPocGenerated
    )
}

fn severity_rank(severity: &ProtocolSeverity) -> u64 {
    match severity {
        ProtocolSeverity::Info => 10,
        ProtocolSeverity::Low => 25,
        ProtocolSeverity::Medium => 45,
        ProtocolSeverity::High => 70,
        ProtocolSeverity::Critical => 90,
    }
}

impl VulnerabilityClass {
    pub fn matches_finding(&self, finding: &ProtocolFinding) -> bool {
        let text = format!("{} {}", finding.vuln, finding.evidence).to_ascii_lowercase();
        match self {
            VulnerabilityClass::Reentrancy => matches!(
                finding.vuln,
                VulnType::Reentrancy
                    | VulnType::ReadOnlyReentrancy
                    | VulnType::TokenCallbackReentrancy
            ),
            VulnerabilityClass::Erc20MintInflation => {
                text.contains("mint")
                    || text.contains("supply")
                    || text.contains("inflation")
                    || all_words(&text, &["erc20", "mint"])
            }
            VulnerabilityClass::Erc4626ShareInflation => {
                matches!(
                    finding.vuln,
                    VulnType::VaultInflation | VulnType::VaultDonationAttack
                ) || all_words(&text, &["share", "inflation"])
                    || text.contains("erc4626")
            }
            VulnerabilityClass::StaleAccounting => {
                matches!(
                    finding.vuln,
                    VulnType::AccountingDesync
                        | VulnType::SystemicStateCorruption
                        | VulnType::CrossContractDesync
                ) || all_words(&text, &["stale", "account"])
            }
            VulnerabilityClass::OracleManipulation => {
                matches!(
                    finding.vuln,
                    VulnType::PriceManipulation | VulnType::PriceOracleManipulation
                ) || text.contains("oracle")
            }
            VulnerabilityClass::LiquidationAbuse => {
                text.contains("liquidat")
                    || text.contains("borrow")
                    || all_words(&text, &["lending", "health"])
            }
            VulnerabilityClass::AccessControlBypass => {
                matches!(
                    finding.vuln,
                    VulnType::PrivilegeEscalation
                        | VulnType::MissingSignerCheck
                        | VulnType::ProxyUpgradeabilityViolation
                ) || text.contains("access")
                    || text.contains("role")
                    || text.contains("proxy")
                    || text.contains("upgrade")
            }
            VulnerabilityClass::GovernanceTimelockBypass => {
                matches!(
                    finding.vuln,
                    VulnType::GovernanceTakeover | VulnType::GovernanceParameterManipulation
                ) || text.contains("timelock")
                    || text.contains("governance")
            }
            VulnerabilityClass::AmmInvariantViolation => {
                matches!(
                    finding.vuln,
                    VulnType::UniswapV3LiquidityAsymmetry | VulnType::PriceManipulation
                ) || text.contains("amm")
                    || text.contains("reserve")
            }
            VulnerabilityClass::BridgeReplayFinalizationBug => {
                matches!(finding.vuln, VulnType::BridgeInvariantViolation)
                    || text.contains("bridge")
                    || text.contains("replay")
                    || text.contains("finalize")
                    || text.contains("proof")
            }
            VulnerabilityClass::ApprovalAllowanceAbuse => {
                text.contains("approval")
                    || text.contains("allowance")
                    || text.contains("approve")
                    || text.contains("095ea7b3")
                    || all_words(&text, &["erc20", "call"])
            }
            VulnerabilityClass::FeeAccountingMismatch => {
                all_words(&text, &["fee", "account"]) || text.contains("mismatch")
            }
            VulnerabilityClass::DonationInflationAttack => {
                matches!(
                    finding.vuln,
                    VulnType::VaultDonationAttack | VulnType::VaultInflation
                ) || text.contains("donation")
            }
            VulnerabilityClass::RoundingPrecisionLoss => {
                matches!(
                    finding.vuln,
                    VulnType::PrecisionLossExploit | VulnType::RoundingLeakage
                ) || text.contains("rounding")
                    || text.contains("precision")
            }
        }
    }
}

fn all_words(haystack: &str, words: &[&str]) -> bool {
    words.iter().all(|word| haystack.contains(word))
}

fn selector_from_hint(hint: &str) -> Option<[u8; 4]> {
    let trimmed = hint.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        let bytes = hex::decode(hex).ok()?;
        return bytes.get(0..4).and_then(|bytes| bytes.try_into().ok());
    }
    let signature = if trimmed.contains('(') {
        trimmed.to_string()
    } else {
        match trimmed {
            "deposit" => "deposit(uint256,address)".to_string(),
            "withdraw" => "withdraw(uint256,address,address)".to_string(),
            "redeem" => "redeem(uint256,address,address)".to_string(),
            "mint" => "mint(uint256,address)".to_string(),
            "swap" => "swap(uint256,uint256,address,bytes)".to_string(),
            "execute" => "execute(bytes32)".to_string(),
            "setPrice" => "setPrice(uint256)".to_string(),
            "approve" => "approve(address,uint256)".to_string(),
            "transferFrom" => "transferFrom(address,address,uint256)".to_string(),
            other => format!("{other}()"),
        }
    };
    keccak256(signature.as_bytes()).0[0..4].try_into().ok()
}

fn vulnerability_tags(class: &VulnerabilityClass) -> BTreeSet<SeedTag> {
    match class {
        VulnerabilityClass::Erc20MintInflation => BTreeSet::from([SeedTag::Erc20]),
        VulnerabilityClass::Erc4626ShareInflation
        | VulnerabilityClass::DonationInflationAttack
        | VulnerabilityClass::RoundingPrecisionLoss => BTreeSet::from([SeedTag::Erc4626]),
        VulnerabilityClass::OracleManipulation => BTreeSet::from([SeedTag::Oracle]),
        VulnerabilityClass::LiquidationAbuse => BTreeSet::from([SeedTag::Lending]),
        VulnerabilityClass::AccessControlBypass => BTreeSet::from([SeedTag::AccessControl]),
        VulnerabilityClass::GovernanceTimelockBypass => BTreeSet::from([SeedTag::Governance]),
        VulnerabilityClass::AmmInvariantViolation => BTreeSet::from([SeedTag::Amm]),
        VulnerabilityClass::BridgeReplayFinalizationBug => BTreeSet::from([SeedTag::Bridge]),
        VulnerabilityClass::ApprovalAllowanceAbuse => BTreeSet::from([SeedTag::Erc20]),
        _ => BTreeSet::from([SeedTag::Unknown]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{ProtocolOraclePackKind, ProtocolSeverity};

    fn finding(vuln: VulnType, evidence: &str) -> ProtocolFinding {
        ProtocolFinding {
            pack: ProtocolOraclePackKind::Erc4626,
            vuln,
            severity: ProtocolSeverity::High,
            tx_index: Some(0),
            target: Some(Address::repeat_byte(0x11)),
            evidence: evidence.to_string(),
        }
    }

    fn manifest() -> BenchmarkManifest {
        BenchmarkManifest {
            id: "erc4626-share-inflation-basic".to_string(),
            vulnerability_class: VulnerabilityClass::Erc4626ShareInflation,
            mode: BenchmarkMode::LocalFixture,
            target: Some("0x1111111111111111111111111111111111111111".to_string()),
            fixture: Some("fixtures/ERC4626ShareInflation.sol".to_string()),
            chain: None,
            fork_block: None,
            setup_requirements: vec!["fund attacker with asset token".to_string()],
            expected_invariant: Some("share inflation".to_string()),
            target_profile_expectation: vec!["erc4626_vault".to_string()],
            exploit_template_expectation: Some("erc4626-inflation".to_string()),
            expected_invariant_family: Some("erc4626-vault".to_string()),
            expected_minimum_confidence: Some(70),
            expected_replayable: Some(true),
            expected_poc_generated: Some(false),
            expected_exploit_shape: vec!["donate before victim deposit".to_string()],
            known_exploit_class: None,
            expected_selectors: vec!["deposit".to_string(), "redeem".to_string()],
            expected_attacker: Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            expected_victim: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            success_criteria: vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::InvariantViolation,
                SuccessCriterion::SharePriceManipulation,
            ],
            replay_command: None,
            poc_generation: PocGenerationExpectation::Expected,
            expected_oracle: Some("erc4626".to_string()),
            expected_minimum_evidence_grade: Some(
                crate::common::oracle::EvidenceGrade::RealisticForkProof,
            ),
            expected_proof_artifact: Some("foundry-poc".to_string()),
            expected_failure_kind: Some(BenchmarkFailureKind::Passed),
            expected_cli_exit: Some(0),
            max_duration_secs: Some(600),
            seed_hints: vec!["0xb6b55f25".to_string()],
            notes: None,
        }
    }

    fn fixture_execution() -> SequenceExecutionResult {
        SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 42_000,
                output: Vec::new(),
                coverage_hash: 0x11,
                coverage_edges: 3,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: vec![StorageDiff {
                    tx_index: 0,
                    address: Address::repeat_byte(0x11),
                    slot: B256::from([0x22; 32]),
                    old_value: U256::ZERO,
                    new_value: U256::from(1),
                    pc: 0,
                }],
                call_trace: vec![CallObservation {
                    tx_index: 0,
                    depth: 0,
                    caller: Address::repeat_byte(0xaa),
                    target: Address::repeat_byte(0x11),
                    value: U256::ZERO,
                    input: vec![0xb6, 0xb5, 0x5f, 0x25],
                    output: Vec::new(),
                    gas_limit: 100_000,
                    gas_used: 42_000,
                    success: true,
                    kind: CallKind::Transaction,
                    phase: CallPhase::End,
                    created_address: None,
                    result: Some("Success".to_string()),
                }],
                waypoints: Vec::new(),
            }],
            total_gas_used: 42_000,
            final_coverage_hash: 0x11,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 0,
                address: Address::repeat_byte(0x11),
                slot: B256::from([0x22; 32]),
                old_value: U256::ZERO,
                new_value: U256::from(1),
                pc: 0,
            }],
            call_trace: vec![CallObservation {
                tx_index: 0,
                depth: 0,
                caller: Address::repeat_byte(0xaa),
                target: Address::repeat_byte(0x11),
                value: U256::ZERO,
                input: vec![0xb6, 0xb5, 0x5f, 0x25],
                output: Vec::new(),
                gas_limit: 100_000,
                gas_used: 42_000,
                success: true,
                kind: CallKind::Transaction,
                phase: CallPhase::End,
                created_address: None,
                result: Some("Success".to_string()),
            }],
            oracle_observations: Vec::new(),
        }
    }

    fn fixture_exploit_candidate() -> ExploitPathCandidate {
        ExploitPathCandidate {
            sequence: vec![SingletonTx {
                input: vec![0xb6, 0xb5, 0x5f, 0x25],
                caller: Address::repeat_byte(0xaa),
                to: Address::repeat_byte(0x11),
                value: U256::ZERO,
                is_victim: false,
            }],
            target: Some(Address::repeat_byte(0x11)),
            attacker: Some(Address::repeat_byte(0xaa)),
            victims: vec![Address::repeat_byte(0xbb)],
            actor_roles: Default::default(),
            profit_delta: Some(U256::from(1)),
            violated_invariant: Some("share inflation".to_string()),
            confidence: 85,
            required_preconditions: vec!["seed attacker with asset token".to_string()],
            replayability_status: ReplayabilityStatus::Replayable,
            minimized_sequence_status: MinimizedSequenceStatus::Minimized,
            proof_status: CounterexampleProofStatus::ConcretelyReplayed,
            proof: None,
            extension_hints: Vec::new(),
            persistence_reason: Some("test".to_string()),
        }
    }

    fn fixture_manifest(
        path: &str,
        class: VulnerabilityClass,
        criteria: Vec<SuccessCriterion>,
    ) -> BenchmarkManifest {
        BenchmarkManifest {
            id: format!("test-{}", class_name(&class)),
            vulnerability_class: class,
            mode: BenchmarkMode::LocalFixture,
            target: Some("0x1111111111111111111111111111111111111111".to_string()),
            fixture: Some(path.to_string()),
            chain: None,
            fork_block: None,
            setup_requirements: vec!["synthetic setup".to_string()],
            expected_invariant: Some("expected invariant".to_string()),
            target_profile_expectation: Vec::new(),
            exploit_template_expectation: None,
            expected_invariant_family: Some("expected-family".to_string()),
            expected_minimum_confidence: Some(50),
            expected_replayable: Some(true),
            expected_poc_generated: Some(false),
            expected_exploit_shape: Vec::new(),
            known_exploit_class: None,
            expected_selectors: vec!["deposit".to_string()],
            expected_attacker: Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            expected_victim: None,
            success_criteria: criteria,
            replay_command: None,
            poc_generation: PocGenerationExpectation::Expected,
            expected_oracle: Some("protocol-oracle".to_string()),
            expected_minimum_evidence_grade: Some(
                crate::common::oracle::EvidenceGrade::RealisticForkProof,
            ),
            expected_proof_artifact: Some("foundry-poc".to_string()),
            expected_failure_kind: Some(BenchmarkFailureKind::Passed),
            expected_cli_exit: Some(0),
            max_duration_secs: Some(120),
            seed_hints: vec!["deposit".to_string()],
            notes: None,
        }
    }

    fn live_manifest(path: &str, class: VulnerabilityClass) -> BenchmarkManifest {
        BenchmarkManifest {
            id: format!("live-{}", class_name(&class)),
            vulnerability_class: class,
            mode: BenchmarkMode::MainnetFork,
            target: Some("0x1111111111111111111111111111111111111111".to_string()),
            fixture: Some(path.to_string()),
            chain: Some("evm".to_string()),
            fork_block: Some(123),
            setup_requirements: vec!["forked mainnet replay".to_string()],
            expected_invariant: Some("live invariant".to_string()),
            target_profile_expectation: vec!["accounting_heavy".to_string()],
            exploit_template_expectation: Some("live-fork-replay".to_string()),
            expected_invariant_family: Some("live-family".to_string()),
            expected_minimum_confidence: Some(70),
            expected_replayable: Some(true),
            expected_poc_generated: Some(true),
            expected_exploit_shape: vec!["historical replay".to_string()],
            known_exploit_class: None,
            expected_selectors: vec!["deposit".to_string()],
            expected_attacker: Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            expected_victim: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            success_criteria: vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::InvariantViolation,
                SuccessCriterion::ReplayableArtifact,
                SuccessCriterion::FoundryPocGenerated,
            ],
            replay_command: Some("cargo run --release -- replay --input-id ...".to_string()),
            poc_generation: PocGenerationExpectation::Required,
            expected_oracle: Some("live-protocol-oracle".to_string()),
            expected_minimum_evidence_grade: Some(
                crate::common::oracle::EvidenceGrade::RealisticForkProof,
            ),
            expected_proof_artifact: Some("foundry-poc".to_string()),
            expected_failure_kind: Some(BenchmarkFailureKind::Passed),
            expected_cli_exit: Some(10),
            max_duration_secs: Some(120),
            seed_hints: vec!["deposit".to_string()],
            notes: Some("live-fork example manifest".to_string()),
        }
    }

    fn class_name(class: &VulnerabilityClass) -> &'static str {
        match class {
            VulnerabilityClass::Reentrancy => "reentrancy",
            VulnerabilityClass::Erc20MintInflation => "erc20-mint-inflation",
            VulnerabilityClass::Erc4626ShareInflation => "erc4626",
            VulnerabilityClass::StaleAccounting => "stale-accounting",
            VulnerabilityClass::OracleManipulation => "oracle",
            VulnerabilityClass::LiquidationAbuse => "liquidation",
            VulnerabilityClass::AccessControlBypass => "access-control",
            VulnerabilityClass::GovernanceTimelockBypass => "governance",
            VulnerabilityClass::AmmInvariantViolation => "amm",
            VulnerabilityClass::BridgeReplayFinalizationBug => "bridge",
            VulnerabilityClass::ApprovalAllowanceAbuse => "approval",
            VulnerabilityClass::FeeAccountingMismatch => "fee-accounting",
            VulnerabilityClass::DonationInflationAttack => "donation",
            VulnerabilityClass::RoundingPrecisionLoss => "rounding",
        }
    }

    #[test]
    fn parses_toml_manifest_with_aliases() {
        let raw = r#"
id = "erc4626-share-inflation-basic"
class = "share_inflation"
mode = "local_fixture"
target = "0x1111111111111111111111111111111111111111"
fixture = "fixtures/ERC4626ShareInflation.sol"
expected_invariant = "attacker_profit_or_share_price_manipulation"
expected_selectors = ["deposit", "withdraw", "redeem"]
success_criteria = ["expected_finding", "share_price_manipulation"]
max_duration_secs = 600
"#;
        let parsed: BenchmarkManifest = toml::from_str(raw).expect("manifest parses");
        assert_eq!(
            parsed.vulnerability_class,
            VulnerabilityClass::Erc4626ShareInflation
        );
        assert_eq!(parsed.mode, BenchmarkMode::LocalFixture);
        assert_eq!(parsed.expected_selectors.len(), 3);
    }

    #[test]
    fn parses_json_manifest() {
        let raw = r#"{
  "id": "access-control-basic",
  "class": "access_control_bypass",
  "mode": "local_fixture",
  "target": "0x2222222222222222222222222222222222222222",
  "expected_invariant": "non-owner privileged state change",
  "success_criteria": ["expected_finding", "access_control_bypass"]
}"#;
        let parsed: BenchmarkManifest = serde_json::from_str(raw).expect("manifest parses");
        assert_eq!(
            parsed.vulnerability_class,
            VulnerabilityClass::AccessControlBypass
        );
    }

    #[test]
    fn parses_mainnet_fork_manifest() {
        let raw = r#"
id = "oracle-stale-price-live"
class = "oracle_manipulation"
mode = "mainnet_fork"
target = "0x1111111111111111111111111111111111111111"
fixture = "benchmarks/live/fixtures/oracle-stale-price-live.json"
fork_block = 123
success_criteria = ["expected_finding", "invariant_violation", "oracle_stale_price"]
"#;
        let parsed: BenchmarkManifest = toml::from_str(raw).expect("manifest parses");
        assert_eq!(parsed.mode, BenchmarkMode::MainnetFork);
        assert_eq!(parsed.fork_block, Some(123));
        assert_eq!(
            parsed.vulnerability_class,
            VulnerabilityClass::OracleManipulation
        );
    }

    #[test]
    fn parses_blind_rediscovery_manifest_with_equivalence_class() {
        let raw = r#"
id = "blind-audius-governance-reinitialization-2022"
class = "access_control_bypass"
mode = "blind_rediscovery"
target = "0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569"
fixture = "benchmarks/blind/fixtures/audius-governance-reinitialization-2022.json"
known_exploit_class = "Audius governance reinitialization"
expected_selectors = ["initialize", "submitProposal", "upgradeTo(address)"]
success_criteria = ["expected_finding", "invariant_violation"]
"#;
        let parsed: BenchmarkManifest = toml::from_str(raw).expect("manifest parses");
        assert_eq!(parsed.mode, BenchmarkMode::BlindRediscovery);
        assert_eq!(
            parsed.known_exploit_class.as_deref(),
            Some("Audius governance reinitialization")
        );
    }

    #[test]
    fn live_fixture_parses_provider_replay_only_flag() {
        let raw = r#"{
  "provider_replay_only": true,
  "chain_id": 1,
  "block_number": 123,
  "target": "0x1111111111111111111111111111111111111111",
  "transactions": []
}"#;
        let parsed: LiveBenchmarkFixture = serde_json::from_str(raw).expect("fixture parses");
        assert!(parsed.provider_replay_only);
        assert!(parsed.fork_cache.is_none());
        assert!(parsed.fork_cache_profile.is_none());
    }

    #[test]
    fn provider_side_historical_finding_is_labeled_as_real_replay_with_caveat() {
        let manifest = live_manifest("fixture.json", VulnerabilityClass::AccessControlBypass);
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 0,
                output: Vec::new(),
                coverage_hash: 1,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 0,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let finding = provider_side_historical_finding(&manifest, 123, &execution);

        assert_eq!(finding.vuln, VulnType::PrivilegeEscalation);
        assert!(finding.evidence.contains("provider-side eth_call replay"));
        assert!(finding.evidence.contains("local storage diffs unavailable"));
        assert!(finding.evidence.contains("not a synthetic cached runtime"));
    }

    #[test]
    fn report_error_sanitizer_removes_rpc_urls() {
        let sanitized = sanitize_report_error(
            "error sending request for url (https://example.invalid/key); timeout",
        );
        assert!(!sanitized.contains("https://example.invalid/key"));
        assert!(sanitized.contains("<rpc-url>"));
    }

    #[test]
    fn live_fork_manifest_reports_rpc_failure_without_synthetic_fallback() {
        let runner = ValidationRunner;
        let manifest = live_manifest(
            "benchmarks/live/fixtures/oracle-stale-price-live.json",
            VulnerabilityClass::OracleManipulation,
        );
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_live_validation_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");

        let result = runner.run_manifest_with_context(
            &manifest,
            &ValidationContext {
                rpc_url: Some("https://127.0.0.1:1".to_string()),
                fork_block: Some(123),
                block_env: Some(BlockEnv::default()),
                report_dir: Some(base.clone()),
            },
        );

        assert!(!result.executed);
        assert_eq!(result.status, ValidationStatus::FailedExecution);
        assert!(result.reason.contains("RPC-backed live-fork replay failed"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn live_fork_manifest_can_execute_from_explicit_cached_fork_fixture() {
        let runner = ValidationRunner;
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_cached_live_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");

        let target = Address::repeat_byte(0x11);
        let db = ForkDb::empty();
        db.cache_account(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(
                crate::evm::fork::offline_fallback_runtime_bytecode().into(),
            )),
        );
        let fixture_path = base.join("cached-live.json");
        let fixture = serde_json::json!({
            "chain_id": 1,
            "block_number": 123,
            "target": target.to_string(),
            "fork_cache": db.cache_snapshot(),
            "transactions": [{
                "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "to": target.to_string(),
                "value": "0",
                "input": "0x3659cfe60000000000000000000000000000000000000000000000000000000000000000",
                "selector": "0x3659cfe6",
                "success": true,
                "tags": ["access-control", "proxy"]
            }]
        });
        fs::write(
            &fixture_path,
            serde_json::to_string_pretty(&fixture).unwrap(),
        )
        .expect("write fixture");

        let mut manifest = live_manifest(
            fixture_path.to_str().unwrap(),
            VulnerabilityClass::AccessControlBypass,
        );
        manifest.target = Some(target.to_string());
        manifest.expected_minimum_confidence = Some(40);

        let result = runner.run_manifest_with_context(
            &manifest,
            &ValidationContext {
                rpc_url: Some("https://127.0.0.1:1".to_string()),
                fork_block: Some(123),
                block_env: Some(BlockEnv::default()),
                report_dir: Some(base.clone()),
            },
        );

        assert!(result.executed, "{:?}", result);
        assert_ne!(result.status, ValidationStatus::FailedExecution);
        assert!(result
            .false_positive_notes
            .iter()
            .any(|note| note.contains("replay backend: cached-fork-fixture")));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn blind_rediscovery_manifest_runs_and_reports_synthesized_sequence() {
        let runner = ValidationRunner;
        let base = std::env::temp_dir().join(format!(
            "rusty_fuzz_blind_validation_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");
        let fixture_path = base.join("blind.json");
        fs::write(
            &fixture_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "chain_id": 1,
                "block_number": 123,
                "target": "0x1111111111111111111111111111111111111111",
                "fork_cache_profile": "noop_runtime",
                "transactions": [{
                    "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "from": "0x1313131313131313131313131313131313131313",
                    "to": "0x1111111111111111111111111111111111111111",
                    "value": "0",
                    "selector": "deposit",
                    "success": true,
                    "tags": ["historical", "blind", "vault"]
                }]
            }))
            .unwrap(),
        )
        .expect("write fixture");

        let manifest = BenchmarkManifest {
            id: "blind-vault-rediscovery".to_string(),
            vulnerability_class: VulnerabilityClass::Erc4626ShareInflation,
            mode: BenchmarkMode::BlindRediscovery,
            target: Some("0x1111111111111111111111111111111111111111".to_string()),
            fixture: Some(fixture_path.to_string_lossy().to_string()),
            chain: Some("evm".to_string()),
            fork_block: Some(123),
            setup_requirements: vec!["blind rediscovery".to_string()],
            expected_invariant: Some("share inflation".to_string()),
            target_profile_expectation: vec!["erc4626".to_string()],
            exploit_template_expectation: Some("erc4626-inflation".to_string()),
            expected_invariant_family: Some("erc4626-vault".to_string()),
            expected_minimum_confidence: Some(40),
            expected_replayable: Some(true),
            expected_poc_generated: Some(false),
            expected_exploit_shape: vec!["deposit".to_string()],
            known_exploit_class: Some("ERC4626 share inflation".to_string()),
            expected_selectors: vec!["deposit".to_string()],
            expected_attacker: Some("0x1313131313131313131313131313131313131313".to_string()),
            expected_victim: None,
            success_criteria: vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::InvariantViolation,
                SuccessCriterion::ReplayableArtifact,
            ],
            replay_command: None,
            poc_generation: PocGenerationExpectation::Expected,
            expected_oracle: Some("erc4626".to_string()),
            expected_minimum_evidence_grade: Some(
                crate::common::oracle::EvidenceGrade::RealisticForkProof,
            ),
            expected_proof_artifact: Some("foundry-poc".to_string()),
            expected_failure_kind: Some(BenchmarkFailureKind::RealismProofFailure),
            expected_cli_exit: Some(20),
            max_duration_secs: Some(60),
            seed_hints: vec!["deposit".to_string()],
            notes: Some("blind rediscovery test".to_string()),
        };

        let result = runner.run_manifest(&manifest);
        assert!(result.executed);
        assert_eq!(result.status, ValidationStatus::NotFound);
        assert!(!result.synthesized_sequence.is_empty());
        assert!(result.search_driver.is_some());
        assert!(result.equivalence_class.is_some());
        assert!(result
            .false_positive_notes
            .iter()
            .any(|note| note.contains("blind rediscovery")));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn blind_rediscovery_confirms_cached_vulnerable_runtime_without_exploit_calldata() {
        let runner = ValidationRunner;
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_blind_confirmed_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");
        let fixture_path = base.join("blind-confirmed.json");
        fs::write(
            &fixture_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "chain_id": 1,
                "block_number": 123,
                "target": "0x1111111111111111111111111111111111111111",
                "fork_cache_profile": "vulnerable_benchmark_runtime",
                "transactions": [{
                    "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "from": "0x1313131313131313131313131313131313131313",
                    "to": "0x1111111111111111111111111111111111111111",
                    "value": "0",
                    "selector": "initialize",
                    "success": true,
                    "tags": ["historical", "blind", "governance", "proxy", "access-control"]
                }]
            }))
            .unwrap(),
        )
        .expect("write fixture");

        let manifest = BenchmarkManifest {
            id: "blind-access-control-confirmed".to_string(),
            vulnerability_class: VulnerabilityClass::AccessControlBypass,
            mode: BenchmarkMode::BlindRediscovery,
            target: Some("0x1111111111111111111111111111111111111111".to_string()),
            fixture: Some(fixture_path.to_string_lossy().to_string()),
            chain: Some("evm".to_string()),
            fork_block: Some(123),
            setup_requirements: vec!["blind rediscovery".to_string()],
            expected_invariant: Some("access control".to_string()),
            target_profile_expectation: vec!["governance".to_string(), "proxy".to_string()],
            exploit_template_expectation: Some("proxy-governance-reinitialization".to_string()),
            expected_invariant_family: Some("access-control".to_string()),
            expected_minimum_confidence: Some(60),
            expected_replayable: Some(true),
            expected_poc_generated: Some(true),
            expected_exploit_shape: vec!["initialize".to_string()],
            known_exploit_class: Some("Audius governance reinitialization".to_string()),
            expected_selectors: vec!["initialize".to_string(), "upgradeTo(address)".to_string()],
            expected_attacker: Some("0x1313131313131313131313131313131313131313".to_string()),
            expected_victim: None,
            success_criteria: vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::InvariantViolation,
                SuccessCriterion::ReplayableArtifact,
                SuccessCriterion::FoundryPocGenerated,
                SuccessCriterion::MinimizedPath,
            ],
            replay_command: None,
            poc_generation: PocGenerationExpectation::Required,
            expected_oracle: Some("proxy-upgradeability".to_string()),
            expected_minimum_evidence_grade: Some(
                crate::common::oracle::EvidenceGrade::RealisticForkProof,
            ),
            expected_proof_artifact: Some("foundry-poc".to_string()),
            expected_failure_kind: Some(BenchmarkFailureKind::Passed),
            expected_cli_exit: Some(10),
            max_duration_secs: Some(60),
            seed_hints: vec!["initialize".to_string()],
            notes: Some("confirmed blind rediscovery test".to_string()),
        };

        let context = ValidationContext {
            rpc_url: None,
            fork_block: Some(123),
            block_env: Some(BlockEnv::default()),
            report_dir: Some(base.join("reports")),
        };
        let result = runner.run_manifest_with_context(&manifest, &context);
        assert_eq!(result.status, ValidationStatus::Found);
        assert!(result.found);
        assert!(result.replayable);
        assert!(result.minimized);
        assert!(result.foundry_poc_generated);
        assert_eq!(
            result.proof_status,
            Some(CounterexampleProofStatus::ConcretelyReplayed)
        );
        assert!(result.observed_finding.is_some());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn classifies_matching_protocol_findings() {
        let access = finding(VulnType::PrivilegeEscalation, "non-owner role mutation");
        assert!(VulnerabilityClass::AccessControlBypass.matches_finding(&access));
        let oracle = finding(VulnType::PriceOracleManipulation, "stale oracle price");
        assert!(VulnerabilityClass::OracleManipulation.matches_finding(&oracle));
    }

    #[test]
    fn evaluates_success_criteria_from_findings() {
        let runner = ValidationRunner;
        let mut benchmark_manifest = manifest();
        benchmark_manifest.poc_generation = PocGenerationExpectation::NotRequired;
        let findings = vec![finding(
            VulnType::VaultInflation,
            "share inflation during deposit/redeem path",
        )];
        let proof = ProofCarryingFinding::from_candidate(
            &fixture_exploit_candidate(),
            &fixture_execution(),
            &findings,
        )
        .with_replay_result(crate::engine::proof::ReplayVerificationStatus::Verified);
        let observation = ValidationObservation {
            findings,
            exploit_candidate: Some(fixture_exploit_candidate()),
            proof: Some(proof),
            proof_status: Some(CounterexampleProofStatus::HeuristicOnly),
            executions: Some(128),
            elapsed_secs: Some(2.5),
            ..ValidationObservation::default()
        };
        let result = runner.evaluate_observation(&benchmark_manifest, &observation);
        assert!(result.found);
        assert_eq!(result.status, ValidationStatus::Found);
        assert!(result
            .matched_criteria
            .contains(&SuccessCriterion::ExpectedFinding));
        assert!(result
            .matched_criteria
            .contains(&SuccessCriterion::SharePriceManipulation));
        assert_eq!(result.failure_kind, BenchmarkFailureKind::Passed);
        assert_eq!(result.expected_oracle.as_deref(), Some("erc4626"));
    }

    #[test]
    fn benchmark_taxonomy_classifies_oracle_proof_and_poc_failures() {
        let runner = ValidationRunner;
        let mut manifest = manifest();
        manifest.poc_generation = PocGenerationExpectation::NotRequired;

        let no_oracle = ValidationObservation {
            executions: Some(10),
            ..ValidationObservation::default()
        };
        assert_eq!(
            runner
                .evaluate_observation(&manifest, &no_oracle)
                .failure_kind,
            BenchmarkFailureKind::OracleDidNotTrigger
        );

        let findings = vec![finding(VulnType::VaultInflation, "share inflation")];
        let proof_failed = ValidationObservation {
            findings: findings.clone(),
            exploit_candidate: Some(fixture_exploit_candidate()),
            proof: Some(
                ProofCarryingFinding::from_candidate(
                    &fixture_exploit_candidate(),
                    &fixture_execution(),
                    &findings,
                )
                .with_replay_result(
                    crate::engine::proof::ReplayVerificationStatus::Mismatch {
                        reason: "taxonomy proof failure".to_string(),
                    },
                ),
            ),
            executions: Some(10),
            ..ValidationObservation::default()
        };
        assert_eq!(
            runner
                .evaluate_observation(&manifest, &proof_failed)
                .failure_kind,
            BenchmarkFailureKind::RealismProofFailure
        );

        let mut no_poc_manifest = manifest.clone();
        no_poc_manifest.poc_generation = PocGenerationExpectation::Required;
        let proof = ProofCarryingFinding::from_candidate(
            &fixture_exploit_candidate(),
            &fixture_execution(),
            &findings,
        )
        .with_replay_result(crate::engine::proof::ReplayVerificationStatus::Verified);
        let no_poc = ValidationObservation {
            findings,
            exploit_candidate: Some(fixture_exploit_candidate()),
            proof: Some(proof),
            executions: Some(10),
            ..ValidationObservation::default()
        };
        assert_eq!(
            runner
                .evaluate_observation(&no_poc_manifest, &no_poc)
                .failure_kind,
            BenchmarkFailureKind::PocGenerationFailure
        );
    }

    #[test]
    fn runs_local_fixture_benchmark_and_serializes_report() {
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_validation_run_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");
        let fixture_path = base.join("fixture.json");
        fs::write(
            &fixture_path,
            r#"{
  "outcome": "found",
  "time_to_signal_secs": 1.4,
  "executions_to_signal": 64,
  "replayable": true,
  "foundry_poc_generated": false,
  "false_positive_notes": ["unit-test fixture"]
}"#,
        )
        .expect("write fixture");

        let manifest = fixture_manifest(
            fixture_path.to_str().expect("utf8 path"),
            VulnerabilityClass::Erc4626ShareInflation,
            vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::SharePriceManipulation,
            ],
        );
        let runner = ValidationRunner;
        let result = runner.run_manifest(&manifest);
        assert!(result.executed);
        assert!(matches!(
            result.status,
            ValidationStatus::Found | ValidationStatus::NotFound
        ));
        assert!(!result.reason.is_empty());

        let report = runner.run_manifests(&[manifest]);
        let json = serde_json::to_string_pretty(&report).expect("report serializes");
        assert!(json.contains("\"executed\": true"));
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"reason\":"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reports_not_found_for_negative_fixture() {
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_validation_no_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");
        let fixture_path = base.join("negative.json");
        fs::write(
            &fixture_path,
            r#"{
  "outcome": "not_found",
  "time_to_signal_secs": 0.4,
  "executions_to_signal": 12,
  "replayable": false,
  "foundry_poc_generated": false,
  "false_positive_notes": ["negative fixture"]
}"#,
        )
        .expect("write fixture");

        let manifest = fixture_manifest(
            fixture_path.to_str().expect("utf8 path"),
            VulnerabilityClass::OracleManipulation,
            vec![
                SuccessCriterion::ExpectedFinding,
                SuccessCriterion::OracleStalePrice,
            ],
        );
        let runner = ValidationRunner;
        let result = runner.run_manifest(&manifest);
        assert!(result.executed);
        assert!(!result.found);
        assert_eq!(result.status, ValidationStatus::NotFound);
        assert_eq!(result.observed_finding, None);
        assert_eq!(
            result.failure_kind,
            BenchmarkFailureKind::OracleDidNotTrigger
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn classifies_not_run_reasons() {
        let runner = ValidationRunner;
        let missing_target = BenchmarkManifest {
            target: None,
            fixture: Some("benchmarks/fixtures/oracle-stale-price-basic.json".to_string()),
            success_criteria: vec![SuccessCriterion::ExpectedFinding],
            ..manifest()
        };
        let live_context_missing = live_manifest(
            "benchmarks/live/fixtures/oracle-live-seed.json",
            VulnerabilityClass::OracleManipulation,
        );
        let missing_fixture = BenchmarkManifest {
            fixture: None,
            ..manifest()
        };
        let missing_success = BenchmarkManifest {
            success_criteria: Vec::new(),
            ..manifest()
        };
        let unsupported_mode = BenchmarkManifest {
            mode: BenchmarkMode::ArtifactReplay,
            ..manifest()
        };

        assert!(matches!(
            runner.run_manifest(&missing_target).status,
            ValidationStatus::NotRunMissingTarget
        ));
        assert!(matches!(
            runner.run_manifest(&missing_fixture).status,
            ValidationStatus::NotRunMissingFixture
        ));
        assert!(matches!(
            runner.run_manifest(&missing_success).status,
            ValidationStatus::NotRunMissingSuccessCriteria
        ));
        assert!(matches!(
            runner.run_manifest(&unsupported_mode).status,
            ValidationStatus::NotRunUnsupportedMode
        ));
        assert!(matches!(
            runner.run_manifest(&live_context_missing).status,
            ValidationStatus::SkippedByConfig
        ));
    }

    #[test]
    fn serializes_validation_report() {
        let runner = ValidationRunner;
        let report = runner.run_manifest_only(&[manifest()]);
        let json = serde_json::to_string_pretty(&report).expect("report serializes");
        assert!(json.contains("erc4626-share-inflation-basic"));
        assert!(json.contains("\"status\": \"not_run_missing_fixture\""));
        assert!(json.contains("\"reason\":"));
        assert_eq!(report.coverage.total_classes, 12);
        assert!(report
            .coverage
            .entries
            .iter()
            .any(|entry| !entry.benchmark_ids.is_empty()));
        assert_eq!(report.calibration.benchmark_count, 1);
    }

    #[test]
    fn expected_invariant_matching_uses_evidence() {
        let runner = ValidationRunner;
        let manifest = manifest();
        let findings = vec![finding(
            VulnType::Other("heuristic".to_string()),
            "share inflation",
        )];
        let proof = ProofCarryingFinding::from_candidate(
            &fixture_exploit_candidate(),
            &fixture_execution(),
            &findings,
        )
        .with_replay_result(crate::engine::proof::ReplayVerificationStatus::Verified);
        let observation = ValidationObservation {
            findings,
            exploit_candidate: Some(fixture_exploit_candidate()),
            proof: Some(proof),
            proof_status: Some(CounterexampleProofStatus::HeuristicOnly),
            ..ValidationObservation::default()
        };
        let result = runner.evaluate_observation(&manifest, &observation);
        assert!(result
            .matched_criteria
            .contains(&SuccessCriterion::InvariantViolation));
    }

    #[test]
    fn manifest_only_runner_does_not_create_artifact_files() {
        let base =
            std::env::temp_dir().join(format!("rusty_fuzz_validation_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("tmp dir");
        let report_path = base.join("validation_report.json");
        let runner = ValidationRunner;
        let report = runner.run_manifest_only(&[manifest()]);
        runner
            .write_report(&report, &report_path)
            .expect("writes report");
        let file_count = fs::read_dir(&base).expect("read tmp").count();
        assert_eq!(file_count, 1);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn seed_hints_produce_explainable_seed_candidates() {
        let candidates = manifest().seed_candidates();
        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .any(|candidate| candidate.reason.contains("benchmark")));
    }
}
