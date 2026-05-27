use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SatoriRun {
    pub run_id: String,
    pub root: PathBuf,
    pub run_dir: PathBuf,
    pub started_at: DateTime<Utc>,
    pub config: SatoriConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SatoriConfig {
    pub model: String,
    pub max_critical_functions: usize,
    pub max_hypotheses_per_function: usize,
    pub min_confidence: f64,
    pub validate: bool,
    pub generate_jobs: bool,
    pub run_forge_tests: bool,
    pub run_slither: bool,
    pub cache_dir: PathBuf,
    pub memory_path: PathBuf,
}

impl Default for SatoriConfig {
    fn default() -> Self {
        Self {
            model: "o3".to_string(),
            max_critical_functions: 8,
            max_hypotheses_per_function: 2,
            min_confidence: 0.4,
            validate: false,
            generate_jobs: true,
            run_forge_tests: false,
            run_slither: true,
            cache_dir: PathBuf::from("satori/cache"),
            memory_path: PathBuf::from("satori/memory/events.jsonl"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectModel {
    pub root: PathBuf,
    pub project_type: ProjectType,
    pub source_files: Vec<SourceFile>,
    pub test_files: Vec<PathBuf>,
    pub docs: Vec<SourceFile>,
    pub foundry_toml: Option<PathBuf>,
    pub hardhat_config: Option<PathBuf>,
    pub package_json: Option<PathBuf>,
    pub remappings: Option<PathBuf>,
    pub detected_protocols: Vec<ProtocolType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProjectType {
    Foundry,
    Hardhat,
    Mixed,
    Solidity,
    Vyper,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub language: String,
    pub content_hash: String,
    pub bytes: usize,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StaticAnalysisBundle {
    pub tool_runs: Vec<ToolRun>,
    pub contracts: Vec<ContractSummary>,
    pub functions: Vec<FunctionSummary>,
    pub detector_signals: Vec<DetectorSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRun {
    pub tool: String,
    pub command: String,
    pub available: bool,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout_snippet: String,
    pub stderr_snippet: String,
    pub artifact: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSummary {
    pub name: String,
    pub file: PathBuf,
    pub protocol_hints: Vec<ProtocolType>,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub id: String,
    pub contract: String,
    pub name: String,
    pub signature: String,
    pub selector: Option<String>,
    pub file: PathBuf,
    pub visibility: String,
    pub mutability: String,
    pub modifiers: Vec<String>,
    pub source_snippet: String,
    pub reads: Vec<StateAccess>,
    pub writes: Vec<StateAccess>,
    pub internal_calls: Vec<String>,
    pub external_calls: Vec<ExternalCallSummary>,
    pub detector_signals: Vec<DetectorSignal>,
    pub criticality_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccess {
    pub name: String,
    pub access_type: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallSummary {
    pub target: String,
    pub call_type: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolModel {
    pub protocol_types: Vec<ProtocolType>,
    pub actors: Vec<ActorModel>,
    pub assets: Vec<AssetModel>,
    pub trust_assumptions: Vec<TrustAssumption>,
    pub economic_assumptions: Vec<EconomicAssumption>,
    pub confidence: f64,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolType {
    ERC20,
    ERC4626Vault,
    LendingMarket,
    AMM,
    Staking,
    Bridge,
    Governance,
    LiquidStaking,
    Perps,
    Options,
    Upgradeability,
    Oracle,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorModel {
    pub role: String,
    pub capabilities: Vec<String>,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetModel {
    pub symbol_or_name: String,
    pub asset_type: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAssumption {
    pub subject: String,
    pub assumption: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicAssumption {
    pub invariant: String,
    pub affected_assets: Vec<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SatoriGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPacket {
    pub project_type: ProjectType,
    pub docs_summary: String,
    pub contracts: Vec<ContractSummary>,
    pub critical_functions: Vec<FunctionSummary>,
    pub tool_runs: Vec<ToolRun>,
    pub graph_stats: BTreeMap<String, usize>,
    pub detected_protocol_hints: Vec<ProtocolType>,
    pub top_bug_class_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPacket {
    pub target_function: FunctionSummary,
    pub related_functions: Vec<FunctionSummary>,
    pub protocol_context: ProtocolModel,
    pub relevant_memories: Vec<MemoryEvent>,
    pub known_bug_classes: Vec<String>,
    pub detector_evidence: Vec<DetectorSignal>,
    pub output_constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationPacket {
    pub hypothesis: VulnerabilityHypothesis,
    pub available_abi: Vec<String>,
    pub rustyfuzz_capabilities: Vec<String>,
    pub foundry_capabilities: Vec<String>,
    pub required_output_shape: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityHypothesis {
    pub id: String,
    pub title: String,
    pub bug_class: String,
    pub root_cause: String,
    pub affected_contracts: Vec<String>,
    pub affected_functions: Vec<String>,
    pub evidence_from_context: Vec<String>,
    pub required_conditions: Vec<String>,
    pub attack_sequence: Vec<AttackStep>,
    pub false_positive_checks: Vec<String>,
    pub validation_plan: Vec<ValidationStep>,
    pub suggested_invariants: Vec<CandidateInvariant>,
    pub rustyfuzz_objective: String,
    pub confidence_before_validation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateInvariant {
    pub id: String,
    pub description: String,
    pub check: String,
    pub expected_signal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub calldata_hint: Option<String>,
    pub value_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStep {
    pub tool: String,
    pub action: String,
    pub success_condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAuditResult {
    pub function_id: String,
    pub hypotheses: Vec<VulnerabilityHypothesis>,
    pub candidate_invariants: Vec<CandidateInvariant>,
    pub rejected_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustyFuzzJobSpec {
    pub job_id: String,
    pub hypothesis_id: String,
    pub job_type: String,
    pub target_contract: Option<String>,
    pub bug_class: String,
    pub actors: Vec<String>,
    pub preconditions: Vec<String>,
    pub sequence_template: Vec<AttackStep>,
    pub mutation_focus: Vec<String>,
    pub invariants: Vec<CandidateInvariant>,
    pub objective: String,
    pub success_condition: String,
    pub max_depth: usize,
    pub fork_rpc_url: Option<String>,
    pub fork_block: Option<u64>,
    pub abi_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryPocSpec {
    pub hypothesis_id: String,
    pub path: PathBuf,
    pub generated: bool,
    pub compile_attempted: bool,
    pub compile_success: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationVerdict {
    pub hypothesis_id: String,
    pub job_id: Option<String>,
    pub status: ValidationStatus,
    pub proof_status: ProofStatus,
    pub reason: String,
    pub artifacts: Vec<PathBuf>,
    pub economic_impact: Option<EconomicImpact>,
    pub confidence_after_validation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Rejected,
    NeedsMoreContext,
    LikelyFalsePositive,
    PlausibleUnvalidated,
    JobGenerated,
    FoundryPocGenerated,
    FoundryCompiled,
    FoundryFailedToCompile,
    FoundryTestSignal,
    RustyFuzzSignal,
    ValidationFailed,
    ValidatedLocal,
    ValidatedMinimized,
    ValidatedEconomicImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofStatus {
    HeuristicOnly,
    JobGeneratedOnly,
    FoundryCompiled,
    FoundryTestFailedAsExpected,
    RustyFuzzSignal,
    ConcretelyReplayed,
    Minimized,
    NotReproducible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicImpact {
    pub impact_type: String,
    pub attacker_delta: Option<String>,
    pub victim_delta: Option<String>,
    pub protocol_delta: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SatoriReport {
    pub run_id: String,
    pub project_summary: String,
    pub tool_status: Vec<ToolRun>,
    pub protocol_model: ProtocolModel,
    pub critical_functions: Vec<FunctionSummary>,
    pub hypotheses: Vec<VulnerabilityHypothesis>,
    pub rejected_hypotheses: Vec<String>,
    pub jobs: Vec<RustyFuzzJobSpec>,
    pub foundry_pocs: Vec<FoundryPocSpec>,
    pub validation_verdicts: Vec<ValidationVerdict>,
    pub budget: BudgetReport,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetReport {
    pub model_calls: usize,
    pub cached_model_hits: usize,
    pub approximate_input_tokens: usize,
    pub approximate_output_tokens: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub protocol_type: Option<ProtocolType>,
    pub bug_class: Option<String>,
    pub contract: Option<String>,
    pub function: Option<String>,
    pub tags: Vec<String>,
    pub summary: String,
    pub artifact: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSignal {
    pub detector: String,
    pub tag: String,
    pub confidence: f64,
    pub evidence: String,
}
