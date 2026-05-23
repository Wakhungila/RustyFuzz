use crate::common::oracle::{ProtocolFinding, ProtocolSeverity, VulnType};
use crate::engine::exploit_path::{
    ExploitPathCandidate, MinimizedSequenceStatus, ReplayabilityStatus,
};
use crate::engine::scoring::CampaignScore;
use crate::engine::seed_intelligence::{SeedCandidate, SeedSourceType, SeedTag};
use anyhow::{Context, Result};
use revm::primitives::{keccak256, Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityClass {
    Reentrancy,
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
    ArtifactReplay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PocGenerationExpectation {
    NotRequired,
    Expected,
    Required,
}

impl Default for PocGenerationExpectation {
    fn default() -> Self {
        Self::Expected
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
    pub expected_selectors: Vec<String>,
    pub expected_attacker: Option<String>,
    pub expected_victim: Option<String>,
    #[serde(default)]
    pub success_criteria: Vec<SuccessCriterion>,
    pub replay_command: Option<String>,
    #[serde(default)]
    pub poc_generation: PocGenerationExpectation,
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

#[derive(Debug, Clone, Default)]
pub struct ValidationObservation {
    pub findings: Vec<ProtocolFinding>,
    pub exploit_candidate: Option<ExploitPathCandidate>,
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
    NotRun,
    NoSignal,
    Found,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkValidationResult {
    pub benchmark_id: String,
    #[serde(rename = "class")]
    pub vulnerability_class: VulnerabilityClass,
    pub status: ValidationStatus,
    pub found: bool,
    pub finding_type: Option<String>,
    pub invariant_id: Option<String>,
    pub selected_exploit_template: Option<String>,
    pub confidence: u64,
    pub exploit_path_length: Option<usize>,
    pub minimized: bool,
    pub replayable: bool,
    pub foundry_poc_generated: bool,
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
    pub benchmarks: Vec<BenchmarkValidationResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationSummary {
    pub total: usize,
    pub found: usize,
    pub not_run: usize,
    pub no_signal: usize,
    pub inconclusive: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationRunner;

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
        let benchmarks = manifests
            .iter()
            .map(|manifest| {
                let seed_count = manifest.seed_candidates().len();
                BenchmarkValidationResult {
                    benchmark_id: manifest.id.clone(),
                    vulnerability_class: manifest.vulnerability_class.clone(),
                    status: ValidationStatus::NotRun,
                    found: false,
                    finding_type: None,
                    invariant_id: manifest.expected_invariant_family.clone().or_else(|| manifest.expected_invariant.clone()),
                    selected_exploit_template: manifest.exploit_template_expectation.clone(),
                    confidence: 0,
                    exploit_path_length: None,
                    minimized: false,
                    replayable: false,
                    foundry_poc_generated: false,
                    executions_to_signal: None,
                    time_to_signal_secs: None,
                    false_positive_notes: vec![format!(
                        "manifest loaded; live campaign validation not run in manifest-only mode; seed_hints={seed_count}"
                    )],
                    artifact_path: None,
                    matched_criteria: Vec::new(),
                    missing_criteria: manifest.normalized_success_criteria(),
                }
            })
            .collect::<Vec<_>>();
        report_from_results(benchmarks)
    }

    pub fn evaluate_observation(
        &self,
        manifest: &BenchmarkManifest,
        observation: ValidationObservation,
    ) -> BenchmarkValidationResult {
        let expected = manifest.normalized_success_criteria();
        let matched = expected
            .iter()
            .filter(|criterion| criterion_matches(manifest, criterion, &observation))
            .cloned()
            .collect::<Vec<_>>();
        let missing = expected
            .iter()
            .filter(|criterion| !matched.contains(criterion))
            .cloned()
            .collect::<Vec<_>>();
        let strongest = strongest_matching_finding(manifest, &observation.findings);
        let candidate = observation.exploit_candidate.as_ref();
        let confidence = confidence(manifest, &observation, strongest, candidate);
        let found = !matched.is_empty()
            && missing
                .iter()
                .all(|criterion| !is_required_criterion(manifest, criterion));
        let status = if found {
            ValidationStatus::Found
        } else if observation.findings.is_empty() && candidate.is_none() {
            ValidationStatus::NoSignal
        } else {
            ValidationStatus::Inconclusive
        };

        BenchmarkValidationResult {
            benchmark_id: manifest.id.clone(),
            vulnerability_class: manifest.vulnerability_class.clone(),
            status,
            found,
            finding_type: strongest
                .map(|finding| finding.vuln.to_string())
                .or_else(|| candidate.and_then(|candidate| candidate.violated_invariant.clone())),
            invariant_id: manifest
                .expected_invariant_family
                .clone()
                .or_else(|| manifest.expected_invariant.clone()),
            selected_exploit_template: manifest.exploit_template_expectation.clone(),
            confidence,
            exploit_path_length: candidate.map(|candidate| candidate.sequence.len()),
            minimized: candidate.is_some_and(|candidate| {
                candidate.minimized_sequence_status == MinimizedSequenceStatus::Minimized
            }),
            replayable: candidate.is_some_and(|candidate| {
                candidate.replayability_status == ReplayabilityStatus::Replayable
            }) || observation.artifact_path.is_some(),
            foundry_poc_generated: observation.foundry_poc_path.is_some(),
            executions_to_signal: observation.executions,
            time_to_signal_secs: observation.elapsed_secs,
            false_positive_notes: observation.false_positive_notes,
            artifact_path: observation.artifact_path,
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
    let mut by_status = BTreeMap::<String, usize>::new();
    for result in &results {
        *by_status.entry(format!("{:?}", result.status)).or_default() += 1;
    }
    let summary = ValidationSummary {
        total: results.len(),
        found: results.iter().filter(|result| result.found).count(),
        not_run: *by_status.get("NotRun").unwrap_or(&0),
        no_signal: *by_status.get("NoSignal").unwrap_or(&0),
        inconclusive: *by_status.get("Inconclusive").unwrap_or(&0),
    };
    ValidationReport {
        generated_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        summary,
        benchmarks: results,
    }
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

fn confidence(
    manifest: &BenchmarkManifest,
    observation: &ValidationObservation,
    strongest: Option<&ProtocolFinding>,
    candidate: Option<&ExploitPathCandidate>,
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
    severity
        .max(candidate_confidence)
        .saturating_add(score_pressure)
        .saturating_add(selector_pressure)
        .min(100)
}

fn is_required_criterion(manifest: &BenchmarkManifest, criterion: &SuccessCriterion) -> bool {
    matches!(
        criterion,
        SuccessCriterion::ReplayableArtifact | SuccessCriterion::FoundryPocGenerated
    ) && manifest.poc_generation == PocGenerationExpectation::Required
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
            VulnerabilityClass::LiquidationAbuse => text.contains("liquidat"),
            VulnerabilityClass::AccessControlBypass => {
                matches!(
                    finding.vuln,
                    VulnType::PrivilegeEscalation | VulnType::MissingSignerCheck
                ) || text.contains("access")
                    || text.contains("role")
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
                text.contains("bridge")
                    || text.contains("replay")
                    || text.contains("finalize")
                    || text.contains("proof")
            }
            VulnerabilityClass::ApprovalAllowanceAbuse => {
                text.contains("approval") || text.contains("allowance") || text.contains("approve")
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
        return bytes.get(0..4).map(|bytes| bytes.try_into().ok()).flatten();
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
    Some(keccak256(signature.as_bytes()).0[0..4].try_into().ok()?)
}

fn vulnerability_tags(class: &VulnerabilityClass) -> BTreeSet<SeedTag> {
    match class {
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
            max_duration_secs: Some(600),
            seed_hints: vec!["0xb6b55f25".to_string()],
            notes: None,
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
    fn classifies_matching_protocol_findings() {
        let access = finding(VulnType::PrivilegeEscalation, "non-owner role mutation");
        assert!(VulnerabilityClass::AccessControlBypass.matches_finding(&access));
        let oracle = finding(VulnType::PriceOracleManipulation, "stale oracle price");
        assert!(VulnerabilityClass::OracleManipulation.matches_finding(&oracle));
    }

    #[test]
    fn evaluates_success_criteria_from_findings() {
        let runner = ValidationRunner;
        let manifest = manifest();
        let observation = ValidationObservation {
            findings: vec![finding(
                VulnType::VaultInflation,
                "share inflation during deposit/redeem path",
            )],
            executions: Some(128),
            elapsed_secs: Some(2.5),
            ..ValidationObservation::default()
        };
        let result = runner.evaluate_observation(&manifest, observation);
        assert!(result.found);
        assert_eq!(result.status, ValidationStatus::Found);
        assert!(result
            .matched_criteria
            .contains(&SuccessCriterion::ExpectedFinding));
        assert!(result
            .matched_criteria
            .contains(&SuccessCriterion::SharePriceManipulation));
    }

    #[test]
    fn serializes_validation_report() {
        let runner = ValidationRunner;
        let report = runner.run_manifest_only(&[manifest()]);
        let json = serde_json::to_string_pretty(&report).expect("report serializes");
        assert!(json.contains("erc4626-share-inflation-basic"));
        assert!(json.contains("not_run"));
    }

    #[test]
    fn expected_invariant_matching_uses_evidence() {
        let runner = ValidationRunner;
        let manifest = manifest();
        let observation = ValidationObservation {
            findings: vec![finding(
                VulnType::Other("heuristic".to_string()),
                "share inflation",
            )],
            ..ValidationObservation::default()
        };
        let result = runner.evaluate_observation(&manifest, observation);
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
