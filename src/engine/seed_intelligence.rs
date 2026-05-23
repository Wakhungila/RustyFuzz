use crate::common::types::SingletonTx;
use crate::engine::foundry_ingest::FoundryHarnessManifest;
use crate::evm::fuzz::{AbiRegistry, EvmInput, MutationProvenance};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedSourceType {
    Synthetic,
    Abi,
    Trace,
    Foundry,
    Manual,
    Historical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedTag {
    Erc20,
    Erc4626,
    Amm,
    Lending,
    Oracle,
    Governance,
    Bridge,
    AccessControl,
    Staking,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedCandidate {
    pub target: Address,
    pub caller: Address,
    pub calldata: Vec<u8>,
    pub selector: Option<[u8; 4]>,
    pub value: U256,
    pub source_type: SeedSourceType,
    pub confidence_score: u64,
    pub reason: String,
    pub touched_addresses: Vec<Address>,
    pub touched_slots: Vec<B256>,
    pub prerequisites: Vec<String>,
    pub tags: BTreeSet<SeedTag>,
}

impl SeedCandidate {
    pub fn into_evm_input(self, base_snapshot_id: u64) -> EvmInput {
        let detail = format!(
            "seed source={:?}, confidence={}, reason={}",
            self.source_type, self.confidence_score, self.reason
        );
        EvmInput {
            txs: vec![SingletonTx {
                input: self.calldata,
                caller: self.caller,
                to: self.target,
                value: self.value,
                is_victim: false,
            }],
            base_snapshot_id,
            waypoints: Vec::new(),
            mutation_provenance: vec![MutationProvenance {
                strategy: "seed_intelligence".to_string(),
                tx_index: Some(0),
                selector: self.selector,
                detail,
            }],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedIntelligenceConfig {
    pub max_candidates: usize,
    pub include_low_confidence_fallbacks: bool,
    pub conservative_startup_only: bool,
}

impl Default for SeedIntelligenceConfig {
    fn default() -> Self {
        Self {
            max_candidates: 64,
            include_low_confidence_fallbacks: true,
            conservative_startup_only: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedIntelligence {
    config: SeedIntelligenceConfig,
}

impl Default for SeedIntelligence {
    fn default() -> Self {
        Self::new(SeedIntelligenceConfig::default())
    }
}

impl SeedIntelligence {
    pub fn new(config: SeedIntelligenceConfig) -> Self {
        Self { config }
    }

    pub fn generate_candidates(
        &self,
        target: Address,
        caller: Address,
        abi_registry: &AbiRegistry,
        foundry_harness: Option<&FoundryHarnessManifest>,
    ) -> Vec<SeedCandidate> {
        let mut candidates = Vec::new();

        for (selector, types) in &abi_registry.functions {
            if self.config.conservative_startup_only && !is_conservative_startup_selector(*selector)
            {
                continue;
            }
            let priority = selector_priority_detail(*selector);
            let calldata = encode_default_call(*selector, types, caller, target);
            candidates.push(SeedCandidate {
                target,
                caller,
                calldata,
                selector: Some(*selector),
                value: default_value_for_selector(*selector, types),
                source_type: SeedSourceType::Abi,
                confidence_score: priority.base_confidence + 10,
                reason: format!(
                    "ABI selector {}: {}",
                    hex::encode(selector),
                    priority.reason
                ),
                touched_addresses: vec![target],
                touched_slots: Vec::new(),
                prerequisites: priority.prerequisites,
                tags: priority.tags,
            });
        }

        if let Some(harness) = foundry_harness {
            for target_selectors in &harness.target_selectors {
                for selector in &target_selectors.selectors {
                    let Some(selector_hex) = selector.selector_hex else {
                        continue;
                    };
                    let priority = selector_priority_detail(selector_hex);
                    let calldata = abi_registry
                        .functions
                        .get(&selector_hex)
                        .map(|types| encode_default_call(selector_hex, types, caller, target))
                        .unwrap_or_else(|| selector_hex.to_vec());

                    candidates.push(SeedCandidate {
                        target,
                        caller,
                        calldata,
                        selector: Some(selector_hex),
                        value: U256::ZERO,
                        source_type: SeedSourceType::Foundry,
                        confidence_score: priority.base_confidence + 20,
                        reason: format!(
                            "Foundry target selector {} from {}:{} ({})",
                            hex::encode(selector_hex),
                            target_selectors.file.display(),
                            target_selectors.line,
                            selector.expression
                        ),
                        touched_addresses: vec![target],
                        touched_slots: Vec::new(),
                        prerequisites: priority.prerequisites,
                        tags: priority.tags,
                    });
                }
            }
        }

        if candidates.is_empty() && self.config.include_low_confidence_fallbacks {
            candidates.push(SeedCandidate {
                target,
                caller,
                calldata: Vec::new(),
                selector: None,
                value: U256::ZERO,
                source_type: SeedSourceType::Synthetic,
                confidence_score: 10,
                reason: "fallback empty calldata; no ABI or Foundry selectors were available"
                    .to_string(),
                touched_addresses: vec![target],
                touched_slots: Vec::new(),
                prerequisites: Vec::new(),
                tags: BTreeSet::from([SeedTag::Unknown]),
            });
        }

        candidates.sort_by(|a, b| {
            b.confidence_score
                .cmp(&a.confidence_score)
                .then_with(|| a.source_type.cmp(&b.source_type))
                .then_with(|| a.selector.cmp(&b.selector))
        });
        candidates.dedup_by(|a, b| {
            a.target == b.target
                && a.caller == b.caller
                && a.calldata == b.calldata
                && a.source_type == b.source_type
        });
        candidates.truncate(self.config.max_candidates);
        candidates
    }

    pub fn parse_trace_seed_bundle_json(&self, json: &str) -> anyhow::Result<Vec<SeedCandidate>> {
        let bundle: TraceSeedBundle = serde_json::from_str(json)?;
        let mut out = Vec::new();

        for tx in bundle.transactions {
            let target = parse_address(tx.target.as_deref().or(tx.to.as_deref()))?;
            let caller = parse_address(tx.caller.as_deref())?;
            let calldata = parse_bytes(tx.calldata.as_deref().or(tx.input.as_deref()))?;
            let selector = calldata.get(0..4).and_then(|bytes| bytes.try_into().ok());
            let priority = selector
                .map(selector_priority_detail)
                .unwrap_or_else(fallback_priority);

            out.push(SeedCandidate {
                target,
                caller,
                calldata,
                selector,
                value: parse_u256(tx.value.as_deref()).unwrap_or_default(),
                source_type: tx.source_type.unwrap_or(SeedSourceType::Trace),
                confidence_score: priority.base_confidence + 15,
                reason: tx
                    .reason
                    .unwrap_or_else(|| "external trace/historical transaction seed".to_string()),
                touched_addresses: tx.touched_addresses.unwrap_or_default(),
                touched_slots: tx.touched_slots.unwrap_or_default(),
                prerequisites: tx.prerequisites.unwrap_or_default(),
                tags: if tx.tags.is_empty() {
                    priority.tags
                } else {
                    tx.tags.into_iter().collect()
                },
            });
        }

        out.sort_by(|a, b| b.confidence_score.cmp(&a.confidence_score));
        out.truncate(self.config.max_candidates);
        Ok(out)
    }
}

fn is_conservative_startup_selector(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        [0x09, 0x5e, 0xa7, 0xb3] // approve(address,uint256)
            | [0xa9, 0x05, 0x9c, 0xbb] // transfer(address,uint256)
            | [0x23, 0xb8, 0x72, 0xdd] // transferFrom(address,address,uint256)
            | [0x18, 0x16, 0x0d, 0xdd] // totalSupply()
            | [0x70, 0xa0, 0x82, 0x31] // balanceOf(address)
    )
}

#[derive(Debug, Clone)]
struct SelectorPriority {
    base_confidence: u64,
    reason: &'static str,
    prerequisites: Vec<String>,
    tags: BTreeSet<SeedTag>,
}

pub fn selector_priority(selector: [u8; 4]) -> u64 {
    selector_priority_profile(selector).base_confidence
}

fn selector_priority_detail(selector: [u8; 4]) -> SelectorPriority {
    selector_priority_profile(selector)
}

fn selector_priority_profile(selector: [u8; 4]) -> SelectorPriority {
    for spec in risk_selector_specs() {
        if spec.selector == selector {
            return SelectorPriority {
                base_confidence: spec.confidence,
                reason: spec.reason,
                prerequisites: spec
                    .prerequisites
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                tags: spec.tags.iter().cloned().collect(),
            };
        }
    }

    fallback_priority()
}

fn fallback_priority() -> SelectorPriority {
    SelectorPriority {
        base_confidence: 25,
        reason: "unknown selector; selector validity is useful but semantic risk is unknown",
        prerequisites: Vec::new(),
        tags: BTreeSet::from([SeedTag::Unknown]),
    }
}

#[derive(Debug, Clone)]
struct RiskSelectorSpec {
    selector: [u8; 4],
    confidence: u64,
    reason: &'static str,
    prerequisites: &'static [&'static str],
    tags: &'static [SeedTag],
}

fn risk_selector_specs() -> Vec<RiskSelectorSpec> {
    [
        (
            "deposit(uint256,address)",
            88,
            "vault deposit/mint path can create share-accounting dependencies",
            &["asset approval or payable funding"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "mint(uint256,address)",
            86,
            "vault mint path exercises share issuance and rounding",
            &["asset approval"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "withdraw(uint256,address,address)",
            90,
            "vault withdraw path consumes shares/assets and depends on prior deposits",
            &["prior deposit or share balance"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "redeem(uint256,address,address)",
            90,
            "vault redeem path is high value for share inflation and rounding checks",
            &["prior mint/deposit"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "borrow(address,uint256,uint256,uint16,address)",
            92,
            "borrow path creates debt/collateral dependencies",
            &["collateral deposit"][..],
            &[SeedTag::Lending][..],
        ),
        (
            "repay(address,uint256,uint256,address)",
            72,
            "repay path validates debt accounting and allowance usage",
            &["borrowed debt", "token approval"][..],
            &[SeedTag::Lending, SeedTag::Erc20][..],
        ),
        (
            "liquidationCall(address,address,address,uint256,bool)",
            95,
            "liquidation is an exploit-relevant terminal action",
            &["unhealthy debt position"][..],
            &[SeedTag::Lending][..],
        ),
        (
            "swap(address,bool,int256,uint160,bytes)",
            86,
            "AMM swap path stresses reserves, oracle reads, and price movement",
            &["token approval or pool funding"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "addLiquidity(uint256,uint256)",
            70,
            "liquidity add path changes reserve/share accounting",
            &["token approvals"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "removeLiquidity(uint256)",
            78,
            "liquidity removal is useful after reserve/share setup",
            &["LP balance"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "approve(address,uint256)",
            72,
            "approval unlocks allowance-dependent multi-transaction flows",
            &[],
            &[SeedTag::Erc20][..],
        ),
        (
            "transferFrom(address,address,uint256)",
            80,
            "transferFrom depends on allowance and exposes token accounting bugs",
            &["prior approval"][..],
            &[SeedTag::Erc20][..],
        ),
        (
            "transfer(address,uint256)",
            62,
            "transfer exercises balance accounting and token hooks",
            &["token balance"][..],
            &[SeedTag::Erc20][..],
        ),
        (
            "claim()",
            68,
            "claim path can expose accounting, reward, or bridge finalization issues",
            &["accrued rewards or finalized message"][..],
            &[SeedTag::Staking, SeedTag::Bridge][..],
        ),
        (
            "harvest()",
            70,
            "harvest path exercises reward accounting and external calls",
            &["accrued rewards"][..],
            &[SeedTag::Staking][..],
        ),
        (
            "stake(uint256)",
            72,
            "stake path creates balance/share dependencies",
            &["token approval"][..],
            &[SeedTag::Staking, SeedTag::Erc20][..],
        ),
        (
            "unstake(uint256)",
            78,
            "unstake path depends on prior stake and reward accounting",
            &["prior stake"][..],
            &[SeedTag::Staking][..],
        ),
        (
            "propose(address[],uint256[],bytes[],string)",
            76,
            "governance proposal starts temporal execution chains",
            &["proposal threshold"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "castVote(uint256,uint8)",
            72,
            "vote path creates governance state dependencies",
            &["active proposal"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "queue(uint256)",
            82,
            "queue path should depend on proposal/vote state and timelock rules",
            &["successful proposal"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "execute(uint256)",
            88,
            "execute path is a high-risk privileged terminal action",
            &["queued proposal or authorized role"][..],
            &[SeedTag::Governance, SeedTag::AccessControl][..],
        ),
        (
            "settle(uint256)",
            74,
            "settlement paths often finalize accounting after delayed state",
            &["open position/order"][..],
            &[SeedTag::Bridge, SeedTag::Amm][..],
        ),
        (
            "finalize(bytes)",
            84,
            "bridge finalization should depend on proof/replay state",
            &["valid message proof"][..],
            &[SeedTag::Bridge][..],
        ),
    ]
    .into_iter()
    .map(
        |(signature, confidence, reason, prerequisites, tags)| RiskSelectorSpec {
            selector: function_selector(signature),
            confidence,
            reason,
            prerequisites,
            tags,
        },
    )
    .collect()
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

fn encode_default_call(
    selector: [u8; 4],
    types: &[DynSolType],
    caller: Address,
    target: Address,
) -> Vec<u8> {
    let values: Vec<_> = types
        .iter()
        .enumerate()
        .map(|(idx, ty)| default_sol_value(ty, idx, caller, target))
        .collect();
    let mut calldata = selector.to_vec();
    calldata.extend_from_slice(&DynSolValue::Tuple(values).abi_encode());
    calldata
}

fn default_sol_value(ty: &DynSolType, idx: usize, caller: Address, target: Address) -> DynSolValue {
    match ty {
        DynSolType::Uint(size) => DynSolValue::Uint(default_uint(idx), *size),
        DynSolType::Int(size) => DynSolValue::Int(alloy_primitives::I256::ZERO, *size),
        DynSolType::Address => {
            let address = if idx == 0 { caller } else { target };
            DynSolValue::Address(address)
        }
        DynSolType::Bool => DynSolValue::Bool(true),
        DynSolType::Bytes => DynSolValue::Bytes(vec![0u8; 32]),
        DynSolType::String => DynSolValue::String("RustyFuzz".to_string()),
        DynSolType::Tuple(inner) => DynSolValue::Tuple(
            inner
                .iter()
                .enumerate()
                .map(|(inner_idx, inner_ty)| default_sol_value(inner_ty, inner_idx, caller, target))
                .collect(),
        ),
        DynSolType::Array(inner) => {
            DynSolValue::Array(vec![default_sol_value(inner, idx, caller, target)])
        }
        DynSolType::FixedArray(inner, len) => DynSolValue::FixedArray(
            (0..*len)
                .map(|array_idx| default_sol_value(inner, array_idx, caller, target))
                .collect(),
        ),
        _ => DynSolValue::Uint(default_uint(idx), 256),
    }
}

fn default_uint(idx: usize) -> U256 {
    match idx {
        0 => U256::from(10u128.pow(18)),
        1 => U256::from(10u128.pow(6)),
        _ => U256::from(1),
    }
}

fn default_value_for_selector(selector: [u8; 4], types: &[DynSolType]) -> U256 {
    if selector == function_selector("deposit()") || types.is_empty() {
        U256::ZERO
    } else {
        U256::ZERO
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TraceSeedBundle {
    #[serde(default)]
    transactions: Vec<TraceSeedTransaction>,
}

#[derive(Debug, Clone, Deserialize)]
struct TraceSeedTransaction {
    target: Option<String>,
    to: Option<String>,
    caller: Option<String>,
    calldata: Option<String>,
    input: Option<String>,
    value: Option<String>,
    #[serde(default)]
    source_type: Option<SeedSourceType>,
    reason: Option<String>,
    #[serde(default)]
    touched_addresses: Option<Vec<Address>>,
    #[serde(default)]
    touched_slots: Option<Vec<B256>>,
    #[serde(default)]
    prerequisites: Option<Vec<String>>,
    #[serde(default)]
    tags: Vec<SeedTag>,
}

fn parse_address(value: Option<&str>) -> anyhow::Result<Address> {
    let value = value.ok_or_else(|| anyhow::anyhow!("trace seed missing address"))?;
    Address::from_str(value).map_err(|err| anyhow::anyhow!("invalid address `{value}`: {err}"))
}

fn parse_bytes(value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let value = value.unwrap_or_default().trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    Ok(hex::decode(value)?)
}

fn parse_u256(value: Option<&str>) -> anyhow::Result<U256> {
    let Some(value) = value else {
        return Ok(U256::ZERO);
    };
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        let bytes = hex::decode(hex)?;
        return Ok(U256::from_be_slice(&bytes));
    }
    U256::from_str(value).map_err(|err| anyhow::anyhow!("invalid U256 `{value}`: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::DynSolType;

    #[test]
    fn selector_prioritization_prefers_exploit_relevant_flows() {
        let withdraw = function_selector("withdraw(uint256,address,address)");
        let unknown = [0xde, 0xad, 0xbe, 0xef];

        assert!(selector_priority(withdraw) > selector_priority(unknown));
    }

    #[test]
    fn abi_generation_produces_explainable_protocol_seed() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let mut abi = AbiRegistry::default();
        let approve = function_selector("approve(address,uint256)");
        abi.functions
            .insert(approve, vec![DynSolType::Address, DynSolType::Uint(256)]);

        let seeds = SeedIntelligence::default().generate_candidates(target, caller, &abi, None);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].selector, Some(approve));
        assert!(seeds[0].confidence_score >= 70);
        assert!(seeds[0].tags.contains(&SeedTag::Erc20));
        assert!(seeds[0].reason.contains("ABI selector"));
        assert!(seeds[0].calldata.len() > 4);
    }

    #[test]
    fn trace_seed_parser_accepts_historical_transaction_json() {
        let json = r#"{
          "transactions": [{
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "caller": "0x1313131313131313131313131313131313131313",
            "input": "0x095ea7b3000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "value": "0",
            "reason": "historical approve"
          }]
        }"#;

        let seeds = SeedIntelligence::default()
            .parse_trace_seed_bundle_json(json)
            .expect("trace seed bundle");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Trace);
        assert_eq!(
            seeds[0].selector,
            Some(function_selector("approve(address,uint256)"))
        );
        assert!(seeds[0].tags.contains(&SeedTag::Erc20));
    }

    #[test]
    fn fallback_seed_is_low_confidence_and_explained() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let seeds = SeedIntelligence::default().generate_candidates(
            target,
            caller,
            &AbiRegistry::default(),
            None,
        );

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Synthetic);
        assert!(seeds[0].confidence_score < 20);
        assert!(seeds[0].reason.contains("fallback"));
    }

    #[test]
    fn conservative_startup_filters_complex_protocol_selectors() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let mut abi = AbiRegistry::default();
        let liquidation =
            function_selector("liquidationCall(address,address,address,uint256,bool)");
        let approve = function_selector("approve(address,uint256)");
        abi.functions.insert(
            liquidation,
            vec![
                DynSolType::Address,
                DynSolType::Address,
                DynSolType::Address,
                DynSolType::Uint(256),
                DynSolType::Bool,
            ],
        );
        abi.functions
            .insert(approve, vec![DynSolType::Address, DynSolType::Uint(256)]);

        let seeds = SeedIntelligence::new(SeedIntelligenceConfig {
            max_candidates: 8,
            include_low_confidence_fallbacks: true,
            conservative_startup_only: true,
        })
        .generate_candidates(target, caller, &abi, None);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].selector, Some(approve));
    }
}
