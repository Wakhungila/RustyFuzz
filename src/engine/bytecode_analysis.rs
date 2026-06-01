use crate::engine::target_profile::{
    function_selector, ProtocolType, TargetProfile, TargetProfiler,
};
use revm::primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BytecodeAnalysisReport {
    pub code_len: usize,
    pub push4_selectors: Vec<[u8; 4]>,
    pub dispatch_selectors: Vec<[u8; 4]>,
    pub function_summaries: Vec<FunctionSliceSummary>,
    pub known_selectors: Vec<KnownSelectorEvidence>,
    pub proxy_patterns: Vec<ProxyPattern>,
    pub risk_flags: Vec<BytecodeRiskFlag>,
    pub storage_slots: Vec<StorageSlotEvidence>,
    pub symbolic_summary: SymbolicBytecodeSummary,
    pub opcode_counts: BTreeMap<String, usize>,
    pub target_profile: TargetProfile,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSliceSummary {
    pub selector: [u8; 4],
    pub entry_pc: usize,
    pub signature_hint: Option<String>,
    pub protocol_type_hint: Option<ProtocolType>,
    pub symbolic_summary: SymbolicBytecodeSummary,
    pub behavior: FunctionBehavior,
    pub seed_hints: Vec<String>,
    pub invariant_hints: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionBehavior {
    pub reads_storage: bool,
    pub writes_storage: bool,
    pub makes_external_call: bool,
    pub makes_delegate_call: bool,
    pub makes_static_call: bool,
    pub uses_call_value: bool,
    pub uses_caller: bool,
    pub uses_origin: bool,
    pub branch_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownSelectorEvidence {
    pub selector: [u8; 4],
    pub signature: String,
    pub protocol_type: ProtocolType,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProxyPattern {
    Eip1167MinimalProxy,
    Eip1967ImplementationSlot,
    Eip1967AdminSlot,
    Eip1967BeaconSlot,
    DelegateCallDispatch,
    UpgradeSelector,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeRiskFlag {
    HasDelegateCall,
    HasExternalCall,
    HasStaticCall,
    HasCreate,
    HasCreate2,
    HasSelfDestruct,
    HasSstore,
    HasCallValue,
    HasOrigin,
    PayableSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageSlotEvidence {
    pub slot: B256,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolicBytecodeSummary {
    pub basic_block_count: usize,
    pub reachable_block_count: usize,
    pub max_stack_depth_observed: usize,
    pub branch_conditions: Vec<SymbolicBranch>,
    pub storage_reads: Vec<SymbolicStorageAccess>,
    pub storage_writes: Vec<SymbolicStorageAccess>,
    pub external_calls: Vec<SymbolicCall>,
    pub delegate_calls: Vec<SymbolicCall>,
    pub static_calls: Vec<SymbolicCall>,
    pub value_sensitive: bool,
    pub caller_sensitive: bool,
    pub origin_sensitive: bool,
    pub decompiler_pseudocode: Vec<String>,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolicBranch {
    pub pc: usize,
    pub destination: Option<usize>,
    pub condition: SymbolicValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolicStorageAccess {
    pub pc: usize,
    pub slot: SymbolicValue,
    #[serde(default)]
    pub value: Option<SymbolicValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolicCall {
    pub pc: usize,
    pub kind: String,
    pub target: SymbolicValue,
    pub value: SymbolicValue,
    pub input_offset: SymbolicValue,
    pub input_size: SymbolicValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolicValue {
    Unknown,
    Const(String),
    CalldataWord(String),
    Selector,
    Caller,
    CallValue,
    Origin,
    Storage(Box<SymbolicValue>),
    Add(Box<SymbolicValue>, Box<SymbolicValue>),
    Sub(Box<SymbolicValue>, Box<SymbolicValue>),
    Mul(Box<SymbolicValue>, Box<SymbolicValue>),
    Div(Box<SymbolicValue>, Box<SymbolicValue>),
    And(Box<SymbolicValue>, Box<SymbolicValue>),
    Shr(Box<SymbolicValue>, Box<SymbolicValue>),
    Eq(Box<SymbolicValue>, Box<SymbolicValue>),
    IsZero(Box<SymbolicValue>),
}

pub fn analyze_bytecode(bytecode: &[u8]) -> BytecodeAnalysisReport {
    let instructions = decode_instructions(bytecode);
    let push4_selectors = extract_push4_from_instructions(&instructions);
    let dispatch_entries = extract_dispatch_entries(&instructions);
    let dispatch_selectors = dispatch_entries
        .iter()
        .map(|entry| entry.selector)
        .collect::<Vec<_>>();
    let known_selectors = known_selector_evidence(&push4_selectors);
    let proxy_patterns = detect_proxy_patterns(bytecode, &instructions, &push4_selectors);
    let risk_flags = detect_risk_flags(&instructions);
    let storage_slots = detect_storage_slots(&instructions);
    let symbolic_summary = symbolic_semantics(&instructions);
    let function_summaries =
        function_slice_summaries(&instructions, &dispatch_entries, &known_selectors);
    let opcode_counts = opcode_counts(&instructions);

    let mut profile_selectors = dispatch_selectors.clone();
    if profile_selectors.is_empty() {
        profile_selectors = push4_selectors.clone();
    }
    let mut target_profile = TargetProfiler::profile_from_selectors(profile_selectors.clone());
    if !proxy_patterns.is_empty()
        && !target_profile
            .protocol_types
            .contains(&ProtocolType::ProxyUpgradeable)
    {
        if target_profile.protocol_types == [ProtocolType::Unknown] {
            target_profile.protocol_types.clear();
        }
        target_profile
            .protocol_types
            .push(ProtocolType::ProxyUpgradeable);
        target_profile.confidence = target_profile.confidence.max(55);
        target_profile
            .recommended_seed_templates
            .push("access-control-sensitive-call".to_string());
        target_profile
            .recommended_invariant_families
            .push("access-control".to_string());
    }
    apply_symbolic_profile_evidence(&mut target_profile, &risk_flags, &symbolic_summary);
    apply_function_slice_profile_evidence(&mut target_profile, &function_summaries);
    target_profile.protocol_types.sort();
    target_profile.protocol_types.dedup();
    target_profile.recommended_seed_templates.sort();
    target_profile.recommended_seed_templates.dedup();
    target_profile.recommended_invariant_families.sort();
    target_profile.recommended_invariant_families.dedup();

    let mut explanation = Vec::new();
    if !dispatch_selectors.is_empty() {
        explanation.push(format!(
            "detected {} dispatch selectors and {} function slices from PUSH4/EQ/JUMPI patterns",
            dispatch_selectors.len(),
            function_summaries.len()
        ));
    } else if !push4_selectors.is_empty() {
        explanation.push(format!(
            "detected {} PUSH4 constants; no dispatcher pattern was proven",
            push4_selectors.len()
        ));
    }
    for selector in &known_selectors {
        explanation.push(format!(
            "selector 0x{} matched {} ({:?})",
            hex::encode(selector.selector),
            selector.signature,
            selector.protocol_type
        ));
    }
    for pattern in &proxy_patterns {
        explanation.push(format!("proxy pattern detected: {pattern:?}"));
    }
    for flag in &risk_flags {
        explanation.push(format!("bytecode risk flag: {flag:?}"));
    }
    for line in symbolic_summary.decompiler_pseudocode.iter().take(12) {
        explanation.push(format!("symbolic: {line}"));
    }

    BytecodeAnalysisReport {
        code_len: bytecode.len(),
        push4_selectors,
        dispatch_selectors,
        function_summaries,
        known_selectors,
        proxy_patterns,
        risk_flags,
        storage_slots,
        symbolic_summary,
        opcode_counts,
        target_profile,
        explanation,
    }
}

pub fn extract_push4_selectors(bytecode: &[u8]) -> Vec<[u8; 4]> {
    extract_push4_from_instructions(&decode_instructions(bytecode))
}

fn apply_symbolic_profile_evidence(
    profile: &mut TargetProfile,
    risk_flags: &[BytecodeRiskFlag],
    symbolic: &SymbolicBytecodeSummary,
) {
    if symbolic.caller_sensitive
        || symbolic.origin_sensitive
        || risk_flags.contains(&BytecodeRiskFlag::HasDelegateCall)
    {
        add_protocol(profile, ProtocolType::AccessControlHeavy, 12);
        add_template(profile, "access-control-sensitive-call");
        add_invariant(profile, "access-control");
    }
    if !symbolic.storage_writes.is_empty() || risk_flags.contains(&BytecodeRiskFlag::HasSstore) {
        add_protocol(profile, ProtocolType::AccountingHeavy, 10);
        add_template(profile, "state-accounting-transition");
        add_invariant(profile, "generic-accounting");
    }
    if !symbolic.external_calls.is_empty() || !symbolic.delegate_calls.is_empty() {
        add_template(profile, "cross-contract-callback");
        add_invariant(profile, "cross-contract-accounting");
        profile.confidence = profile.confidence.saturating_add(5).min(95);
    }
    if symbolic.value_sensitive {
        profile.confidence = profile.confidence.saturating_add(5).min(95);
        add_template(profile, "value-sensitive-sequence");
    }
    if !symbolic.branch_conditions.is_empty() {
        profile.confidence = profile.confidence.saturating_add(3).min(95);
    }
}

fn apply_function_slice_profile_evidence(
    profile: &mut TargetProfile,
    summaries: &[FunctionSliceSummary],
) {
    for summary in summaries {
        if summary.behavior.writes_storage {
            add_template(profile, "selector-storage-mutation");
            add_invariant(profile, "selector-accounting");
            if !profile.state_changing_functions.contains(&summary.selector) {
                profile.state_changing_functions.push(summary.selector);
            }
        }
        if summary.behavior.uses_call_value {
            add_template(profile, "selector-value-boundary");
            if !profile
                .value_sensitive_functions
                .contains(&summary.selector)
            {
                profile.value_sensitive_functions.push(summary.selector);
            }
        }
        if summary.behavior.uses_caller || summary.behavior.uses_origin {
            add_protocol(profile, ProtocolType::AccessControlHeavy, 3);
            add_invariant(profile, "selector-access-control");
            if !profile.role_sensitive_functions.contains(&summary.selector) {
                profile.role_sensitive_functions.push(summary.selector);
            }
        }
        if summary.behavior.makes_external_call || summary.behavior.makes_delegate_call {
            add_template(profile, "selector-cross-contract-callback");
            add_invariant(profile, "selector-cross-contract");
        }
    }
    profile.state_changing_functions.sort();
    profile.state_changing_functions.dedup();
    profile.value_sensitive_functions.sort();
    profile.value_sensitive_functions.dedup();
    profile.role_sensitive_functions.sort();
    profile.role_sensitive_functions.dedup();
}

fn add_protocol(profile: &mut TargetProfile, protocol: ProtocolType, confidence_delta: u64) {
    if profile.protocol_types == [ProtocolType::Unknown] {
        profile.protocol_types.clear();
    }
    if !profile.protocol_types.contains(&protocol) {
        profile.protocol_types.push(protocol);
    }
    profile.confidence = profile.confidence.saturating_add(confidence_delta).min(95);
}

fn add_template(profile: &mut TargetProfile, template: &str) {
    if !profile
        .recommended_seed_templates
        .iter()
        .any(|candidate| candidate == template)
    {
        profile
            .recommended_seed_templates
            .push(template.to_string());
    }
}

fn add_invariant(profile: &mut TargetProfile, invariant: &str) {
    if !profile
        .recommended_invariant_families
        .iter()
        .any(|candidate| candidate == invariant)
    {
        profile
            .recommended_invariant_families
            .push(invariant.to_string());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Instruction {
    pc: usize,
    opcode: u8,
    immediate: Vec<u8>,
}

fn decode_instructions(bytecode: &[u8]) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        let push_len = push_len(opcode);
        let start = pc + 1;
        let end = start.saturating_add(push_len).min(bytecode.len());
        out.push(Instruction {
            pc,
            opcode,
            immediate: bytecode[start..end].to_vec(),
        });
        pc = end;
    }
    out
}

fn push_len(opcode: u8) -> usize {
    if (0x60..=0x7f).contains(&opcode) {
        (opcode - 0x5f) as usize
    } else {
        0
    }
}

fn extract_push4_from_instructions(instructions: &[Instruction]) -> Vec<[u8; 4]> {
    instructions
        .iter()
        .filter(|instruction| instruction.opcode == 0x63 && instruction.immediate.len() == 4)
        .map(|instruction| {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&instruction.immediate);
            selector
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchEntry {
    selector: [u8; 4],
    entry_pc: usize,
}

fn extract_dispatch_entries(instructions: &[Instruction]) -> Vec<DispatchEntry> {
    let mut entries = BTreeMap::<[u8; 4], usize>::new();
    for (idx, instruction) in instructions.iter().enumerate() {
        if instruction.opcode != 0x63 || instruction.immediate.len() != 4 {
            continue;
        }
        if let Some(entry_pc) = dispatch_entry_target(instructions, idx) {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&instruction.immediate);
            entries.insert(selector, entry_pc);
        }
    }
    entries
        .into_iter()
        .map(|(selector, entry_pc)| DispatchEntry { selector, entry_pc })
        .collect()
}

fn dispatch_entry_target(instructions: &[Instruction], selector_idx: usize) -> Option<usize> {
    let window_end = (selector_idx + 12).min(instructions.len());
    let mut saw_eq = false;
    let mut pending_dest = None;
    for instruction in &instructions[selector_idx + 1..window_end] {
        if instruction.opcode == 0x14 {
            saw_eq = true;
            continue;
        }
        if saw_eq && (0x60..=0x7f).contains(&instruction.opcode) {
            pending_dest =
                const_from_push(instruction).and_then(|value| usize::try_from(value).ok());
            continue;
        }
        if saw_eq && instruction.opcode == 0x57 {
            return pending_dest;
        }
    }
    None
}

fn known_selector_evidence(selectors: &[[u8; 4]]) -> Vec<KnownSelectorEvidence> {
    let mut evidence = Vec::new();
    for selector in selectors {
        for (signature, protocol_type, reason) in known_selector_specs() {
            if function_selector(signature) == *selector {
                evidence.push(KnownSelectorEvidence {
                    selector: *selector,
                    signature: signature.to_string(),
                    protocol_type,
                    reason: reason.to_string(),
                });
            }
        }
    }
    evidence.sort_by(|a, b| {
        a.selector
            .cmp(&b.selector)
            .then(a.signature.cmp(&b.signature))
    });
    evidence.dedup_by(|a, b| a.selector == b.selector && a.signature == b.signature);
    evidence
}

fn detect_proxy_patterns(
    bytecode: &[u8],
    instructions: &[Instruction],
    selectors: &[[u8; 4]],
) -> Vec<ProxyPattern> {
    let mut patterns = BTreeSet::new();
    if contains_subsequence(bytecode, &hex_literal("363d3d373d3d3d363d73"))
        && contains_subsequence(bytecode, &hex_literal("5af43d82803e903d91602b57fd5bf3"))
    {
        patterns.insert(ProxyPattern::Eip1167MinimalProxy);
    }
    if instructions
        .iter()
        .any(|instruction| instruction.opcode == 0xf4)
    {
        patterns.insert(ProxyPattern::DelegateCallDispatch);
    }
    if selectors.iter().any(|selector| {
        [
            "upgradeTo(address)",
            "upgradeToAndCall(address,bytes)",
            "implementation()",
            "admin()",
        ]
        .iter()
        .any(|signature| function_selector(signature) == *selector)
    }) {
        patterns.insert(ProxyPattern::UpgradeSelector);
    }
    for slot in detect_storage_slots(instructions) {
        match slot.label.as_str() {
            "eip1967.proxy.implementation" => {
                patterns.insert(ProxyPattern::Eip1967ImplementationSlot);
            }
            "eip1967.proxy.admin" => {
                patterns.insert(ProxyPattern::Eip1967AdminSlot);
            }
            "eip1967.proxy.beacon" => {
                patterns.insert(ProxyPattern::Eip1967BeaconSlot);
            }
            _ => {}
        }
    }
    patterns.into_iter().collect()
}

fn detect_risk_flags(instructions: &[Instruction]) -> Vec<BytecodeRiskFlag> {
    let mut flags = BTreeSet::new();
    for instruction in instructions {
        match instruction.opcode {
            0x32 => {
                flags.insert(BytecodeRiskFlag::HasOrigin);
            }
            0x34 => {
                flags.insert(BytecodeRiskFlag::HasCallValue);
                flags.insert(BytecodeRiskFlag::PayableSurface);
            }
            0x55 => {
                flags.insert(BytecodeRiskFlag::HasSstore);
            }
            0xf1 => {
                flags.insert(BytecodeRiskFlag::HasExternalCall);
            }
            0xfa => {
                flags.insert(BytecodeRiskFlag::HasStaticCall);
            }
            0xf0 => {
                flags.insert(BytecodeRiskFlag::HasCreate);
            }
            0xf5 => {
                flags.insert(BytecodeRiskFlag::HasCreate2);
            }
            0xf4 => {
                flags.insert(BytecodeRiskFlag::HasDelegateCall);
            }
            0xff => {
                flags.insert(BytecodeRiskFlag::HasSelfDestruct);
            }
            _ => {}
        }
    }
    flags.into_iter().collect()
}

fn detect_storage_slots(instructions: &[Instruction]) -> Vec<StorageSlotEvidence> {
    let known = [
        (
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "eip1967.proxy.implementation",
        ),
        (
            "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            "eip1967.proxy.admin",
        ),
        (
            "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
            "eip1967.proxy.beacon",
        ),
    ];
    let mut slots = Vec::new();
    for instruction in instructions {
        if instruction.opcode != 0x7f || instruction.immediate.len() != 32 {
            continue;
        }
        for (hex_slot, label) in known {
            let slot = hex_literal(hex_slot);
            if instruction.immediate == slot {
                slots.push(StorageSlotEvidence {
                    slot: B256::from_slice(&slot),
                    label: label.to_string(),
                });
            }
        }
    }
    slots.sort_by(|a, b| a.label.cmp(&b.label));
    slots.dedup_by(|a, b| a.slot == b.slot);
    slots
}

fn opcode_counts(instructions: &[Instruction]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for instruction in instructions {
        *counts
            .entry(opcode_name(instruction.opcode).to_string())
            .or_default() += 1;
    }
    counts
}

fn symbolic_semantics(instructions: &[Instruction]) -> SymbolicBytecodeSummary {
    symbolic_semantics_from_entry(instructions, None)
}

fn symbolic_semantics_from_entry(
    instructions: &[Instruction],
    entry_pc: Option<usize>,
) -> SymbolicBytecodeSummary {
    let blocks = basic_blocks(instructions);
    let reachable = reachable_blocks_from(&blocks, entry_pc);
    let mut summary = SymbolicBytecodeSummary {
        basic_block_count: blocks.len(),
        reachable_block_count: reachable.len(),
        caveats: vec![
            "static symbolic bytecode summary is bounded and path-insensitive; dynamic replay remains required for proof".to_string(),
        ],
        ..SymbolicBytecodeSummary::default()
    };
    for block in blocks {
        if !reachable.contains(&block.start_pc) {
            continue;
        }
        execute_block_symbolically(&block.instructions, &mut summary);
    }
    summary.storage_reads.sort_by_key(|access| access.pc);
    summary.storage_writes.sort_by_key(|access| access.pc);
    summary.external_calls.sort_by_key(|call| call.pc);
    summary.delegate_calls.sort_by_key(|call| call.pc);
    summary.static_calls.sort_by_key(|call| call.pc);
    summary.branch_conditions.sort_by_key(|branch| branch.pc);
    summary
}

fn function_slice_summaries(
    instructions: &[Instruction],
    dispatch_entries: &[DispatchEntry],
    known_selectors: &[KnownSelectorEvidence],
) -> Vec<FunctionSliceSummary> {
    let mut summaries = dispatch_entries
        .iter()
        .map(|entry| {
            let symbolic_summary =
                symbolic_semantics_from_entry(instructions, Some(entry.entry_pc));
            let behavior = function_behavior_from_symbolic(&symbolic_summary);
            let selector_hint = known_selectors
                .iter()
                .find(|candidate| candidate.selector == entry.selector);
            let protocol_type_hint = selector_hint.map(|candidate| candidate.protocol_type.clone());
            let signature_hint = selector_hint.map(|candidate| candidate.signature.clone());
            FunctionSliceSummary {
                selector: entry.selector,
                entry_pc: entry.entry_pc,
                signature_hint,
                protocol_type_hint: protocol_type_hint.clone(),
                seed_hints: seed_hints_from_behavior(&behavior, protocol_type_hint.as_ref()),
                invariant_hints: invariant_hints_from_behavior(
                    &behavior,
                    protocol_type_hint.as_ref(),
                ),
                symbolic_summary,
                behavior,
            }
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|a, b| {
        a.selector
            .cmp(&b.selector)
            .then(a.entry_pc.cmp(&b.entry_pc))
    });
    summaries
}

fn function_behavior_from_symbolic(symbolic: &SymbolicBytecodeSummary) -> FunctionBehavior {
    FunctionBehavior {
        reads_storage: !symbolic.storage_reads.is_empty(),
        writes_storage: !symbolic.storage_writes.is_empty(),
        makes_external_call: !symbolic.external_calls.is_empty(),
        makes_delegate_call: !symbolic.delegate_calls.is_empty(),
        makes_static_call: !symbolic.static_calls.is_empty(),
        uses_call_value: symbolic.value_sensitive,
        uses_caller: symbolic.caller_sensitive,
        uses_origin: symbolic.origin_sensitive,
        branch_count: symbolic.branch_conditions.len(),
    }
}

fn seed_hints_from_behavior(
    behavior: &FunctionBehavior,
    protocol_type_hint: Option<&ProtocolType>,
) -> Vec<String> {
    let mut hints = BTreeSet::new();
    if behavior.uses_call_value {
        hints.insert("vary-msg-value".to_string());
    }
    if behavior.uses_caller || behavior.uses_origin {
        hints.insert("rotate-funded-actors".to_string());
    }
    if behavior.writes_storage {
        hints.insert("pair-with-state-readback".to_string());
    }
    if behavior.makes_external_call || behavior.makes_delegate_call {
        hints.insert("pair-with-callback-contract".to_string());
    }
    match protocol_type_hint {
        Some(ProtocolType::Erc20Token) => {
            hints.insert("erc20-balance-allowance-sequence".to_string());
        }
        Some(ProtocolType::Erc4626Vault) => {
            hints.insert("deposit-withdraw-share-sequence".to_string());
        }
        Some(ProtocolType::AmmDexPool) => {
            hints.insert("reserve-changing-swap-sequence".to_string());
        }
        Some(ProtocolType::OraclePriceFeed) => {
            hints.insert("oracle-read-before-after".to_string());
        }
        Some(ProtocolType::GovernanceTimelock) => {
            hints.insert("proposal-vote-execute-sequence".to_string());
        }
        Some(ProtocolType::ProxyUpgradeable) => {
            hints.insert("proxy-admin-upgrade-sequence".to_string());
        }
        Some(ProtocolType::AccessControlHeavy) => {
            hints.insert("privileged-vs-unprivileged-caller".to_string());
        }
        _ => {}
    }
    hints.into_iter().collect()
}

fn invariant_hints_from_behavior(
    behavior: &FunctionBehavior,
    protocol_type_hint: Option<&ProtocolType>,
) -> Vec<String> {
    let mut hints = BTreeSet::new();
    if behavior.writes_storage {
        hints.insert("selector-accounting-integrity".to_string());
    }
    if behavior.uses_call_value {
        hints.insert("selector-profit-bound".to_string());
    }
    if behavior.uses_caller || behavior.uses_origin || behavior.makes_delegate_call {
        hints.insert("selector-access-control".to_string());
    }
    if behavior.makes_external_call {
        hints.insert("selector-cross-contract-accounting".to_string());
    }
    match protocol_type_hint {
        Some(ProtocolType::Erc4626Vault) => {
            hints.insert("erc4626-share-price-bound".to_string());
        }
        Some(ProtocolType::AmmDexPool) | Some(ProtocolType::OraclePriceFeed) => {
            hints.insert("price-move-bound".to_string());
        }
        Some(ProtocolType::GovernanceTimelock) => {
            hints.insert("governance-lifecycle-integrity".to_string());
        }
        Some(ProtocolType::ProxyUpgradeable) => {
            hints.insert("proxy-implementation-integrity".to_string());
        }
        _ => {}
    }
    hints.into_iter().collect()
}

#[derive(Debug, Clone)]
struct BasicBlock {
    start_pc: usize,
    successors: Vec<usize>,
    instructions: Vec<Instruction>,
}

fn basic_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    let mut starts = BTreeSet::new();
    if let Some(first) = instructions.first() {
        starts.insert(first.pc);
    }
    for (idx, instruction) in instructions.iter().enumerate() {
        if instruction.opcode == 0x5b {
            starts.insert(instruction.pc);
        }
        if is_terminal_or_branch(instruction.opcode) {
            if let Some(next) = instructions.get(idx + 1) {
                starts.insert(next.pc);
            }
        }
    }
    let starts_vec = starts.into_iter().collect::<Vec<_>>();
    let mut blocks = Vec::new();
    for (idx, start) in starts_vec.iter().enumerate() {
        let end = starts_vec.get(idx + 1).copied().unwrap_or(usize::MAX);
        let block_instructions = instructions
            .iter()
            .filter(|instruction| instruction.pc >= *start && instruction.pc < end)
            .cloned()
            .collect::<Vec<_>>();
        if block_instructions.is_empty() {
            continue;
        }
        let successors = block_successors(&block_instructions, starts_vec.get(idx + 1).copied());
        blocks.push(BasicBlock {
            start_pc: *start,
            successors,
            instructions: block_instructions,
        });
    }
    blocks
}

fn block_successors(instructions: &[Instruction], fallthrough: Option<usize>) -> Vec<usize> {
    let Some(last) = instructions.last() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match last.opcode {
        0x56 => {
            if let Some(dest) = preceding_push_as_usize(instructions) {
                out.push(dest);
            }
        }
        0x57 => {
            if let Some(dest) = preceding_push_as_usize(instructions) {
                out.push(dest);
            }
            if let Some(next) = fallthrough {
                out.push(next);
            }
        }
        0x00 | 0xfd | 0xfe | 0xff | 0xf3 => {}
        _ => {
            if let Some(next) = fallthrough {
                out.push(next);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn preceding_push_as_usize(instructions: &[Instruction]) -> Option<usize> {
    instructions
        .iter()
        .rev()
        .skip(1)
        .find(|instruction| (0x60..=0x7f).contains(&instruction.opcode))
        .and_then(|instruction| const_from_push(instruction))
        .and_then(|value| usize::try_from(value).ok())
}

fn reachable_blocks_from(blocks: &[BasicBlock], entry_pc: Option<usize>) -> BTreeSet<usize> {
    let Some(default_entry) = blocks.first().map(|block| block.start_pc) else {
        return BTreeSet::new();
    };
    let entry = entry_pc
        .and_then(|pc| block_start_for_pc(blocks, pc))
        .unwrap_or(default_entry);
    let by_start = blocks
        .iter()
        .map(|block| (block.start_pc, block.successors.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut stack = vec![entry];
    while let Some(pc) = stack.pop() {
        if !seen.insert(pc) {
            continue;
        }
        if let Some(successors) = by_start.get(&pc) {
            stack.extend(successors.iter().copied());
        }
    }
    seen
}

fn block_start_for_pc(blocks: &[BasicBlock], pc: usize) -> Option<usize> {
    blocks
        .iter()
        .find(|block| {
            block
                .instructions
                .iter()
                .any(|instruction| instruction.pc == pc)
        })
        .map(|block| block.start_pc)
}

fn execute_block_symbolically(instructions: &[Instruction], summary: &mut SymbolicBytecodeSummary) {
    let mut stack = Vec::<SymbolicValue>::new();
    for instruction in instructions {
        match instruction.opcode {
            0x01 => binary(&mut stack, SymbolicValue::Add),
            0x02 => binary(&mut stack, SymbolicValue::Mul),
            0x03 => binary(&mut stack, SymbolicValue::Sub),
            0x04 => binary(&mut stack, SymbolicValue::Div),
            0x14 => binary(&mut stack, SymbolicValue::Eq),
            0x15 => {
                let value = pop(&mut stack);
                stack.push(SymbolicValue::IsZero(Box::new(value)));
            }
            0x16 => binary(&mut stack, SymbolicValue::And),
            0x1c => binary(&mut stack, SymbolicValue::Shr),
            0x32 => {
                summary.origin_sensitive = true;
                stack.push(SymbolicValue::Origin);
            }
            0x33 => {
                summary.caller_sensitive = true;
                stack.push(SymbolicValue::Caller);
            }
            0x34 => {
                summary.value_sensitive = true;
                stack.push(SymbolicValue::CallValue);
            }
            0x35 => {
                let offset = pop(&mut stack);
                if matches!(offset, SymbolicValue::Const(ref value) if value == "0x0") {
                    stack.push(SymbolicValue::Selector);
                } else {
                    stack.push(SymbolicValue::CalldataWord(format_symbolic(&offset)));
                }
            }
            0x54 => {
                let slot = pop(&mut stack);
                summary.storage_reads.push(SymbolicStorageAccess {
                    pc: instruction.pc,
                    slot: slot.clone(),
                    value: None,
                });
                summary.decompiler_pseudocode.push(format!(
                    "sload {} at pc {}",
                    format_symbolic(&slot),
                    instruction.pc
                ));
                stack.push(SymbolicValue::Storage(Box::new(slot)));
            }
            0x55 => {
                let slot = pop(&mut stack);
                let value = pop(&mut stack);
                summary.storage_writes.push(SymbolicStorageAccess {
                    pc: instruction.pc,
                    slot: slot.clone(),
                    value: Some(value.clone()),
                });
                summary.decompiler_pseudocode.push(format!(
                    "sstore {} := {} at pc {}",
                    format_symbolic(&slot),
                    format_symbolic(&value),
                    instruction.pc
                ));
            }
            0x57 => {
                let destination = pop(&mut stack);
                let condition = pop(&mut stack);
                summary.branch_conditions.push(SymbolicBranch {
                    pc: instruction.pc,
                    destination: const_symbolic_usize(&destination),
                    condition: condition.clone(),
                });
                summary.decompiler_pseudocode.push(format!(
                    "if {} jump {} at pc {}",
                    format_symbolic(&condition),
                    format_symbolic(&destination),
                    instruction.pc
                ));
            }
            0x60..=0x7f => stack.push(push_symbolic(instruction)),
            0x80..=0x8f => {
                let idx = (instruction.opcode - 0x80) as usize;
                let value = stack
                    .iter()
                    .rev()
                    .nth(idx)
                    .cloned()
                    .unwrap_or(SymbolicValue::Unknown);
                stack.push(value);
            }
            0x90..=0x9f => {
                let idx = (instruction.opcode - 0x8f) as usize;
                let len = stack.len();
                if len > idx {
                    stack.swap(len - 1, len - 1 - idx);
                }
            }
            0xf1 | 0xf4 | 0xfa => record_symbolic_call(instruction, &mut stack, summary),
            0xf0 | 0xf5 => {
                summary.decompiler_pseudocode.push(format!(
                    "contract creation opcode 0x{:02x} at pc {}",
                    instruction.opcode, instruction.pc
                ));
                stack.clear();
                stack.push(SymbolicValue::Unknown);
            }
            _ => apply_generic_stack_effect(instruction.opcode, &mut stack),
        }
        summary.max_stack_depth_observed = summary.max_stack_depth_observed.max(stack.len());
    }
}

fn record_symbolic_call(
    instruction: &Instruction,
    stack: &mut Vec<SymbolicValue>,
    summary: &mut SymbolicBytecodeSummary,
) {
    let kind = match instruction.opcode {
        0xf1 => "call",
        0xf4 => "delegatecall",
        0xfa => "staticcall",
        _ => "call",
    };
    let gas = pop(stack);
    let target = pop(stack);
    let value = if instruction.opcode == 0xf1 {
        pop(stack)
    } else {
        SymbolicValue::Const("0x0".to_string())
    };
    let input_offset = pop(stack);
    let input_size = pop(stack);
    let _output_offset = pop(stack);
    let _output_size = pop(stack);
    let call = SymbolicCall {
        pc: instruction.pc,
        kind: kind.to_string(),
        target: target.clone(),
        value: value.clone(),
        input_offset: input_offset.clone(),
        input_size: input_size.clone(),
    };
    summary.decompiler_pseudocode.push(format!(
        "{} target={} value={} input=[{}, {}] gas={} at pc {}",
        kind,
        format_symbolic(&target),
        format_symbolic(&value),
        format_symbolic(&input_offset),
        format_symbolic(&input_size),
        format_symbolic(&gas),
        instruction.pc
    ));
    match instruction.opcode {
        0xf4 => summary.delegate_calls.push(call),
        0xfa => summary.static_calls.push(call),
        _ => summary.external_calls.push(call),
    }
    stack.push(SymbolicValue::Unknown);
}

fn apply_generic_stack_effect(opcode: u8, stack: &mut Vec<SymbolicValue>) {
    let (inputs, outputs) = stack_effect(opcode);
    for _ in 0..inputs {
        let _ = pop(stack);
    }
    for _ in 0..outputs {
        stack.push(SymbolicValue::Unknown);
    }
}

fn stack_effect(opcode: u8) -> (usize, usize) {
    match opcode {
        0x00 | 0x5b => (0, 0),
        0x10..=0x13 | 0x17..=0x1b | 0x20 => (2, 1),
        0x30 | 0x31 | 0x36 | 0x3a | 0x42..=0x48 | 0x58 | 0x59 => (0, 1),
        0x37 | 0x39 | 0x3c => (3, 0),
        0x38 | 0x3d | 0x3f | 0x40 | 0x41 => (0, 1),
        0x3e => (3, 0),
        0x50 => (1, 0),
        0x51 | 0x52 | 0x53 => (1, 1),
        0x56 => (1, 0),
        0xfd | 0xf3 => (2, 0),
        0xff => (1, 0),
        _ => (0, 0),
    }
}

fn binary(
    stack: &mut Vec<SymbolicValue>,
    build: fn(Box<SymbolicValue>, Box<SymbolicValue>) -> SymbolicValue,
) {
    let rhs = pop(stack);
    let lhs = pop(stack);
    stack.push(build(Box::new(lhs), Box::new(rhs)));
}

fn pop(stack: &mut Vec<SymbolicValue>) -> SymbolicValue {
    stack.pop().unwrap_or(SymbolicValue::Unknown)
}

fn push_symbolic(instruction: &Instruction) -> SymbolicValue {
    const_from_push(instruction)
        .map(|value| SymbolicValue::Const(format!("0x{value:x}")))
        .unwrap_or(SymbolicValue::Unknown)
}

fn const_from_push(instruction: &Instruction) -> Option<u128> {
    if !(0x60..=0x7f).contains(&instruction.opcode) || instruction.immediate.len() > 16 {
        return None;
    }
    let mut value = 0u128;
    for byte in &instruction.immediate {
        value = (value << 8) | u128::from(*byte);
    }
    Some(value)
}

fn const_symbolic_usize(value: &SymbolicValue) -> Option<usize> {
    if let SymbolicValue::Const(value) = value {
        return usize::from_str_radix(value.trim_start_matches("0x"), 16).ok();
    }
    None
}

fn format_symbolic(value: &SymbolicValue) -> String {
    match value {
        SymbolicValue::Unknown => "?".to_string(),
        SymbolicValue::Const(value) => value.clone(),
        SymbolicValue::CalldataWord(offset) => format!("calldata[{offset}]"),
        SymbolicValue::Selector => "selector".to_string(),
        SymbolicValue::Caller => "caller".to_string(),
        SymbolicValue::CallValue => "callvalue".to_string(),
        SymbolicValue::Origin => "tx.origin".to_string(),
        SymbolicValue::Storage(slot) => format!("storage[{}]", format_symbolic(slot)),
        SymbolicValue::Add(lhs, rhs) => {
            format!("({} + {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::Sub(lhs, rhs) => {
            format!("({} - {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::Mul(lhs, rhs) => {
            format!("({} * {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::Div(lhs, rhs) => {
            format!("({} / {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::And(lhs, rhs) => {
            format!("({} & {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::Shr(lhs, rhs) => {
            format!("({} >> {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::Eq(lhs, rhs) => {
            format!("({} == {})", format_symbolic(lhs), format_symbolic(rhs))
        }
        SymbolicValue::IsZero(value) => format!("iszero({})", format_symbolic(value)),
    }
}

fn is_terminal_or_branch(opcode: u8) -> bool {
    matches!(opcode, 0x00 | 0x56 | 0x57 | 0xfd | 0xfe | 0xff | 0xf3)
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x14 => "EQ",
        0x32 => "ORIGIN",
        0x34 => "CALLVALUE",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x5b => "JUMPDEST",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xff => "SELFDESTRUCT",
        0x60..=0x7f => "PUSH",
        0x80..=0x8f => "DUP",
        0x90..=0x9f => "SWAP",
        _ => "OTHER",
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex_literal(value: &str) -> Vec<u8> {
    hex::decode(value).expect("static bytecode hex literal must decode")
}

fn known_selector_specs() -> Vec<(&'static str, ProtocolType, &'static str)> {
    vec![
        (
            "balanceOf(address)",
            ProtocolType::Erc20Token,
            "ERC20 balance read",
        ),
        (
            "totalSupply()",
            ProtocolType::Erc20Token,
            "ERC20 supply read",
        ),
        (
            "transfer(address,uint256)",
            ProtocolType::Erc20Token,
            "ERC20 transfer",
        ),
        (
            "approve(address,uint256)",
            ProtocolType::Erc20Token,
            "ERC20 approval",
        ),
        (
            "transferFrom(address,address,uint256)",
            ProtocolType::Erc20Token,
            "allowance transfer",
        ),
        (
            "deposit(uint256,address)",
            ProtocolType::Erc4626Vault,
            "ERC4626 deposit",
        ),
        (
            "mint(uint256,address)",
            ProtocolType::Erc4626Vault,
            "ERC4626 mint",
        ),
        (
            "withdraw(uint256,address,address)",
            ProtocolType::Erc4626Vault,
            "ERC4626 withdraw",
        ),
        (
            "redeem(uint256,address,address)",
            ProtocolType::Erc4626Vault,
            "ERC4626 redeem",
        ),
        (
            "totalAssets()",
            ProtocolType::Erc4626Vault,
            "ERC4626 asset accounting",
        ),
        (
            "convertToShares(uint256)",
            ProtocolType::Erc4626Vault,
            "ERC4626 share conversion",
        ),
        ("getReserves()", ProtocolType::AmmDexPool, "AMM reserves"),
        (
            "swap(uint256,uint256,address,bytes)",
            ProtocolType::AmmDexPool,
            "AMM swap",
        ),
        (
            "latestAnswer()",
            ProtocolType::OraclePriceFeed,
            "oracle price read",
        ),
        (
            "latestRoundData()",
            ProtocolType::OraclePriceFeed,
            "oracle round data",
        ),
        (
            "propose(address[],uint256[],bytes[],string)",
            ProtocolType::GovernanceTimelock,
            "governance proposal",
        ),
        (
            "queue(uint256)",
            ProtocolType::GovernanceTimelock,
            "timelock queue",
        ),
        (
            "execute(uint256)",
            ProtocolType::GovernanceTimelock,
            "timelock execution",
        ),
        ("owner()", ProtocolType::AccessControlHeavy, "owner read"),
        (
            "grantRole(bytes32,address)",
            ProtocolType::AccessControlHeavy,
            "role grant",
        ),
        (
            "upgradeTo(address)",
            ProtocolType::ProxyUpgradeable,
            "UUPS upgrade",
        ),
        (
            "upgradeToAndCall(address,bytes)",
            ProtocolType::ProxyUpgradeable,
            "UUPS upgrade and call",
        ),
        (
            "implementation()",
            ProtocolType::ProxyUpgradeable,
            "proxy implementation read",
        ),
        (
            "admin()",
            ProtocolType::ProxyUpgradeable,
            "proxy admin read",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_dispatch_selectors_without_reading_push_data_as_opcodes() {
        let selector = function_selector("transfer(address,uint256)");
        let bytecode = [
            vec![0x63],
            selector.to_vec(),
            vec![0x14, 0x61, 0x00, 0x10, 0x57, 0x7f],
            vec![0x63; 32],
            vec![0x00],
        ]
        .concat();

        let report = analyze_bytecode(&bytecode);

        assert_eq!(report.push4_selectors, vec![selector]);
        assert_eq!(report.dispatch_selectors, vec![selector]);
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::Erc20Token));
    }

    #[test]
    fn detects_proxy_slots_and_delegatecall() {
        let mut bytecode = vec![0x7f];
        bytecode.extend(hex_literal(
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        ));
        bytecode.extend([0x54, 0xf4]);

        let report = analyze_bytecode(&bytecode);

        assert!(report
            .proxy_patterns
            .contains(&ProxyPattern::Eip1967ImplementationSlot));
        assert!(report
            .proxy_patterns
            .contains(&ProxyPattern::DelegateCallDispatch));
        assert!(report
            .risk_flags
            .contains(&BytecodeRiskFlag::HasDelegateCall));
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::ProxyUpgradeable));
    }

    #[test]
    fn detects_minimal_proxy_pattern() {
        let bytecode = hex_literal(
            "363d3d373d3d3d363d7300000000000000000000000000000000000000015af43d82803e903d91602b57fd5bf3",
        );
        let report = analyze_bytecode(&bytecode);
        assert!(report
            .proxy_patterns
            .contains(&ProxyPattern::Eip1167MinimalProxy));
    }

    #[test]
    fn symbolic_semantics_tracks_storage_and_calls() {
        let bytecode = vec![
            0x60, 0x02, // slot
            0x33, // caller
            0x55, // sstore(slot, caller)
            0x60, 0x02, // slot
            0x54, // sload(slot)
            0x60, 0x00, // out size
            0x60, 0x00, // out offset
            0x60, 0x00, // in size
            0x60, 0x00, // in offset
            0x34, // callvalue
            0x73, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // target
            0x60, 0xff, // gas
            0xf1, // call
        ];

        let report = analyze_bytecode(&bytecode);

        assert!(report.symbolic_summary.caller_sensitive);
        assert!(report.symbolic_summary.value_sensitive);
        assert_eq!(report.symbolic_summary.storage_writes.len(), 1);
        assert_eq!(report.symbolic_summary.storage_reads.len(), 1);
        assert_eq!(report.symbolic_summary.external_calls.len(), 1);
        assert!(report
            .symbolic_summary
            .decompiler_pseudocode
            .iter()
            .any(|line| line.contains("sstore")));
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::AccountingHeavy));
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::AccessControlHeavy));
    }

    #[test]
    fn symbolic_semantics_tracks_dispatch_condition() {
        let selector = function_selector("approve(address,uint256)");
        let mut bytecode = vec![0x60, 0x00, 0x35, 0x63];
        bytecode.extend(selector);
        bytecode.extend([0x14, 0x61, 0x00, 0x20, 0x57]);

        let report = analyze_bytecode(&bytecode);

        assert_eq!(report.symbolic_summary.branch_conditions.len(), 1);
        assert_eq!(
            report.symbolic_summary.branch_conditions[0].destination,
            Some(0x20)
        );
        assert!(matches!(
            report.symbolic_summary.branch_conditions[0].condition,
            SymbolicValue::Eq(_, _)
        ));
    }

    #[test]
    fn function_slicing_summarizes_selector_specific_behavior() {
        let caller_selector = function_selector("grantRole(bytes32,address)");
        let value_selector = function_selector("deposit(uint256,address)");
        let mut bytecode = vec![0x60, 0x00, 0x35, 0x63];
        bytecode.extend(caller_selector);
        bytecode.extend([0x14, 0x60, 0x30, 0x57, 0x63]);
        bytecode.extend(value_selector);
        bytecode.extend([0x14, 0x60, 0x40, 0x57, 0x00]);
        while bytecode.len() < 0x30 {
            bytecode.push(0x00);
        }
        bytecode.extend([
            0x5b, // jumpdest
            0x33, // caller
            0x60, 0x01, // slot
            0x55, // sstore
            0x00, // stop
        ]);
        while bytecode.len() < 0x40 {
            bytecode.push(0x00);
        }
        bytecode.extend([
            0x5b, // jumpdest
            0x34, // callvalue
            0x60, 0x02, // slot
            0x55, // sstore
            0x00, // stop
        ]);

        let report = analyze_bytecode(&bytecode);

        assert_eq!(report.function_summaries.len(), 2);
        let caller_slice = report
            .function_summaries
            .iter()
            .find(|summary| summary.selector == caller_selector)
            .unwrap();
        assert!(caller_slice.behavior.uses_caller);
        assert!(caller_slice.behavior.writes_storage);
        assert!(caller_slice
            .invariant_hints
            .contains(&"selector-access-control".to_string()));
        let value_slice = report
            .function_summaries
            .iter()
            .find(|summary| summary.selector == value_selector)
            .unwrap();
        assert!(value_slice.behavior.uses_call_value);
        assert!(value_slice.behavior.writes_storage);
        assert!(value_slice
            .seed_hints
            .contains(&"vary-msg-value".to_string()));
        assert!(report
            .target_profile
            .value_sensitive_functions
            .contains(&value_selector));
    }
}
