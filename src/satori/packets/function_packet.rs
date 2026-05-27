use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{sha256_hex, write_json};
use crate::satori::graph::query::{related_functions, top_critical_functions};
use crate::satori::memory::store::MemoryStore;
use crate::satori::types::{
    ActorModel, EconomicAssumption, FunctionPacket, FunctionSummary, ProjectModel, ProtocolModel,
    ProtocolType, StaticAnalysisBundle, TrustAssumption,
};
use std::path::Path;

pub fn build_function_packets(
    project: &ProjectModel,
    analysis: &StaticAnalysisBundle,
    run_dir: &Path,
    limit: usize,
    memory: &MemoryStore,
) -> SatoriResult<Vec<FunctionPacket>> {
    let functions = top_critical_functions(analysis, limit);
    let mut packets = Vec::new();
    for function in functions {
        let memories = memory.retrieve(&[
            function.name.as_str(),
            function.contract.as_str(),
            &function
                .detector_signals
                .iter()
                .map(|s| s.tag.clone())
                .collect::<Vec<_>>()
                .join(" "),
        ])?;
        let packet = FunctionPacket {
            detector_evidence: function.detector_signals.clone(),
            protocol_context: protocol_model_for_function(project, &function),
            related_functions: related_functions(analysis, &function),
            relevant_memories: memories,
            known_bug_classes: bug_class_library(),
            output_constraints: vec![
                "Return strict JSON only.".to_string(),
                "Do not invent missing contracts or functions.".to_string(),
                "A hypothesis is not a finding until local validation exists.".to_string(),
            ],
            target_function: function,
        };
        let key = sha256_hex(packet.target_function.id.as_bytes());
        write_json(
            run_dir.join(format!("packets/function_{key}.json")),
            &packet,
        )?;
        packets.push(packet);
    }
    Ok(packets)
}

fn protocol_model_for_function(
    project: &ProjectModel,
    function: &FunctionSummary,
) -> ProtocolModel {
    let mut types = project.detected_protocols.clone();
    for signal in &function.detector_signals {
        match signal.tag.as_str() {
            "oracle-read" => types.push(ProtocolType::Oracle),
            "erc4626-raw-total-assets" | "erc4626-virtual-offset" => {
                types.push(ProtocolType::ERC4626Vault)
            }
            "upgradeability-init" => types.push(ProtocolType::Upgradeability),
            _ => {}
        }
    }
    types.sort();
    types.dedup();
    if types.is_empty() {
        types.push(ProtocolType::Unknown);
    }
    ProtocolModel {
        protocol_types: types,
        actors: vec![ActorModel {
            role: "attacker".to_string(),
            capabilities: vec!["public transaction sender".to_string()],
            trust_level: "untrusted".to_string(),
        }],
        assets: Vec::new(),
        trust_assumptions: vec![TrustAssumption {
            subject: function.contract.clone(),
            assumption: "Only supplied source context is trusted.".to_string(),
            evidence: "Satori packet construction".to_string(),
        }],
        economic_assumptions: vec![EconomicAssumption {
            invariant: "User-neutral actions should not create attacker profit or protocol loss."
                .to_string(),
            affected_assets: Vec::new(),
            evidence: "generic DeFi economic invariant".to_string(),
        }],
        confidence: 0.45,
        explanation: "Protocol model inferred from source names and detector signals.".to_string(),
    }
}

pub fn bug_class_library() -> Vec<String> {
    [
        "erc4626_share_inflation_via_donation",
        "erc4626_rounding_to_zero_victim_shares",
        "fee_on_transfer_accounting_mismatch",
        "stale_total_assets_after_strategy_loss",
        "lending_bad_debt_creation",
        "incorrect_health_factor",
        "liquidation_discount_miscalculation",
        "stale_oracle_accepted",
        "amm_reserve_desync",
        "amm_flash_loan_reserve_manipulation",
        "lp_token_inflation",
        "governance_reinitialization_takeover",
        "timelock_delay_bypass",
        "signature_replay",
        "bridge_message_replay",
        "upgradeability_unprotected_initializer",
        "delegatecall_to_untrusted_implementation",
    ]
    .iter()
    .map(|class| class.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{DetectorSignal, ProjectType, SourceFile};
    use std::path::PathBuf;

    #[test]
    fn packet_builder_includes_detector_evidence() {
        let function = FunctionSummary {
            id: "Vault::deposit(uint256)".to_string(),
            contract: "Vault".to_string(),
            name: "deposit".to_string(),
            signature: "deposit(uint256)".to_string(),
            selector: None,
            file: PathBuf::from("Vault.sol"),
            visibility: "external".to_string(),
            mutability: "nonpayable".to_string(),
            modifiers: Vec::new(),
            source_snippet: "asset.safeTransferFrom(msg.sender,address(this),assets);".to_string(),
            reads: Vec::new(),
            writes: Vec::new(),
            internal_calls: Vec::new(),
            external_calls: Vec::new(),
            detector_signals: vec![DetectorSignal {
                detector: "token_transfer".to_string(),
                tag: "token-transfer".to_string(),
                confidence: 0.8,
                evidence: "x".to_string(),
            }],
            criticality_score: 0.8,
        };
        let project = ProjectModel {
            root: PathBuf::from("."),
            project_type: ProjectType::Solidity,
            source_files: vec![SourceFile {
                path: PathBuf::from("Vault.sol"),
                relative_path: PathBuf::from("Vault.sol"),
                language: "solidity".to_string(),
                content_hash: "x".to_string(),
                bytes: 1,
                text: None,
            }],
            test_files: Vec::new(),
            docs: Vec::new(),
            foundry_toml: None,
            hardhat_config: None,
            package_json: None,
            remappings: None,
            detected_protocols: vec![ProtocolType::ERC4626Vault],
        };
        let model = protocol_model_for_function(&project, &function);
        assert!(model.protocol_types.contains(&ProtocolType::ERC4626Vault));
    }
}
