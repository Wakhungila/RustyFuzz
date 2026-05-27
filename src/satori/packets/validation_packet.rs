use crate::satori::types::{ValidationPacket, VulnerabilityHypothesis};

pub fn build_validation_packet(hypothesis: VulnerabilityHypothesis) -> ValidationPacket {
    ValidationPacket {
        hypothesis,
        available_abi: Vec::new(),
        rustyfuzz_capabilities: vec![
            "stateful EVM sequence fuzzing".to_string(),
            "fork-aware replay".to_string(),
            "economic oracle scoring".to_string(),
            "minimization and Foundry PoC generation".to_string(),
        ],
        foundry_capabilities: vec!["local forge test scaffolding".to_string()],
        required_output_shape: "ValidationVerdict JSON".to_string(),
    }
}
