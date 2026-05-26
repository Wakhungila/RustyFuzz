use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    pub fork_block: Option<u64>,
    pub chain: String, // "evm" or "svm"
    pub target_contract: Option<String>,
    pub timeout_secs: u64,
    pub corpus_dir: String,
    pub report_dir: String,
    pub llm_enabled: bool,
    pub foundry_project: Option<String>,
    #[serde(default)]
    pub mainnet_seed_bundle: Option<String>,
    #[serde(default)]
    pub hardened_defi: HardenedDefiConfig,
    #[serde(default)]
    pub target_invariant_manifest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HardenedDefiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub single_process: bool,
    #[serde(default)]
    pub deterministic: bool,
    #[serde(default)]
    pub rng_seed: Option<u64>,
    #[serde(default)]
    pub enable_bounded_search: bool,
    #[serde(default)]
    pub historical_seed_file: Option<String>,
    #[serde(default = "default_max_template_sequences")]
    pub max_template_sequences: usize,
    #[serde(default = "default_max_actor_roles")]
    pub max_actor_roles: usize,
    #[serde(default = "default_max_tx_depth")]
    pub max_tx_depth: usize,
    #[serde(default = "default_true")]
    pub enable_actor_model: bool,
    #[serde(default = "default_true")]
    pub enable_economic_delta: bool,
    #[serde(default = "default_true")]
    pub enable_protocol_invariants: bool,
    #[serde(default = "default_true")]
    pub enable_exploit_templates: bool,
    #[serde(default = "default_min_persist_confidence")]
    pub min_persist_confidence: f64,
    #[serde(default)]
    pub require_confirmation_for_poc: bool,
}

impl Default for HardenedDefiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            single_process: false,
            deterministic: false,
            rng_seed: None,
            enable_bounded_search: true,
            historical_seed_file: None,
            max_template_sequences: default_max_template_sequences(),
            max_actor_roles: default_max_actor_roles(),
            max_tx_depth: default_max_tx_depth(),
            enable_actor_model: true,
            enable_economic_delta: true,
            enable_protocol_invariants: true,
            enable_exploit_templates: true,
            min_persist_confidence: default_min_persist_confidence(),
            require_confirmation_for_poc: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_template_sequences() -> usize {
    128
}

fn default_max_actor_roles() -> usize {
    4
}

fn default_max_tx_depth() -> usize {
    4
}

fn default_min_persist_confidence() -> f64 {
    0.70
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_defi_defaults_include_deterministic_controls() {
        let config = HardenedDefiConfig::default();
        assert!(!config.deterministic);
        assert_eq!(config.rng_seed, None);
        assert!(config.enable_bounded_search);
        assert!(config.enable_actor_model);
    }
}
