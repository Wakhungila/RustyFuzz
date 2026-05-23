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
}

#[derive(Debug, Clone, Deserialize)]
pub struct HardenedDefiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub historical_seed_file: Option<String>,
    #[serde(default = "default_max_template_sequences")]
    pub max_template_sequences: usize,
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
}

impl Default for HardenedDefiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            historical_seed_file: None,
            max_template_sequences: default_max_template_sequences(),
            enable_actor_model: true,
            enable_economic_delta: true,
            enable_protocol_invariants: true,
            enable_exploit_templates: true,
            min_persist_confidence: default_min_persist_confidence(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_template_sequences() -> usize {
    128
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
