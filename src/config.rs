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
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}