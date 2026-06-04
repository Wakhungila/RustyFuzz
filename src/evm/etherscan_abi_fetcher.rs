use alloy_json_abi::JsonAbi;
use anyhow::{anyhow, Result};
use revm::primitives::Address;
// TODO: reqwest dependency needs to be added to Cargo.toml
// use reqwest::Client;
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Etherscan API response structure for ABI fetching.
#[derive(Deserialize, Debug)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: String, // This contains the JSON ABI string
}

/// EtherscanAbiFetcher: Dynamically pulls and caches contract ABIs from Etherscan.
/// This eliminates manual ABI input and enables the fuzzer to understand new contracts.
#[derive(Clone)]
pub struct EtherscanAbiFetcher {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    cache: Arc<RwLock<HashMap<Address, JsonAbi>>>,
}

impl std::fmt::Debug for EtherscanAbiFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtherscanAbiFetcher")
            .field("api_key", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("cache_size", &self.cache.read().len())
            .finish()
    }
}

impl EtherscanAbiFetcher {
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetches the ABI for a given contract address from Etherscan.
    pub async fn fetch_abi(&self, address: Address) -> Result<JsonAbi> {
        // Check cache first
        {
            let cache_read = self.cache.read();
            if let Some(abi) = cache_read.get(&address) {
                return Ok(abi.clone());
            }
        }

        let separator = if self.base_url.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{}module=contract&action=getabi&address={:?}&apikey={}",
            self.base_url, separator, address, self.api_key
        );

        let response: EtherscanResponse = self.client.get(&url).send().await?.json().await?;

        if response.status != "1" {
            return Err(anyhow!(
                "Etherscan API error: {}; result={}",
                response.message,
                response.result
            ));
        }

        let abi: JsonAbi = serde_json::from_str(&response.result)?;

        // Cache the fetched ABI
        self.cache.write().insert(address, abi.clone());
        Ok(abi)
    }
}
