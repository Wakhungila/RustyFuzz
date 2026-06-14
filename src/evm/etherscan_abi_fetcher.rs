use alloy_json_abi::JsonAbi;
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use revm::primitives::Address;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Etherscan API response structure for ABI fetching.
#[derive(Deserialize, Debug)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: String, // This contains the JSON ABI string
}

/// EtherscanAbiFetcher: Dynamically pulls and caches contract ABIs from Etherscan.
/// This eliminates manual ABI input and enables the fuzzer to understand new contracts.
/// Implements rate limiting to respect Etherscan API constraints.
#[derive(Clone)]
pub struct EtherscanAbiFetcher {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    cache: Arc<RwLock<HashMap<Address, JsonAbi>>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

/// Rate limiter for Etherscan API calls
#[derive(Debug, Default)]
struct RateLimiter {
    last_request: Option<Instant>,
    min_request_interval: Duration,
}

impl RateLimiter {
    fn new(requests_per_second: u32) -> Self {
        Self {
            last_request: None,
            min_request_interval: Duration::from_millis(1000 / requests_per_second as u64),
        }
    }

    fn acquire(&mut self) {
        if let Some(last) = self.last_request {
            let elapsed = last.elapsed();
            if elapsed < self.min_request_interval {
                std::thread::sleep(self.min_request_interval - elapsed);
            }
        }
        self.last_request = Some(Instant::now());
    }
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
    /// Creates a new EtherscanAbiFetcher with rate limiting (default: 5 requests/second)
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            api_key,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(5))),
        }
    }

    /// Creates a new EtherscanAbiFetcher with custom rate limiting
    pub fn with_rate_limit(api_key: String, base_url: String, requests_per_second: u32) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            api_key,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(requests_per_second))),
        }
    }

    /// Fetches the ABI for a given contract address from Etherscan.
    /// Implements rate limiting and caching to respect API constraints.
    pub async fn fetch_abi(&self, address: Address) -> Result<JsonAbi> {
        // Check cache first
        {
            let cache_read = self.cache.read();
            if let Some(abi) = cache_read.get(&address) {
                return Ok(abi.clone());
            }
        }

        // Acquire rate limit
        self.rate_limiter.write().acquire();

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

    /// Clears the ABI cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Returns the number of cached ABIs
    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }
}
