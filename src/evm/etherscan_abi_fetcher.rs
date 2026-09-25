use alloy_json_abi::JsonAbi;
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use revm::primitives::Address;
use rustyfuzz_evm::rpc_url::{resolve_rpc_url, test_loopback_allowed, validate_rpc_url};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

const DEFAULT_REQUESTS_PER_SECOND: u32 = 5;
const MAX_REQUESTS_PER_SECOND: u32 = 100;
const MAX_EXPLORER_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize, Debug)]
struct EtherscanResponse {
    status: String,
    result: String,
}

#[derive(Deserialize, Debug)]
struct BlockscoutV2Response {
    abi: JsonAbi,
    is_verified: bool,
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
    rate_limiter: Arc<AsyncMutex<RateLimiter>>,
}

/// Rate limiter for Etherscan API calls
#[derive(Debug, Default)]
struct RateLimiter {
    last_request: Option<Instant>,
    min_request_interval: Duration,
}

impl RateLimiter {
    fn new(requests_per_second: u32) -> Result<Self> {
        if !(1..=MAX_REQUESTS_PER_SECOND).contains(&requests_per_second) {
            return Err(anyhow!(
                "requests_per_second must be between 1 and {MAX_REQUESTS_PER_SECOND}"
            ));
        }
        let milliseconds = 1000_u64.div_ceil(u64::from(requests_per_second));
        Ok(Self {
            last_request: None,
            min_request_interval: Duration::from_millis(milliseconds),
        })
    }

    async fn acquire(&mut self) {
        if let Some(last) = self.last_request {
            let elapsed = last.elapsed();
            if elapsed < self.min_request_interval {
                tokio::time::sleep(self.min_request_interval - elapsed).await;
            }
        }
        self.last_request = Some(Instant::now());
    }
}

impl std::fmt::Debug for EtherscanAbiFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtherscanAbiFetcher")
            .field("api_key", &"<redacted>")
            .field("base_url", &"<redacted>")
            .field("cache_size", &self.cache.read().len())
            .finish()
    }
}

impl EtherscanAbiFetcher {
    /// Creates a new EtherscanAbiFetcher with rate limiting (default: 5 requests/second)
    pub fn new(api_key: String, base_url: String) -> Result<Self> {
        Self::with_rate_limit(api_key, base_url, DEFAULT_REQUESTS_PER_SECOND)
    }

    /// Creates a new EtherscanAbiFetcher with custom rate limiting
    pub fn with_rate_limit(
        api_key: String,
        base_url: String,
        requests_per_second: u32,
    ) -> Result<Self> {
        let rate_limiter = RateLimiter::new(requests_per_second)?;
        let parsed_url = validate_rpc_url(&base_url, test_loopback_allowed())
            .map_err(|error| anyhow!("invalid explorer URL: {error}"))?;
        let (_, addresses) = resolve_rpc_url(&base_url, false)
            .or_else(|_| resolve_rpc_url(&base_url, test_loopback_allowed()))
            .map_err(|error| anyhow!("invalid explorer URL resolution: {error}"))?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| anyhow!("explorer URL must contain a host"))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| anyhow!("explorer client configuration failed"))?;
        Ok(Self {
            client,
            api_key,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(AsyncMutex::new(rate_limiter)),
        })
    }

    fn request_url(&self, address: Address) -> Result<Url> {
        let mut url = Url::parse(&self.base_url).map_err(|_| anyhow!("explorer URL is invalid"))?;
        if self.base_url.contains("/api/v2") {
            url.path_segments_mut()
                .map_err(|_| anyhow!("explorer URL cannot contain this path"))?
                .pop_if_empty()
                .push("smart-contracts")
                .push(&format!("{address:?}"));
            url.query_pairs_mut().append_pair("apikey", &self.api_key);
        } else {
            url.query_pairs_mut()
                .append_pair("module", "contract")
                .append_pair("action", "getabi")
                .append_pair("address", &format!("{address:?}"))
                .append_pair("apikey", &self.api_key);
        }
        Ok(url)
    }

    async fn get_json(&self, url: &Url) -> Result<serde_json::Value> {
        let mut response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| anyhow!("explorer request failed; provider details redacted"))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "explorer request failed with HTTP {}; provider details redacted",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_EXPLORER_RESPONSE_BYTES)
        {
            return Err(anyhow!("explorer response exceeded the size limit"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("explorer response read failed; provider details redacted"))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_EXPLORER_RESPONSE_BYTES as usize {
                return Err(anyhow!("explorer response exceeded the size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            anyhow!("explorer returned an invalid response; provider details redacted")
        })
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
        self.rate_limiter.lock().await.acquire().await;

        let url = self.request_url(address)?;
        let abi = if self.base_url.contains("/api/v2") {
            let response: BlockscoutV2Response = serde_json::from_value(self.get_json(&url).await?)
                .map_err(|_| {
                    anyhow!("explorer returned an invalid response; provider details redacted")
                })?;
            if !response.is_verified {
                return Err(anyhow!("Blockscout contract ABI is not verified"));
            }
            response.abi
        } else {
            let response: EtherscanResponse = serde_json::from_value(self.get_json(&url).await?)
                .map_err(|_| {
                    anyhow!("explorer returned an invalid response; provider details redacted")
                })?;
            if response.status != "1" {
                return Err(anyhow!(
                    "Etherscan API rejected the request; provider details redacted"
                ));
            }
            serde_json::from_str(&response.result).map_err(|_| {
                anyhow!("Etherscan returned an invalid ABI; provider details redacted")
            })?
        };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_serializes_async_acquisitions_without_blocking_the_executor() {
        let limiter = Arc::new(AsyncMutex::new(
            RateLimiter::new(MAX_REQUESTS_PER_SECOND).expect("reasonable test rate"),
        ));
        let first = Arc::clone(&limiter);
        let second = Arc::clone(&limiter);
        let (first_result, second_result) = tokio::join!(
            tokio::spawn(async move {
                first.lock().await.acquire().await;
            }),
            tokio::spawn(async move {
                second.lock().await.acquire().await;
            })
        );
        first_result.expect("first limiter task");
        second_result.expect("second limiter task");
    }

    #[test]
    fn explorer_rejects_unsafe_production_urls() {
        assert!(rustyfuzz_evm::rpc_url::validate_rpc_url("http://127.0.0.1", false).is_err());
        assert!(EtherscanAbiFetcher::new(
            "key".to_string(),
            "https://user:pass@api.example.com".to_string()
        )
        .is_err());
        assert!(EtherscanAbiFetcher::new("key".to_string(), "https://8.8.8.8".to_string()).is_ok());
    }

    #[tokio::test]
    async fn provider_error_body_and_api_key_are_not_returned() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind explorer mock");
        let address = listener.local_addr().expect("explorer mock address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept explorer request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = stream
                    .read(&mut chunk)
                    .await
                    .expect("read explorer request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let body = r#"{"status":"0","message":"secret-provider-message","result":"https://user:pass@example.com/?apikey=secret-provider-result"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write explorer response");
        });

        let previous = std::env::var("RUSTYFUZZ_TEST_ALLOW_LOOPBACK").ok();
        std::env::set_var("RUSTYFUZZ_TEST_ALLOW_LOOPBACK", "1");
        let fetcher =
            EtherscanAbiFetcher::new("secret-api-key".to_string(), format!("http://{address}"))
                .expect("test explorer");
        let error = fetcher
            .fetch_abi(Address::repeat_byte(0x11))
            .await
            .expect_err("provider error");
        server.await.expect("explorer mock task");
        match previous {
            Some(value) => std::env::set_var("RUSTYFUZZ_TEST_ALLOW_LOOPBACK", value),
            None => std::env::remove_var("RUSTYFUZZ_TEST_ALLOW_LOOPBACK"),
        }

        let rendered = format!("{error:#}");
        assert!(rendered.contains("provider details redacted"));
        assert!(!rendered.contains("secret-provider-message"));
        assert!(!rendered.contains("secret-provider-result"));
        assert!(!rendered.contains("secret-api-key"));
        assert!(!rendered.contains("user:pass"));
    }

    #[test]
    fn custom_rate_rejects_zero_and_unreasonable_values() {
        for rate in [0, MAX_REQUESTS_PER_SECOND + 1, u32::MAX] {
            let result = EtherscanAbiFetcher::with_rate_limit(
                "key".to_string(),
                "https://8.8.8.8".to_string(),
                rate,
            );
            assert!(result.is_err(), "rate {rate} should be rejected");
        }
        assert!(RateLimiter::new(1).is_ok());
        assert!(RateLimiter::new(MAX_REQUESTS_PER_SECOND).is_ok());
    }
}
