use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::Http;
use alloy::rpc::client::Client;
use reqwest::Client as ReqwestClient;
use revm::db::CacheDB;
use revm::primitives::BlockId;
use url::Url;
use anyhow::{Context, Result};

/// Creates a forked database state from a live RPC endpoint.
/// 
/// # Arguments
/// * `rpc_url` - The HTTP RPC endpoint (e.g., Ethereum Mainnet)
/// * `block` - Optional block number to fork from. If None, uses latest.
pub async fn create_fork_db(
    rpc_url: &str,
    block: Option<u64>,
) -> Result<CacheDB<revm::db::AlloyDB<Http<ReqwestClient>, u64>>> {
    let url: Url = rpc_url.parse().context("Invalid RPC URL")?;
    
    // Initialize Alloy HTTP transport
    let client = ReqwestClient::new();
    let http = Http::new(url);
    let provider = ProviderBuilder::new()
        .on_client(Client::new(http, client));

    // Determine fork block
    let block_id = match block {
        Some(num) => BlockId::number(num),
        None => BlockId::default(), // Latest
    };

    // Create AlloyDB (handles caching and RPC fetching automatically)
    let alloy_db = revm::db::AlloyDB::new(provider, block_id)
        .await
        .context("Failed to initialize AlloyDB fork")?;

    // Wrap in CacheDB for fast local state mutations during fuzzing
    Ok(CacheDB::new(alloy_db))
}