use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::transports::http::Http;
use revm::db::{CacheDB, EmptyDB, alloydb::AlloyDB};
use url::Url;
use reqwest::Client;
use revm::primitives::BlockEnv;

pub async fn create_fork_db(rpc_url: &str, block_number: Option<u64>) -> anyhow::Result<CacheDB<AlloyDB<Http<Client>, EmptyDB, RootProvider<Http<Client>>>>> {
    let url: Url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().on_http(url);
    
    let block_id = match block_number {
        Some(n) => alloy::eips::BlockId::number(n),
        None => alloy::eips::BlockId::latest(),
    };

    // AlloyDB provides a Database implementation for revm that fetches
    // state from a remote RPC on-demand (SSTORE/SLOAD).
    let alloy_db = AlloyDB::new(provider, block_id).unwrap();
    let cache_db = CacheDB::new(alloy_db);
    
    Ok(cache_db)
}