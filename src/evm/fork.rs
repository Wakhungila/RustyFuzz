use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::transports::http::Http;
use revm::db::{CacheDB, EmptyDB, alloydb::AlloyDB};
use url::Url;
use reqwest::Client;
use revm::primitives::BlockEnv;
use alloy::eips::BlockId;

pub async fn create_fork_db(
    rpc_url: &str,
    block_number: Option<u64>,
) -> anyhow::Result<CacheDB<AlloyDB<Http<Client>, EmptyDB, RootProvider<Http<Client>>>>> {
    let url: Url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().on_http(url);

    let block_id = match block_number {
        Some(n) => BlockId::number(n),
        None => BlockId::latest(),
    };

    let alloy_db = AlloyDB::new(provider, block_id)
        .map_err(|e| anyhow::anyhow!("Failed to create AlloyDB: {:?}", e))?;

    Ok(CacheDB::new(alloy_db))
}