#[cfg(feature = "evm")]
use alloy::providers::{Provider, ProviderBuilder};
#[cfg(feature = "evm")]
use alloy::rpc::types::eth::BlockNumberOrTag;
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::{BlockEnv, U256, Address};
use anyhow::Context;

#[cfg(feature = "evm")]
pub async fn create_fork_db(rpc_url: &str, _block_number: u64) -> anyhow::Result<CacheDB<EmptyDB>> {
    // In v38, we initialize a CacheDB with an EmptyDB backend.
    // Real-world state is usually fetched via a custom 'AlloyDB' wrapper
    // that implements the revm 'Database' trait.
    let _url = rpc_url.parse().context("Invalid RPC URL")?;
    
    // Placeholder for actual state syncing logic
    let db = CacheDB::new(EmptyDB::default());
    Ok(db)
}

#[cfg(feature = "evm")]
pub async fn create_fork_block_env(rpc_url: &str, block_number: u64) -> anyhow::Result<BlockEnv> {
    let url = rpc_url.parse().context("Invalid RPC URL")?;
    let provider = ProviderBuilder::new().on_http(url);
    
    // Fetch actual block metadata to make the fuzzing environment realistic
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number), false)
        .await?
        .context("Block not found")?;

    let header = block.header;

    Ok(BlockEnv {
        number: U256::from(header.number.unwrap_or(block_number)),
        coinbase: header.miner,
        timestamp: U256::from(header.timestamp),
        gas_limit: U256::from(header.gas_limit),
        basefee: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        difficulty: U256::from(header.difficulty),
        prevrandao: Some(header.mix_hash.unwrap_or_default()),
        blob_excess_gas_and_price: None, // Update if fuzzing EIP-4844
    })
}