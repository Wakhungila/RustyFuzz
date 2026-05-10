#[cfg(feature = "evm")]
use alloy::providers::{Provider, ProviderBuilder};
#[cfg(feature = "evm")]
use alloy::rpc::types::eth::BlockNumberOrTag;
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::U256;
use revm::context::BlockEnv;
use anyhow::Context;

#[cfg(feature = "evm")]
pub async fn create_fork_db(rpc_url: &str, _block_number: u64) -> anyhow::Result<CacheDB<EmptyDB>> {
    // In v38, we initialize a CacheDB with an EmptyDB backend.
    // Real-world state is usually fetched via a custom 'AlloyDB' wrapper
    // that implements the revm 'Database' trait.
    let _url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
    
    // Placeholder for actual state syncing logic
    let db = CacheDB::new(EmptyDB::default());
    Ok(db)
}

#[cfg(feature = "evm")]
pub async fn create_fork_block_env(rpc_url: &str, block_number: u64) -> anyhow::Result<BlockEnv> {
    let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
    let provider = ProviderBuilder::new().connect_http(url);
    
    // Fetch actual block metadata to make the fuzzing environment realistic
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number))
        .await?
        .context("Block not found")?;

    let header = block.header;

    Ok(BlockEnv {
        number: U256::from(header.number),
        beneficiary: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: header.mix_hash,
        blob_excess_gas_and_price: None, // Update if fuzzing EIP-4844
        slot_num: 0, // Placeholder - needs actual calculation
    })
}