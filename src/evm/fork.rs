#[cfg(feature = "evm")]
use alloy::eips::BlockId;
#[cfg(feature = "evm")]
use alloy::providers::{Provider, ProviderBuilder};
#[cfg(feature = "evm")]
use alloy::rpc::types::eth::BlockNumberOrTag;
use anyhow::Context;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::{Address, U256};
use revm::state::{AccountInfo, Bytecode};

use crate::evm::fork_db::{EvmCacheDb, ForkDb};

#[cfg(feature = "evm")]
pub async fn create_fork_db(
    rpc_url: &str,
    block_number: u64,
    target_contract: Option<Address>,
) -> anyhow::Result<EvmCacheDb> {
    let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
    let provider = ProviderBuilder::new().connect_http(url);
    let mut db = CacheDB::new(ForkDb::new(rpc_url.to_string(), block_number));

    if let Some(target) = target_contract {
        let code = provider
            .get_code_at(target)
            .block_id(BlockId::number(block_number))
            .await
            .with_context(|| {
                format!("failed to fetch bytecode for target {target} at block {block_number}")
            })?;
        anyhow::ensure!(
            !code.is_empty(),
            "target contract {target} has no bytecode at fork block {block_number}"
        );
        db.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(code)),
        );
    }

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
        prevrandao: Some(header.mix_hash),
        blob_excess_gas_and_price: None, // Update if fuzzing EIP-4844
        slot_num: 0,                     // Placeholder - needs actual calculation
    })
}
