// #[cfg(feature = "evm")]
// use alloy::eips::BlockId;
// #[cfg(feature = "evm")]
// use alloy::providers::{Provider, ProviderBuilder};
// #[cfg(feature = "evm")]
// use alloy::rpc::types::eth::BlockNumberOrTag;
// use anyhow::Context;
// use revm::context::BlockEnv;
// use revm::database::CacheDB;
// use revm::primitives::{Address, U256};
// use revm::state::{AccountInfo, Bytecode};

// use crate::evm::fork_db::{EvmCacheDb, ForkDb};

// #[cfg(feature = "evm")]
// pub async fn create_fork_db(
//     rpc_url: &str,
//     block_number: u64,
//     target_contract: Option<Address>,
// ) -> anyhow::Result<EvmCacheDb> {
//     let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
//     let provider = ProviderBuilder::new().connect_http(url);
//     let mut db = CacheDB::new(ForkDb::new(rpc_url.to_string(), block_number));

//     if let Some(target) = target_contract {
//         let code = provider
//             .get_code_at(target)
//             .block_id(BlockId::number(block_number))
//             .await
//             .with_context(|| {
//                 format!("failed to fetch bytecode for target {target} at block {block_number}")
//             })?;
//         anyhow::ensure!(
//             !code.is_empty(),
//             "target contract {target} has no bytecode at fork block {block_number}"
//         );
//         db.insert_account_info(
//             target,
//             AccountInfo::default().with_code(Bytecode::new_raw(code)),
//         );
//     }

//     Ok(db)
// }

// #[cfg(feature = "evm")]
// pub async fn create_fork_block_env(rpc_url: &str, block_number: u64) -> anyhow::Result<BlockEnv> {
//     let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
//     let provider = ProviderBuilder::new().connect_http(url);

//     // Fetch actual block metadata to make the fuzzing environment realistic
//     let block = provider
//         .get_block_by_number(BlockNumberOrTag::Number(block_number))
//         .await?
//         .context("Block not found")?;

//     let header = block.header;

//     Ok(BlockEnv {
//         number: U256::from(header.number),
//         beneficiary: header.beneficiary,
//         timestamp: U256::from(header.timestamp),
//         gas_limit: header.gas_limit,
//         basefee: header.base_fee_per_gas.unwrap_or_default(),
//         difficulty: header.difficulty,
//         prevrandao: Some(header.mix_hash),
//         blob_excess_gas_and_price: None, // Update if fuzzing EIP-4844
//         slot_num: 0,                     // Placeholder - needs actual calculation
//     })
// }

#[cfg(feature = "evm")]
use alloy::eips::BlockId;
#[cfg(feature = "evm")]
use alloy::providers::{Provider, ProviderBuilder};
#[cfg(feature = "evm")]
use alloy::rpc::types::eth::BlockNumberOrTag;

use anyhow::Context;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::{Address, B256, U256};
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

    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number))
        .await?
        .context("Block not found")?;

    let header = block.header;

    let mut block_env = BlockEnv {
        number: U256::from(header.number),
        beneficiary: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao: Some(header.mix_hash),

        // Set below with `set_blob_excess_gas_and_price`.
        blob_excess_gas_and_price: None,

        // Placeholder for now. Not related to the current failure.
        slot_num: 0,
    };

    // Required when revm validates under Cancun/latest EVM rules.
    //
    // 3_338_477 is the Cancun blob base-fee update fraction.
    // Use 0 for excess_blob_gas as a safe default when the provider/header
    // does not expose the field cleanly through the current Alloy type.
    block_env.set_blob_excess_gas_and_price(0, 3_338_477);

    Ok(block_env)
}

pub fn create_offline_fallback_fork_db(target_contract: Option<Address>) -> EvmCacheDb {
    let db = CacheDB::new(ForkDb::empty());
    if let Some(target) = target_contract {
        let code = Bytecode::new_raw(offline_fallback_runtime_bytecode().into());
        db.db
            .cache_account(target, AccountInfo::default().with_code(code));
    }
    db
}

pub fn create_offline_fallback_block_env(block_number: u64) -> BlockEnv {
    let mut block_env = BlockEnv {
        number: U256::from(block_number),
        beneficiary: Address::ZERO,
        timestamp: U256::ZERO,
        gas_limit: 30_000_000,
        basefee: 0,
        difficulty: U256::ZERO,
        prevrandao: Some(B256::ZERO),
        blob_excess_gas_and_price: None,
        slot_num: 0,
    };
    block_env.set_blob_excess_gas_and_price(0, 3_338_477);
    block_env
}

pub fn offline_fallback_runtime_bytecode() -> Vec<u8> {
    let mut code = vec![
        0x60, 0x00, 0x54, // PUSH1 0x00; SLOAD
        0x60, 0x01, 0x01, // PUSH1 0x01; ADD
        0x80, // DUP1
        0x60, 0x00, 0x55, // PUSH1 0x00; SSTORE
    ];
    let large_value = U256::from(10u128.pow(18)).to_be_bytes::<32>();
    for slot in 1u8..7 {
        code.push(0x7f); // PUSH32
        code.extend_from_slice(&large_value);
        code.extend_from_slice(&[0x60, slot, 0x55]); // PUSH1 slot; SSTORE
    }
    code.extend_from_slice(&[
        0x60, 0x00, 0x52, // PUSH1 0x00; MSTORE
        0x60, 0x20, 0x60, 0x00, 0xf3, // PUSH1 0x20; PUSH1 0x00; RETURN
    ]);
    code
}
