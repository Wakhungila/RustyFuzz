use crate::common::types::{EvmInput, SingletonTx};
use crate::evm::fork_db::{ForkDb, ForkDbCacheSnapshot};
use alloy::consensus::Transaction;
use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockTransactions;
use anyhow::Context;
use revm::database_interface::DatabaseRef;
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_SEARCH_DEPTH: u64 = 100;
const DEFAULT_MAX_RETRIES: usize = 3;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 250;

/// Controls deterministic mainnet seed ingestion. Every range is walked from
/// newest to oldest, then normalized before being returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainnetSeedConfig {
    pub fork_block: u64,
    pub target: Address,
    pub start_block: Option<u64>,
    pub search_depth: u64,
    pub max_seeds: usize,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
}

impl MainnetSeedConfig {
    pub fn new(fork_block: u64, target: Address, max_seeds: usize) -> Self {
        Self {
            fork_block,
            target,
            start_block: None,
            search_depth: DEFAULT_SEARCH_DEPTH,
            max_seeds,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_backoff_ms: DEFAULT_RETRY_BACKOFF_MS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainnetSeedBundle {
    pub fork_block: u64,
    pub target: Address,
    pub seeds: Vec<MainnetSeed>,
    pub discovered_accounts: Vec<DiscoveredAccount>,
    pub fork_cache: ForkDbCacheSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainnetSeed {
    pub id: String,
    pub input: EvmInput,
    pub metadata: SeedMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeedMetadata {
    pub source_block: u64,
    pub block_offset: u64,
    pub transaction_ordinal: usize,
    pub caller: Address,
    pub target: Address,
    pub value: U256,
    pub selector: Option<[u8; 4]>,
    pub calldata_len: usize,
    pub discovered_address_hints: Vec<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredAccount {
    pub address: Address,
    pub is_contract: bool,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub code_len: usize,
    pub observed_selectors: Vec<[u8; 4]>,
    pub referenced_by_seed_ids: Vec<String>,
}

/// SeedIngester pulls real-world transaction data from a mainnet RPC and
/// turns it into deterministic, replayable campaign seeds.
pub struct SeedIngester<P> {
    provider: Arc<P>,
}

impl<P: Provider> SeedIngester<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    /// Compatibility wrapper for callers that only need inputs.
    pub async fn ingest_from_target(
        &self,
        target: Address,
        max_seeds: usize,
    ) -> anyhow::Result<Vec<EvmInput>> {
        let latest_block = self
            .provider
            .get_block_number()
            .await
            .context("failed to fetch latest block number")?;
        let config = MainnetSeedConfig::new(latest_block, target, max_seeds);
        let fork_db = ForkDb::new_offline(format!("0x{latest_block:x}"));
        Ok(self
            .ingest_bundle_from_target(&config, &fork_db)
            .await?
            .seeds
            .into_iter()
            .map(|seed| seed.input)
            .collect())
    }

    /// Fetch target-directed mainnet transactions, normalize them, discover
    /// touched accounts/contracts through the fork DB, and snapshot the cache.
    pub async fn ingest_bundle_from_target(
        &self,
        config: &MainnetSeedConfig,
        fork_db: &ForkDb,
    ) -> anyhow::Result<MainnetSeedBundle> {
        let latest_block = self
            .provider
            .get_block_number()
            .await
            .context("failed to fetch latest block number")?;
        let start_block = config.start_block.unwrap_or(latest_block);
        let mut candidates = Vec::new();

        for offset in 0..config.search_depth {
            if candidates.len() >= config.max_seeds {
                break;
            }
            let block_num = start_block.saturating_sub(offset);
            let Some(block) = self.fetch_block_with_retries(block_num, config).await? else {
                continue;
            };

            let BlockTransactions::Full(txs) = block.transactions else {
                continue;
            };

            for (transaction_ordinal, tx) in txs.into_iter().enumerate() {
                let envelope = &*tx.inner;
                if envelope.to() != Some(config.target) {
                    continue;
                }

                let input_bytes = envelope.input().to_vec();
                let caller = Address::from(*tx.inner.signer());
                let seed_input = EvmInput {
                    txs: vec![SingletonTx {
                        input: input_bytes.clone(),
                        caller,
                        to: config.target,
                        value: envelope.value(),
                        is_victim: false,
                    }],
                    base_snapshot_id: 0,
                    waypoints: Vec::new(),
                    mutation_provenance: Vec::new(),
                };
                let metadata = SeedMetadata {
                    source_block: block_num,
                    block_offset: offset,
                    transaction_ordinal,
                    caller,
                    target: config.target,
                    value: envelope.value(),
                    selector: selector(&input_bytes),
                    calldata_len: input_bytes.len(),
                    discovered_address_hints: extract_address_hints(&input_bytes),
                };
                candidates.push(MainnetSeed {
                    id: stable_seed_id(&seed_input, &metadata),
                    input: seed_input,
                    metadata,
                });

                if candidates.len() >= config.max_seeds {
                    break;
                }
            }
        }

        let seeds = normalize_seeds(candidates);
        let discovered_accounts = discover_accounts_from_seeds(&seeds, fork_db)?;
        let fork_cache = fork_db.cache_snapshot();

        log::info!(
            "Ingested {} mainnet seeds for target {} with {} discovered accounts",
            seeds.len(),
            config.target,
            discovered_accounts.len()
        );

        Ok(MainnetSeedBundle {
            fork_block: config.fork_block,
            target: config.target,
            seeds,
            discovered_accounts,
            fork_cache,
        })
    }

    async fn fetch_block_with_retries(
        &self,
        block_num: u64,
        config: &MainnetSeedConfig,
    ) -> anyhow::Result<Option<alloy::rpc::types::eth::Block>> {
        let mut last_error = None;
        for attempt in 0..config.max_retries.max(1) {
            match self.provider.get_block_by_number(block_num.into()).await {
                Ok(block) => return Ok(block),
                Err(err) => {
                    last_error = Some(err);
                    if attempt + 1 < config.max_retries.max(1) {
                        tokio::time::sleep(Duration::from_millis(
                            config.retry_backoff_ms.max(1) * (attempt as u64 + 1),
                        ))
                        .await;
                    }
                }
            }
        }
        Err(last_error
            .map(anyhow::Error::new)
            .unwrap_or_else(|| anyhow::anyhow!("failed to fetch block {block_num}")))
        .with_context(|| format!("failed to fetch block {block_num}"))
    }
}

pub fn normalize_seeds(mut seeds: Vec<MainnetSeed>) -> Vec<MainnetSeed> {
    seeds.sort_by(|a, b| {
        a.metadata
            .cmp(&b.metadata)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.input.txs.len().cmp(&b.input.txs.len()))
    });
    seeds.dedup_by(|a, b| a.id == b.id);
    seeds
}

pub fn discover_accounts_from_seeds(
    seeds: &[MainnetSeed],
    fork_db: &ForkDb,
) -> anyhow::Result<Vec<DiscoveredAccount>> {
    let mut referenced_by: BTreeMap<Address, BTreeSet<String>> = BTreeMap::new();
    let mut selectors_by_target: BTreeMap<Address, BTreeSet<[u8; 4]>> = BTreeMap::new();

    for seed in seeds {
        for tx in &seed.input.txs {
            referenced_by
                .entry(tx.caller)
                .or_default()
                .insert(seed.id.clone());
            referenced_by
                .entry(tx.to)
                .or_default()
                .insert(seed.id.clone());
            if let Some(selector) = selector(&tx.input) {
                selectors_by_target
                    .entry(tx.to)
                    .or_default()
                    .insert(selector);
            }
            for hint in extract_address_hints(&tx.input) {
                referenced_by
                    .entry(hint)
                    .or_default()
                    .insert(seed.id.clone());
            }
        }
    }

    let mut discovered = Vec::new();
    for (address, seed_ids) in referenced_by {
        let account = fork_db.basic_ref(address).with_context(|| {
            format!("failed to load account {address} while discovering seed accounts")
        })?;
        let Some(info) = account else {
            continue;
        };
        discovered.push(DiscoveredAccount {
            address,
            is_contract: info.code.as_ref().is_some_and(|code| !code.is_empty()),
            balance: info.balance,
            nonce: info.nonce,
            code_hash: info.code_hash,
            code_len: info
                .code
                .as_ref()
                .map(|code| code.original_byte_slice().len())
                .unwrap_or_default(),
            observed_selectors: selectors_by_target
                .remove(&address)
                .unwrap_or_default()
                .into_iter()
                .collect(),
            referenced_by_seed_ids: seed_ids.into_iter().collect(),
        });
    }
    discovered.sort_by_key(|account| account.address);
    Ok(discovered)
}

pub fn selector(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata
        .get(..4)
        .map(|bytes| bytes.try_into().expect("slice length is fixed"))
}

pub fn extract_address_hints(calldata: &[u8]) -> Vec<Address> {
    let mut hints = BTreeSet::new();
    for word in calldata.get(4..).unwrap_or_default().chunks_exact(32) {
        if word[..12].iter().all(|byte| *byte == 0) && word[12..31].iter().any(|byte| *byte != 0) {
            hints.insert(Address::from_slice(&word[12..]));
        }
    }
    hints.into_iter().collect()
}

fn stable_seed_id(input: &EvmInput, metadata: &SeedMetadata) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(&metadata.source_block.to_be_bytes());
    material.extend_from_slice(&metadata.transaction_ordinal.to_be_bytes());
    material.extend_from_slice(&serde_json::to_vec(input).unwrap_or_default());
    format!("seed-{}", &hex::encode(keccak256(material))[..16])
}
