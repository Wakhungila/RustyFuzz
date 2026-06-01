use crate::common::types::{EvmInput, SingletonTx};
use crate::engine::abi_ingest::{AbiFunctionSummary, SelectorClassification};
use crate::evm::fork_db::{ForkDb, ForkDbCacheSnapshot};
use alloy::consensus::Transaction;
use alloy::providers::Provider;
use alloy::rpc::types::eth::{BlockTransactions, Filter};
use anyhow::Context;
use revm::database_interface::DatabaseRef;
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_SEARCH_DEPTH: u64 = 100;
const DEFAULT_MAX_RETRIES: usize = 3;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 250;
const DIRECT_MATCH: &str = "direct";
const ADDRESS_HINT_MATCH: &str = "address-hint";

/// Controls deterministic mainnet seed ingestion. Every range is walked from
/// newest to oldest, then normalized before being returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MainnetSeedConfig {
    pub fork_block: u64,
    pub target: Address,
    pub start_block: Option<u64>,
    pub search_depth: u64,
    pub max_seeds: usize,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub include_address_hints: bool,
    #[serde(default)]
    pub max_blocks_per_second: Option<f64>,
    #[serde(default)]
    pub resume_cursor: Option<String>,
    #[serde(default)]
    pub output_manifest: Option<String>,
    #[serde(default)]
    pub scan_mode: SeedScanMode,
    #[serde(default)]
    pub abi_functions: BTreeMap<[u8; 4], SeedAbiFunction>,
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
            include_address_hints: false,
            max_blocks_per_second: None,
            resume_cursor: None,
            output_manifest: None,
            scan_mode: SeedScanMode::BlockScan,
            abi_functions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeedScanMode {
    #[default]
    BlockScan,
    Logs,
    DebugTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedAbiFunction {
    pub name: String,
    pub signature: String,
    pub selector: [u8; 4],
    pub inputs: Vec<String>,
    pub classification: SelectorClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MainnetSeedBundle {
    pub fork_block: u64,
    pub target: Address,
    pub seeds: Vec<MainnetSeed>,
    pub discovered_accounts: Vec<DiscoveredAccount>,
    pub fork_cache: ForkDbCacheSnapshot,
    #[serde(default)]
    pub scan: Option<SeedScanManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedScanCursor {
    pub last_scanned_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeedScanManifest {
    pub chain_id: Option<u64>,
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub search_depth: u64,
    pub include_address_hints: bool,
    pub max_blocks_per_second: Option<f64>,
    pub scan_mode: SeedScanMode,
    pub decoded_abi: bool,
    pub seed_count: usize,
    pub discovered_selectors: Vec<[u8; 4]>,
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
    #[serde(default)]
    pub matched_target: Option<Address>,
    #[serde(default)]
    pub match_kind: Option<String>,
    #[serde(default)]
    pub confidence: Option<u64>,
    #[serde(default)]
    pub provenance: Option<String>,
    #[serde(default)]
    pub decoded: Option<DecodedCalldataMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecodedCalldataMetadata {
    pub function_name: String,
    pub signature: String,
    pub selector: [u8; 4],
    pub inputs: Vec<String>,
    pub classification: SelectorClassification,
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
        let start_block = resume_start_block(config)
            .transpose()?
            .flatten()
            .or(config.start_block)
            .unwrap_or(latest_block);
        let mut candidates = Vec::new();
        let mut last_fetch = None::<Instant>;

        match config.scan_mode {
            SeedScanMode::BlockScan | SeedScanMode::DebugTrace => {
                self.ingest_block_scan(
                    config,
                    start_block,
                    &mut candidates,
                    &mut last_fetch,
                )
                .await?;
            }
            SeedScanMode::Logs => {
                self.ingest_logs_scan(config, start_block, &mut candidates).await?;
            }
        }

        let seeds = normalize_seeds(candidates);
        let discovered_accounts = discover_accounts_from_seeds(&seeds, fork_db)?;
        let fork_cache = fork_db.cache_snapshot();
        let scan = SeedScanManifest {
            chain_id: None,
            start_block: Some(start_block),
            end_block: Some(start_block.saturating_sub(config.search_depth.saturating_sub(1))),
            search_depth: config.search_depth,
            include_address_hints: config.include_address_hints,
            max_blocks_per_second: config.max_blocks_per_second,
            scan_mode: config.scan_mode,
            decoded_abi: !config.abi_functions.is_empty(),
            seed_count: seeds.len(),
            discovered_selectors: seeds
                .iter()
                .filter_map(|seed| seed.metadata.selector)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        if let Some(path) = &config.output_manifest {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(path, serde_json::to_vec_pretty(&scan)?)?;
        }

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
            scan: Some(scan),
        })
    }

    async fn ingest_block_scan(
        &self,
        config: &MainnetSeedConfig,
        start_block: u64,
        candidates: &mut Vec<MainnetSeed>,
        last_fetch: &mut Option<Instant>,
    ) -> anyhow::Result<()> {
        for offset in 0..config.search_depth {
            if candidates.len() >= config.max_seeds {
                break;
            }
            let block_num = start_block.saturating_sub(offset);
            if config.scan_mode == SeedScanMode::DebugTrace {
                self.debug_trace_block(config, block_num).await;
            }
            rate_limit_block_fetch(config, last_fetch).await;
            let Some(block) = self.fetch_block_with_retries(block_num, config).await? else {
                write_seed_scan_cursor(config, block_num)?;
                continue;
            };
            write_seed_scan_cursor(config, block_num)?;

            let BlockTransactions::Full(txs) = block.transactions else {
                continue;
            };

            for (transaction_ordinal, tx) in txs.into_iter().enumerate() {
                let envelope = &*tx.inner;
                let Some(to) = envelope.to() else {
                    continue;
                };
                let input_bytes = envelope.input().to_vec();
                let Some(match_kind) = seed_match_kind(
                    to,
                    config.target,
                    &input_bytes,
                    config.include_address_hints,
                ) else {
                    continue;
                };

                candidates.push(seed_from_parts(
                    config,
                    block_num,
                    offset,
                    transaction_ordinal,
                    Address::from(*tx.inner.signer()),
                    to,
                    envelope.value(),
                    input_bytes,
                    match_kind,
                    match config.scan_mode {
                        SeedScanMode::DebugTrace => "rpc-debug-trace-block-scan",
                        _ => "rpc-block-scan",
                    },
                ));

                if candidates.len() >= config.max_seeds {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn ingest_logs_scan(
        &self,
        config: &MainnetSeedConfig,
        start_block: u64,
        candidates: &mut Vec<MainnetSeed>,
    ) -> anyhow::Result<()> {
        let end_block = start_block.saturating_sub(config.search_depth.saturating_sub(1));
        let filter = Filter::new()
            .from_block(end_block)
            .to_block(start_block)
            .address(config.target);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .context("failed to fetch target logs with eth_getLogs")?;
        for log in logs {
            if candidates.len() >= config.max_seeds {
                break;
            }
            let Some(hash) = log.transaction_hash else {
                continue;
            };
            let Some(tx) = self.provider.get_transaction_by_hash(hash).await? else {
                continue;
            };
            let envelope = &*tx.inner;
            let Some(to) = envelope.to() else {
                continue;
            };
            let input_bytes = envelope.input().to_vec();
            let Some(match_kind) = seed_match_kind(
                to,
                config.target,
                &input_bytes,
                true,
            ) else {
                continue;
            };
            candidates.push(seed_from_parts(
                config,
                log.block_number.unwrap_or(start_block),
                start_block.saturating_sub(log.block_number.unwrap_or(start_block)),
                log.transaction_index.unwrap_or(0) as usize,
                Address::from(*tx.inner.signer()),
                to,
                envelope.value(),
                input_bytes,
                match_kind,
                "rpc-log-scan",
            ));
        }
        Ok(())
    }

    async fn debug_trace_block(&self, config: &MainnetSeedConfig, block_num: u64) {
        let params = (
            format!("0x{block_num:x}"),
            serde_json::json!({ "tracer": "callTracer", "timeout": "10s" }),
        );
        if let Err(err) = self
            .provider
            .client()
            .request::<_, serde_json::Value>("debug_traceBlockByNumber", params)
            .await
        {
            log::warn!(
                "debug_traceBlockByNumber unavailable for seed scan block {} target {}: {}",
                block_num,
                config.target,
                err
            );
        }
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
                        let delay_ms = retry_backoff_delay_ms(config.retry_backoff_ms, attempt);
                        log::warn!(
                            "seed discovery RPC block fetch failed for block {}; retrying attempt {}/{} after {}ms",
                            block_num,
                            attempt + 2,
                            config.max_retries.max(1),
                            delay_ms
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
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

pub fn seed_abi_functions(
    functions: impl IntoIterator<Item = AbiFunctionSummary>,
) -> BTreeMap<[u8; 4], SeedAbiFunction> {
    functions
        .into_iter()
        .map(|function| {
            (
                function.selector,
                SeedAbiFunction {
                    name: function.name,
                    signature: function.signature,
                    selector: function.selector,
                    inputs: function.inputs,
                    classification: function.classification,
                },
            )
        })
        .collect()
}

fn seed_from_parts(
    config: &MainnetSeedConfig,
    source_block: u64,
    block_offset: u64,
    transaction_ordinal: usize,
    caller: Address,
    to: Address,
    value: U256,
    input_bytes: Vec<u8>,
    match_kind: &str,
    provenance: &str,
) -> MainnetSeed {
    let selector = selector(&input_bytes);
    let decoded = selector
        .and_then(|selector| config.abi_functions.get(&selector))
        .map(|function| DecodedCalldataMetadata {
            function_name: function.name.clone(),
            signature: function.signature.clone(),
            selector: function.selector,
            inputs: function.inputs.clone(),
            classification: function.classification.clone(),
        });
    let seed_input = EvmInput {
        txs: vec![SingletonTx {
            input: input_bytes.clone(),
            caller,
            to,
            value,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let metadata = SeedMetadata {
        source_block,
        block_offset,
        transaction_ordinal,
        caller,
        target: to,
        value,
        selector,
        calldata_len: input_bytes.len(),
        discovered_address_hints: extract_address_hints(&input_bytes),
        matched_target: Some(config.target),
        match_kind: Some(match_kind.to_string()),
        confidence: Some(if match_kind == DIRECT_MATCH { 95 } else { 75 }),
        provenance: Some(provenance.to_string()),
        decoded,
    };
    MainnetSeed {
        id: stable_seed_id(&seed_input, &metadata),
        input: seed_input,
        metadata,
    }
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

pub fn seed_match_kind(
    to: Address,
    target: Address,
    calldata: &[u8],
    include_address_hints: bool,
) -> Option<&'static str> {
    if to == target {
        return Some(DIRECT_MATCH);
    }
    if include_address_hints && extract_address_hints(calldata).contains(&target) {
        return Some(ADDRESS_HINT_MATCH);
    }
    None
}

fn resume_start_block(config: &MainnetSeedConfig) -> Option<anyhow::Result<Option<u64>>> {
    config.resume_cursor.as_ref().map(|path| {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let cursor: SeedScanCursor = serde_json::from_slice(&bytes)?;
        Ok(cursor.last_scanned_block.checked_sub(1))
    })
}

fn write_seed_scan_cursor(config: &MainnetSeedConfig, block_num: u64) -> anyhow::Result<()> {
    let Some(path) = &config.resume_cursor else {
        return Ok(());
    };
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&SeedScanCursor {
            last_scanned_block: block_num,
        })?,
    )?;
    Ok(())
}

fn retry_backoff_delay_ms(base_ms: u64, attempt: usize) -> u64 {
    let multiplier = 1u64.checked_shl(attempt.min(20) as u32).unwrap_or(1 << 20);
    base_ms.max(1).saturating_mul(multiplier)
}

async fn rate_limit_block_fetch(config: &MainnetSeedConfig, last_fetch: &mut Option<Instant>) {
    let Some(blocks_per_second) = config.max_blocks_per_second else {
        return;
    };
    if blocks_per_second <= 0.0 {
        return;
    }
    let min_interval = Duration::from_secs_f64(1.0 / blocks_per_second);
    if let Some(previous) = last_fetch {
        let elapsed = previous.elapsed();
        if elapsed < min_interval {
            tokio::time::sleep(min_interval - elapsed).await;
        }
    }
    *last_fetch = Some(Instant::now());
}

fn stable_seed_id(input: &EvmInput, metadata: &SeedMetadata) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(&metadata.source_block.to_be_bytes());
    material.extend_from_slice(&metadata.transaction_ordinal.to_be_bytes());
    material.extend_from_slice(&serde_json::to_vec(input).unwrap_or_default());
    format!("seed-{}", &hex::encode(keccak256(material))[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rustyfuzz-{name}-{}-{suffix}.json",
            std::process::id()
        ))
    }

    #[test]
    fn seed_match_kind_accepts_direct_and_address_hint_matches() {
        let target = Address::repeat_byte(0xaa);
        let router = Address::repeat_byte(0xbb);
        let mut calldata = vec![0xde, 0xad, 0xbe, 0xef];
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(target.as_slice());

        assert_eq!(
            seed_match_kind(target, target, &calldata, false),
            Some(DIRECT_MATCH)
        );
        assert_eq!(
            seed_match_kind(router, target, &calldata, true),
            Some(ADDRESS_HINT_MATCH)
        );
        assert_eq!(seed_match_kind(router, target, &calldata, false), None);
    }

    #[test]
    fn seed_scan_cursor_is_written_and_resume_continues_from_previous_block() {
        let target = Address::repeat_byte(0xaa);
        let cursor = temp_path("seed-cursor");
        let mut config = MainnetSeedConfig::new(100, target, 8);
        config.resume_cursor = Some(cursor.display().to_string());

        write_seed_scan_cursor(&config, 99).expect("write cursor");
        let resumed = resume_start_block(&config)
            .expect("cursor configured")
            .expect("read cursor")
            .expect("resume block");

        assert_eq!(resumed, 98);
        let _ = std::fs::remove_file(cursor);
    }

    #[test]
    fn retry_backoff_is_exponential_and_saturating() {
        assert_eq!(retry_backoff_delay_ms(250, 0), 250);
        assert_eq!(retry_backoff_delay_ms(250, 1), 500);
        assert_eq!(retry_backoff_delay_ms(250, 2), 1000);
        assert_eq!(retry_backoff_delay_ms(0, 3), 8);
    }
}
