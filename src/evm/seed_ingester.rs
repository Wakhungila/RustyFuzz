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
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_SEARCH_DEPTH: u64 = 100;
const DEFAULT_MAX_RETRIES: usize = 3;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 250;
const LOG_SCAN_CHUNK_BLOCKS: u64 = 10;
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
    #[serde(default)]
    pub scan_mode: SeedScanMode,
    #[serde(default)]
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
    #[serde(default)]
    pub tx_hash: Option<B256>,
    #[serde(default)]
    pub top_level_caller: Option<Address>,
    #[serde(default)]
    pub internal_caller: Option<Address>,
    #[serde(default)]
    pub trace_path: Option<String>,
    #[serde(default)]
    pub trace_source: Option<String>,
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
                self.ingest_block_scan(config, start_block, &mut candidates, &mut last_fetch)
                    .await?;
            }
            SeedScanMode::Logs => {
                self.ingest_logs_scan(config, start_block, &mut candidates)
                    .await?;
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
                let mut trace_seeds = self.debug_trace_block(config, block_num).await;
                candidates.append(&mut trace_seeds);
                if candidates.len() >= config.max_seeds {
                    candidates.truncate(config.max_seeds);
                    break;
                }
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
        let mut chunk_to = start_block;
        let mut last_fetch = None::<Instant>;
        while chunk_to >= end_block {
            if candidates.len() >= config.max_seeds {
                break;
            }
            let chunk_from = chunk_to
                .saturating_sub(LOG_SCAN_CHUNK_BLOCKS.saturating_sub(1))
                .max(end_block);
            rate_limit_block_fetch(config, &mut last_fetch).await;
            let filter = Filter::new()
                .from_block(chunk_from)
                .to_block(chunk_to)
                .address(config.target);
            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .with_context(|| {
                    format!(
                        "failed to fetch target logs with eth_getLogs for block range [{chunk_from}, {chunk_to}]"
                    )
                })?;
            write_seed_scan_cursor(config, chunk_from)?;
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
                let Some(match_kind) = seed_match_kind(to, config.target, &input_bytes, true)
                else {
                    continue;
                };
                candidates.push(seed_from_parts(
                    config,
                    log.block_number.unwrap_or(chunk_to),
                    start_block.saturating_sub(log.block_number.unwrap_or(chunk_to)),
                    log.transaction_index.unwrap_or(0) as usize,
                    Address::from(*tx.inner.signer()),
                    to,
                    envelope.value(),
                    input_bytes,
                    match_kind,
                    "rpc-log-scan",
                ));
            }
            if chunk_from == 0 {
                break;
            }
            chunk_to = chunk_from - 1;
        }
        Ok(())
    }

    async fn debug_trace_block(
        &self,
        config: &MainnetSeedConfig,
        block_num: u64,
    ) -> Vec<MainnetSeed> {
        let params = (
            format!("0x{block_num:x}"),
            serde_json::json!({ "tracer": "callTracer", "timeout": "10s" }),
        );
        match self
            .provider
            .client()
            .request::<_, serde_json::Value>("debug_traceBlockByNumber", params)
            .await
        {
            Ok(trace) => seeds_from_debug_trace_value(config, &trace),
            Err(err) => {
                log::warn!(
                    "debug_traceBlockByNumber unavailable for seed scan block {} target {}: {}",
                    block_num,
                    config.target,
                    err
                );
                Vec::new()
            }
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

#[allow(clippy::too_many_arguments)]
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
        tx_hash: None,
        top_level_caller: Some(caller),
        internal_caller: None,
        trace_path: None,
        trace_source: None,
    };
    MainnetSeed {
        id: stable_seed_id(&seed_input, &metadata),
        input: seed_input,
        metadata,
    }
}

pub fn seeds_from_debug_trace_value(config: &MainnetSeedConfig, trace: &Value) -> Vec<MainnetSeed> {
    let mut out = Vec::new();
    let trace_source = detect_trace_source(trace);
    let entries: Vec<&Value> = match trace {
        Value::Array(values) => values.iter().collect(),
        Value::Object(_) => vec![trace],
        _ => Vec::new(),
    };
    for (tx_ordinal, entry) in entries.into_iter().enumerate() {
        let tx_hash = entry
            .get("txHash")
            .or_else(|| entry.get("hash"))
            .or_else(|| entry.get("transactionHash"))
            .and_then(parse_b256);
        let block_number = entry
            .get("blockNumber")
            .and_then(parse_u64_quantity)
            .unwrap_or(config.fork_block);
        let root = if entry.get("action").is_some() {
            entry
        } else {
            entry.get("result").unwrap_or(entry)
        };
        let root_call = trace_call_view(root);
        let top_level_caller = root_call.get("from").and_then(parse_address);
        collect_trace_call_seeds(
            config,
            root,
            block_number,
            tx_ordinal,
            tx_hash,
            top_level_caller,
            &trace_source,
            "0".to_string(),
            &mut out,
        );
        collect_log_only_trace_seed(
            config,
            root,
            block_number,
            tx_ordinal,
            tx_hash,
            top_level_caller,
            &trace_source,
            &mut out,
        );
    }
    normalize_seeds(out)
}

#[allow(clippy::too_many_arguments)]
fn collect_trace_call_seeds(
    config: &MainnetSeedConfig,
    call: &Value,
    block_number: u64,
    transaction_ordinal: usize,
    tx_hash: Option<B256>,
    top_level_caller: Option<Address>,
    trace_source: &str,
    trace_path: String,
    out: &mut Vec<MainnetSeed>,
) {
    let call_view = trace_call_view(call);
    let Some(to) = call_view.get("to").and_then(parse_address) else {
        return;
    };
    let input_bytes = call
        .get("input")
        .or_else(|| call.get("calldata"))
        .or_else(|| call_view.get("input"))
        .or_else(|| call_view.get("calldata"))
        .and_then(parse_hex_bytes)
        .unwrap_or_default();
    let include_address_hints = config.include_address_hints || !config.abi_functions.is_empty();
    if let Some(match_kind) =
        seed_match_kind(to, config.target, &input_bytes, include_address_hints)
    {
        let internal_caller = call_view.get("from").and_then(parse_address);
        let value = call_view
            .get("value")
            .and_then(parse_u256_quantity)
            .unwrap_or_default();
        let mut seed = seed_from_parts(
            config,
            block_number,
            0,
            transaction_ordinal,
            internal_caller.or(top_level_caller).unwrap_or_default(),
            to,
            value,
            input_bytes,
            if to == config.target {
                "trace-internal-target"
            } else {
                match_kind
            },
            "debug-trace-call",
        );
        seed.metadata.tx_hash = tx_hash;
        seed.metadata.top_level_caller = top_level_caller;
        seed.metadata.internal_caller = internal_caller;
        seed.metadata.trace_path = Some(trace_path.clone());
        seed.metadata.trace_source = Some(trace_source.to_string());
        out.push(seed);
    }

    if let Some(calls) = call
        .get("calls")
        .or_else(|| call.get("children"))
        .and_then(|calls| calls.as_array())
    {
        for (idx, child) in calls.iter().enumerate() {
            collect_trace_call_seeds(
                config,
                child,
                block_number,
                transaction_ordinal,
                tx_hash,
                top_level_caller,
                trace_source,
                format!("{trace_path}.{idx}"),
                out,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_log_only_trace_seed(
    config: &MainnetSeedConfig,
    root: &Value,
    block_number: u64,
    transaction_ordinal: usize,
    tx_hash: Option<B256>,
    top_level_caller: Option<Address>,
    trace_source: &str,
    out: &mut Vec<MainnetSeed>,
) {
    let Some(logs) = root.get("logs").and_then(|logs| logs.as_array()) else {
        return;
    };
    if !logs
        .iter()
        .any(|log| log.get("address").and_then(parse_address) == Some(config.target))
    {
        return;
    }
    let call_view = trace_call_view(root);
    let to = call_view
        .get("to")
        .and_then(parse_address)
        .unwrap_or(config.target);
    let input_bytes = call_view
        .get("input")
        .or_else(|| call_view.get("calldata"))
        .and_then(parse_hex_bytes)
        .unwrap_or_default();
    let caller = call_view
        .get("from")
        .and_then(parse_address)
        .or(top_level_caller)
        .unwrap_or_default();
    let mut seed = seed_from_parts(
        config,
        block_number,
        0,
        transaction_ordinal,
        caller,
        to,
        U256::ZERO,
        input_bytes,
        "trace-log-target",
        "debug-trace-log",
    );
    seed.metadata.tx_hash = tx_hash;
    seed.metadata.top_level_caller = top_level_caller;
    seed.metadata.internal_caller = Some(caller);
    seed.metadata.trace_path = Some("logs".to_string());
    seed.metadata.trace_source = Some(trace_source.to_string());
    out.push(seed);
}

fn trace_call_view(value: &Value) -> &Value {
    value.get("action").unwrap_or(value)
}

fn detect_trace_source(trace: &Value) -> String {
    let first = match trace {
        Value::Array(values) => values.first(),
        Value::Object(_) => Some(trace),
        _ => None,
    };
    let Some(first) = first else {
        return "unknown".to_string();
    };
    let root = first.get("result").unwrap_or(first);
    if root.get("calls").is_some() {
        "geth-callTracer".to_string()
    } else if root.get("action").is_some() || first.get("action").is_some() {
        "openethereum-erigon-flat".to_string()
    } else if root.get("logs").is_some() {
        "logs-only".to_string()
    } else {
        "unknown-debug-trace".to_string()
    }
}

fn parse_address(value: &Value) -> Option<Address> {
    let raw = value.as_str()?.trim();
    raw.parse().ok()
}

fn parse_b256(value: &Value) -> Option<B256> {
    let raw = value.as_str()?.trim();
    raw.parse().ok()
}

fn parse_hex_bytes(value: &Value) -> Option<Vec<u8>> {
    let raw = value
        .as_str()?
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.as_str()?.trim());
    hex::decode(raw).ok()
}

fn parse_u256_quantity(value: &Value) -> Option<U256> {
    if let Some(raw) = value.as_str() {
        let raw = raw.trim();
        if let Some(hex) = raw.strip_prefix("0x") {
            return U256::from_str_radix(hex, 16).ok();
        }
        return U256::from_str_radix(raw, 10).ok();
    }
    value.as_u64().map(U256::from)
}

fn parse_u64_quantity(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_str() {
        let raw = raw.trim();
        if let Some(hex) = raw.strip_prefix("0x") {
            return u64::from_str_radix(hex, 16).ok();
        }
        return raw.parse().ok();
    }
    value.as_u64()
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

    #[test]
    fn debug_trace_parser_extracts_internal_router_seed_with_provenance() {
        let target: Address = "0xf4326F612bF8Dbc8d2b685fCb5B78BB978b08D65"
            .parse()
            .expect("target");
        let router = Address::repeat_byte(0xbb);
        let top = Address::repeat_byte(0xaa);
        let mut config = MainnetSeedConfig::new(123, target, 8);
        config.include_address_hints = true;
        let trace = serde_json::json!([
            {
                "txHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "result": {
                    "from": top,
                    "to": router,
                    "input": "0x12345678",
                    "value": "0x0",
                    "calls": [
                        {
                            "from": router,
                            "to": target,
                            "input": "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
                            "value": "0x0"
                        }
                    ]
                }
            }
        ]);

        let seeds = seeds_from_debug_trace_value(&config, &trace);

        assert_eq!(seeds.len(), 1);
        let seed = &seeds[0];
        assert_eq!(seed.input.txs[0].to, target);
        assert_eq!(seed.metadata.top_level_caller, Some(top));
        assert_eq!(seed.metadata.internal_caller, Some(router));
        assert_eq!(seed.metadata.trace_path.as_deref(), Some("0.0"));
        assert_eq!(
            seed.metadata.trace_source.as_deref(),
            Some("geth-callTracer")
        );
        assert_eq!(
            seed.metadata.match_kind.as_deref(),
            Some("trace-internal-target")
        );
        assert_eq!(
            seed.metadata.tx_hash,
            Some(
                "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .parse()
                    .expect("hash")
            )
        );
    }

    #[test]
    fn debug_trace_parser_accepts_flat_action_result_trace() {
        let target = Address::repeat_byte(0x41);
        let caller = Address::repeat_byte(0x42);
        let mut config = MainnetSeedConfig::new(123, target, 8);
        config.include_address_hints = true;
        let trace = serde_json::json!([
            {
                "transactionHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "blockNumber": "0x7b",
                "traceAddress": [0, 1],
                "action": {
                    "from": caller,
                    "to": target,
                    "input": "0xabcdef01",
                    "value": "0x0",
                    "callType": "call"
                },
                "result": {
                    "output": "0x"
                }
            }
        ]);

        let seeds = seeds_from_debug_trace_value(&config, &trace);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].metadata.source_block, 123);
        assert_eq!(
            seeds[0].metadata.trace_source.as_deref(),
            Some("openethereum-erigon-flat")
        );
        assert_eq!(
            seeds[0].metadata.tx_hash,
            Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn debug_trace_parser_extracts_nested_delegatecall_proxy_target() {
        let proxy = Address::repeat_byte(0x51);
        let implementation = Address::repeat_byte(0x52);
        let target = implementation;
        let config = MainnetSeedConfig::new(500, target, 8);
        let trace = serde_json::json!({
            "txHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "blockNumber": 500,
            "result": {
                "from": Address::repeat_byte(0x53),
                "to": proxy,
                "input": "0x11111111",
                "calls": [{
                    "type": "DELEGATECALL",
                    "from": proxy,
                    "to": implementation,
                    "input": "0x12345678",
                    "value": "0x0"
                }]
            }
        });

        let seeds = seeds_from_debug_trace_value(&config, &trace);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].input.txs[0].to, target);
        assert_eq!(seeds[0].metadata.trace_path.as_deref(), Some("0.0"));
        assert_eq!(seeds[0].metadata.internal_caller, Some(proxy));
    }

    #[test]
    fn debug_trace_parser_emits_logs_only_target_seed() {
        let target = Address::repeat_byte(0x61);
        let router = Address::repeat_byte(0x62);
        let caller = Address::repeat_byte(0x63);
        let config = MainnetSeedConfig::new(600, target, 8);
        let trace = serde_json::json!({
            "txHash": "0x4444444444444444444444444444444444444444444444444444444444444444",
            "blockNumber": 600,
            "result": {
                "from": caller,
                "to": router,
                "input": "0x99999999",
                "logs": [{
                    "address": target,
                    "topics": []
                }]
            }
        });

        let seeds = seeds_from_debug_trace_value(&config, &trace);

        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].metadata.match_kind.as_deref(),
            Some("trace-log-target")
        );
        assert_eq!(seeds[0].metadata.trace_path.as_deref(), Some("logs"));
        assert_eq!(seeds[0].metadata.trace_source.as_deref(), Some("logs-only"));
    }

    #[test]
    fn debug_trace_parser_matches_calldata_embedded_target_hint() {
        let target = Address::repeat_byte(0x71);
        let aggregator = Address::repeat_byte(0x72);
        let mut config = MainnetSeedConfig::new(700, target, 8);
        config.include_address_hints = true;
        let calldata = format!("0xaaaaaaaa000000000000000000000000{}", hex::encode(target));
        let trace = serde_json::json!({
            "txHash": "0x5555555555555555555555555555555555555555555555555555555555555555",
            "result": {
                "from": Address::repeat_byte(0x73),
                "to": aggregator,
                "input": calldata
            }
        });

        let seeds = seeds_from_debug_trace_value(&config, &trace);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].input.txs[0].to, aggregator);
        assert_eq!(seeds[0].metadata.matched_target, Some(target));
        assert_eq!(
            seeds[0].metadata.match_kind.as_deref(),
            Some("address-hint")
        );
    }
}
