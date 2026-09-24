use crate::rpc_url::{resolve_rpc_url, test_loopback_allowed};
use parking_lot::Mutex;
use revm::database::CacheDB;
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::primitives::{Address, StorageKey, StorageValue, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const DEFAULT_FORK_RPC_TIMEOUT_SECS: u64 = 3;
const DEFAULT_FORK_RPC_RETRIES: usize = 1;
const DEFAULT_THREAD_RPC_BUDGET: usize = 16;
const RPC_BUDGET_EXHAUSTED: &str = "fork RPC budget exhausted";
const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

thread_local! {
    static THREAD_RPC_BUDGET: RefCell<Option<usize>> = const { RefCell::new(None) };
}

pub type EvmCacheDb = CacheDB<ForkDb>;

/// Provenance recorded with every persisted fork-cache snapshot (Gate 4).
///
/// Freshness / invalidation rules (also documented in
/// `docs/reengineering/LIVE_RPC_CONSISTENCY.md`):
/// 1. A snapshot is valid only for the exact `block_number` it was fetched at
///    (or `block_tag == "latest"` if unnumbered).
/// 2. If `block_hash` was recorded, re-fetching that block must yield the same
///    hash; a mismatch means a reorg and invalidates the cache.
/// 3. Snapshots with `fetched_at_unix` older than the campaign max-age (when
///    configured) are stale for mutable tags (`latest`/`safe`/`finalized`);
///    historically pinned block numbers do not expire by wall-clock time.
/// 4. Missing provenance on an online snapshot is treated as unknown, not as
///    fresh: callers must either re-probe or refuse under fail-closed rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
// Checkpoints use positional postcard encoding: optional fields must never be
// skipped during serialization, or subsequent fields become misaligned.
pub struct ForkCacheProvenance {
    /// Sanitized provider identity (`scheme://host[:port]`), never credentials.
    #[serde(default)]
    pub provider_sanitized: String,
    /// Chain id when known from `eth_chainId`.
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Numeric fork block when the tag was a quantity; `None` for `latest`.
    #[serde(default)]
    pub block_number: Option<u64>,
    /// Block hash at fetch time (reorg detection).
    #[serde(default)]
    pub block_hash: Option<String>,
    /// Unix seconds when the snapshot was first populated from RPC.
    #[serde(default)]
    pub fetched_at_unix: Option<u64>,
    /// Opaque cache identity (stable hash of provider+block+chain).
    #[serde(default)]
    pub cache_id: Option<String>,
}

/// Why a fork-cache snapshot is unusable under Gate 4 consistency rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheStaleReason {
    BlockNumberMismatch { expected: u64, found: Option<u64> },
    BlockHashMismatch { expected: String, found: String },
    AgeExceeded { age_secs: u64, max_age_secs: u64 },
    MissingProvenance,
    TagNotPinned,
}

impl fmt::Display for CacheStaleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockNumberMismatch { expected, found } => {
                write!(
                    f,
                    "fork cache block mismatch: expected {expected}, snapshot has {found:?}"
                )
            }
            Self::BlockHashMismatch { expected, found } => {
                write!(
                    f,
                    "fork cache reorg detected: expected hash {expected}, chain has {found}"
                )
            }
            Self::AgeExceeded {
                age_secs,
                max_age_secs,
            } => {
                write!(f, "fork cache age {age_secs}s exceeds max {max_age_secs}s")
            }
            Self::MissingProvenance => write!(f, "fork cache missing provenance (fail-closed)"),
            Self::TagNotPinned => {
                write!(f, "fork cache tag is not a pinned block number")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkDbCacheSnapshot {
    pub block_tag: String,
    pub accounts: Vec<ForkAccountCacheEntry>,
    pub code_by_hash: Vec<ForkCodeCacheEntry>,
    pub storage: Vec<ForkStorageCacheEntry>,
    pub block_hashes: Vec<ForkBlockHashCacheEntry>,
    /// Gate 4 provenance; optional for legacy snapshots (treated as unknown).
    #[serde(default)]
    pub provenance: ForkCacheProvenance,
    #[serde(default)]
    pub content_digest: String,
}

impl ForkDbCacheSnapshot {
    pub fn calculate_content_digest(&self) -> Result<String, serde_json::Error> {
        let mut snapshot = self.clone();
        snapshot.content_digest.clear();
        let bytes = serde_json::to_vec(&snapshot)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn verify_content_digest(&self) -> Result<(), String> {
        if self.content_digest.is_empty() {
            return Err("fork cache is missing its complete snapshot digest".to_string());
        }
        let expected = self
            .calculate_content_digest()
            .map_err(|error| format!("cannot calculate fork cache digest: {error}"))?;
        if self.content_digest != expected {
            return Err("fork cache complete snapshot digest mismatch".to_string());
        }
        Ok(())
    }

    /// Validates this snapshot against a pinned campaign block under fail-closed
    /// rules. `now_unix` and `max_age_secs` apply only when the caller wants a
    /// freshness bound (pass `None` to skip age checks for historical pins).
    pub fn ensure_consistent(
        &self,
        expected_block: Option<u64>,
        observed_block_hash: Option<&str>,
        now_unix: Option<u64>,
        max_age_secs: Option<u64>,
        require_provenance: bool,
    ) -> Result<(), CacheStaleReason> {
        if require_provenance
            && (self.provenance.provider_sanitized.is_empty()
                || self.provenance.chain_id.is_none()
                || self.provenance.block_number.is_none()
                || self
                    .provenance
                    .block_hash
                    .as_deref()
                    .is_none_or(|hash| validate_block_hash(hash).is_err())
                || self.provenance.fetched_at_unix.is_none()
                || self
                    .provenance
                    .cache_id
                    .as_deref()
                    .is_none_or(str::is_empty))
        {
            return Err(CacheStaleReason::MissingProvenance);
        }

        if let Some(expected) = expected_block {
            match self.provenance.block_number {
                Some(found) if found == expected => {}
                Some(found) => {
                    return Err(CacheStaleReason::BlockNumberMismatch {
                        expected,
                        found: Some(found),
                    });
                }
                None => {
                    // Legacy snapshots only carry block_tag.
                    let tag_num = parse_block_tag_number(&self.block_tag);
                    match tag_num {
                        Some(found) if found == expected => {}
                        other => {
                            return Err(CacheStaleReason::BlockNumberMismatch {
                                expected,
                                found: other,
                            });
                        }
                    }
                }
            }
        }

        if let (Some(expected_hash), Some(observed)) =
            (self.provenance.block_hash.as_deref(), observed_block_hash)
        {
            if !expected_hash.eq_ignore_ascii_case(observed) {
                return Err(CacheStaleReason::BlockHashMismatch {
                    expected: expected_hash.to_string(),
                    found: observed.to_string(),
                });
            }
        }

        if let (Some(now), Some(max_age), Some(fetched)) =
            (now_unix, max_age_secs, self.provenance.fetched_at_unix)
        {
            let is_pinned = self.provenance.block_number.is_some()
                || parse_block_tag_number(&self.block_tag).is_some();
            if !is_pinned {
                // Mutable tags (`latest`, etc.) always honor age limits.
                let age = now.saturating_sub(fetched);
                if age > max_age {
                    return Err(CacheStaleReason::AgeExceeded {
                        age_secs: age,
                        max_age_secs: max_age,
                    });
                }
            } else if now < fetched {
                // Clock skew: treat as stale rather than trusting negative age.
                return Err(CacheStaleReason::AgeExceeded {
                    age_secs: 0,
                    max_age_secs: max_age,
                });
            }
        }

        Ok(())
    }
}

fn parse_block_tag_number(tag: &str) -> Option<u64> {
    let t = tag.trim();
    if t == "latest" || t == "safe" || t == "finalized" || t == "pending" || t == "earliest" {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    t.parse().ok()
}

/// Classification of live-RPC failures for fail-closed handling (Gate 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcFailureKind {
    RateLimited,
    Timeout,
    ArchiveGap,
    Reorg,
    ProviderError,
    BudgetExhausted,
    Decode,
    Offline,
}

impl RpcFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::ArchiveGap => "archive_gap",
            Self::Reorg => "reorg",
            Self::ProviderError => "provider_error",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Decode => "decode",
            Self::Offline => "offline",
        }
    }
}

/// Classifies a fork RPC error message / HTTP status into a failure kind.
pub fn classify_rpc_failure(message: &str, http_status: Option<u16>) -> RpcFailureKind {
    if message.contains(RPC_BUDGET_EXHAUSTED) {
        return RpcFailureKind::BudgetExhausted;
    }
    if let Some(status) = http_status {
        if status == 429 || status == 503 {
            return RpcFailureKind::RateLimited;
        }
        if status == 408 || status == 504 {
            return RpcFailureKind::Timeout;
        }
    }
    let lower = message.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("timed out") || lower.contains("deadline") {
        return RpcFailureKind::Timeout;
    }
    if lower.contains("rate limit")
        || lower.contains("429")
        || lower.contains("-32005")
        || lower.contains("too many requests")
    {
        return RpcFailureKind::RateLimited;
    }
    if lower.contains("missing trie node")
        || lower.contains("no state available")
        || lower.contains("header not found")
        || lower.contains("block not found")
        || lower.contains("historical state")
        || lower.contains("pruned")
        || lower.contains("archive")
    {
        return RpcFailureKind::ArchiveGap;
    }
    if lower.contains("reorg") || lower.contains("reorganized") {
        return RpcFailureKind::Reorg;
    }
    if lower.contains("offline fork") {
        return RpcFailureKind::Offline;
    }
    RpcFailureKind::ProviderError
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkAccountCacheEntry {
    pub address: Address,
    pub info: Option<ForkAccountInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkAccountInfo {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkCodeCacheEntry {
    pub code_hash: B256,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkStorageCacheEntry {
    pub address: Address,
    pub slot: StorageKey,
    pub value: StorageValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkBlockHashCacheEntry {
    pub number: u64,
    pub hash: B256,
}

#[derive(Debug)]
pub enum ForkDbError {
    Rpc(String),
    Decode(String),
    /// Classified live-RPC failure (Gate 4 fail-closed path).
    Classified {
        kind: RpcFailureKind,
        message: String,
    },
}

impl ForkDbError {
    pub fn failure_kind(&self) -> RpcFailureKind {
        match self {
            Self::Classified { kind, .. } => *kind,
            Self::Decode(_) => RpcFailureKind::Decode,
            Self::Rpc(message) => classify_rpc_failure(message, None),
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self.failure_kind(),
            RpcFailureKind::RateLimited | RpcFailureKind::Timeout | RpcFailureKind::ProviderError
        )
    }
}

impl fmt::Display for ForkDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(message) => write!(f, "fork RPC error: {message}"),
            Self::Decode(message) => write!(f, "fork RPC decode error: {message}"),
            Self::Classified { kind, message } => {
                write!(f, "fork RPC error [{}]: {message}", kind.as_str())
            }
        }
    }
}

impl std::error::Error for ForkDbError {}
impl DBErrorMarker for ForkDbError {}

#[derive(Clone)]
pub struct ForkDb {
    inner: Arc<ForkDbInner>,
}

struct ForkDbInner {
    rpc_url: Option<String>,
    block_tag: String,
    allow_loopback: bool,
    rpc_options: Option<(Duration, usize)>,
    provenance: Mutex<ForkCacheProvenance>,
    accounts: Mutex<HashMap<Address, Option<AccountInfo>>>,
    code_by_hash: Mutex<HashMap<B256, Bytecode>>,
    storage: Mutex<HashMap<(Address, StorageKey), StorageValue>>,
    block_hashes: Mutex<HashMap<u64, B256>>,
}

impl fmt::Debug for ForkDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkDb")
            .field(
                "rpc_url",
                &sanitize_rpc_origin(self.inner.rpc_url.as_deref().unwrap_or("")),
            )
            .field("block_tag", &self.inner.block_tag)
            .finish_non_exhaustive()
    }
}

impl Default for ForkDb {
    fn default() -> Self {
        Self::empty()
    }
}

impl ForkDb {
    pub fn empty() -> Self {
        Self::new_offline("latest")
    }

    pub fn new_for_test(
        rpc_url: impl Into<String>,
        block_number: u64,
        timeout: Duration,
        max_attempts: usize,
    ) -> Self {
        let mut db = Self::new(rpc_url, block_number);
        let inner = Arc::get_mut(&mut db.inner).expect("fresh fork db must be unique");
        inner.allow_loopback = true;
        inner.rpc_options = Some((timeout, max_attempts.max(1)));
        db
    }

    pub fn new(rpc_url: impl Into<String>, block_number: u64) -> Self {
        let rpc_url: String = rpc_url.into();
        let provider_sanitized = sanitize_rpc_origin(&rpc_url);
        let block_tag = to_quantity(block_number);
        let mut provenance = ForkCacheProvenance {
            provider_sanitized,
            block_number: Some(block_number),
            ..ForkCacheProvenance::default()
        };
        provenance.cache_id = Some(compute_cache_id(
            provenance.provider_sanitized.as_str(),
            provenance.chain_id,
            Some(block_number),
        ));
        Self {
            inner: Arc::new(ForkDbInner {
                rpc_url: Some(rpc_url),
                block_tag,
                allow_loopback: test_loopback_allowed(),
                rpc_options: None,
                provenance: Mutex::new(provenance),
                accounts: Mutex::new(HashMap::new()),
                code_by_hash: Mutex::new(HashMap::new()),
                storage: Mutex::new(HashMap::new()),
                block_hashes: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn new_offline(block_tag: impl Into<String>) -> Self {
        let block_tag = block_tag.into();
        let block_number = parse_block_tag_number(&block_tag);
        Self {
            inner: Arc::new(ForkDbInner {
                rpc_url: None,
                block_tag,
                allow_loopback: false,
                rpc_options: None,
                provenance: Mutex::new(ForkCacheProvenance {
                    provider_sanitized: String::new(),
                    block_number,
                    ..ForkCacheProvenance::default()
                }),
                accounts: Mutex::new(HashMap::new()),
                code_by_hash: Mutex::new(HashMap::new()),
                storage: Mutex::new(HashMap::new()),
                block_hashes: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Records chain id / block hash / fetch time on the live snapshot (Gate 4).
    pub fn set_provenance_chain(
        &self,
        chain_id: u64,
        block_hash: Option<String>,
        fetched_at_unix: u64,
    ) {
        let mut provenance = self.inner.provenance.lock();
        provenance.chain_id = Some(chain_id);
        if block_hash.is_some() {
            provenance.block_hash = block_hash;
        }
        if provenance.fetched_at_unix.is_none() {
            provenance.fetched_at_unix = Some(fetched_at_unix);
        }
        provenance.cache_id = Some(compute_cache_id(
            provenance.provider_sanitized.as_str(),
            provenance.chain_id,
            provenance.block_number,
        ));
    }

    pub fn provenance(&self) -> ForkCacheProvenance {
        self.inner.provenance.lock().clone()
    }

    /// Probes `eth_chainId` and requires a valid block hash for provenance.
    pub fn refresh_remote_provenance(&self) -> Result<ForkCacheProvenance, ForkDbError> {
        if self.inner.rpc_url.is_none() {
            return Err(ForkDbError::Rpc(
                "cannot establish remote provenance for an offline fork".to_string(),
            ));
        }
        let chain_hex: String = self.rpc("eth_chainId", json!([]))?;
        let chain_id = hex_to_u64(&chain_hex)?;
        let block: Option<Value> = self.rpc(
            "eth_getBlockByNumber",
            json!([self.inner.block_tag.clone(), false]),
        )?;
        let block = block.ok_or_else(|| ForkDbError::Classified {
            kind: RpcFailureKind::ArchiveGap,
            message: format!(
                "block {} not found (archive gap or reorg)",
                self.inner.block_tag
            ),
        })?;
        let block_hash = block
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| ForkDbError::Decode("block response is missing a hash".to_string()))?;
        validate_block_hash(block_hash)?;
        let block_hash = Some(block_hash.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.set_provenance_chain(chain_id, block_hash, now);
        Ok(self.provenance())
    }

    pub fn from_cache_snapshot(snapshot: ForkDbCacheSnapshot) -> Self {
        let db = Self::new_offline(snapshot.block_tag.clone());
        *db.inner.provenance.lock() = snapshot.provenance;

        {
            let mut accounts = db.inner.accounts.lock();
            for entry in snapshot.accounts {
                let info = entry.info.map(ForkAccountInfo::into_account_info);
                accounts.insert(entry.address, info);
            }
        }

        {
            let mut code_by_hash = db.inner.code_by_hash.lock();
            for entry in snapshot.code_by_hash {
                code_by_hash.insert(entry.code_hash, Bytecode::new_raw(entry.code.into()));
            }
        }

        {
            let mut storage = db.inner.storage.lock();
            for entry in snapshot.storage {
                storage.insert((entry.address, entry.slot), entry.value);
            }
        }

        {
            let mut block_hashes = db.inner.block_hashes.lock();
            for entry in snapshot.block_hashes {
                block_hashes.insert(entry.number, entry.hash);
            }
        }

        db
    }

    pub fn cache_snapshot(&self) -> ForkDbCacheSnapshot {
        let mut accounts: Vec<_> = self
            .inner
            .accounts
            .lock()
            .iter()
            .map(|(address, info)| ForkAccountCacheEntry {
                address: *address,
                info: info.as_ref().map(ForkAccountInfo::from_account_info),
            })
            .collect();
        accounts.sort_by_key(|entry| entry.address);

        let mut code_by_hash: Vec<_> = self
            .inner
            .code_by_hash
            .lock()
            .iter()
            .map(|(code_hash, code)| ForkCodeCacheEntry {
                code_hash: *code_hash,
                code: code.original_byte_slice().to_vec(),
            })
            .collect();
        code_by_hash.sort_by_key(|entry| entry.code_hash);

        let mut storage: Vec<_> = self
            .inner
            .storage
            .lock()
            .iter()
            .map(|((address, slot), value)| ForkStorageCacheEntry {
                address: *address,
                slot: *slot,
                value: *value,
            })
            .collect();
        storage.sort_by_key(|entry| (entry.address, entry.slot));

        let mut block_hashes: Vec<_> = self
            .inner
            .block_hashes
            .lock()
            .iter()
            .map(|(number, hash)| ForkBlockHashCacheEntry {
                number: *number,
                hash: *hash,
            })
            .collect();
        block_hashes.sort_by_key(|entry| entry.number);

        // Stamp first populate time so persisted snapshots carry fetch freshness.
        {
            let mut provenance = self.inner.provenance.lock();
            if provenance.fetched_at_unix.is_none() && self.inner.rpc_url.is_some() {
                provenance.fetched_at_unix = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
            }
        }

        let mut snapshot = ForkDbCacheSnapshot {
            block_tag: self.inner.block_tag.clone(),
            accounts,
            code_by_hash,
            storage,
            block_hashes,
            provenance: self.inner.provenance.lock().clone(),
            content_digest: String::new(),
        };
        snapshot.content_digest = snapshot
            .calculate_content_digest()
            .expect("fork cache snapshot serialization must succeed");
        snapshot
    }

    pub fn cache_account(&self, address: Address, info: AccountInfo) {
        if let Some(code) = &info.code {
            self.inner
                .code_by_hash
                .lock()
                .insert(info.code_hash, code.clone());
        }
        self.inner.accounts.lock().insert(address, Some(info));
    }

    pub fn cache_storage(&self, address: Address, slot: StorageKey, value: StorageValue) {
        self.inner.storage.lock().insert((address, slot), value);
    }

    pub fn cache_code(&self, code_hash: B256, code: Bytecode) {
        self.inner.code_by_hash.lock().insert(code_hash, code);
    }

    pub fn cache_block_hash(&self, number: u64, hash: B256) {
        self.inner.block_hashes.lock().insert(number, hash);
    }

    pub fn with_thread_rpc_budget<T>(budget: Option<usize>, f: impl FnOnce() -> T) -> T {
        struct BudgetGuard(Option<usize>);
        impl Drop for BudgetGuard {
            fn drop(&mut self) {
                let previous = self.0;
                THREAD_RPC_BUDGET.with(|budget| {
                    *budget.borrow_mut() = previous;
                });
            }
        }

        let previous = THREAD_RPC_BUDGET.with(|current| current.replace(budget));
        let _guard = BudgetGuard(previous);
        f()
    }

    fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, ForkDbError> {
        let Some(rpc_url) = &self.inner.rpc_url else {
            return Err(ForkDbError::Rpc("offline fork database miss".to_string()));
        };
        let (_, addresses) = resolve_rpc_url(rpc_url, self.inner.allow_loopback)
            .map_err(|error| ForkDbError::Rpc(format!("invalid RPC URL: {error}")))?;
        reserve_thread_rpc_call()?;

        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response =
            rpc_on_blocking_thread(rpc_url.clone(), request, addresses, self.inner.rpc_options)?;
        if let Some(error) = response.get("error") {
            let kind = classify_rpc_failure(&error.to_string(), None);
            return Err(ForkDbError::Classified {
                kind,
                message: safe_rpc_failure_message(kind),
            });
        }

        serde_json::from_value(
            response
                .get("result")
                .cloned()
                .ok_or_else(|| ForkDbError::Decode("missing JSON-RPC result".to_string()))?,
        )
        .map_err(|_| ForkDbError::Decode("invalid JSON-RPC response".to_string()))
    }
}

fn rpc_on_blocking_thread(
    rpc_url: String,
    request: Value,
    addresses: Vec<std::net::SocketAddr>,
    options: Option<(Duration, usize)>,
) -> Result<Value, ForkDbError> {
    thread::spawn(move || {
        let (timeout, max_attempts) =
            options.unwrap_or_else(|| (fork_rpc_timeout(), fork_rpc_retries()));
        let host = reqwest::Url::parse(&rpc_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| ForkDbError::Rpc("invalid RPC URL".to_string()))?;
        let mut client_builder = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(0)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addresses)
            .user_agent("rusty-fuzz-fork-db/0.1");
        if let Ok(api_key) = std::env::var("RUSTYFUZZ_RPC_API_KEY") {
            if !api_key.trim().is_empty() {
                if let Ok(value) =
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {api_key}"))
                {
                    let mut headers = reqwest::header::HeaderMap::new();
                    headers.insert(reqwest::header::AUTHORIZATION, value);
                    client_builder = client_builder.default_headers(headers);
                }
            }
        }
        let client = client_builder
            .build()
            .map_err(|_| ForkDbError::Rpc("RPC client configuration failed".to_string()))?;
        let mut last_rpc_error = None;
        for attempt in 0..max_attempts {
            let mut response = match client.post(&rpc_url).json(&request).send() {
                Ok(response) => response,
                Err(error) => {
                    let kind = classify_reqwest_error(&error, None);
                    last_rpc_error = Some(ForkDbError::Classified {
                        kind,
                        message: safe_rpc_failure_message(kind),
                    });
                    if attempt + 1 < max_attempts {
                        thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                    }
                    continue;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let raw = format!("HTTP {status}");
                let kind = classify_rpc_failure(&raw, Some(status.as_u16()));
                let error = ForkDbError::Classified {
                    kind,
                    message: safe_rpc_failure_message(kind),
                };
                let retryable = matches!(error.failure_kind(), RpcFailureKind::ProviderError);
                if !retryable {
                    return Err(error);
                }
                last_rpc_error = Some(error);
                if attempt + 1 < max_attempts {
                    thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                }
                continue;
            }

            if let Some(content_length) = response.content_length() {
                if content_length > MAX_RPC_RESPONSE_BYTES as u64 {
                    return Err(ForkDbError::Decode(format!(
                        "JSON-RPC response exceeds {MAX_RPC_RESPONSE_BYTES} byte limit"
                    )));
                }
            }
            let mut bytes = Vec::with_capacity(
                response
                    .content_length()
                    .unwrap_or(0)
                    .min(MAX_RPC_RESPONSE_BYTES as u64) as usize,
            );
            let mut chunk = [0u8; 16 * 1024];
            let mut body_failed = false;
            loop {
                let read = match response.read(&mut chunk) {
                    Ok(read) => read,
                    Err(error) => {
                        let kind = classify_rpc_body_error(&error);
                        let classified = ForkDbError::Classified {
                            kind,
                            message: safe_rpc_failure_message(kind),
                        };
                        if !matches!(
                            classified.failure_kind(),
                            RpcFailureKind::Timeout | RpcFailureKind::ProviderError
                        ) || attempt + 1 >= max_attempts
                        {
                            return Err(classified);
                        }
                        last_rpc_error = Some(classified);
                        body_failed = true;
                        thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                        break;
                    }
                };
                if read == 0 {
                    break;
                }
                if bytes.len().saturating_add(read) > MAX_RPC_RESPONSE_BYTES {
                    return Err(ForkDbError::Decode(format!(
                        "JSON-RPC response exceeds {MAX_RPC_RESPONSE_BYTES} byte limit"
                    )));
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            if body_failed {
                continue;
            }
            return serde_json::from_slice(&bytes)
                .map_err(|_| ForkDbError::Decode("invalid JSON-RPC response".to_string()));
        }

        Err(last_rpc_error
            .unwrap_or_else(|| ForkDbError::Rpc("request failed without error".to_string())))
    })
    .join()
    .map_err(|_| ForkDbError::Rpc("fork RPC worker thread panicked".to_string()))?
}

fn classify_rpc_body_error(error: &std::io::Error) -> RpcFailureKind {
    if error.kind() == std::io::ErrorKind::TimedOut {
        return RpcFailureKind::Timeout;
    }
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("reset") || message.contains("broken pipe") {
        RpcFailureKind::ProviderError
    } else {
        RpcFailureKind::Timeout
    }
}

fn classify_reqwest_error(error: &reqwest::Error, http_status: Option<u16>) -> RpcFailureKind {
    if error.is_timeout() {
        RpcFailureKind::Timeout
    } else {
        classify_rpc_failure(&error.to_string(), http_status)
    }
}

fn sanitize_rpc_origin(rpc_url: &str) -> String {
    match reqwest::Url::parse(rpc_url) {
        Ok(url) => {
            let host = url.host_str().unwrap_or("unknown");
            match url.port() {
                Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
                None => format!("{}://{}", url.scheme(), host),
            }
        }
        Err(_) => "<invalid-rpc-url>".to_string(),
    }
}

fn compute_cache_id(provider: &str, chain_id: Option<u64>, block: Option<u64>) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    provider.hash(&mut hasher);
    chain_id.hash(&mut hasher);
    block.hash(&mut hasher);
    format!("fc_{:016x}", hasher.finish())
}

fn fork_rpc_timeout() -> Duration {
    fork_rpc_timeout_from_value(
        std::env::var("RUSTYFUZZ_FORK_RPC_TIMEOUT_SECS")
            .ok()
            .as_deref(),
    )
}

fn fork_rpc_timeout_from_value(value: Option<&str>) -> Duration {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_FORK_RPC_TIMEOUT_SECS))
}

fn fork_rpc_retries() -> usize {
    fork_rpc_retries_from_value(std::env::var("RUSTYFUZZ_FORK_RPC_RETRIES").ok().as_deref())
}

fn fork_rpc_retries_from_value(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FORK_RPC_RETRIES)
}

pub fn fork_rpc_budget_exhausted(error: &ForkDbError) -> bool {
    matches!(
        error,
        ForkDbError::Classified {
            kind: RpcFailureKind::BudgetExhausted,
            ..
        }
    ) || matches!(error, ForkDbError::Rpc(message) if message.contains(RPC_BUDGET_EXHAUSTED))
}

/// True when the error is a live-RPC failure that must fail closed unless
/// synthetic fallback is explicitly enabled (Gate 4).
pub fn is_live_rpc_failure(error: &ForkDbError) -> bool {
    !matches!(error.failure_kind(), RpcFailureKind::Offline)
        && !matches!(
            error,
            ForkDbError::Classified {
                kind: RpcFailureKind::BudgetExhausted,
                ..
            }
        )
        && !fork_rpc_budget_exhausted(error)
}

pub fn execution_rpc_budget() -> usize {
    std::env::var("RUSTYFUZZ_EXEC_RPC_BUDGET")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_THREAD_RPC_BUDGET)
}

fn reserve_thread_rpc_call() -> Result<(), ForkDbError> {
    THREAD_RPC_BUDGET.with(|budget| {
        let mut budget = budget.borrow_mut();
        match budget.as_mut() {
            Some(remaining) if *remaining == 0 => Err(ForkDbError::Rpc(format!(
                "{RPC_BUDGET_EXHAUSTED}; increase RUSTYFUZZ_EXEC_RPC_BUDGET for deeper live-fork exploration"
            ))),
            Some(remaining) => {
                *remaining -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    })
}

fn safe_rpc_failure_message(kind: RpcFailureKind) -> String {
    let category = match kind {
        RpcFailureKind::RateLimited => "rate limit",
        RpcFailureKind::Timeout => "timeout",
        RpcFailureKind::ArchiveGap => "archive gap",
        RpcFailureKind::Reorg => "reorg",
        RpcFailureKind::BudgetExhausted => RPC_BUDGET_EXHAUSTED,
        RpcFailureKind::ProviderError => "provider error",
        RpcFailureKind::Decode => "decode error",
        RpcFailureKind::Offline => "offline fork",
    };
    format!("JSON-RPC {category}; provider details redacted")
}

impl ForkAccountInfo {
    fn from_account_info(info: &AccountInfo) -> Self {
        Self {
            balance: info.balance,
            nonce: info.nonce,
            code_hash: info.code_hash,
            code: info
                .code
                .as_ref()
                .map(|code| code.original_byte_slice().to_vec())
                .unwrap_or_default(),
        }
    }

    fn into_account_info(self) -> AccountInfo {
        AccountInfo::new(
            self.balance,
            self.nonce,
            self.code_hash,
            Bytecode::new_raw(self.code.into()),
        )
    }
}

impl DatabaseRef for ForkDb {
    type Error = ForkDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(info) = self.inner.accounts.lock().get(&address).cloned() {
            return Ok(info);
        }

        let Some(_) = &self.inner.rpc_url else {
            self.inner.accounts.lock().insert(address, None);
            return Ok(None);
        };

        let block = Value::String(self.inner.block_tag.clone());
        let balance_hex: String = self.rpc(
            "eth_getBalance",
            json!([address.to_string(), block.clone()]),
        )?;
        let nonce_hex: String = self.rpc(
            "eth_getTransactionCount",
            json!([address.to_string(), block.clone()]),
        )?;
        let code_hex: String = self.rpc("eth_getCode", json!([address.to_string(), block]))?;

        let balance = hex_to_u256(&balance_hex)?;
        let nonce = hex_to_u64(&nonce_hex)?;
        let code_bytes = hex_to_bytes(&code_hex)?;
        let code = Bytecode::new_raw(code_bytes.into());
        let code_hash = code.hash_slow();

        if balance.is_zero() && nonce == 0 && code.is_empty() {
            self.inner.accounts.lock().insert(address, None);
            return Ok(None);
        }

        let info = AccountInfo::new(balance, nonce, code_hash, code.clone());
        self.inner.code_by_hash.lock().insert(code_hash, code);
        self.inner
            .accounts
            .lock()
            .insert(address, Some(info.clone()));
        Ok(Some(info))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self
            .inner
            .code_by_hash
            .lock()
            .get(&code_hash)
            .cloned()
            .unwrap_or_default())
    }

    fn storage_ref(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if let Some(value) = self.inner.storage.lock().get(&(address, index)).copied() {
            return Ok(value);
        }

        let Some(_) = &self.inner.rpc_url else {
            self.cache_storage(address, index, U256::ZERO);
            return Ok(U256::ZERO);
        };

        let value_hex: String = self.rpc(
            "eth_getStorageAt",
            json!([
                address.to_string(),
                format!("0x{:x}", index),
                self.inner.block_tag.clone()
            ]),
        )?;
        let value = hex_to_u256(&value_hex)?;
        self.cache_storage(address, index, value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        if let Some(hash) = self.inner.block_hashes.lock().get(&number).copied() {
            return Ok(hash);
        }

        let Some(_) = &self.inner.rpc_url else {
            self.inner.block_hashes.lock().insert(number, B256::ZERO);
            return Ok(B256::ZERO);
        };

        let block: Option<Value> =
            self.rpc("eth_getBlockByNumber", json!([to_quantity(number), false]))?;
        let hash = block
            .and_then(|block| block.get("hash").and_then(Value::as_str).map(str::to_owned))
            .map(|hash| validate_block_hash(&hash))
            .transpose()?
            .unwrap_or(B256::ZERO);
        self.inner.block_hashes.lock().insert(number, hash);
        Ok(hash)
    }
}

fn to_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, ForkDbError> {
    let hex = strip_0x(value);
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    let padded = if hex.len().is_multiple_of(2) {
        hex.to_string()
    } else {
        format!("0{hex}")
    };
    hex::decode(padded).map_err(|err| ForkDbError::Decode(err.to_string()))
}

fn hex_to_u256(value: &str) -> Result<U256, ForkDbError> {
    let bytes = hex_to_bytes(value)?;
    if bytes.len() > 32 {
        return Err(ForkDbError::Decode(
            "JSON-RPC U256 value exceeds 32 bytes".to_string(),
        ));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(padded))
}

fn hex_to_u64(value: &str) -> Result<u64, ForkDbError> {
    let parsed = hex_to_u256(value)?;
    parsed
        .try_into()
        .map_err(|_| ForkDbError::Decode("JSON-RPC U256 value exceeds u64".to_string()))
}

pub fn validate_block_hash(value: &str) -> Result<B256, ForkDbError> {
    let encoded = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| ForkDbError::Decode("block hash must be 0x-prefixed".to_string()))?;
    if encoded.len() != 64 {
        return Err(ForkDbError::Decode(
            "block hash must encode exactly 32 bytes".to_string(),
        ));
    }
    let bytes = hex::decode(encoded)
        .map_err(|_| ForkDbError::Decode("block hash contains invalid hexadecimal".to_string()))?;
    Ok(B256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_remote_provenance_rejects_offline_databases() {
        let error = ForkDb::new_offline("0x10")
            .refresh_remote_provenance()
            .expect_err("offline databases cannot establish remote provenance");
        assert_eq!(error.failure_kind(), RpcFailureKind::Offline);
    }

    #[test]
    fn fork_rpc_timeout_and_retries_use_fail_fast_defaults_and_overrides() {
        assert_eq!(
            fork_rpc_timeout_from_value(None),
            Duration::from_secs(DEFAULT_FORK_RPC_TIMEOUT_SECS)
        );
        assert_eq!(fork_rpc_retries_from_value(None), DEFAULT_FORK_RPC_RETRIES);
        assert_eq!(
            fork_rpc_timeout_from_value(Some("9")),
            Duration::from_secs(9)
        );
        assert_eq!(fork_rpc_retries_from_value(Some("3")), 3);
        assert_eq!(
            fork_rpc_timeout_from_value(Some("0")),
            Duration::from_secs(DEFAULT_FORK_RPC_TIMEOUT_SECS)
        );
        assert_eq!(
            fork_rpc_retries_from_value(Some("0")),
            DEFAULT_FORK_RPC_RETRIES
        );
    }

    #[test]
    fn sanitizes_embedded_rpc_urls_without_losing_error_context() {
        let sanitized = crate::rpc_url::redact_rpc_error(
            "provider error at (https://user:pass@example.test/path) while calling http://rpc.test",
        );
        assert_eq!(
            sanitized,
            "provider error at (<rpc-url>) while calling <rpc-url>"
        );
    }

    #[test]
    fn provider_errors_do_not_return_controlled_content() {
        let error = ForkDbError::Classified {
            kind: RpcFailureKind::ProviderError,
            message: safe_rpc_failure_message(RpcFailureKind::ProviderError),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("provider details redacted"));
        assert!(!rendered.contains("secret-provider-body"));
    }

    #[test]
    fn debug_redacts_rpc_query_credentials() {
        let db = ForkDb::new("https://user:pass@rpc.example.com/?apikey=secret", 1);
        let rendered = format!("{db:?}");
        assert!(!rendered.contains("user"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn thread_rpc_budget_exhausts_and_restores() {
        let db = ForkDb::new("http://127.0.0.1:1", 1);
        let exhausted = ForkDb::with_thread_rpc_budget(Some(0), || {
            db.basic_ref(Address::repeat_byte(0x11)).unwrap_err()
        });
        assert!(fork_rpc_budget_exhausted(&exhausted));

        let unbudgeted = db.basic_ref(Address::repeat_byte(0x12)).unwrap_err();
        assert!(!fork_rpc_budget_exhausted(&unbudgeted));
    }

    #[test]
    fn classifies_rate_limit_timeout_archive_and_budget_failures() {
        assert_eq!(
            classify_rpc_failure("429 Too Many Requests", Some(429)),
            RpcFailureKind::RateLimited
        );
        assert_eq!(
            classify_rpc_failure("request timed out", None),
            RpcFailureKind::Timeout
        );
        assert_eq!(
            classify_rpc_failure("missing trie node 0xabc", None),
            RpcFailureKind::ArchiveGap
        );
        assert_eq!(
            classify_rpc_failure(RPC_BUDGET_EXHAUSTED, None),
            RpcFailureKind::BudgetExhausted
        );
        assert_eq!(
            classify_rpc_failure("execution reverted", None),
            RpcFailureKind::ProviderError
        );
    }

    #[test]
    fn complete_snapshot_digest_detects_content_tampering() {
        let db = ForkDb::new("https://rpc.example.com", 16);
        let mut snapshot = db.cache_snapshot();
        snapshot.verify_content_digest().unwrap();
        snapshot.accounts.push(ForkAccountCacheEntry {
            address: Address::repeat_byte(0x11),
            info: None,
        });
        assert!(snapshot.verify_content_digest().is_err());
    }

    #[test]
    fn cache_snapshot_detects_block_mismatch_and_reorg() {
        let mut snap = ForkDbCacheSnapshot {
            block_tag: "0x10".to_string(),
            accounts: vec![],
            code_by_hash: vec![],
            storage: vec![],
            block_hashes: vec![],
            provenance: ForkCacheProvenance {
                provider_sanitized: "https://example.com".to_string(),
                chain_id: Some(1),
                block_number: Some(16),
                block_hash: Some(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
                fetched_at_unix: Some(1_000),
                cache_id: Some("fc_test".to_string()),
            },
            content_digest: String::new(),
        };

        assert!(snap
            .ensure_consistent(
                Some(16),
                Some("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                None,
                None,
                true,
            )
            .is_ok());

        assert_eq!(
            snap.ensure_consistent(Some(17), None, None, None, true),
            Err(CacheStaleReason::BlockNumberMismatch {
                expected: 17,
                found: Some(16),
            })
        );

        assert_eq!(
            snap.ensure_consistent(
                Some(16),
                Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                None,
                None,
                true,
            ),
            Err(CacheStaleReason::BlockHashMismatch {
                expected: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                found: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            })
        );

        // Missing provenance fails closed when required.
        snap.provenance = ForkCacheProvenance::default();
        assert_eq!(
            snap.ensure_consistent(Some(16), None, None, None, true),
            Err(CacheStaleReason::MissingProvenance)
        );
    }

    #[test]
    fn ensure_consistent_requires_every_provenance_field() {
        let complete = ForkCacheProvenance {
            provider_sanitized: "https://rpc.example.com".to_string(),
            chain_id: Some(1),
            block_number: Some(16),
            block_hash: Some(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            fetched_at_unix: Some(1_000),
            cache_id: Some("fc_test".to_string()),
        };
        let partial = [
            ForkCacheProvenance {
                provider_sanitized: String::new(),
                ..complete.clone()
            },
            ForkCacheProvenance {
                chain_id: None,
                ..complete.clone()
            },
            ForkCacheProvenance {
                block_number: None,
                ..complete.clone()
            },
            ForkCacheProvenance {
                block_hash: None,
                ..complete.clone()
            },
            ForkCacheProvenance {
                fetched_at_unix: None,
                ..complete.clone()
            },
            ForkCacheProvenance {
                cache_id: None,
                ..complete.clone()
            },
        ];
        for provenance in partial {
            let snapshot = ForkDbCacheSnapshot {
                block_tag: "0x10".to_string(),
                accounts: vec![],
                code_by_hash: vec![],
                storage: vec![],
                block_hashes: vec![],
                provenance,
                content_digest: String::new(),
            };
            assert_eq!(
                snapshot.ensure_consistent(Some(16), None, None, None, true),
                Err(CacheStaleReason::MissingProvenance)
            );
        }
    }

    #[test]
    fn age_limit_applies_to_mutable_tags_but_not_pinned_blocks() {
        let pinned = ForkDbCacheSnapshot {
            block_tag: "0x10".to_string(),
            accounts: vec![],
            code_by_hash: vec![],
            storage: vec![],
            block_hashes: vec![],
            provenance: ForkCacheProvenance {
                provider_sanitized: "https://example.com".to_string(),
                block_number: Some(16),
                fetched_at_unix: Some(1_000),
                ..ForkCacheProvenance::default()
            },
            content_digest: String::new(),
        };
        assert!(pinned
            .ensure_consistent(Some(16), None, Some(1_000 + 10_000), Some(60), false)
            .is_ok());

        let mutable = ForkDbCacheSnapshot {
            block_tag: "latest".to_string(),
            provenance: ForkCacheProvenance {
                provider_sanitized: "https://example.com".to_string(),
                block_number: None,
                fetched_at_unix: Some(1_000),
                ..ForkCacheProvenance::default()
            },
            ..pinned.clone()
        };
        assert_eq!(
            mutable.ensure_consistent(None, None, Some(1_000 + 10_000), Some(60), false),
            Err(CacheStaleReason::AgeExceeded {
                age_secs: 10_000,
                max_age_secs: 60,
            })
        );
    }

    #[test]
    fn fork_new_records_provider_and_cache_provenance() {
        let db = ForkDb::new("https://api.example.com/v2/secret-key", 15_201_793);
        let prov = db.provenance();
        assert_eq!(prov.provider_sanitized, "https://api.example.com");
        assert_eq!(prov.block_number, Some(15_201_793));
        assert!(prov.cache_id.is_some());
        assert!(!prov.provider_sanitized.contains("secret-key"));

        let snap = db.cache_snapshot();
        assert_eq!(snap.provenance.block_number, Some(15_201_793));
        assert_eq!(
            snap.ensure_consistent(Some(15_201_793), None, None, None, true),
            Err(CacheStaleReason::MissingProvenance)
        );
    }
}
