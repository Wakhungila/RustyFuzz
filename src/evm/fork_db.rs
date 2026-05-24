use parking_lot::Mutex;
use revm::database::CacheDB;
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::primitives::{Address, StorageKey, StorageValue, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

pub type EvmCacheDb = CacheDB<ForkDb>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkDbCacheSnapshot {
    pub block_tag: String,
    pub accounts: Vec<ForkAccountCacheEntry>,
    pub code_by_hash: Vec<ForkCodeCacheEntry>,
    pub storage: Vec<ForkStorageCacheEntry>,
    pub block_hashes: Vec<ForkBlockHashCacheEntry>,
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
}

impl fmt::Display for ForkDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(message) => write!(f, "fork RPC error: {message}"),
            Self::Decode(message) => write!(f, "fork RPC decode error: {message}"),
        }
    }
}

impl std::error::Error for ForkDbError {}
impl DBErrorMarker for ForkDbError {}

#[derive(Clone, Debug)]
pub struct ForkDb {
    inner: Arc<ForkDbInner>,
}

#[derive(Debug)]
struct ForkDbInner {
    rpc_url: Option<String>,
    block_tag: String,
    accounts: Mutex<HashMap<Address, Option<AccountInfo>>>,
    code_by_hash: Mutex<HashMap<B256, Bytecode>>,
    storage: Mutex<HashMap<(Address, StorageKey), StorageValue>>,
    block_hashes: Mutex<HashMap<u64, B256>>,
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

    pub fn new(rpc_url: impl Into<String>, block_number: u64) -> Self {
        Self {
            inner: Arc::new(ForkDbInner {
                rpc_url: Some(rpc_url.into()),
                block_tag: to_quantity(block_number),
                accounts: Mutex::new(HashMap::new()),
                code_by_hash: Mutex::new(HashMap::new()),
                storage: Mutex::new(HashMap::new()),
                block_hashes: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn new_offline(block_tag: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(ForkDbInner {
                rpc_url: None,
                block_tag: block_tag.into(),
                accounts: Mutex::new(HashMap::new()),
                code_by_hash: Mutex::new(HashMap::new()),
                storage: Mutex::new(HashMap::new()),
                block_hashes: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn from_cache_snapshot(snapshot: ForkDbCacheSnapshot) -> Self {
        let db = Self::new_offline(snapshot.block_tag);

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

        ForkDbCacheSnapshot {
            block_tag: self.inner.block_tag.clone(),
            accounts,
            code_by_hash,
            storage,
            block_hashes,
        }
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

    fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, ForkDbError> {
        let Some(rpc_url) = &self.inner.rpc_url else {
            return Err(ForkDbError::Rpc("offline fork database miss".to_string()));
        };

        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut last_rpc_error = None;
        for attempt in 0..4 {
            let result = self
                .blocking_client()
                .post(rpc_url)
                .json(&request)
                .send()
                .map_err(|err| ForkDbError::Rpc(sanitize_rpc_error(&err.to_string())))
                .and_then(|response| {
                    response
                        .error_for_status()
                        .map_err(|err| ForkDbError::Rpc(sanitize_rpc_error(&err.to_string())))
                });

            match result {
                Ok(response) => {
                    let response: Value = response
                        .json()
                        .map_err(|err| ForkDbError::Decode(err.to_string()))?;

                    if let Some(error) = response.get("error") {
                        return Err(ForkDbError::Rpc(error.to_string()));
                    }

                    return serde_json::from_value(response.get("result").cloned().ok_or_else(
                        || ForkDbError::Decode("missing JSON-RPC result".to_string()),
                    )?)
                    .map_err(|err| ForkDbError::Decode(err.to_string()));
                }
                Err(error) => {
                    last_rpc_error = Some(error);
                    if attempt < 3 {
                        thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                    }
                }
            }
        }

        Err(last_rpc_error
            .unwrap_or_else(|| ForkDbError::Rpc("request failed without error".to_string())))
    }

    fn blocking_client(&self) -> &'static reqwest::blocking::Client {
        static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
        CLIENT.get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(0)
                .user_agent("rusty-fuzz-fork-db/0.1")
                .build()
                .expect("valid reqwest client")
        })
    }
}

fn sanitize_rpc_error(message: &str) -> String {
    message
        .split_whitespace()
        .map(|part| {
            if part.starts_with("http://") || part.starts_with("https://") {
                "<rpc-url>"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
            .map(|hash| parse_b256(&hash))
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
        return Err(ForkDbError::Decode(format!("U256 overflow: {value}")));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(padded))
}

fn hex_to_u64(value: &str) -> Result<u64, ForkDbError> {
    let parsed = hex_to_u256(value)?;
    parsed
        .try_into()
        .map_err(|_| ForkDbError::Decode(format!("u64 overflow: {value}")))
}

fn parse_b256(value: &str) -> Result<B256, ForkDbError> {
    let bytes = hex_to_bytes(value)?;
    if bytes.len() != 32 {
        return Err(ForkDbError::Decode(format!("invalid B256: {value}")));
    }
    Ok(B256::from_slice(&bytes))
}
