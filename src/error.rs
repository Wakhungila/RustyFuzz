//! Domain-specific error types for RustyFuzz.
//!
//! This module defines error types for different components of the fuzzer,
//! providing better error handling and type safety compared to generic errors.
//!
//! # Example
//!
//! ```rust
//! use rusty_fuzz::error::{RustyFuzzError, Result, Validator};
//!
//! fn validate_rpc(url: &str) -> Result<()> {
//!     Validator::validate_rpc_endpoint(url)?;
//!     Ok(())
//! }
//! ```

use std::fmt;

/// Domain-specific error type for RustyFuzz operations.
///
/// This enum encapsulates all possible errors that can occur during fuzzing,
/// categorized by component (EVM, corpus, oracle, etc.) for better error handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustyFuzzError {
    /// EVM execution errors
    EvmExecution(EvmExecutionError),
    /// Corpus management errors
    Corpus(CorpusError),
    /// Oracle detection errors
    Oracle(OracleError),
    /// Configuration errors
    Config(ConfigError),
    /// Network/RPC errors
    Network(NetworkError),
    /// Validation errors
    Validation(ValidationError),
    /// Resource limit errors
    ResourceLimit(ResourceLimitError),
}

impl fmt::Display for RustyFuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RustyFuzzError::EvmExecution(e) => write!(f, "EVM execution error: {}", e),
            RustyFuzzError::Corpus(e) => write!(f, "Corpus error: {}", e),
            RustyFuzzError::Oracle(e) => write!(f, "Oracle error: {}", e),
            RustyFuzzError::Config(e) => write!(f, "Configuration error: {}", e),
            RustyFuzzError::Network(e) => write!(f, "Network error: {}", e),
            RustyFuzzError::Validation(e) => write!(f, "Validation error: {}", e),
            RustyFuzzError::ResourceLimit(e) => write!(f, "Resource limit error: {}", e),
        }
    }
}

impl std::error::Error for RustyFuzzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RustyFuzzError::EvmExecution(e) => Some(e),
            RustyFuzzError::Corpus(e) => Some(e),
            RustyFuzzError::Oracle(e) => Some(e),
            RustyFuzzError::Config(e) => Some(e),
            RustyFuzzError::Network(e) => Some(e),
            RustyFuzzError::Validation(e) => Some(e),
            RustyFuzzError::ResourceLimit(e) => Some(e),
        }
    }
}

/// EVM execution-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmExecutionError {
    /// Transaction execution failed
    TransactionFailed(String),
    /// Revert with reason
    Revert(String),
    /// Out of gas
    OutOfGas,
    /// Invalid calldata
    InvalidCalldata,
    /// Invalid address
    InvalidAddress,
    /// Snapshot not found
    SnapshotNotFound(u64),
    /// Fork creation failed
    ForkCreationFailed(String),
}

impl fmt::Display for EvmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmExecutionError::TransactionFailed(msg) => write!(f, "Transaction failed: {}", msg),
            EvmExecutionError::Revert(reason) => write!(f, "Revert: {}", reason),
            EvmExecutionError::OutOfGas => write!(f, "Out of gas"),
            EvmExecutionError::InvalidCalldata => write!(f, "Invalid calldata"),
            EvmExecutionError::InvalidAddress => write!(f, "Invalid address"),
            EvmExecutionError::SnapshotNotFound(id) => write!(f, "Snapshot not found: {}", id),
            EvmExecutionError::ForkCreationFailed(msg) => {
                write!(f, "Fork creation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for EvmExecutionError {}

/// Corpus management errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    /// Input not found in corpus
    InputNotFound(String),
    /// Corpus persistence failed
    PersistenceFailed(String),
    /// Corpus load failed
    LoadFailed(String),
    /// Corpus corruption detected
    Corruption(String),
    /// Invalid input format
    InvalidFormat(String),
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorpusError::InputNotFound(id) => write!(f, "Input not found: {}", id),
            CorpusError::PersistenceFailed(msg) => write!(f, "Persistence failed: {}", msg),
            CorpusError::LoadFailed(msg) => write!(f, "Load failed: {}", msg),
            CorpusError::Corruption(msg) => write!(f, "Corruption detected: {}", msg),
            CorpusError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for CorpusError {}

/// Oracle detection errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// Oracle evaluation failed
    EvaluationFailed(String),
    /// Invalid oracle configuration
    InvalidConfig(String),
    /// Oracle timeout
    Timeout,
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::EvaluationFailed(msg) => write!(f, "Evaluation failed: {}", msg),
            OracleError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            OracleError::Timeout => write!(f, "Oracle timeout"),
        }
    }
}

impl std::error::Error for OracleError {}

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid configuration value
    InvalidValue(String),
    /// Missing required configuration
    MissingRequired(String),
    /// Configuration parse error
    ParseError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidValue(key) => write!(f, "Invalid value for: {}", key),
            ConfigError::MissingRequired(key) => write!(f, "Missing required: {}", key),
            ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Network/RPC errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// RPC request failed
    RpcFailed(String),
    /// Connection timeout
    Timeout,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid endpoint
    InvalidEndpoint(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::RpcFailed(msg) => write!(f, "RPC failed: {}", msg),
            NetworkError::Timeout => write!(f, "Connection timeout"),
            NetworkError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            NetworkError::InvalidEndpoint(url) => write!(f, "Invalid endpoint: {}", url),
        }
    }
}

impl std::error::Error for NetworkError {}

/// Validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Input validation failed
    InvalidInput(String),
    /// Sequence too long
    SequenceTooLong { max: usize, actual: usize },
    /// Waypoints exceeded limit
    WaypointsExceeded { max: usize, actual: usize },
    /// Memory limit exceeded
    MemoryLimitExceeded { max: usize, actual: usize },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ValidationError::SequenceTooLong { max, actual } => {
                write!(f, "Sequence too long: {} (max: {})", actual, max)
            }
            ValidationError::WaypointsExceeded { max, actual } => {
                write!(f, "Waypoints exceeded: {} (max: {})", actual, max)
            }
            ValidationError::MemoryLimitExceeded { max, actual } => {
                write!(f, "Memory limit exceeded: {} bytes (max: {})", actual, max)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Resource limit errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceLimitError {
    /// Memory limit exceeded
    MemoryExceeded { limit: usize, usage: usize },
    /// Timeout exceeded
    TimeoutExceeded { limit_secs: u64 },
    /// Corpus size limit exceeded
    CorpusSizeExceeded { limit: usize, size: usize },
}

impl fmt::Display for ResourceLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceLimitError::MemoryExceeded { limit, usage } => {
                write!(f, "Memory exceeded: {} bytes (limit: {})", usage, limit)
            }
            ResourceLimitError::TimeoutExceeded { limit_secs } => {
                write!(f, "Timeout exceeded: {}s", limit_secs)
            }
            ResourceLimitError::CorpusSizeExceeded { limit, size } => {
                write!(f, "Corpus size exceeded: {} (limit: {})", size, limit)
            }
        }
    }
}

impl std::error::Error for ResourceLimitError {}

/// Type alias for Result with RustyFuzzError
pub type Result<T> = std::result::Result<T, RustyFuzzError>;

/// Convenience macro for creating RustyFuzzError from string
#[macro_export]
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        RustyFuzzError::$variant($variant($msg))
    };
    ($variant:ident, $($arg:tt)*) => {
        RustyFuzzError::$variant($variant($($arg)*))
    };
}

/// Input validation utilities for RustyFuzz.
pub struct Validator;

impl Validator {
    /// Validates an Ethereum address
    pub fn validate_address(addr: &[u8]) -> Result<()> {
        if addr.len() != 20 {
            return Err(RustyFuzzError::Validation(ValidationError::InvalidInput(
                format!("Address must be 20 bytes, got {}", addr.len()),
            )));
        }
        Ok(())
    }

    /// Validates calldata length (must not exceed reasonable limits)
    pub fn validate_calldata(calldata: &[u8]) -> Result<()> {
        const MAX_CALLDATA_SIZE: usize = 128 * 1024; // 128KB
        if calldata.len() > MAX_CALLDATA_SIZE {
            return Err(RustyFuzzError::Validation(ValidationError::InvalidInput(
                format!(
                    "Calldata too large: {} bytes (max: {})",
                    calldata.len(),
                    MAX_CALLDATA_SIZE
                ),
            )));
        }
        Ok(())
    }

    /// Validates a U256 value for overflow/underflow safety
    pub fn validate_u256(value: &str) -> Result<u64> {
        value.parse::<u64>().map_err(|_| {
            RustyFuzzError::Validation(ValidationError::InvalidInput(format!(
                "Invalid U256 value: {}",
                value
            )))
        })
    }

    /// Validates an RPC endpoint URL
    pub fn validate_rpc_endpoint(url: &str) -> Result<()> {
        if url.is_empty() {
            return Err(RustyFuzzError::Validation(ValidationError::InvalidInput(
                "RPC endpoint cannot be empty".to_string(),
            )));
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(RustyFuzzError::Validation(ValidationError::InvalidInput(
                "RPC endpoint must start with http:// or https://".to_string(),
            )));
        }

        Ok(())
    }

    /// Validates a block number
    pub fn validate_block_number(block: u64) -> Result<()> {
        if block > 100_000_000 {
            return Err(RustyFuzzError::Validation(ValidationError::InvalidInput(
                format!("Block number too large: {}", block),
            )));
        }
        Ok(())
    }

    /// Sanitizes a string input by removing null bytes and trimming whitespace
    pub fn sanitize_string(input: &str) -> String {
        input.replace('\0', "").trim().to_string()
    }

    /// Validates that a sequence length is within bounds
    pub fn validate_sequence_length(len: usize, max: usize) -> Result<()> {
        if len > max {
            return Err(RustyFuzzError::Validation(
                ValidationError::SequenceTooLong { max, actual: len },
            ));
        }
        Ok(())
    }
}
