//! EVM execution domain types shared by the backend and the fuzzer.
//!
//! These types are serialized into persisted artifacts; field names and enum
//! variants are compatibility-sensitive.

use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::fork_db::EvmCacheDb;
pub use rustyfuzz_core::ExecutionStatus;

/// Maximum number of waypoints allowed per transaction to prevent unbounded memory growth
pub const MAX_WAYPOINTS_PER_TX: usize = 1000;

/// Maximum total waypoints allowed across all transactions in an input
pub const MAX_TOTAL_WAYPOINTS: usize = 10000;

/// Maximum memory usage in bytes before triggering backpressure (default: 2GB)
pub const MAX_MEMORY_USAGE_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Maximum number of memory bytes inspected for taint propagation in one execution.
pub const MAX_MEMORY_TAINT_TRACKING_BYTES: usize = 64 * 1024;

/// Maximum number of call/create observations retained in one execution.
pub const MAX_CALL_TRACE_OBSERVATIONS: usize = 512;

/// Maximum calldata or init-code prefix retained in telemetry.
pub const MAX_CALLDATA_TELEMETRY_BYTES: usize = 4 * 1024;

/// Maximum returndata or deployed-code prefix retained in telemetry.
pub const MAX_RETURN_DATA_TELEMETRY_BYTES: usize = 4 * 1024;

pub(crate) fn bounded_calldata(bytes: &[u8]) -> Vec<u8> {
    bounded_telemetry_bytes(bytes, MAX_CALLDATA_TELEMETRY_BYTES)
}

pub(crate) fn bounded_returndata(bytes: &[u8]) -> Vec<u8> {
    bounded_telemetry_bytes(bytes, MAX_RETURN_DATA_TELEMETRY_BYTES)
}

fn bounded_telemetry_bytes(bytes: &[u8], limit: usize) -> Vec<u8> {
    bytes.iter().copied().take(limit).collect()
}

/// Memory usage monitoring utilities
pub struct MemoryMonitor;

impl MemoryMonitor {
    /// Gets the current memory usage of the process in bytes
    pub fn current_memory_usage() -> usize {
        #[cfg(target_os = "linux")]
        {
            // Read from /proc/self/status
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        // VmRSS is in kB
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(kb) = parts[1].parse::<usize>() {
                                return kb * 1024;
                            }
                        }
                    }
                }
            }
            // Fallback: estimate based on allocation
            0
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux systems, we can't easily get memory usage without external crates
            // Return 0 to indicate unknown, or use platform-specific code
            0
        }
    }

    /// Checks if memory usage exceeds the limit
    pub fn exceeds_limit() -> bool {
        Self::current_memory_usage() > MAX_MEMORY_USAGE_BYTES
    }

    /// Gets memory usage as a human-readable string
    pub fn memory_usage_string() -> String {
        let bytes = Self::current_memory_usage();
        let mb = bytes / (1024 * 1024);
        let gb = mb / 1024;
        if gb > 0 {
            format!("{} GB", gb)
        } else if mb > 0 {
            format!("{} MB", mb)
        } else {
            format!("{} KB", bytes / 1024)
        }
    }
}

#[derive(Clone)]
pub enum ChainState {
    Evm(EvmCacheDb),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TxExecutionResult {
    pub tx_index: usize,
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub coverage_hash: u64,
    pub coverage_edges: usize,
    pub storage_reads: Vec<StorageAccess>,
    pub storage_writes: Vec<StorageAccess>,
    pub storage_diffs: Vec<StorageDiff>,
    pub call_trace: Vec<CallObservation>,
    pub waypoints: Vec<Waypoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SequenceExecutionResult {
    pub tx_results: Vec<TxExecutionResult>,
    pub total_gas_used: u64,
    pub final_coverage_hash: u64,
    pub storage_reads: Vec<StorageAccess>,
    pub storage_writes: Vec<StorageAccess>,
    pub storage_diffs: Vec<StorageDiff>,
    pub call_trace: Vec<CallObservation>,
    pub oracle_observations: Vec<OracleObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StorageAccess {
    pub tx_index: usize,
    pub address: Address,
    pub slot: B256,
    pub value: Option<U256>,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StorageDiff {
    pub tx_index: usize,
    pub address: Address,
    pub slot: B256,
    pub old_value: U256,
    pub new_value: U256,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CallObservation {
    pub tx_index: usize,
    pub depth: usize,
    pub caller: Address,
    pub target: Address,
    pub value: U256,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub success: bool,
    pub kind: CallKind,
    pub phase: CallPhase,
    pub created_address: Option<Address>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CallKind {
    Transaction,
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CallPhase {
    Start,
    End,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OracleObservation {
    pub oracle: String,
    pub finding: String,
    pub tx_index: Option<usize>,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintSource {
    Calldata(usize),
    Storage(usize, usize),
    Caller,
    CallValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComparisonOperand {
    Lhs,
    Rhs,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SymbolicExpression {
    Source(TaintSource),
    Constant(U256),
    Add(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Sub(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Mul(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Div(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Mod(Box<SymbolicExpression>, Box<SymbolicExpression>),
    And(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Or(Box<SymbolicExpression>, Box<SymbolicExpression>),
    Xor(Box<SymbolicExpression>, Box<SymbolicExpression>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Waypoint {
    Dataflow {
        address: Address,
        slot: Vec<u8>,
        influenced: bool,
    },
    Comparison {
        op: u8,
        lhs: U256,
        rhs: U256,
        pc: usize,
        calldata_offset: Option<usize>,
        condition: bool,
        hit: bool,
        taint_source: Option<TaintSource>,
        tainted_operand: ComparisonOperand,
        lhs_expression: Option<SymbolicExpression>,
        rhs_expression: Option<SymbolicExpression>,
        branch_distance: Option<U256>,
    },
    StaticCall {
        caller: Address,
        target: Address,
        data: Vec<u8>,
        output: Vec<u8>,
    },
    CallTrace {
        tx_idx: usize,
        depth: usize,
        caller: Address,
        target: Address,
        value: U256,
        input: Vec<u8>,
        output: Vec<u8>,
        gas_limit: u64,
        gas_used: u64,
        success: bool,
        kind: CallKind,
        phase: CallPhase,
        result: Option<String>,
    },
    CreateTrace {
        tx_idx: usize,
        depth: usize,
        creator: Address,
        created_address: Option<Address>,
        value: U256,
        init_code: Vec<u8>,
        deployed_code: Vec<u8>,
        gas_limit: u64,
        gas_used: u64,
        success: bool,
        kind: CallKind,
        phase: CallPhase,
        result: Option<String>,
    },
    Arithmetic {
        op: u8,
        lhs: U256,
        rhs: U256,
        third: Option<U256>,
        pc: usize,
        taint_source: Option<TaintSource>,
        result_expression: Option<SymbolicExpression>,
    },
    StorageRead {
        address: Address,
        slot: B256,
        value: U256,
        pc: usize,
        read_tx_idx: usize,
        taint_source: Option<TaintSource>,
        expression: Option<SymbolicExpression>,
    },
    StorageWrite {
        address: Address,
        slot: Vec<u8>,
        value: U256,
        pc: usize,
        tx_idx: usize,
        taint_source_of_value: Option<TaintSource>,
        value_expression: Option<SymbolicExpression>,
    },
    TransientStorageRead {
        address: Address,
        slot: B256,
        value: U256,
        pc: usize,
    },
    TransientStorageWrite {
        address: Address,
        slot: B256,
        value: U256,
        pc: usize,
    },
    MappingDerivation {
        base_slot: U256,
        key: U256,
        derived_slot: B256,
        key_expression: Option<SymbolicExpression>,
        base_slot_expression: Option<SymbolicExpression>,
    },
    FlashloanExecution {
        lender: Address,
        token: Address,
        amount: U256,
        fee: U256,
        is_repaid: bool,
    },
    GovernanceAction {
        target: Address,
        selector: [u8; 4],
        caller: Address,
    },
    TokenCallback {
        target: Address,
        selector: [u8; 4],
        data: Vec<u8>,
    },
    SvmCpiCall {
        caller_program: [u8; 32],
        callee_program: [u8; 32],
        instruction_data: Vec<u8>,
        accounts: Vec<[u8; 32]>,
        signers: Vec<[u8; 32]>,
    },
    BranchPath {
        pc: usize,
        taken: bool,
        constraint: Box<Waypoint>,
    },
    MevSignal {
        victim_caller: Address,
        slippage_harvested: U256,
        is_sandwich: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_payload_helpers_keep_deterministic_prefixes() {
        let calldata = vec![0xAA; MAX_CALLDATA_TELEMETRY_BYTES + 32];
        let returndata = vec![0x55; MAX_RETURN_DATA_TELEMETRY_BYTES + 32];

        assert_eq!(
            bounded_calldata(&calldata),
            vec![0xAA; MAX_CALLDATA_TELEMETRY_BYTES]
        );
        assert_eq!(
            bounded_returndata(&returndata),
            vec![0x55; MAX_RETURN_DATA_TELEMETRY_BYTES]
        );
    }

    #[test]
    fn telemetry_payload_helpers_accept_empty_input() {
        assert!(bounded_calldata(&[]).is_empty());
        assert!(bounded_returndata(&[]).is_empty());
    }
}
