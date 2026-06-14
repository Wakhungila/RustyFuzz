use crate::evm::fork_db::EvmCacheDb;
use revm::primitives::{Address, Bytes, B256, U256};

use bitvec::prelude::{BitVec, Lsb0};
use parking_lot::RwLock;
use revm::context::TxEnv;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use crate::evm::fuzz::EvmInput;

/// Maximum number of waypoints allowed per transaction to prevent unbounded memory growth
pub const MAX_WAYPOINTS_PER_TX: usize = 1000;

/// Maximum total waypoints allowed across all transactions in an input
pub const MAX_TOTAL_WAYPOINTS: usize = 10000;

/// Maximum memory usage in bytes before triggering backpressure (default: 2GB)
pub const MAX_MEMORY_USAGE_BYTES: usize = 2 * 1024 * 1024 * 1024;

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

/// Represents a single EVM transaction in a fuzzing sequence.
///
/// A `SingletonTx` contains all the necessary information to execute a transaction
/// during fuzzing, including calldata, caller, target address, value, and victim status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SingletonTx {
    /// The transaction calldata (function selector + arguments)
    pub input: Vec<u8>,
    /// The address of the transaction sender
    pub caller: Address,
    /// The target contract address
    pub to: Address,
    /// The ETH value sent with the transaction
    pub value: U256,
    /// Whether this transaction is marked as a victim (for MEV/sandwich attacks)
    pub is_victim: bool,
}

#[derive(Clone)]
pub enum ChainState {
    Evm(EvmCacheDb),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExecutionStatus {
    Success,
    Revert,
    Halt(String),
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

#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub state: Arc<RwLock<ChainState>>,
    pub coverage: BitVec<u8, Lsb0>,
    pub producing_input: Option<EvmInput>,
    pub waypoints: Vec<Waypoint>,
    pub depth: u32,
    pub gas_used: u64,
}

impl Snapshot {
    /// Applies backpressure to waypoint accumulation by truncating if over limit
    pub fn apply_waypoint_backpressure(&mut self) {
        if self.waypoints.len() > MAX_WAYPOINTS_PER_TX {
            // Keep the most recent waypoints (they're more relevant for concolic solving)
            let excess = self.waypoints.len() - MAX_WAYPOINTS_PER_TX;
            self.waypoints.drain(0..excess);
        }
    }
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

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        TxEnv {
            caller: self.caller,
            kind: revm::primitives::TxKind::Call(self.to),
            gas_limit: 10_000_000,
            gas_price: 0,
            value: self.value,
            data: Bytes::copy_from_slice(&self.input),
            gas_priority_fee: Some(0),
            access_list: Default::default(),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            ..Default::default()
        }
    }
}
