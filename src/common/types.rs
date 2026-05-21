use crate::evm::fork_db::EvmCacheDb;
use revm::primitives::{Address, Bytes, B256, U256};

use bitvec::prelude::{BitVec, Lsb0};
use parking_lot::RwLock;
use revm::context::TxEnv;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use crate::evm::fuzz::EvmInput;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SingletonTx {
    pub input: Vec<u8>,
    pub caller: Address,
    pub to: Address,
    pub value: U256,
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
    pub waypoints: Vec<Waypoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SequenceExecutionResult {
    pub tx_results: Vec<TxExecutionResult>,
    pub total_gas_used: u64,
    pub final_coverage_hash: u64,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintSource {
    Calldata(usize),
    Storage(usize, usize),
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
    },
    StaticCall {
        caller: Address,
        target: Address,
        data: Vec<u8>,
        output: Vec<u8>,
    },
    Arithmetic {
        op: u8,
        lhs: U256,
        rhs: U256,
        third: Option<U256>,
        pc: usize,
        taint_source: Option<TaintSource>,
    },
    StorageRead {
        address: Address,
        slot: B256,
        value: U256,
        pc: usize,
        read_tx_idx: usize,
        taint_source: Option<TaintSource>,
    },
    StorageWrite {
        address: Address,
        slot: Vec<u8>,
        value: U256,
        pc: usize,
        tx_idx: usize,
        taint_source_of_value: Option<TaintSource>,
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
