use revm::primitives::{Address, U256, TxEnv, TransactTo, B256};
use revm::db::{CacheDB, EmptyDB};
use std::{sync::Arc, collections::HashMap};
use std::ops::Range;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bitvec::prelude::{BitVec, Lsb0};
use crate::evm::fuzz::EvmInput;

#[derive(Clone, Debug)]
pub enum ChainId {
    Evm(u64),
    Svm,
}

#[derive(Clone)]
pub enum ChainState {
    Evm(CacheDB<EmptyDB>),
    // Svm(SvmState), // Disabled to avoid Solana conflicts
}

#[derive(Clone, Debug, Default)]
pub struct SvmState {
    // pub accounts: HashMap<[u8; 32], SvmAccount>,
    pub influenced_data_regions: HashMap<[u8; 32], Vec<Range<usize>>>, // simplified
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SingletonTx {
    pub input: Vec<u8>,
    pub caller: Address,
    pub to: Address,
    pub value: U256,
    pub is_victim: bool,
}

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        TxEnv {
            caller: self.caller,
            transact_to: TransactTo::Call(self.to),
            gas_limit: 21_000_000,
            gas_price: 0.into(),
            value: self.value,
            data: self.input.clone().into(),
            ..Default::default()
        }
    }
}