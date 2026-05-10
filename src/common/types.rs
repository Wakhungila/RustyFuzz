use revm::primitives::{
    Address, U256, B256, 
    Bytes, 
};
use revm::context::TxEnv;
use revm::database::{CacheDB, EmptyDB}; 
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bitvec::prelude::{BitVec, Lsb0};

pub use crate::evm::fuzz::EvmInput;

#[derive(Clone, Serialize)]
pub enum ChainState {
    Evm(CacheDB<EmptyDB>),
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

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum Waypoint {
    Dataflow { address: Address, slot: Vec<u8>, influenced: bool },
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
    StaticCall { caller: Address, target: Address, data: Vec<u8>, output: Vec<u8> },
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
    TransientStorageRead { address: Address, slot: B256, value: U256, pc: usize },
    TransientStorageWrite { address: Address, slot: B256, value: U256, pc: usize },
    MappingDerivation { base_slot: U256, key: U256, derived_slot: B256 },
    FlashloanExecution { lender: Address, token: Address, amount: U256, fee: U256, is_repaid: bool },
    GovernanceAction { target: Address, selector: [u8; 4], caller: Address },
    TokenCallback { target: Address, selector: [u8; 4], data: Vec<u8> },
    SvmCpiCall {
        caller_program: [u8; 32],
        callee_program: [u8; 32],
        instruction_data: Vec<u8>,
        accounts: Vec<[u8; 32]>,
        signers: Vec<[u8; 32]>,
    },
    BranchPath { pc: usize, taken: bool, constraint: Box<Waypoint> },
    MevSignal { victim_caller: Address, slippage_harvested: U256, is_sandwich: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct SingletonTx {
    pub input: Vec<u8>,
    pub caller: Address,
    pub to: Address,
    pub value: U256,
    pub is_victim: bool,
}

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        let mut env = TxEnv::default();
        
        env.caller = self.caller;
        env.kind = revm::primitives::TxKind::Call(self.to);
        
        env.gas_limit = 30_000_000; 
        env.gas_price = 0;
        env.value = self.value;

        env.data = Bytes::copy_from_slice(&self.input);
        
        env.gas_priority_fee = Some(0); 
        env.access_list = Default::default();
        
        // Blob transactions (EIP-4844) support - default to 0
        env.blob_hashes = Vec::new();
        env.max_fee_per_blob_gas = 0;

        env
    }
}