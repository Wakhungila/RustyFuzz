use revm::primitives::{Address, U256, TxEnv, TransactTo};
use revm::db::{CacheDB, EmptyDB};
use std::{sync::Arc, collections::HashMap};
use std::ops::Range;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bitvec::prelude::{BitVec, Lsb0};
use crate::evm::fuzz::EvmInput;
use crate::svm::bridge::SvmAccount;

#[derive(Clone, Debug)]
pub enum ChainId {
    Evm(u64),
    Svm,
}

#[derive(Clone)]
pub enum ChainState {
    Evm(CacheDB<EmptyDB>),
    Svm(SvmState),
}

#[derive(Clone, Debug, Default)]
pub struct SvmState {
    pub accounts: HashMap<[u8; 32], SvmAccount>,
    pub influenced_data_regions: HashMap<solana_sdk::pubkey::Pubkey, Vec<Range<usize>>>, // Tracks which parts of account data are influenced by EVM calldata
}

#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub state: Arc<RwLock<ChainState>>,
    pub coverage: BitVec<u8, Lsb0>,
    pub producing_input: Option<EvmInput>, // The input that generated this snapshot
    pub waypoints: Vec<Waypoint>,
    pub depth: u32,
    pub gas_used: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintSource {
    Calldata(usize),             // offset in current transaction calldata
    Storage(usize, usize),       // (tx_index, original_calldata_offset)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Waypoint {
    Dataflow { address: Address, slot: Vec<u8>, influenced: bool },
    Comparison { 
        op: u8, 
        lhs: U256, 
        rhs: U256, 
        pc: usize,
        taint_source: Option<TaintSource>,
    },
    StaticCall {
        caller: alloy::primitives::Address,
        target: alloy::primitives::Address,
        data: Vec<u8>,
        output: Vec<u8>,
    },
    Arithmetic {
        op: u8,
        lhs: U256,
        rhs: U256,
        third: Option<U256>, // For ternary ops like ADDMOD/MULMOD
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
    StorageRead {
        address: Address,
        slot: B256,
        value: U256,
        pc: usize,
        read_tx_idx: usize,
        taint_source: Option<TaintSource>, // The taint source of the value read from storage
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
        constraint: Waypoint, // The Comparison waypoint associated with this branch
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
    pub caller: alloy::primitives::Address,
    pub to: alloy::primitives::Address,
    pub value: alloy::primitives::U256,
    pub is_victim: bool, // If true, this TX represents a 'fixed' mainnet victim for MEV simulation
}

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        TxEnv {
            caller: Address::from_slice(self.caller.as_slice()),
            transact_to: TransactTo::Call(Address::from_slice(self.to.as_slice())),
            gas_limit: 21_000_000,
            gas_price: 0,                         // now u128
            value: U256::from_limbs(self.value.into_limbs()),
            data: self.input.clone().into(),
            ..Default::default()
        }
    }
}