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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Waypoint {
    Dataflow { slot: Vec<u8>, influenced: bool },
    Comparison { 
        op: u8, 
        lhs: U256, 
        rhs: U256, 
        pc: usize,
        calldata_offset: Option<usize> // The "Elite" touch: pinpoint the byte to change
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
        pc: usize,
        calldata_offset: Option<usize>,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SingletonTx {
    pub input: Vec<u8>,
    pub caller: alloy::primitives::Address,
    pub to: alloy::primitives::Address,
    pub value: alloy::primitives::U256,
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