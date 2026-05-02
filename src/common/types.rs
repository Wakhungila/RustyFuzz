use revm::primitives::{Address, U256, TxEnv};
use revm::db::{CacheDB, EmptyDB};
use std::sync::Arc;
use parking_lot::RwLock;
use bitvec::prelude::{BitVec, Lsb0};

#[derive(Clone, Debug)]
pub enum ChainId {
    Evm(u64),
}

#[derive(Clone)]
pub enum ChainState {
    Evm(CacheDB<EmptyDB>),
}

#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub state: Arc<RwLock<ChainState>>,
    pub coverage: BitVec<u8, Lsb0>,
    pub waypoints: Vec<Waypoint>,
    pub depth: u32,
}

#[derive(Clone, Debug)]
pub enum Waypoint {
    Dataflow { slot: Vec<u8>, influenced: bool },
    Comparison { condition: String, hit: bool },
}

#[derive(Clone)]
pub struct SingletonTx {
    pub input: Vec<u8>,
    pub caller: alloy::primitives::Address,
    pub value: alloy::primitives::U256,
}

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        TxEnv {
            caller: Address::from_slice(self.caller.as_slice()),
            gas_limit: 21_000_000,
            gas_price: 0,                         // now u128
            value: U256::from_limbs(self.value.into_limbs()),
            data: self.input.clone().into(),
            ..Default::default()
        }
    }
}