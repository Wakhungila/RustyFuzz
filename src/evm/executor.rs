use crate::common::types::{SingletonTx, ChainState, Waypoint};
use crate::evm::inspector::CoverageInspector;
use crate::evm::dataflow::DataflowRegistry;

// v38 organized types into specific sub-modules for Context/Handler separation
use revm::{
    primitives::{Address, TxKind},
    DatabaseCommit,
    handler::ExecuteEvm,
};
use revm::context::{BlockEnv, TxEnv};
use anyhow::{Result, anyhow};

pub struct EvmExecutor {}

impl EvmExecutor {
    pub fn new() -> Self {
        EvmExecutor {}
    }

    pub fn execute(
        &self,
        chain_state: &mut ChainState,
        block_env: &mut BlockEnv,
        tx: &SingletonTx,
        coverage: &mut [u8],
        dataflow: &mut DataflowRegistry,
        waypoints: &mut Vec<Waypoint>,
        tx_idx: usize,
    ) -> Result<u64> {
        let ChainState::Evm(ref mut db) = chain_state;

        // 1. Setup Transaction Environment
        let mut tx_env = TxEnv::default();
        tx_env.caller = tx.caller;
        tx_env.gas_limit = 30_000_000;
        tx_env.gas_price = 1_000_000_000;
        tx_env.value = tx.value;
        tx_env.data = tx.input.clone().into();

        tx_env.kind = if tx.to == Address::ZERO {
            TxKind::Create
        } else {
            TxKind::Call(tx.to)
        };

        // 2. Initialize Inspector
        let mut inspector = CoverageInspector::new(
            coverage,
            dataflow,
            waypoints,
            tx_idx
        );

        // 3. Execute transaction using revm v38 ExecuteEvm trait
        // The v38 API uses a different execution model
        let result = ExecuteEvm::execute(
            db,
            block_env.clone(),
            tx_env,
        ).map_err(|e| anyhow!("EVM Error: {:?}", e))?;

        // 4. Commit state changes
        db.commit(result.state);

        // 5. Return gas used
        Ok(result.result.gas_used())
    }
}