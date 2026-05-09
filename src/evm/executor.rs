use crate::common::types::{SingletonTx, ChainState};
use revm::primitives::SpecId;
use revm::inspector_handle_register;
use crate::evm::inspector::CoverageInspector;
use bitvec::prelude::*;
use revm::DatabaseCommit;

pub struct EvmExecutor {}

impl EvmExecutor {
    pub fn new() -> Self { EvmExecutor {} }

    pub fn execute(
        &self, 
        chain_state: &mut ChainState, 
        tx: &SingletonTx,
        coverage: &mut BitSlice<u8, Lsb0>,
        dataflow: &mut crate::evm::dataflow::DataflowRegistry,
        waypoints: &mut Vec<crate::common::types::Waypoint>,
    ) -> anyhow::Result<u64> {
        let revm_state = match chain_state {
            ChainState::Evm(state) => state,
        };

        let mut inspector = CoverageInspector::new(coverage, dataflow, waypoints);

        let mut evm = revm::Evm::builder()
            .with_db(revm_state)
            .with_external_context(&mut inspector)
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|revm_tx| *revm_tx = tx.to_revm_tx_env())
            .append_handler_register(inspector_handle_register)
            .build();

        let result = evm.transact()?;
        evm.context.evm.db.commit(result.state);
        
        let gas_used = result.result.gas_used();

        Ok(gas_used)
    }
}