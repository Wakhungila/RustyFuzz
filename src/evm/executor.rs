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
        block_env: &mut revm::primitives::BlockEnv,
        tx: &SingletonTx,
        coverage: &mut [u8],
        dataflow: &mut crate::evm::dataflow::DataflowRegistry,
        waypoints: &mut Vec<crate::common::types::Waypoint>,
        _tx_idx: usize,
    ) -> anyhow::Result<u64> {
        let revm_state = match chain_state {
            ChainState::Evm(state) => state,
        };

        let mut inspector = CoverageInspector::new(coverage, dataflow, waypoints);

        let mut evm = revm::Evm::builder()
            .with_db(revm_state)
            .with_external_context(&mut inspector)
            .with_block_env(block_env.clone())
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|revm_tx| *revm_tx = tx.to_revm_tx_env())
            .append_handler_register(inspector_handle_register)
            .build();

        // Execute the transaction
        let result = evm.transact().map_err(|e| anyhow::anyhow!("EVM Execution Error: {:?}", e))?;
        
        // Only commit the state to the DB if the transaction didn't hit a fatal system error.
        // Reverts (ExitKind::Revert) are committed so the fuzzer can explore error-handling branches.
        if !result.result.is_halt() {
            evm.context.evm.db.commit(result.state);
        } else {
            anyhow::bail!("EVM Halt: {:?}", result.result);
        }

        let gas_used = result.result.gas_used();
        Ok(gas_used)
    }
}