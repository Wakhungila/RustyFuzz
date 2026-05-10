use crate::common::types::{SingletonTx, ChainState};
use crate::evm::inspector::CoverageInspector;

// v38: Primitives are unified in revm::primitives (or revm_primitives)
use revm::primitives::{SpecId, BlockEnv, ExecutionResult};
use revm::{Evm, DatabaseCommit};

// v38: Database traits and implementations have moved
use revm::database::CacheDB;
use revm::database::EmptyDB; // Moved from revm::db to revm::database
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
        dataflow: &mut crate::evm::dataflow::DataflowRegistry,
        waypoints: &mut Vec<crate::common::types::Waypoint>,
        tx_idx: usize,
    ) -> Result<u64> {
        // Extract the database from the ChainState enum
        let revm_db = match chain_state {
            ChainState::Evm(db) => db,
        };

        // Initialize your custom LibAFL inspector
        let mut inspector = CoverageInspector::new(coverage, dataflow, waypoints, tx_idx);

        // v38: The Builder pattern is now the exclusive way to construct the EVM.
        // It decouples the EvmContext from the Handler logic.
        let mut evm = Evm::builder()
            .with_db(revm_db)
            .with_external_context(&mut inspector)
            .with_block_env(block_env.clone())
            // Prague/Amsterdam 2026 specs support EIP-7702 and EIP-7843
            .with_spec_id(SpecId::CANCUN) 
            .modify_tx_env(|revm_tx| {
                *revm_tx = tx.to_revm_tx_env();
            })
            // REPLACEMENT: Manual registers are gone. 
            // Use this built-in register to wire the Inspector to the Handler.
            .append_handler_register(revm::inspector::register_builtin_inspectors)
            .build();

        // v38: transact() returns ResultAndState, which contains both 
        // the execution result and the post-state BundleState.
        let result_and_state = evm.transact().map_err(|e| {
            anyhow!("EVM Execution Error [TX {}]: {:?}", tx_idx, e)
        })?;

        let ExecutionResult::Success { gas_used, .. } = result_and_state.result else {
            // If it's a Revert or Halt, we still might want to keep the coverage,
            // but we usually don't commit the state.
            return Ok(result_and_state.result.gas_used());
        };

        // v38: DatabaseCommit::commit now takes the BundleState directly.
        // This is significantly more efficient than the old state-merge logic.
        evm.context.evm.db.commit(result_and_state.state);

        Ok(gas_used)
    }
}