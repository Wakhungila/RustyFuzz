use crate::common::types::{SingletonTx, ChainState, Waypoint};
use crate::evm::inspector::CoverageInspector;
use crate::evm::dataflow::DataflowRegistry;

// v38 organized types into specific sub-modules for Context/Handler separation
use revm::{
    primitives::{Address, TransactTo, TxEnv, U256, ExecutionResult, SpecId},
    DatabaseCommit,
    // Note: Evm here is the entry point for the builder
    Evm,
};
use revm::context::BlockEnv;
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
        tx_env.gas_price = U256::from(1_000_000_000); 
        tx_env.value = tx.value;
        tx_env.data = tx.input.clone().into();

        tx_env.transact_to = if tx.to == Address::ZERO {
            TransactTo::Create
        } else {
            TransactTo::Call(tx.to)
        };

        // 2. Initialize Inspector
        let mut inspector = CoverageInspector::new(
            coverage, 
            dataflow, 
            waypoints, 
            tx_idx
        );

        // 3. Build EVM with Correct v38 Handler Registration
        // The helper 'inspector_handle_register' moved to the 'inspectors' module
        let mut evm = Evm::builder()
            .with_db(db)
            .with_external_context(&mut inspector)
            .with_block_env(block_env.clone())
            .with_tx_env(tx_env)
            .with_spec_id(SpecId::CANCUN) 
            .append_handler_register(revm::inspectors::inspector_handle_register)
            .build();

        // 4. Transact
        // returns Result<ResultAndState, EVMError>
        let ref_tx = evm.transact().map_err(|e| anyhow!("EVM Error: {:?}", e))?;
        
        // 5. Commit state changes
        // Accessing the database via context.evm.db is the standard v38 pattern
        evm.context.evm.db.commit(ref_tx.state);

        // 6. Final Results
        match ref_tx.result {
            ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Revert { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Halt { reason, gas_used } => {
                Err(anyhow!("EVM Halted: {:?} (Gas used: {})", reason, gas_used))
            }
        }
    }
}