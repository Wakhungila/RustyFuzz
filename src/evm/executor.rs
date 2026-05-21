use crate::common::types::{ChainState, ExecutionStatus, SingletonTx, TxExecutionResult, Waypoint};
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fork_db::ForkDb;
use crate::evm::inspector::CoverageInspector;

use anyhow::Result;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::database::CacheDB;
use revm::primitives::{Address, TxKind};
use revm::{Context, InspectCommitEvm, MainBuilder, MainContext};

pub struct EvmExecutor {}

impl EvmExecutor {
    pub fn new() -> Self {
        EvmExecutor {}
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        chain_state: &mut ChainState,
        _block_env: &mut BlockEnv,
        tx: &SingletonTx,
        _coverage: &mut [u8],
        _dataflow: &mut DataflowRegistry,
        _waypoints: &mut Vec<Waypoint>,
        _tx_idx: usize,
    ) -> Result<u64> {
        Ok(self
            .execute_with_result(
                chain_state,
                _block_env,
                tx,
                _coverage,
                _dataflow,
                _waypoints,
                _tx_idx,
            )?
            .gas_used)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_result(
        &self,
        chain_state: &mut ChainState,
        _block_env: &mut BlockEnv,
        tx: &SingletonTx,
        _coverage: &mut [u8],
        _dataflow: &mut DataflowRegistry,
        _waypoints: &mut Vec<Waypoint>,
        _tx_idx: usize,
    ) -> Result<TxExecutionResult> {
        let ChainState::Evm(db) = chain_state;

        let tx_env = TxEnv {
            caller: tx.caller,
            gas_limit: 10_000_000,
            gas_price: 1_000_000_000_u128,
            value: tx.value,
            data: tx.input.clone().into(),
            kind: if tx.to == Address::ZERO {
                TxKind::Create
            } else {
                TxKind::Call(tx.to)
            },
            ..Default::default()
        };

        let (result, final_db) = {
            let execution_db = std::mem::replace(db, CacheDB::new(ForkDb::empty()));
            let ctx = Context::mainnet()
                .with_db(execution_db)
                .with_block(_block_env.clone());
            let mut evm = ctx.build_mainnet_with_inspector(CoverageInspector::new(
                _coverage, _dataflow, _waypoints, _tx_idx,
            ));

            let result = evm.inspect_tx_commit(tx_env)?;
            (result, evm.ctx.journaled_state.database)
        };

        let gas_used = result.tx_gas_used();
        let status = match &result {
            ExecutionResult::Success { .. } => ExecutionStatus::Success,
            ExecutionResult::Revert { .. } => ExecutionStatus::Revert,
            ExecutionResult::Halt { reason, .. } => ExecutionStatus::Halt(format!("{reason:?}")),
        };
        let output = result
            .output()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let coverage_hash = EvmCoverageFeedback::stable_path_hash(_coverage);
        let coverage_edges = _coverage.iter().filter(|&&hit| hit != 0).count();
        let waypoints = _waypoints.clone();
        *db = final_db;
        Ok(TxExecutionResult {
            tx_index: _tx_idx,
            status,
            gas_used,
            output,
            coverage_hash,
            coverage_edges,
            waypoints,
        })
    }
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self::new()
    }
}
