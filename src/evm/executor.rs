use crate::common::types::{SingletonTx, ChainState};
use revm::primitives::SpecId;
use revm::inspector_handle_register;
use crate::evm::inspector::CoverageInspector;
use crate::evm::trace::{TraceInspector, ExecutionTrace};
use bitvec::prelude::*;
use libafl::observers::Observer;
use std::borrow::Cow;
use revm::primitives::Log;

/// Observer that wraps the coverage bitmap for LibAFL integration.
/// This allows the feedback system to access coverage data after each execution.
pub struct CoverageObserver {
    name: Cow<'static, str>,
    pub cov_map: Vec<u8>,
}

impl CoverageObserver {
    pub fn new(size: usize) -> Self {
        Self {
            name: Cow::Borrowed("coverage"),
            cov_map: vec![0u8; size],
        }
    }
    
    /// Update the observer's coverage map from a BitSlice
    pub fn update_from_bitslice(&mut self, bits: &BitSlice<u8, Lsb0>) {
        let bytes = bits.as_raw_slice();
        let len = bytes.len().min(self.cov_map.len());
        self.cov_map[..len].copy_from_slice(&bytes[..len]);
    }
    
    /// Get mutable access to the underlying BitSlice for the inspector
    pub fn as_mut_bitslice(&mut self) -> &mut BitSlice<u8, Lsb0> {
        BitSlice::from_slice_mut(&mut self.cov_map)
    }
}

impl<I, S> Observer<I, S> for CoverageObserver {
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut I,
    ) -> Result<(), libafl::Error> {
        // Reset coverage before each execution if needed
        // For edge coverage, we preserve the historical map
        // but the inspector will track new edges in this execution
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut I,
    ) -> Result<(), libafl::Error> {
        // Coverage is already updated by the inspector during execution
        Ok(())
    }
    
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct EvmExecutor {}

impl EvmExecutor {
    pub fn new() -> Self { EvmExecutor {} }

    pub fn execute(
        &self, 
        chain_state: &mut ChainState, 
        tx: &SingletonTx,
        coverage: &mut BitSlice<u8, Lsb0>
    ) -> anyhow::Result<()> {
        let revm_state = match chain_state {
            ChainState::Evm(state) => state,
        };

        let mut inspector = CoverageInspector::new();

        let mut evm = revm::Evm::builder()
            .with_db(revm_state)
            .with_external_context(&mut inspector)
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|revm_tx| *revm_tx = tx.to_revm_tx_env())
            .append_handler_register(inspector_handle_register)
            .build();

        evm.transact_commit()?;

        Ok(())
    }
    
    /// Execute with full trace collection for vulnerability analysis
    pub fn execute_with_trace(
        &self,
        chain_state: &mut ChainState,
        tx: &SingletonTx,
        coverage: &mut BitSlice<u8, Lsb0>,
    ) -> anyhow::Result<ExecutionTrace> {
        let revm_state = match chain_state {
            ChainState::Evm(state) => state,
        };
        
        // Create logs buffer for trace inspector
        let mut logs_buffer: Vec<Log> = Vec::new();
        
        // Create trace inspector
        let mut trace_inspector = TraceInspector::new(&mut logs_buffer);
        
        // Wrap both inspectors (would need MultiInspector in production)
        // For now, we use trace inspector which also captures coverage-relevant info
        let mut evm = revm::Evm::builder()
            .with_db(revm_state)
            .with_external_context(&mut trace_inspector)
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|revm_tx| *revm_tx = tx.to_revm_tx_env())
            .append_handler_register(inspector_handle_register)
            .build();
        
        let result = evm.transact_commit();
        
        // Update coverage from trace (simplified - real impl would extract edges)
        for step in &trace_inspector.trace.steps {
            let edge = step.pc % coverage.len();
            coverage.set(edge, true);
        }
        
        trace_inspector.trace.success = result.is_ok();
        trace_inspector.trace.revert_reason = result.as_ref().err().map(|e| e.to_string());
        trace_inspector.trace.total_gas_used = result
            .as_ref()
            .ok()
            .map(|r| r.gas_used())
            .unwrap_or(0);
        
        Ok(trace_inspector.trace)
    }
}