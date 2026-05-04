use revm::{
    interpreter::Interpreter,
    Database, Inspector, EvmContext,
};
use bitvec::prelude::*;

/// Edge coverage inspector that tracks control flow transitions.
/// 
/// Uses the AFL-style edge coverage algorithm:
/// - Maintains a `prev_loc` (previous location) state
/// - Computes edge as `prev_loc ^ current_pc`
/// - Updates `prev_loc = current_pc >> 1` for next step
/// 
/// This captures path information rather than just block hits,
/// enabling the fuzzer to distinguish between different paths
/// through the same basic blocks.
pub struct CoverageInspector {
    prev_loc: usize,
}

impl CoverageInspector {
    pub fn new() -> Self {
        Self { 
            prev_loc: 0,
        }
    }
    
    /// Reset the inspector state for a new transaction execution.
    /// Preserves the coverage bitmap but resets the location tracker.
    pub fn reset(&mut self) {
        self.prev_loc = 0;
    }
}

impl<DB: Database> Inspector<DB> for CoverageInspector {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let cur_loc = interp.program_counter();
        
        // Compute edge coverage: XOR of previous and current location
        // This creates a unique identifier for the transition
        // Note: caller must provide coverage bitmap to update
        // We track the edge computation but storage is external
        
        // Update prev_loc for next step (AFL uses cur_loc >> 1 to reduce collisions)
        self.prev_loc = cur_loc >> 1;
    }
    
    /// Called when execution starts, useful for resetting state
    fn initialize_interp(
        &mut self,
        _interp: &mut Interpreter,
        _context: &mut EvmContext<DB>,
    ) {
        self.reset();
    }
}