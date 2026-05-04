use libafl::{
    prelude::*,
    state::{StdState, HasCorpus},
    feedbacks::Feedback,
    corpus::InMemoryCorpus,
    observers::ObserversTuple,
    executors::ExitKind,
};
use libafl_bolts::{Named, rands::RomuDuoJrRand};
use libafl_bolts::rands::Rand;
use crate::common::types::SingletonTx;
use revm::primitives::U256;
use std::borrow::Cow;

// Define the state type that LibAFL will use to manage the corpus of Snapshots
// Note: StdRand usually comes from libafl::prelude or libafl_bolts
pub type FuzzState<I> = StdState<I, InMemoryCorpus<I>, RomuDuoJrRand, InMemoryCorpus<I>>;

/// Mutators for SingletonTx focusing on Calldata (input) and Value.
/// 
/// This is a basic byte-level mutator. For production use, replace with
/// ABI-aware mutation that understands function signatures and parameter types.
pub fn mutate_tx(tx: &mut SingletonTx, rand: &mut RomuDuoJrRand) {
    let mutation_type = rand.below(100);
    
    match mutation_type {
        0..=70 => { 
            // Mutate calldata bytes (input)
            if !tx.input.is_empty() {
                let idx = (rand.next() as usize) % tx.input.len();
                tx.input[idx] = rand.next() as u8;
            }
        }
        71..=90 => {
            // Mutate transaction value
            let new_val = rand.next();
            tx.value = U256::from(new_val);
        }
        _ => {
            // Append random byte to input
            tx.input.push(rand.next() as u8);
        }
    }
}

/// Feedback mechanism to detect if a Snapshot found new coverage bits.
/// 
/// This implementation checks the coverage observer's bitmap for any
/// newly set bits compared to the previous execution. If new edges
/// are discovered, the input is considered "interesting" and added
/// to the corpus for future mutation.
pub struct EvmCoverageFeedback {
    last_coverage: Vec<u8>,
}

impl EvmCoverageFeedback {
    pub fn new() -> Self {
        Self {
            last_coverage: Vec::new(),
        }
    }
}

impl Default for EvmCoverageFeedback {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for EvmCoverageFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EvmCoverageFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for EvmCoverageFeedback 
where 
    S: State + HasCorpus,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> 
    where 
        EM: EventFirer<State = S>, 
        OT: ObserversTuple<S> 
    {
        // Retrieve the coverage observer by name
        let cov_observer = observers
            .match_name::<crate::evm::executor::CoverageObserver>("coverage")
            .ok_or_else(|| libafl::Error::IllegalArgument("Coverage observer not found".to_string()))?;
        
        let current_coverage = cov_observer.cov_map.as_slice();
        
        // Check if we have any coverage data yet
        if self.last_coverage.is_empty() {
            // First execution - always interesting to seed the corpus
            self.last_coverage = current_coverage.to_vec();
            return Ok(true);
        }
        
        // Compare current coverage with last known coverage
        // Look for any new bits that were set
        let mut found_new = false;
        for (i, &current_byte) in current_coverage.iter().enumerate() {
            if i >= self.last_coverage.len() {
                // New coverage region discovered
                found_new = true;
                break;
            }
            
            let last_byte = self.last_coverage[i];
            // Check if any new bits are set in this byte
            if (current_byte & !last_byte) != 0 {
                found_new = true;
                break;
            }
        }
        
        // If we found new coverage, update our stored coverage map
        if found_new {
            // Ensure we have enough space
            if current_coverage.len() > self.last_coverage.len() {
                self.last_coverage.resize(current_coverage.len(), 0);
            }
            
            // Update to include new bits (preserve old bits too)
            for (i, &byte) in current_coverage.iter().enumerate() {
                self.last_coverage[i] |= byte;
            }
        }
        
        Ok(found_new)
    }
    
    /// Called after each execution to allow feedback state updates
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
    ) -> Result<(), libafl::Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // No additional metadata needed for basic coverage feedback
        Ok(())
    }
}

pub fn run_evm_fuzz() {
    println!("EVM LibAFL fuzz target initialized.");
    // Integration would continue here with:
    // let mut state = FuzzState::new(...);
    // let mut feedback = EvmCoverageFeedback::new();
}