use crate::engine::formal_spec::TemporalConstraint;
use crate::evm::fuzz::EvmInput;
use libafl::prelude::*;
use libafl_bolts::{prelude::Rand, Named};
use std::num::NonZero;

#[derive(Debug)]
pub struct OrderingConstraintMutator {
    temporal_constraints: Vec<TemporalConstraint>,
}

impl OrderingConstraintMutator {
    pub fn new(constraints: Vec<TemporalConstraint>) -> Self {
        Self {
            temporal_constraints: constraints,
        }
    }

    pub fn mutate_violate_ordering(
        &self,
        input: &mut EvmInput,
        rand: &mut impl Rand,
    ) -> MutationResult {
        if input.txs.is_empty() || self.temporal_constraints.is_empty() {
            return MutationResult::Skipped;
        }

        let constraint_idx =
            (rand.below(NonZero::new(self.temporal_constraints.len()).unwrap()) - 1) as usize;
        let constraint = &self.temporal_constraints[constraint_idx];

        match constraint.functions.as_slice() {
            [] | [_] => MutationResult::Skipped,
            [first, second, ..] => {
                // Try to find these functions in input and reorder them
                let first_pos = input.txs.iter().position(|tx| {
                    tx.input.len() >= 4 && Self::selector_matches(&tx.input[0..4], first)
                });

                let second_pos = input.txs.iter().position(|tx| {
                    tx.input.len() >= 4 && Self::selector_matches(&tx.input[0..4], second)
                });

                if let (Some(pos1), Some(pos2)) = (first_pos, second_pos) {
                    // Swap to violate must_precede constraint
                    if pos1 < pos2 {
                        input.txs.swap(pos1, pos2);
                        return MutationResult::Mutated;
                    }
                }

                MutationResult::Skipped
            }
        }
    }

    pub fn mutate_skip_initialization(
        &self,
        input: &mut EvmInput,
        _rand: &mut impl Rand,
    ) -> MutationResult {
        // Try to remove or move initialize() calls to later in sequence
        let init_positions: Vec<usize> = input
            .txs
            .iter()
            .enumerate()
            .filter(|(_, tx)| {
                tx.input.len() >= 4
                    && (tx.input[0..4].starts_with(&[0x8f, 0x62, 0x5c]) || // heuristic for initialize
                 String::from_utf8_lossy(&tx.input).contains("initialize"))
            })
            .map(|(i, _)| i)
            .collect();

        if init_positions.len() > 1 {
            // Move first initialize to middle/end
            if let Some(&first) = init_positions.first() {
                if first == 0 && input.txs.len() > 2 {
                    let tx = input.txs.remove(first);
                    input.txs.push(tx);
                    return MutationResult::Mutated;
                }
            }
        }

        MutationResult::Skipped
    }

    pub fn mutate_extend_gap(&self, input: &mut EvmInput, rand: &mut impl Rand) -> MutationResult {
        if input.txs.len() < 2 {
            return MutationResult::Skipped;
        }

        // Create gap between related functions by inserting dummy transactions
        let gap_size = (rand.below(NonZero::new(3).unwrap())) + 1; // 1-3 dummy txs

        let insert_pos = (rand.below(NonZero::new(input.txs.len()).unwrap()) - 1) as usize;

        for _ in 0..gap_size {
            // Create dummy transaction (e.g., no-op or unrelated call)
            input.txs.insert(insert_pos, input.txs[insert_pos].clone());
        }

        MutationResult::Mutated
    }

    pub fn mutate_duplicate_function(
        &self,
        input: &mut EvmInput,
        rand: &mut impl Rand,
    ) -> MutationResult {
        if input.txs.is_empty() {
            return MutationResult::Skipped;
        }

        let idx = (rand.below(NonZero::new(input.txs.len()).unwrap()) - 1) as usize;
        let tx = input.txs[idx].clone();
        input.txs.insert(idx + 1, tx);

        MutationResult::Mutated
    }

    fn selector_matches(selector: &[u8], function_name: &str) -> bool {
        // Simplified: check if function name is contained in hex representation
        let hex_repr = hex::encode(selector);
        function_name.contains(&hex_repr)
            || function_name.contains("initialize") && selector[0] == 0x8f
            || function_name.contains("pause") && selector[0] == 0x8d
    }
}

impl Named for OrderingConstraintMutator {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Borrowed("OrderingConstraintMutator");
        &NAME
    }
}

#[derive(Debug)]
pub struct SequenceLengthPenalty;

impl SequenceLengthPenalty {
    pub fn compute_penalty(
        sequence_length: usize,
        min_valid_length: usize,
        max_valid_length: usize,
    ) -> f64 {
        if sequence_length < min_valid_length {
            // Penalize for being too short
            1.0 - (sequence_length as f64 / min_valid_length as f64).min(1.0)
        } else if sequence_length > max_valid_length {
            // Penalize for being too long
            0.1 * ((sequence_length - max_valid_length) as f64 / max_valid_length as f64)
        } else {
            0.0 // No penalty
        }
    }

    pub fn is_valid_length(
        sequence_length: usize,
        min_valid_length: usize,
        max_valid_length: usize,
    ) -> bool {
        sequence_length >= min_valid_length && sequence_length <= max_valid_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_length_penalty_works() {
        // Too short
        let penalty = SequenceLengthPenalty::compute_penalty(1, 3, 10);
        assert!(penalty > 0.0);

        // Too long
        let penalty = SequenceLengthPenalty::compute_penalty(15, 3, 10);
        assert!(penalty > 0.0);

        // Valid range
        let penalty = SequenceLengthPenalty::compute_penalty(5, 3, 10);
        assert_eq!(penalty, 0.0);
    }

    #[test]
    fn detects_valid_sequence_length() {
        assert!(SequenceLengthPenalty::is_valid_length(5, 3, 10));
        assert!(!SequenceLengthPenalty::is_valid_length(1, 3, 10));
        assert!(!SequenceLengthPenalty::is_valid_length(15, 3, 10));
    }
}
