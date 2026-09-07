//! Experimental temporal-ordering mutation helpers.
//!
//! This module is intentionally compiled for tests only. It is not wired into
//! the active `EvmMutator` dispatch because the campaign configuration does not
//! yet provide a formal-spec constraint path to the mutator without changing
//! default mutation probabilities.

use crate::engine::formal_spec::TemporalConstraint;
use crate::evm::fuzz::EvmInput;
use libafl::prelude::*;
use libafl_bolts::{prelude::Rand, Named};
use std::num::NonZero;

#[derive(Debug)]
struct OrderingConstraintMutator {
    temporal_constraints: Vec<TemporalConstraint>,
}

impl OrderingConstraintMutator {
    fn new(constraints: Vec<TemporalConstraint>) -> Self {
        Self {
            temporal_constraints: constraints,
        }
    }

    fn mutate_violate_ordering(
        &self,
        input: &mut EvmInput,
        rand: &mut impl Rand,
    ) -> MutationResult {
        if input.txs.is_empty() || self.temporal_constraints.is_empty() {
            return MutationResult::Skipped;
        }

        let Some(constraint_idx) = Self::random_index(rand, self.temporal_constraints.len()) else {
            return MutationResult::Skipped;
        };
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

    fn mutate_skip_initialization(
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

    fn mutate_extend_gap(&self, input: &mut EvmInput, rand: &mut impl Rand) -> MutationResult {
        if input.txs.len() < 2 {
            return MutationResult::Skipped;
        }

        // Create gap between related functions by inserting dummy transactions
        let gap_size = (rand.below(NonZero::new(3).unwrap())) + 1; // 1-3 dummy txs

        let Some(insert_pos) = Self::random_index(rand, input.txs.len()) else {
            return MutationResult::Skipped;
        };
        let template = input.txs[insert_pos].clone();

        for _ in 0..gap_size {
            // Create dummy transaction (e.g., no-op or unrelated call)
            input.txs.insert(insert_pos, template.clone());
        }

        MutationResult::Mutated
    }

    fn mutate_duplicate_function(
        &self,
        input: &mut EvmInput,
        rand: &mut impl Rand,
    ) -> MutationResult {
        if input.txs.is_empty() {
            return MutationResult::Skipped;
        }

        let Some(idx) = Self::random_index(rand, input.txs.len()) else {
            return MutationResult::Skipped;
        };
        let tx = input.txs[idx].clone();
        input.txs.insert(idx + 1, tx);

        MutationResult::Mutated
    }

    fn random_index(rand: &mut impl Rand, len: usize) -> Option<usize> {
        NonZero::new(len).map(|bound| rand.below(bound))
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
struct SequenceLengthPenalty;

impl SequenceLengthPenalty {
    fn compute_penalty(
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

    fn is_valid_length(
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
    use crate::common::types::SingletonTx;
    use crate::engine::formal_spec::TemporalConstraintKind;
    use revm::primitives::{Address, U256};
    use std::num::NonZeroUsize;

    #[derive(Debug)]
    struct ScriptedRand {
        draws: Vec<usize>,
        cursor: usize,
    }

    impl ScriptedRand {
        fn new(draws: impl Into<Vec<usize>>) -> Self {
            Self {
                draws: draws.into(),
                cursor: 0,
            }
        }
    }

    impl Rand for ScriptedRand {
        fn set_seed(&mut self, _seed: u64) {
            self.cursor = 0;
        }

        fn next(&mut self) -> u64 {
            0
        }

        fn below(&mut self, upper_bound_excl: NonZeroUsize) -> usize {
            let value = self.draws.get(self.cursor).copied().unwrap_or(0);
            self.cursor += 1;
            assert!(
                value < upper_bound_excl.get(),
                "scripted draw {value} is outside 0..{}",
                upper_bound_excl.get()
            );
            value
        }
    }

    fn tx(selector_first_byte: u8) -> SingletonTx {
        SingletonTx {
            input: vec![selector_first_byte, 0, 0, 0],
            caller: Address::repeat_byte(selector_first_byte),
            to: Address::repeat_byte(0xaa),
            value: U256::from(selector_first_byte),
            is_victim: false,
        }
    }

    fn input(selectors: &[u8]) -> EvmInput {
        EvmInput::new(selectors.iter().copied().map(tx).collect(), 0)
    }

    fn must_precede_constraint() -> TemporalConstraint {
        TemporalConstraint {
            id: "init-before-pause".to_string(),
            kind: TemporalConstraintKind::MustPrecede,
            functions: vec!["initialize()".to_string(), "pause()".to_string()],
            max_gap_blocks: None,
        }
    }

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

    #[test]
    fn random_index_handles_empty_and_all_valid_indices() {
        let mut empty_rand = ScriptedRand::new([]);
        assert_eq!(
            OrderingConstraintMutator::random_index(&mut empty_rand, 0),
            None
        );

        for len in [1, 2, 5] {
            for expected in 0..len {
                let mut rand = ScriptedRand::new([expected]);
                assert_eq!(
                    OrderingConstraintMutator::random_index(&mut rand, len),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn empty_sequences_skip_without_panicking() {
        let mutator = OrderingConstraintMutator::new(vec![must_precede_constraint()]);
        let mut empty = input(&[]);

        assert_eq!(
            mutator.mutate_violate_ordering(&mut empty, &mut ScriptedRand::new([])),
            MutationResult::Skipped
        );
        assert_eq!(
            mutator.mutate_extend_gap(&mut empty, &mut ScriptedRand::new([])),
            MutationResult::Skipped
        );
        assert_eq!(
            mutator.mutate_duplicate_function(&mut empty, &mut ScriptedRand::new([])),
            MutationResult::Skipped
        );
    }

    #[test]
    fn length_one_zero_draw_never_underflows() {
        let mutator = OrderingConstraintMutator::new(vec![must_precede_constraint()]);
        let mut single = input(&[0x8f]);

        assert_eq!(
            mutator.mutate_violate_ordering(&mut single, &mut ScriptedRand::new([0])),
            MutationResult::Skipped
        );
        assert_eq!(
            mutator.mutate_extend_gap(&mut single, &mut ScriptedRand::new([])),
            MutationResult::Skipped
        );

        let mut duplicated = single.clone();
        assert_eq!(
            mutator.mutate_duplicate_function(&mut duplicated, &mut ScriptedRand::new([0])),
            MutationResult::Mutated
        );
        assert_eq!(duplicated.txs.len(), 2);
        assert_eq!(duplicated.txs[0], duplicated.txs[1]);
    }

    #[test]
    fn skip_initialization_moves_multiple_initializers_only_when_safe() {
        let mutator = OrderingConstraintMutator::new(Vec::new());
        let mut single_initializer = input(&[0x8f, 0x20, 0x30]);
        single_initializer.txs[0].input = vec![0x8f, 0x62, 0x5c, 0];
        assert_eq!(
            mutator.mutate_skip_initialization(&mut single_initializer, &mut ScriptedRand::new([])),
            MutationResult::Skipped
        );

        let mut multiple_initializers = input(&[0x8f, 0x10, 0x8f]);
        multiple_initializers.txs[0].input = vec![0x8f, 0x62, 0x5c, 0];
        multiple_initializers.txs[2].input = vec![0x8f, 0x62, 0x5c, 1];
        assert_eq!(
            mutator
                .mutate_skip_initialization(&mut multiple_initializers, &mut ScriptedRand::new([])),
            MutationResult::Mutated
        );
        assert_eq!(
            multiple_initializers
                .txs
                .iter()
                .map(|tx| tx.input[0])
                .collect::<Vec<_>>(),
            vec![0x10, 0x8f, 0x8f]
        );
    }

    #[test]
    fn length_two_mutations_can_select_zero_and_last_index() {
        let mutator = OrderingConstraintMutator::new(vec![must_precede_constraint()]);

        for selected in [0, 1] {
            let mut duplicated = input(&[0x10, 0x20]);
            assert_eq!(
                mutator
                    .mutate_duplicate_function(&mut duplicated, &mut ScriptedRand::new([selected])),
                MutationResult::Mutated
            );
            assert_eq!(duplicated.txs.len(), 3);
            assert_eq!(duplicated.txs[selected], duplicated.txs[selected + 1]);

            let mut gap = input(&[0x30, 0x40]);
            assert_eq!(
                mutator.mutate_extend_gap(&mut gap, &mut ScriptedRand::new([0, selected])),
                MutationResult::Mutated
            );
            assert_eq!(gap.txs.len(), 3);
            assert_eq!(gap.txs[selected], gap.txs[selected + 1]);
        }
    }

    #[test]
    fn ordering_mutation_can_select_first_and_later_constraints() {
        let skipped_constraint = TemporalConstraint {
            id: "does-not-match".to_string(),
            kind: TemporalConstraintKind::MustPrecede,
            functions: vec!["mint(bytes32)".to_string(), "burn(bytes32)".to_string()],
            max_gap_blocks: None,
        };
        let mutator =
            OrderingConstraintMutator::new(vec![must_precede_constraint(), skipped_constraint]);

        let mut first_selected = input(&[0x8f, 0x8d]);
        assert_eq!(
            mutator.mutate_violate_ordering(&mut first_selected, &mut ScriptedRand::new([0])),
            MutationResult::Mutated
        );
        assert_eq!(first_selected.txs[0].input[0], 0x8d);
        assert_eq!(first_selected.txs[1].input[0], 0x8f);

        let mut later_selected = input(&[0x8f, 0x8d]);
        assert_eq!(
            mutator.mutate_violate_ordering(&mut later_selected, &mut ScriptedRand::new([1])),
            MutationResult::Skipped
        );
        assert_eq!(later_selected.txs[0].input[0], 0x8f);
        assert_eq!(later_selected.txs[1].input[0], 0x8d);
    }

    #[test]
    fn larger_sequences_can_select_every_valid_duplicate_index() {
        for selected in 0..5 {
            let mutator = OrderingConstraintMutator::new(Vec::new());
            let mut duplicated = input(&[1, 2, 3, 4, 5]);
            assert_eq!(
                mutator
                    .mutate_duplicate_function(&mut duplicated, &mut ScriptedRand::new([selected])),
                MutationResult::Mutated
            );
            assert_eq!(duplicated.txs.len(), 6);
            assert_eq!(duplicated.txs[selected], duplicated.txs[selected + 1]);
        }
    }

    #[test]
    fn larger_gap_mutation_can_insert_at_last_index() {
        let mutator = OrderingConstraintMutator::new(Vec::new());
        let mut gap = input(&[1, 2, 3, 4, 5]);

        assert_eq!(
            mutator.mutate_extend_gap(&mut gap, &mut ScriptedRand::new([2, 4])),
            MutationResult::Mutated
        );
        assert_eq!(gap.txs.len(), 8);
        assert_eq!(gap.txs[4], gap.txs[5]);
        assert_eq!(gap.txs[5], gap.txs[6]);
        assert_eq!(gap.txs[6], gap.txs[7]);
    }
}
