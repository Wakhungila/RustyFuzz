use crate::common::types::{ComparisonOperand, TaintSource, Waypoint};
use revm::primitives::U256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcolicHint {
    pub source: TaintSource,
    pub tx_index: usize,
    pub calldata_offset: usize,
    pub word: [u8; 32],
    pub pc: usize,
    pub strategy: ConcolicStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcolicStrategy {
    FlipComparison { opcode: u8, target_true: bool },
    FlipBranch { taken: bool },
    ArithmeticBoundary { opcode: u8 },
}

#[derive(Debug, Default)]
pub struct ConcolicSolver;

impl ConcolicSolver {
    pub fn new() -> Self {
        Self
    }

    pub fn solve_hint(&self, tx_index: usize, waypoint: &Waypoint) -> Option<ConcolicHint> {
        match waypoint {
            Waypoint::BranchPath {
                taken, constraint, ..
            } => {
                let mut hint = self.solve_hint(tx_index, constraint)?;
                hint.strategy = ConcolicStrategy::FlipBranch { taken: *taken };
                Some(hint)
            }
            Waypoint::Comparison {
                op,
                lhs,
                rhs,
                pc,
                condition,
                taint_source: Some(source),
                tainted_operand,
                ..
            } => {
                let target_true = !*condition;
                let operand = match tainted_operand {
                    ComparisonOperand::Unknown => {
                        infer_tainted_operand(*op, *lhs, *rhs, target_true)
                    }
                    known => known.clone(),
                };
                let solved = solve_comparison_word(*op, *lhs, *rhs, &operand, target_true)?;
                Some(hint_from_source(
                    source,
                    tx_index,
                    *pc,
                    solved,
                    ConcolicStrategy::FlipComparison {
                        opcode: *op,
                        target_true,
                    },
                ))
            }
            Waypoint::Arithmetic {
                op,
                lhs,
                rhs,
                third,
                pc,
                taint_source: Some(source),
            } => {
                let solved = solve_arithmetic_boundary(*op, *lhs, *rhs, *third)?;
                Some(hint_from_source(
                    source,
                    tx_index,
                    *pc,
                    solved,
                    ConcolicStrategy::ArithmeticBoundary { opcode: *op },
                ))
            }
            _ => None,
        }
    }

    pub fn solve_hints<'a>(
        &self,
        tx_waypoints: impl Iterator<Item = (usize, &'a Waypoint)>,
    ) -> Vec<ConcolicHint> {
        let mut hints: Vec<_> = tx_waypoints
            .filter_map(|(tx_index, waypoint)| self.solve_hint(tx_index, waypoint))
            .collect();
        hints.sort_by_key(|hint| {
            (
                hint.tx_index,
                hint.calldata_offset,
                hint.pc,
                strategy_rank(&hint.strategy),
            )
        });
        hints.dedup_by_key(|hint| (hint.tx_index, hint.calldata_offset, hint.word));
        hints
    }
}

fn hint_from_source(
    source: &TaintSource,
    fallback_tx_index: usize,
    pc: usize,
    value: U256,
    strategy: ConcolicStrategy,
) -> ConcolicHint {
    let (tx_index, calldata_offset) = match source {
        TaintSource::Calldata(offset) => (fallback_tx_index, *offset),
        TaintSource::Storage(origin_tx, offset) => (*origin_tx, *offset),
    };
    ConcolicHint {
        source: source.clone(),
        tx_index,
        calldata_offset,
        word: value.to_be_bytes::<32>(),
        pc,
        strategy,
    }
}

fn infer_tainted_operand(op: u8, lhs: U256, rhs: U256, target_true: bool) -> ComparisonOperand {
    let lhs_candidate = solve_comparison_word(op, lhs, rhs, &ComparisonOperand::Lhs, target_true);
    let rhs_candidate = solve_comparison_word(op, lhs, rhs, &ComparisonOperand::Rhs, target_true);
    match (lhs_candidate, rhs_candidate) {
        (Some(_), None) => ComparisonOperand::Lhs,
        (None, Some(_)) => ComparisonOperand::Rhs,
        _ => ComparisonOperand::Lhs,
    }
}

fn solve_comparison_word(
    op: u8,
    lhs: U256,
    rhs: U256,
    tainted_operand: &ComparisonOperand,
    target_true: bool,
) -> Option<U256> {
    match tainted_operand {
        ComparisonOperand::Lhs => solve_lhs_comparison(op, rhs, target_true),
        ComparisonOperand::Rhs => solve_rhs_comparison(op, lhs, target_true),
        ComparisonOperand::Unknown => None,
    }
}

fn solve_lhs_comparison(op: u8, rhs: U256, target_true: bool) -> Option<U256> {
    match (op, target_true) {
        (0x10 | 0x12, true) => rhs.checked_sub(U256::from(1)),
        (0x10 | 0x12, false) => Some(rhs),
        (0x11 | 0x13, true) => rhs.checked_add(U256::from(1)),
        (0x11 | 0x13, false) => Some(rhs),
        (0x14, true) => Some(rhs),
        (0x14, false) => perturb(rhs),
        _ => None,
    }
}

fn solve_rhs_comparison(op: u8, lhs: U256, target_true: bool) -> Option<U256> {
    match (op, target_true) {
        (0x10 | 0x12, true) => lhs.checked_add(U256::from(1)),
        (0x10 | 0x12, false) => Some(lhs),
        (0x11 | 0x13, true) => lhs.checked_sub(U256::from(1)),
        (0x11 | 0x13, false) => Some(lhs),
        (0x14, true) => Some(lhs),
        (0x14, false) => perturb(lhs),
        _ => None,
    }
}

fn perturb(value: U256) -> Option<U256> {
    value
        .checked_add(U256::from(1))
        .or_else(|| value.checked_sub(U256::from(1)))
}

fn solve_arithmetic_boundary(op: u8, lhs: U256, rhs: U256, third: Option<U256>) -> Option<U256> {
    match op {
        0x01 => U256::MAX.checked_sub(rhs).and_then(perturb),
        0x02 if rhs > U256::from(1) => Some(U256::MAX / rhs + U256::from(1)),
        0x03 => Some(rhs.checked_sub(U256::from(1)).unwrap_or(U256::ZERO)),
        0x04 | 0x05 => Some(
            rhs.saturating_mul(U256::from(2))
                .saturating_add(U256::from(1)),
        ),
        0x08 | 0x09 => third.filter(|n| !n.is_zero()),
        _ => Some(lhs),
    }
}

fn strategy_rank(strategy: &ConcolicStrategy) -> u8 {
    match strategy {
        ConcolicStrategy::FlipBranch { .. } => 0,
        ConcolicStrategy::FlipComparison { .. } => 1,
        ConcolicStrategy::ArithmeticBoundary { .. } => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_false_eq_into_matching_calldata_word() {
        let waypoint = Waypoint::Comparison {
            op: 0x14,
            lhs: U256::from(7),
            rhs: U256::from(42),
            pc: 11,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(TaintSource::Calldata(4)),
            tainted_operand: ComparisonOperand::Lhs,
        };

        let hint = ConcolicSolver::new()
            .solve_hint(0, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 0);
        assert_eq!(hint.calldata_offset, 4);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(42));
    }

    #[test]
    fn storage_taint_targets_originating_transaction() {
        let waypoint = Waypoint::Comparison {
            op: 0x10,
            lhs: U256::from(100),
            rhs: U256::from(10),
            pc: 99,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(TaintSource::Storage(1, 36)),
            tainted_operand: ComparisonOperand::Lhs,
        };

        let hint = ConcolicSolver::new()
            .solve_hint(3, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 1);
        assert_eq!(hint.calldata_offset, 36);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(9));
    }
}
