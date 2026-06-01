use crate::common::types::{ComparisonOperand, SymbolicExpression, TaintSource, Waypoint};
use revm::primitives::U256;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcolicHint {
    pub source: TaintSource,
    pub tx_index: usize,
    pub calldata_offset: usize,
    pub word: [u8; 32],
    pub pc: usize,
    pub strategy: ConcolicStrategy,
    pub repair_target: ConcolicRepairTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConcolicStrategy {
    FlipComparison { opcode: u8, target_true: bool },
    FlipBranch { taken: bool },
    ArithmeticBoundary { opcode: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConcolicRepairTarget {
    CalldataWord,
    Caller,
    TxValue,
}

#[derive(Debug, Default)]
pub struct ConcolicHintStats {
    generated: AtomicU64,
    deduplicated: AtomicU64,
    applied: AtomicU64,
    successful: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConcolicHintStatsSnapshot {
    pub generated: u64,
    pub deduplicated: u64,
    pub applied: u64,
    pub successful: u64,
}

impl ConcolicHintStats {
    pub fn record_generated(&self, count: u64) {
        self.generated.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_deduplicated(&self, count: u64) {
        self.deduplicated.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_applied(&self) {
        self.applied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_successful(&self) {
        self.successful.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConcolicHintStatsSnapshot {
        ConcolicHintStatsSnapshot {
            generated: self.generated.load(Ordering::Relaxed),
            deduplicated: self.deduplicated.load(Ordering::Relaxed),
            applied: self.applied.load(Ordering::Relaxed),
            successful: self.successful.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default)]
pub struct ConcolicSolver;

struct ComparisonSolveInput<'a> {
    op: u8,
    lhs: U256,
    rhs: U256,
    tainted_operand: &'a ComparisonOperand,
    target_true: bool,
    lhs_expression: Option<&'a SymbolicExpression>,
    rhs_expression: Option<&'a SymbolicExpression>,
    fallback_source: &'a TaintSource,
}

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
                lhs_expression,
                rhs_expression,
                ..
            } => {
                let target_true = !*condition;
                let operand = match tainted_operand {
                    ComparisonOperand::Unknown => {
                        infer_tainted_operand(*op, *lhs, *rhs, target_true)
                    }
                    known => known.clone(),
                };
                let (source, solved) = solve_expression_comparison(ComparisonSolveInput {
                    op: *op,
                    lhs: *lhs,
                    rhs: *rhs,
                    tainted_operand: &operand,
                    target_true,
                    lhs_expression: lhs_expression.as_ref(),
                    rhs_expression: rhs_expression.as_ref(),
                    fallback_source: source,
                })?;
                Some(hint_from_source(
                    &source,
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
                ..
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
    let (tx_index, calldata_offset, repair_target) = match source {
        TaintSource::Calldata(offset) => (
            fallback_tx_index,
            *offset,
            ConcolicRepairTarget::CalldataWord,
        ),
        TaintSource::Storage(origin_tx, offset) => {
            (*origin_tx, *offset, ConcolicRepairTarget::CalldataWord)
        }
        TaintSource::Caller => (fallback_tx_index, 0, ConcolicRepairTarget::Caller),
        TaintSource::CallValue => (fallback_tx_index, 0, ConcolicRepairTarget::TxValue),
    };
    ConcolicHint {
        source: source.clone(),
        tx_index,
        calldata_offset,
        word: value.to_be_bytes::<32>(),
        pc,
        strategy,
        repair_target,
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

fn solve_expression_comparison(input: ComparisonSolveInput<'_>) -> Option<(TaintSource, U256)> {
    match input.tainted_operand {
        ComparisonOperand::Lhs => {
            let desired = solve_lhs_comparison(input.op, input.rhs, input.target_true)?;
            input
                .lhs_expression
                .and_then(|expr| solve_expression_to_source(expr, desired))
                .or_else(|| Some((input.fallback_source.clone(), desired)))
        }
        ComparisonOperand::Rhs => {
            let desired = solve_rhs_comparison(input.op, input.lhs, input.target_true)?;
            input
                .rhs_expression
                .and_then(|expr| solve_expression_to_source(expr, desired))
                .or_else(|| Some((input.fallback_source.clone(), desired)))
        }
        ComparisonOperand::Unknown => {
            let lhs_desired = solve_lhs_comparison(input.op, input.rhs, input.target_true)
                .and_then(|desired| solve_expression_to_source(input.lhs_expression?, desired));
            lhs_desired.or_else(|| {
                solve_rhs_comparison(input.op, input.lhs, input.target_true)
                    .and_then(|desired| solve_expression_to_source(input.rhs_expression?, desired))
            })
        }
    }
}

fn solve_expression_to_source(
    expr: &SymbolicExpression,
    target: U256,
) -> Option<(TaintSource, U256)> {
    match expr {
        SymbolicExpression::Source(source) => Some((source.clone(), target)),
        SymbolicExpression::Constant(_) => None,
        SymbolicExpression::Add(lhs, rhs) => {
            if let Some(rhs_const) = constant_value(rhs) {
                return target
                    .checked_sub(rhs_const)
                    .and_then(|next| solve_expression_to_source(lhs, next));
            }
            if let Some(lhs_const) = constant_value(lhs) {
                return target
                    .checked_sub(lhs_const)
                    .and_then(|next| solve_expression_to_source(rhs, next));
            }
            None
        }
        SymbolicExpression::Sub(lhs, rhs) => {
            if let Some(rhs_const) = constant_value(rhs) {
                return target
                    .checked_add(rhs_const)
                    .and_then(|next| solve_expression_to_source(lhs, next));
            }
            if let Some(lhs_const) = constant_value(lhs) {
                return lhs_const
                    .checked_sub(target)
                    .and_then(|next| solve_expression_to_source(rhs, next));
            }
            None
        }
        SymbolicExpression::Mul(lhs, rhs) => {
            if let Some(rhs_const) = constant_value(rhs) {
                return solve_mul_inverse(lhs, rhs_const, target);
            }
            if let Some(lhs_const) = constant_value(lhs) {
                return solve_mul_inverse(rhs, lhs_const, target);
            }
            None
        }
        SymbolicExpression::Div(lhs, rhs) => {
            if let Some(rhs_const) = constant_value(rhs) {
                if rhs_const.is_zero() {
                    return None;
                }
                return target
                    .checked_mul(rhs_const)
                    .and_then(|next| solve_expression_to_source(lhs, next));
            }
            None
        }
        SymbolicExpression::Mod(lhs, rhs) => {
            let modulus = constant_value(rhs)?;
            if target < modulus {
                solve_expression_to_source(lhs, target)
            } else {
                None
            }
        }
        SymbolicExpression::Xor(lhs, rhs) => {
            if let Some(rhs_const) = constant_value(rhs) {
                return solve_expression_to_source(lhs, target ^ rhs_const);
            }
            if let Some(lhs_const) = constant_value(lhs) {
                return solve_expression_to_source(rhs, target ^ lhs_const);
            }
            None
        }
        SymbolicExpression::And(_, _) | SymbolicExpression::Or(_, _) => None,
    }
}

fn constant_value(expr: &SymbolicExpression) -> Option<U256> {
    match expr {
        SymbolicExpression::Constant(value) => Some(*value),
        _ => None,
    }
}

fn solve_mul_inverse(
    expr: &SymbolicExpression,
    factor: U256,
    target: U256,
) -> Option<(TaintSource, U256)> {
    if factor.is_zero() || target % factor != U256::ZERO {
        return None;
    }
    solve_expression_to_source(expr, target / factor)
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
            lhs_expression: Some(SymbolicExpression::Source(TaintSource::Calldata(4))),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(42))),
            branch_distance: Some(U256::from(35)),
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
            lhs_expression: Some(SymbolicExpression::Source(TaintSource::Storage(1, 36))),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(10))),
            branch_distance: Some(U256::from(91)),
        };

        let hint = ConcolicSolver::new()
            .solve_hint(3, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 1);
        assert_eq!(hint.calldata_offset, 36);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(9));
    }

    #[test]
    fn solves_linear_expression_before_comparison() {
        let source = TaintSource::Calldata(4);
        let waypoint = Waypoint::Comparison {
            op: 0x14,
            lhs: U256::from(17),
            rhs: U256::from(42),
            pc: 77,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(source.clone()),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: Some(SymbolicExpression::Add(
                Box::new(SymbolicExpression::Source(source)),
                Box::new(SymbolicExpression::Constant(U256::from(5))),
            )),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(42))),
            branch_distance: Some(U256::from(25)),
        };

        let hint = ConcolicSolver::new()
            .solve_hint(0, &waypoint)
            .expect("hint");
        assert_eq!(hint.calldata_offset, 4);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(37));
    }

    #[test]
    fn solves_msg_value_threshold() {
        let waypoint = Waypoint::Comparison {
            op: 0x10,
            lhs: U256::from(1),
            rhs: U256::from(10),
            pc: 101,
            calldata_offset: None,
            condition: true,
            hit: true,
            taint_source: Some(TaintSource::CallValue),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: Some(SymbolicExpression::Source(TaintSource::CallValue)),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(10))),
            branch_distance: Some(U256::from(9)),
        };

        let hint = ConcolicSolver::new()
            .solve_hint(0, &waypoint)
            .expect("hint");
        assert_eq!(hint.repair_target, ConcolicRepairTarget::TxValue);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(10));
    }

    #[test]
    fn solves_msg_sender_role_equality() {
        let expected = U256::from(0x1234_u64);
        let waypoint = Waypoint::Comparison {
            op: 0x14,
            lhs: U256::from(0x99_u64),
            rhs: expected,
            pc: 102,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(TaintSource::Caller),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: Some(SymbolicExpression::Source(TaintSource::Caller)),
            rhs_expression: Some(SymbolicExpression::Constant(expected)),
            branch_distance: Some(U256::from(1)),
        };

        let hint = ConcolicSolver::new()
            .solve_hint(0, &waypoint)
            .expect("hint");
        assert_eq!(hint.repair_target, ConcolicRepairTarget::Caller);
        assert_eq!(U256::from_be_bytes(hint.word), expected);
    }

    #[test]
    fn solves_storage_derived_balance_threshold_to_originating_amount() {
        let waypoint = Waypoint::Comparison {
            op: 0x11,
            lhs: U256::from(5),
            rhs: U256::from(100),
            pc: 103,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(TaintSource::Storage(0, 36)),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: Some(SymbolicExpression::Add(
                Box::new(SymbolicExpression::Source(TaintSource::Storage(0, 36))),
                Box::new(SymbolicExpression::Constant(U256::from(5))),
            )),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(100))),
            branch_distance: Some(U256::from(95)),
        };

        let hint = ConcolicSolver::new()
            .solve_hint(2, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 0);
        assert_eq!(hint.calldata_offset, 36);
        assert_eq!(hint.repair_target, ConcolicRepairTarget::CalldataWord);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(96));
    }
}
