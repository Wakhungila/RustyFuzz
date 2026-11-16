use crate::common::types::{ComparisonOperand, SymbolicExpression, TaintSource, Waypoint};
use revm::primitives::U256;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

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

// Stage 3: stats live in `rustyfuzz-engine::concolic_stats`.
pub use rustyfuzz_engine::concolic_stats::{ConcolicHintStats, ConcolicHintStatsSnapshot};

/// Concolic solver for generating input mutations based on execution constraints.
///
/// The `ConcolicSolver` analyzes execution waypoints (comparisons, branches, arithmetic operations)
/// and generates hints for mutating inputs to explore alternative execution paths.
#[derive(Debug, Clone)]
pub struct ConcolicSolver {
    /// Maximum time allowed for solving operations (default: 1 second)
    timeout: Duration,
    /// Start time for the current solving operation
    start_time: Option<Instant>,
}

impl Default for ConcolicSolver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            start_time: None,
        }
    }
}

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
        Self::default()
    }

    /// Creates a new ConcolicSolver with a custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            start_time: None,
        }
    }

    /// Checks if the timeout has been exceeded
    fn check_timeout(&self) -> bool {
        if let Some(start) = self.start_time {
            start.elapsed() > self.timeout
        } else {
            false
        }
    }

    /// Starts a new timeout window for solving operations
    fn start_timeout(&mut self) {
        self.start_time = Some(Instant::now());
    }

    pub fn solve_hint(&self, tx_index: usize, waypoint: &Waypoint) -> Option<ConcolicHint> {
        // Check timeout before starting solve operation
        if self.check_timeout() {
            return None;
        }

        // SMT-backed path (GAP-3). When the `smt` cargo feature is enabled,
        // discharge accumulated path constraints over symbolic calldata via
        // z3 first. If SMT returns `None` (unsupported constraint shape,
        // e.g. keccak/mappings, or UNSAT), fall back to the deterministic
        // inversion heuristic below. The default build (no `smt` feature) is
        // byte-for-byte unchanged — this entire block is cfg-gated.
        #[cfg(feature = "smt")]
        if let Some(hint) = self.solve_hint_via_smt(tx_index, waypoint) {
            return Some(hint);
        }

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
                // Check timeout during complex comparison solving
                if self.check_timeout() {
                    return None;
                }

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
                // Check timeout during arithmetic solving
                if self.check_timeout() {
                    return None;
                }

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
        &mut self,
        tx_waypoints: impl Iterator<Item = (usize, &'a Waypoint)>,
    ) -> Vec<ConcolicHint> {
        // Start timeout window for batch solve operation
        self.start_timeout();

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

    /// SMT-first dispatch helper (GAP-3). Tries the z3-backed solver on a
    /// single-waypoint path with `flip_last = true`. Returns `None` when the
    /// constraint shape is unsupported (keccak/mappings, arithmetic boundary
    /// waypoints, etc.) or when z3 reports UNSAT/Unknown — in both cases the
    /// caller falls back to the deterministic inversion heuristic.
    ///
    /// Strictly feature-gated: the default build never compiles this method.
    #[cfg(feature = "smt")]
    fn solve_hint_via_smt(&self, tx_index: usize, waypoint: &Waypoint) -> Option<ConcolicHint> {
        let bytes = smt_solver::solve_path_constraint_smt(std::slice::from_ref(waypoint), true)?;
        if bytes.len() != 32 {
            return None;
        }
        let word_arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        let value = U256::from_be_bytes(word_arr);
        let (source, pc, strategy) = match waypoint {
            Waypoint::Comparison {
                op,
                pc,
                condition,
                taint_source: Some(s),
                ..
            } => (
                s.clone(),
                *pc,
                ConcolicStrategy::FlipComparison {
                    opcode: *op,
                    target_true: !*condition,
                },
            ),
            Waypoint::BranchPath {
                pc,
                taken,
                constraint,
                ..
            } => {
                // The inner constraint is a Comparison (inspector invariant);
                // pull its taint source so the hint targets the right
                // calldata/caller/value slot.
                if let Waypoint::Comparison {
                    taint_source: Some(s),
                    ..
                } = constraint.as_ref()
                {
                    (
                        s.clone(),
                        *pc,
                        ConcolicStrategy::FlipBranch { taken: *taken },
                    )
                } else {
                    return None;
                }
            }
            // Arithmetic / Dataflow / StorageRead / MappingDerivation / etc.
            // are not boolean constraints — SMT cannot flip them. The
            // deterministic heuristic below handles the ones that have one.
            _ => return None,
        };
        Some(hint_from_source(&source, tx_index, pc, value, strategy))
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

/// Two's-complement sign bit: values >= 2^255 are negative.
#[cfg(test)]
fn signed_bit(value: U256) -> bool {
    value >> 255 == U256::ONE
}

#[cfg(test)]
fn signed_lt(lhs: U256, rhs: U256) -> bool {
    match (signed_bit(lhs), signed_bit(rhs)) {
        // A negative operand always sorts below a non-negative one.
        (true, false) => true,
        (false, true) => false,
        // Same sign bit: unsigned order matches signed order.
        (lhs_negative, rhs_negative) => lhs_negative == rhs_negative && lhs < rhs,
    }
}

fn signed_min() -> U256 {
    U256::ONE << 255
}

fn signed_max() -> U256 {
    signed_min().checked_sub(U256::ONE).expect("2^255 - 1")
}

/// The two's-complement predecessor (-1 + 1 = 0 wraps to U256::MAX).
fn signed_predecessor(value: U256) -> Option<U256> {
    if value == signed_min() {
        return None;
    }
    Some(if value.is_zero() {
        U256::MAX
    } else {
        value - U256::ONE
    })
}

/// The two's-complement successor (-1 + 1 = 0).
fn signed_successor(value: U256) -> Option<U256> {
    if value == signed_max() {
        return None;
    }
    Some(if value == U256::MAX {
        U256::ZERO
    } else {
        value + U256::ONE
    })
}

fn solve_lhs_comparison(op: u8, rhs: U256, target_true: bool) -> Option<U256> {
    match (op, target_true) {
        // Unsigned LT: no value is below zero.
        (0x10, true) => rhs.checked_sub(U256::from(1)),
        // SLT: the two's-complement predecessor satisfies lhs < rhs unless rhs
        // is the signed minimum (nothing below it).
        (0x12, true) => signed_predecessor(rhs),
        (0x10 | 0x12, false) => Some(rhs),
        // Unsigned GT: nothing is above the unsigned maximum.
        (0x11, true) => rhs.checked_add(U256::from(1)),
        // SGT: the two's-complement successor satisfies lhs > rhs unless rhs
        // is the signed maximum (nothing above it).
        (0x13, true) => signed_successor(rhs),
        (0x11 | 0x13, false) => Some(rhs),
        (0x14, true) => Some(rhs),
        (0x14, false) => perturb(rhs),
        _ => None,
    }
}

fn solve_rhs_comparison(op: u8, lhs: U256, target_true: bool) -> Option<U256> {
    match (op, target_true) {
        (0x10, true) => lhs.checked_add(U256::from(1)),
        // SLT: rhs must be greater than lhs in signed order.
        (0x12, true) => signed_successor(lhs),
        (0x10 | 0x12, false) => Some(lhs),
        (0x11, true) => lhs.checked_sub(U256::from(1)),
        // SGT: rhs must be smaller than lhs in signed order.
        (0x13, true) => signed_predecessor(lhs),
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

// ─────────────────────────────────────────────────────────────────────────────
// SMT-backed concolic solver (GAP-3).
//
// Compiled only when the `smt` cargo feature is enabled. Discharges
// linear-arithmetic, bitwise, and comparison path constraints over 256-bit
// symbolic calldata using z3. Keccak/mappings remain unsupported (honest
// ceiling — the deterministic inversion heuristic above handles those paths
// when SMT returns `None`).
//
// The default build (no `smt` feature) never compiles this module. The
// `solve_hint_via_smt` method on `ConcolicSolver` above is the sole caller
// and is itself cfg-gated.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "smt")]
pub mod smt_solver {
    use crate::common::types::{SymbolicExpression, TaintSource, Waypoint};
    use revm::primitives::U256;
    use std::collections::HashMap;
    use z3::ast::{Ast, Bool, BV};
    use z3::{SatResult, Solver};

    /// All EVM symbolic values are encoded as 256-bit bitvectors.
    const BV_WIDTH: u32 = 256;

    /// Mapping from `TaintSource` to the z3 symbolic BV that represents it.
    /// Deduplicating by source ensures the same calldata offset maps to the
    /// same BV across multiple waypoints in a path.
    #[derive(Default)]
    struct SymEnv {
        consts: HashMap<TaintSource, BV>,
    }

    impl SymEnv {
        fn bv_for_source(&mut self, source: &TaintSource) -> BV {
            if let Some(bv) = self.consts.get(source) {
                return bv.clone();
            }
            let name = source_symbol_name(source);
            let bv = BV::new_const(name, BV_WIDTH);
            self.consts.insert(source.clone(), bv.clone());
            bv
        }

        /// Returns the symbolic consts collected during encoding.
        fn symbolic_consts(&self) -> Vec<(&TaintSource, &BV)> {
            self.consts.iter().collect()
        }
    }

    /// Deterministic z3 symbol name for a taint source. Stable across
    /// invocations so the same source always maps to the same BV.
    fn source_symbol_name(source: &TaintSource) -> String {
        match source {
            TaintSource::Calldata(offset) => format!("calldata_{offset}"),
            TaintSource::Storage(tx, offset) => format!("storage_{tx}_{offset}"),
            TaintSource::Caller => "caller".to_string(),
            TaintSource::CallValue => "call_value".to_string(),
        }
    }

    /// Convert a U256 to a 256-bit z3 bitvector numeral. `BV::from_str`
    /// accepts decimal strings, which is the safest round-trip path for the
    /// full 256-bit range (`BV::from_u64` only covers the low 64 bits).
    fn u256_to_bv(value: &U256) -> BV {
        BV::from_str(BV_WIDTH, &value.to_string())
            .expect("U256 decimal string is a valid z3 numeral")
    }

    /// Convert a 256-bit z3 BV numeral back to a U256 by extracting four
    /// 64-bit chunks. `extract` returns an expression (not a simplified
    /// numeral), so each chunk must be `simplify()`-d before `as_u64()` can
    /// read it. Robust against z3's `#x...`/`#b...` Display formats.
    fn bv_to_u256(bv: &BV) -> U256 {
        let chunk = |high: u32, low: u32| -> u64 {
            bv.extract(high, low)
                .simplify()
                .as_u64()
                .expect("simplified 64-bit numeral chunk fits in u64")
        };
        let hi3 = chunk(255, 192);
        let hi2 = chunk(191, 128);
        let hi1 = chunk(127, 64);
        let lo0 = chunk(63, 0);
        (U256::from(hi3) << 192)
            | (U256::from(hi2) << 128)
            | (U256::from(hi1) << 64)
            | U256::from(lo0)
    }

    /// Encode a `SymbolicExpression` as a z3 256-bit BV. Every variant is
    /// encodable; keccak/mappings are represented as separate `Waypoint`
    /// variants and rejected at the waypoint level (`encode_flip_target`
    /// returns `None`).
    fn encode_expression(expr: &SymbolicExpression, env: &mut SymEnv) -> Option<BV> {
        match expr {
            SymbolicExpression::Source(source) => Some(env.bv_for_source(source)),
            SymbolicExpression::Constant(value) => Some(u256_to_bv(value)),
            SymbolicExpression::Add(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvadd(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Sub(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvsub(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Mul(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvmul(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Div(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvudiv(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Mod(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvurem(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Xor(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvxor(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::And(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvand(&encode_expression(rhs, env)?))
            }
            SymbolicExpression::Or(lhs, rhs) => {
                Some(encode_expression(lhs, env)?.bvor(&encode_expression(rhs, env)?))
            }
        }
    }

    /// Encode an EVM comparison opcode as a z3 Bool. Opcode mapping mirrors
    /// the EVM yellow paper: 0x10 LT, 0x11 GT, 0x12 SLT, 0x13 SGT, 0x14 EQ.
    /// Returns `None` for unsupported opcodes.
    fn encode_comparison_op(op: u8, lhs: &BV, rhs: &BV) -> Option<Bool> {
        match op {
            0x10 => Some(lhs.bvult(rhs)), // LT  (unsigned)
            0x11 => Some(lhs.bvugt(rhs)), // GT  (unsigned)
            0x12 => Some(lhs.bvslt(rhs)), // SLT (signed)
            0x13 => Some(lhs.bvsgt(rhs)), // SGT (signed)
            0x14 => Some(lhs.eq(rhs)),    // EQ
            _ => None,
        }
    }

    /// Encode the FLIP TARGET of a waypoint as a z3 Bool — that is, the
    /// boolean condition which, when satisfied, flips the executed path.
    ///
    /// For `Waypoint::Comparison`:
    ///   - if `condition` is true (comparison held): flip target is `!inner_bool`
    ///   - if `condition` is false (comparison failed): flip target is `inner_bool`
    ///
    /// For `Waypoint::BranchPath`: the inspector constructs the inner
    /// `Comparison` with `condition = false` and an `rhs` chosen so the
    /// comparison currently does NOT hold — the inner comparison's truth is
    /// exactly the flip target. We recurse and let the `Comparison` arm
    /// handle it.
    ///
    /// Returns `None` for waypoint kinds with no boolean encoding in this
    /// integration (`Arithmetic`, `Dataflow`, `StorageRead`, `StorageWrite`,
    /// `MappingDerivation`, etc.). Those fall back to the deterministic
    /// inversion heuristic.
    fn encode_flip_target(waypoint: &Waypoint, env: &mut SymEnv) -> Option<Bool> {
        match waypoint {
            Waypoint::Comparison {
                op,
                lhs,
                rhs,
                lhs_expression,
                rhs_expression,
                condition,
                ..
            } => {
                let lhs_bv = lhs_expression
                    .as_ref()
                    .and_then(|e| encode_expression(e, env))
                    .unwrap_or_else(|| u256_to_bv(lhs));
                let rhs_bv = rhs_expression
                    .as_ref()
                    .and_then(|e| encode_expression(e, env))
                    .unwrap_or_else(|| u256_to_bv(rhs));
                let inner_bool = encode_comparison_op(*op, &lhs_bv, &rhs_bv)?;
                Some(if *condition {
                    inner_bool.not()
                } else {
                    inner_bool
                })
            }
            Waypoint::BranchPath { constraint, .. } => {
                // Inspector invariant: inner Comparison has `condition = false`
                // and rhs chosen so the comparison currently does NOT hold.
                // Its flip target is therefore `inner_bool` — exactly what the
                // `Comparison` arm produces with `condition = false`.
                encode_flip_target(constraint, env)
            }
            _ => None,
        }
    }

    /// Solve accumulated path constraints with optional branch-flip on the
    /// final waypoint. Returns the 32-byte big-endian encoding of the first
    /// symbolic source's solved value, or `None` if the constraints are
    /// unsatisfiable, unsupported, or contain no symbolic variables.
    ///
    /// Constraint accumulation:
    ///   - For each non-last waypoint: assert the path-that-was-taken, which
    ///     is the negation of the flip target.
    ///   - For the last waypoint: assert the flip target if `flip_last` is
    ///     true, else the path-that-was-taken.
    ///
    /// This is sound for standalone `Comparison` waypoints and for
    /// `BranchPath` waypoints where the executed branch is the negation of
    /// the flip target (the inspector's encoding for `taken = true`). For
    /// `BranchPath` with `taken = false`, the path predicate is approximate;
    /// single-waypoint `flip_last = true` calls (the only use site today)
    /// are unaffected because no path accumulation occurs.
    pub fn solve_path_constraint_smt(waypoints: &[Waypoint], flip_last: bool) -> Option<Vec<u8>> {
        if waypoints.is_empty() {
            return None;
        }
        let solver = Solver::new();
        let mut env = SymEnv::default();

        for (idx, waypoint) in waypoints.iter().enumerate() {
            let is_last = idx + 1 == waypoints.len();
            let flip_target = encode_flip_target(waypoint, &mut env)?;
            let asserted = if is_last && flip_last {
                flip_target
            } else {
                flip_target.not()
            };
            solver.assert(&asserted);
        }

        if solver.check() != SatResult::Sat {
            return None;
        }
        let model = solver.get_model()?;
        let consts = env.symbolic_consts();
        if consts.is_empty() {
            return None;
        }
        // Prefer Calldata sources first (the most common concolic target),
        // then Caller/CallValue, then Storage. Deterministic ordering makes
        // the solved value reproducible across runs.
        let priority = |s: &TaintSource| match s {
            TaintSource::Calldata(_) => 0,
            TaintSource::Caller => 1,
            TaintSource::CallValue => 2,
            TaintSource::Storage(_, _) => 3,
        };
        let (_source, bv) = consts.into_iter().min_by_key(|(s, _)| priority(s))?;
        let value_bv = model.eval(bv, true)?;
        Some(bv_to_u256(&value_bv).to_be_bytes::<32>().to_vec())
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

        let hint = ConcolicSolver::default()
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

        let hint = ConcolicSolver::default()
            .solve_hint(3, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 1);
        assert_eq!(hint.calldata_offset, 36);
        // Deterministic heuristic returns the boundary value 9 (rhs - 1).
        // SMT solver may return any value < 10; only the constraint matters.
        #[cfg(not(feature = "smt"))]
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(9));
        #[cfg(feature = "smt")]
        assert!(U256::from_be_bytes(hint.word) < U256::from(10));
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

        let hint = ConcolicSolver::default()
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

        let hint = ConcolicSolver::default()
            .solve_hint(0, &waypoint)
            .expect("hint");
        assert_eq!(hint.repair_target, ConcolicRepairTarget::TxValue);
        // Deterministic heuristic returns the boundary value 10 (rhs).
        // SMT solver may return any value >= 10; only the constraint matters.
        #[cfg(not(feature = "smt"))]
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(10));
        #[cfg(feature = "smt")]
        assert!(U256::from_be_bytes(hint.word) >= U256::from(10));
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

        let hint = ConcolicSolver::default()
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

        let hint = ConcolicSolver::default()
            .solve_hint(2, &waypoint)
            .expect("hint");
        assert_eq!(hint.tx_index, 0);
        assert_eq!(hint.calldata_offset, 36);
        assert_eq!(hint.repair_target, ConcolicRepairTarget::CalldataWord);
        // Deterministic heuristic returns the boundary value 96 (rhs - 5 + 1).
        // SMT solver may return any value > 95; only the constraint matters.
        #[cfg(not(feature = "smt"))]
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(96));
        #[cfg(feature = "smt")]
        assert!(U256::from_be_bytes(hint.word) > U256::from(95));
    }

    /// SLT/SGT solving must use two's-complement order: the solved operand
    /// always satisfies the signed comparison it was solved for, and signed
    /// boundary operands that make the constraint unsatisfiable yield None
    /// instead of a wrong or bogus value.
    #[test]
    fn slt_sgt_solves_in_two_complement_order() {
        // SLT with lhs unknown, rhs = 0: flipping to true needs lhs < 0. The
        // unsigned code underflowed to None; the signed solver wraps to -1.
        let solved = solve_lhs_comparison(0x12, U256::ZERO, true).expect("solvable");
        assert_eq!(solved, U256::MAX);
        assert!(signed_lt(solved, U256::ZERO));

        // rhs = signed minimum: nothing is below it, so the constraint is
        // unsatisfiable.
        assert_eq!(solve_lhs_comparison(0x12, signed_min(), true), None);

        // SGT with rhs unknown, lhs = signed minimum: nothing is below it in
        // signed order, so the constraint is unsatisfiable.
        assert_eq!(solve_rhs_comparison(0x13, signed_min(), true), None);

        // SGT with lhs unknown, rhs = -1: the successor wraps to 0, which is
        // greater than -1 in signed order (the unsigned code overflowed to
        // None here).
        let solved = solve_lhs_comparison(0x13, U256::MAX, true).expect("solvable");
        assert_eq!(solved, U256::ZERO);
        assert!(signed_gt(solved, U256::MAX));

        // SGT with rhs unknown, lhs = 0: rhs = -1 satisfies lhs > rhs.
        let solved = solve_rhs_comparison(0x13, U256::ZERO, true).expect("solvable");
        assert_eq!(solved, U256::MAX);
        assert!(signed_gt(U256::ZERO, solved));

        // Falsification keeps the known operand: lhs == rhs makes both SLT and
        // SGT false.
        assert_eq!(
            solve_lhs_comparison(0x12, U256::from(7), false),
            Some(U256::from(7))
        );
        assert_eq!(
            solve_rhs_comparison(0x13, U256::from(7), false),
            Some(U256::from(7))
        );
    }

    fn signed_gt(lhs: U256, rhs: U256) -> bool {
        signed_lt(rhs, lhs)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SMT solver unit tests (GAP-3).
//
// Compiled only when BOTH `test` and `smt` are enabled. Run with:
//   cargo test -p rusty-fuzz --lib --features smt smt_
// These tests exercise the z3-backed solver directly via
// `smt_solver::solve_path_constraint_smt`. They do not run in the default
// build (no `smt` feature).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "smt"))]
mod smt_tests {
    use super::*;
    use crate::common::types::{ComparisonOperand, SymbolicExpression, TaintSource, Waypoint};
    use revm::primitives::U256;

    /// Convenience: build a `Waypoint::Comparison` with the given fields and
    /// sensible defaults for the rest.
    fn comparison_waypoint(
        op: u8,
        lhs: U256,
        rhs: U256,
        lhs_expression: Option<SymbolicExpression>,
        rhs_expression: Option<SymbolicExpression>,
        condition: bool,
    ) -> Waypoint {
        Waypoint::Comparison {
            op,
            lhs,
            rhs,
            pc: 0,
            calldata_offset: None,
            condition,
            hit: condition,
            taint_source: Some(TaintSource::Calldata(0)),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression,
            rhs_expression,
            branch_distance: None,
        }
    }

    /// `x + 5 == 10` (currently false; flip to true) → solve x = 5.
    #[test]
    fn test_smt_solves_linear_constraint() {
        let lhs_expr = SymbolicExpression::Add(
            Box::new(SymbolicExpression::Source(TaintSource::Calldata(0))),
            Box::new(SymbolicExpression::Constant(U256::from(5))),
        );
        // lhs runtime value 17 (so 17+5=22 ≠ 10), rhs 10, comparison false.
        let waypoint = comparison_waypoint(
            0x14, // EQ
            U256::from(17),
            U256::from(10),
            Some(lhs_expr),
            Some(SymbolicExpression::Constant(U256::from(10))),
            false,
        );

        let bytes = smt_solver::solve_path_constraint_smt(std::slice::from_ref(&waypoint), true)
            .expect("linear constraint is SAT");
        assert_eq!(bytes.len(), 32, "solver returns a 32-byte word");
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
        let value = U256::from_be_bytes(arr);
        assert_eq!(value, U256::from(5), "x + 5 == 10 ⇒ x = 5");
    }

    /// `x ^ 0xff == 0x0f` (currently false; flip to true) → solve x = 0xf0.
    #[test]
    fn test_smt_solves_bv_xor() {
        let lhs_expr = SymbolicExpression::Xor(
            Box::new(SymbolicExpression::Source(TaintSource::Calldata(0))),
            Box::new(SymbolicExpression::Constant(U256::from(0xff))),
        );
        // lhs runtime value 0x00 (so 0^0xff=0xff ≠ 0x0f), rhs 0x0f, false.
        let waypoint = comparison_waypoint(
            0x14, // EQ
            U256::ZERO,
            U256::from(0x0f),
            Some(lhs_expr),
            Some(SymbolicExpression::Constant(U256::from(0x0f))),
            false,
        );

        let bytes = smt_solver::solve_path_constraint_smt(std::slice::from_ref(&waypoint), true)
            .expect("xor constraint is SAT");
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
        let value = U256::from_be_bytes(arr);
        assert_eq!(value, U256::from(0xf0), "x ^ 0xff == 0x0f ⇒ x = 0xf0");
    }

    /// `x > 100` was taken with x=150 (condition=true); flip it → solve
    /// x ≤ 100. The SMT solver returns any value satisfying `!(x > 100)`,
    /// so we only assert the bound, not an exact value.
    #[test]
    fn test_smt_solves_branch_flip() {
        let waypoint = comparison_waypoint(
            0x11, // GT (unsigned)
            U256::from(150),
            U256::from(100),
            Some(SymbolicExpression::Source(TaintSource::Calldata(0))),
            Some(SymbolicExpression::Constant(U256::from(100))),
            true, // 150 > 100 held; flip target is !(x > 100) i.e. x <= 100
        );

        let bytes = smt_solver::solve_path_constraint_smt(std::slice::from_ref(&waypoint), true)
            .expect("flipped branch constraint is SAT");
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
        let value = U256::from_be_bytes(arr);
        assert!(
            value <= U256::from(100),
            "flipped branch must satisfy x <= 100, got {value}"
        );
    }

    /// Keccak-derived `MappingDerivation` waypoint has no boolean encoding
    /// in this integration → solver returns `None` (honest ceiling).
    #[test]
    fn test_smt_returns_none_for_keccak() {
        use revm::primitives::B256;
        let waypoint = Waypoint::MappingDerivation {
            base_slot: U256::from(0xdead_beef_u64),
            key: U256::from(0x42),
            derived_slot: B256::ZERO,
            key_expression: Some(SymbolicExpression::Source(TaintSource::Calldata(0))),
            base_slot_expression: None,
        };

        let result = smt_solver::solve_path_constraint_smt(std::slice::from_ref(&waypoint), true);
        assert!(
            result.is_none(),
            "keccak/mapping constraints are unsupported; solver must return None"
        );
    }

    /// End-to-end: `ConcolicSolver::solve_hint` with `smt` feature should
    /// route through the SMT path for an EQ comparison and return the
    /// SMT-derived word (x = 5 for `x + 5 == 10`).
    #[test]
    fn test_smt_wired_into_solve_hint() {
        let lhs_expr = SymbolicExpression::Add(
            Box::new(SymbolicExpression::Source(TaintSource::Calldata(4))),
            Box::new(SymbolicExpression::Constant(U256::from(5))),
        );
        let waypoint = Waypoint::Comparison {
            op: 0x14,
            lhs: U256::from(17),
            rhs: U256::from(10),
            pc: 77,
            calldata_offset: None,
            condition: false,
            hit: false,
            taint_source: Some(TaintSource::Calldata(4)),
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: Some(lhs_expr),
            rhs_expression: Some(SymbolicExpression::Constant(U256::from(10))),
            branch_distance: None,
        };

        let hint = ConcolicSolver::default()
            .solve_hint(0, &waypoint)
            .expect("hint produced via SMT path");
        assert_eq!(hint.calldata_offset, 4);
        assert_eq!(U256::from_be_bytes(hint.word), U256::from(5));
    }
}
