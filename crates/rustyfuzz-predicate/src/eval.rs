//! The tri-state evaluator (§5) and `requires_no_overflow` (§3 item 2).
//!
//! # The three outcomes, and the fourth
//!
//! A predicate yields `True`, `False`, or `Unknown`. Division by zero adds a fourth
//! state that is *not* the same as a clean pass:
//!
//! | outcome | meaning |
//! |---|---|
//! | `True` | the property holds, on authoritative evidence |
//! | `False` | the property is violated — a finding, subject to replay |
//! | `Unknown` | no evidence; never a finding, never a pass |
//! | `SatisfiedButDiv0` | would have passed, but a divisor was 0, so `a / b <= X` passed for the wrong reason |
//!
//! The last one exists because EVM `DIV` returns 0 and `0 <= X` holds: a predicate
//! like `a / b <= X` would otherwise report a clean pass when `b == 0`, which is the
//! evaluator actively hiding a chance that the contract is broken (owner ruling).

use crate::binding::Binding;
use crate::resolve::{KeyCoverage, Provenance, ReReadBudget, Resolved, Resolver, StateReader};
use crate::types::{ArithmeticCounters, Int256, Widened};
use crate::{BinOp, BlockField, Expr};
use std::collections::BTreeMap;

/// Outcome of evaluating a predicate at a point in a sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The property holds on authoritative evidence.
    True,
    /// The property is violated. This is the only outcome that may become a finding.
    False,
    /// Would have passed, but division or modulo by zero occurred. Not a pass.
    SatisfiedButDiv0,
    /// No usable evidence. Never a finding, never a pass (§5.1).
    Unknown(Reason),
}

impl Outcome {
    /// True only for `False`. Findings require a violation, not an absence.
    pub fn is_violation(&self) -> bool {
        matches!(self, Outcome::False)
    }

    /// True only for a clean `True`. `SatisfiedButDiv0` and `Unknown` are not passes.
    pub fn is_clean_pass(&self) -> bool {
        matches!(self, Outcome::True)
    }

    /// Whether the scheduler may treat this as a signal at all (§5.1).
    ///
    /// `Unknown` and `SatisfiedButDiv0` are both "no signal": neither promotes a
    /// finding nor rewards the input.
    pub fn is_signal(&self) -> bool {
        matches!(self, Outcome::True | Outcome::False)
    }

    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Outcome::Unknown(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Why an evaluation produced `Unknown`. Typed so the metric is diagnosable (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Unresolved(String),
    UnobservedKeys {
        observed: usize,
        total: usize,
    },
    ReReadBudgetExhausted,
    NoWriteAtCurrentIndex {
        tx_index: usize,
    },
    // A well-typed predicate cannot place a Bool where an Int belongs, but this is
    // kept as a defensive variant rather than an `unreachable!`: the evaluator must
    // not panic on any input (§5).
    SortMismatch {
        expected: &'static str,
        actual: &'static str,
    },
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::Unresolved(message) => f.write_str(message),
            Reason::UnobservedKeys { observed, total } => {
                write!(f, "{observed} of {total} mapping keys were observed")
            }
            Reason::ReReadBudgetExhausted => f.write_str("re-read budget exhausted"),
            Reason::NoWriteAtCurrentIndex { tx_index } => {
                write!(
                    f,
                    "no write at transaction {tx_index}, so old()/delta() is undefined"
                )
            }
            Reason::SortMismatch { expected, actual } => {
                write!(f, "expected {expected}, found {actual}")
            }
        }
    }
}

/// A value as the evaluator sees it: an integer, a boolean, or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(Int256),
    Bool(bool),
}

/// Result of evaluating a subexpression: a value with provenance, or an unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Eval {
    Known {
        value: Value,
        provenance: Provenance,
    },
    Unknown,
}

impl Eval {
    fn int(self) -> Option<(Int256, Provenance)> {
        match self {
            Eval::Known {
                value: Value::Int(v),
                provenance,
            } => Some((v, provenance)),
            _ => None,
        }
    }

    fn boolean(self) -> Option<(bool, Provenance)> {
        match self {
            Eval::Known {
                value: Value::Bool(b),
                provenance,
            } => Some((b, provenance)),
            _ => None,
        }
    }
}

/// Block environment as the sequence observed it. Read-only (§9 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    pub number: Int256,
    pub timestamp: Int256,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            number: Int256::ZERO,
            timestamp: Int256::ZERO,
        }
    }
}

/// Everything one evaluation needs.
pub struct EvalContext<'a> {
    pub bindings: &'a BTreeMap<String, Binding>,
    pub resolver: &'a Resolver<'a>,
    pub block: BlockContext,
    pub tx_index: usize,
}

/// Evaluates `expr` at `ctx.tx_index`.
///
/// Returns the outcome plus the counters arithmetic produced, so a caller can put
/// `division_by_zero_observed` into the finding text (§6.6).
pub fn evaluate(
    expr: &Expr,
    ctx: &EvalContext<'_>,
    reader: &mut dyn StateReader,
    mut budget: ReReadBudget,
) -> (Outcome, ArithmeticCounters, KeyCoverage) {
    let mut counters = ArithmeticCounters::default();
    let mut coverage = KeyCoverage::default();
    let eval = eval_expr(expr, ctx, reader, &mut budget, &mut counters, &mut coverage);

    // `requires_no_overflow` is False on wrap, and that reaches here as a plain
    // `Bool(false)`, which is a violation. Documented in §3 item 2.
    let outcome = match eval.boolean() {
        Some((true, _)) => {
            if counters.division_by_zero_observed > 0 {
                // A pass that depended on dividing by zero is not a pass.
                Outcome::SatisfiedButDiv0
            } else {
                Outcome::True
            }
        }
        Some((false, _)) => Outcome::False,
        None => {
            if coverage.unobserved_keys > 0 && coverage.observed_keys > 0 {
                Outcome::Unknown(Reason::UnobservedKeys {
                    observed: coverage.observed_keys,
                    total: coverage.total(),
                })
            } else if budget.remaining() == 0 {
                Outcome::Unknown(Reason::ReReadBudgetExhausted)
            } else {
                Outcome::Unknown(Reason::Unresolved(
                    "predicate could not be evaluated from the available evidence".to_string(),
                ))
            }
        }
    };

    (outcome, counters, coverage)
}

fn eval_expr(
    expr: &Expr,
    ctx: &EvalContext<'_>,
    reader: &mut dyn StateReader,
    budget: &mut ReReadBudget,
    counters: &mut ArithmeticCounters,
    coverage: &mut KeyCoverage,
) -> Eval {
    match expr {
        Expr::Int(lit) => Eval::Known {
            value: Value::Int(Int256(*lit.value_bytes())),
            provenance: Provenance::Write,
        },
        Expr::Bool(value) => Eval::Known {
            value: Value::Bool(*value),
            provenance: Provenance::Write,
        },
        Expr::BlockEnv(field) => {
            let value = match field {
                BlockField::Number => ctx.block.number,
                BlockField::Timestamp => ctx.block.timestamp,
            };
            Eval::Known {
                value: Value::Int(value),
                provenance: Provenance::Write,
            }
        }
        Expr::Symbol(symbol) => match ctx.resolver.resolve(symbol, reader, budget) {
            Ok(Resolved { value, provenance }) => Eval::Known {
                value: Value::Int(value),
                provenance,
            },
            Err(error) => {
                note_unresolved(&error, coverage);
                Eval::Unknown
            }
        },
        Expr::Old(symbol) => match ctx.resolver.resolve_old(symbol) {
            Ok(Resolved { value, provenance }) => Eval::Known {
                value: Value::Int(value),
                provenance,
            },
            Err(error) => {
                note_unresolved(&error, coverage);
                Eval::Unknown
            }
        },
        Expr::Delta(symbol) => {
            let before = ctx.resolver.resolve_old(symbol);
            let after = ctx.resolver.resolve(symbol, reader, budget);
            match (before, after) {
                (
                    Ok(Resolved { value: before, .. }),
                    Ok(Resolved {
                        value: after,
                        provenance,
                    }),
                ) => Eval::Known {
                    // Wrapping subtraction, matching EVM SUB (§3 item 1).
                    value: Value::Int(after.wrapping_sub(before)),
                    provenance,
                },
                (Err(error), _) | (_, Err(error)) => {
                    note_unresolved(&error, coverage);
                    Eval::Unknown
                }
            }
        }
        Expr::Sum(symbol) => match ctx.resolver.resolve_sum(symbol, reader, budget) {
            Ok((Resolved { value, provenance }, observed)) => {
                coverage.observed_keys += observed.observed_keys;
                Eval::Known {
                    value: Value::Int(value),
                    provenance,
                }
            }
            Err(error) => {
                note_unresolved(&error, coverage);
                Eval::Unknown
            }
        },
        Expr::Count(symbol) => match ctx.resolver.resolve_count(symbol, reader, budget) {
            Ok((Resolved { value, provenance }, observed)) => {
                coverage.observed_keys += observed.observed_keys;
                Eval::Known {
                    value: Value::Int(value),
                    provenance,
                }
            }
            Err(error) => {
                note_unresolved(&error, coverage);
                Eval::Unknown
            }
        },
        Expr::RequiresNoOverflow(inner) => {
            // Evaluates the operand twice: once wrapping (the value the contract
            // would compute) and once widened (whether it fit). The wrapping value is
            // what every other use of this operand sees; this operator is a check on
            // the arithmetic, never a replacement for it (§3 item 2).
            counters.overflow_checked_sites += 1;
            let widened = widen(inner, ctx, reader, budget, counters, coverage);
            match widened {
                Some(Widened::Fits(_value)) => Eval::Known {
                    value: Value::Bool(true),
                    provenance: Provenance::Write,
                },
                Some(Widened::Overflowed) => {
                    counters.overflow_violations += 1;
                    let _ = value_of(inner, ctx, reader, budget, counters, coverage);
                    Eval::Known {
                        value: Value::Bool(false),
                        provenance: Provenance::Write,
                    }
                }
                None => Eval::Unknown,
            }
        }
        Expr::Neg(inner) => match eval_expr(inner, ctx, reader, budget, counters, coverage).int() {
            Some((value, provenance)) => Eval::Known {
                value: Value::Int(Int256::ZERO.wrapping_sub(value)),
                provenance,
            },
            None => Eval::Unknown,
        },
        Expr::Not(inner) => {
            match eval_expr(inner, ctx, reader, budget, counters, coverage).boolean() {
                Some((value, provenance)) => Eval::Known {
                    value: Value::Bool(!value),
                    provenance,
                },
                None => Eval::Unknown,
            }
        }
        Expr::Binary(op, left, right) => {
            eval_binary(op, left, right, ctx, reader, budget, counters, coverage)
        }
    }
}

/// Evaluates a subexpression and returns its integer value, ignoring the outcome.
fn value_of(
    expr: &Expr,
    ctx: &EvalContext<'_>,
    reader: &mut dyn StateReader,
    budget: &mut ReReadBudget,
    counters: &mut ArithmeticCounters,
    coverage: &mut KeyCoverage,
) -> Option<Int256> {
    eval_expr(expr, ctx, reader, budget, counters, coverage)
        .int()
        .map(|(value, _)| value)
}

/// Evaluates an expression in widened arithmetic, for `requires_no_overflow`.
///
/// Only the operators the grammar allows in an `arith` position are meaningful here;
/// anything else yields `None`, which the caller turns into `Unknown`.
fn widen(
    expr: &Expr,
    ctx: &EvalContext<'_>,
    reader: &mut dyn StateReader,
    budget: &mut ReReadBudget,
    counters: &mut ArithmeticCounters,
    coverage: &mut KeyCoverage,
) -> Option<Widened> {
    match expr {
        Expr::Binary(op, left, right) if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) => {
            let a = widen(left, ctx, reader, budget, counters, coverage)?;
            let b = widen(right, ctx, reader, budget, counters, coverage)?;
            let (Widened::Fits(a), Widened::Fits(b)) = (a, b) else {
                return Some(Widened::Overflowed);
            };
            Some(match op {
                BinOp::Add => Widened::add(a, b),
                BinOp::Sub => Widened::sub(a, b),
                BinOp::Mul => Widened::mul(a, b),
                _ => unreachable!("guarded by the matches! above"),
            })
        }
        Expr::Neg(inner) => {
            let value = widen(inner, ctx, reader, budget, counters, coverage)?;
            match value {
                Widened::Fits(v) => {
                    if v.is_zero() {
                        Some(Widened::Fits(v))
                    } else {
                        // Negation of a non-zero value cannot fit in an unsigned word.
                        Some(Widened::Overflowed)
                    }
                }
                Widened::Overflowed => Some(Widened::Overflowed),
            }
        }
        // Leaves and everything else re-enter the ordinary evaluator; wrapping there
        // is exact for a leaf because a leaf cannot overflow.
        other => value_of(other, ctx, reader, budget, counters, coverage).map(Widened::Fits),
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_binary(
    op: &BinOp,
    left: &Expr,
    right: &Expr,
    ctx: &EvalContext<'_>,
    reader: &mut dyn StateReader,
    budget: &mut ReReadBudget,
    counters: &mut ArithmeticCounters,
    coverage: &mut KeyCoverage,
) -> Eval {
    // Short-circuit logical operators before evaluating the right side, so an
    // unevaluable right operand cannot poison a decidable left one.
    match op {
        BinOp::And | BinOp::Or => {
            let left_eval = eval_expr(left, ctx, reader, budget, counters, coverage);
            let Some((left_bool, _)) = left_eval.boolean() else {
                return Eval::Unknown;
            };
            match (op, left_bool) {
                // false && x is false regardless of x.
                (BinOp::And, false) => {
                    return Eval::Known {
                        value: Value::Bool(false),
                        provenance: Provenance::Write,
                    }
                }
                // true || x is true regardless of x.
                (BinOp::Or, true) => {
                    return Eval::Known {
                        value: Value::Bool(true),
                        provenance: Provenance::Write,
                    }
                }
                _ => {}
            }
            let right_eval = eval_expr(right, ctx, reader, budget, counters, coverage);
            let Some((right_bool, provenance)) = right_eval.boolean() else {
                return Eval::Unknown;
            };
            return Eval::Known {
                value: Value::Bool(right_bool),
                provenance,
            };
        }
        _ => {}
    }

    let left_eval = eval_expr(left, ctx, reader, budget, counters, coverage);
    let right_eval = eval_expr(right, ctx, reader, budget, counters, coverage);

    if op.is_comparison() {
        // Both sides must have resolved, or the comparison is undecidable. This check
        // comes first: reading `.int()` and `.boolean()` eagerly and then branching
        // silently dropped the int-vs-bool-literal case, which is the one real code
        // needs (`verify(...) == false`).
        let (
            Eval::Known {
                value: left_value,
                provenance: left_prov,
            },
            Eval::Known {
                value: right_value,
                provenance: right_prov,
            },
        ) = (left_eval, right_eval)
        else {
            return Eval::Unknown;
        };
        let provenance = weaker(left_prov, right_prov);
        let result = match (left_value, right_value) {
            (Value::Int(a), Value::Int(b)) => match op {
                BinOp::Eq => a == b,
                BinOp::NotEq => a != b,
                BinOp::Lt => a < b,
                BinOp::LtEq => a <= b,
                BinOp::Gt => a > b,
                BinOp::GtEq => a >= b,
                _ => return Eval::Unknown,
            },
            (Value::Bool(a), Value::Bool(b)) => match op {
                BinOp::Eq => a == b,
                BinOp::NotEq => a != b,
                _ => return Eval::Unknown,
            },
            // Int against a boolean literal: the ABI word a verifier returns is an
            // integer, so `verify(...) == false` must mean "the returned word is zero".
            // The type checker only permits this against a literal (§3), so there is
            // exactly one sensible reading and no silent coercion of two values.
            (Value::Int(word), Value::Bool(literal)) | (Value::Bool(literal), Value::Int(word)) => {
                let is_true = !word.is_zero();
                match op {
                    BinOp::Eq => is_true == literal,
                    BinOp::NotEq => is_true != literal,
                    _ => return Eval::Unknown,
                }
            }
        };
        return Eval::Known {
            value: Value::Bool(result),
            provenance,
        };
    }

    let (Some((a, pa)), Some((b, pb))) = (left_eval.int(), right_eval.int()) else {
        return Eval::Unknown;
    };
    let provenance = weaker(pa, pb);
    let value = match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Div => {
            if b.is_zero() {
                // EVM DIV returns 0 rather than trapping; count it so the pass this
                // may produce is degraded to SatisfiedButDiv0 (§3 item 3).
                counters.division_by_zero_observed += 1;
            }
            a.evm_div(b)
        }
        BinOp::Rem => {
            if b.is_zero() {
                counters.division_by_zero_observed += 1;
            }
            a.evm_rem(b)
        }
        _ => return Eval::Unknown,
    };
    Eval::Known {
        value: Value::Int(value),
        provenance,
    }
}

fn note_unresolved(error: &crate::resolve::Unresolved, coverage: &mut KeyCoverage) {
    if let crate::resolve::Unresolved::UnobservedKeys { observed, total } = error {
        coverage.unobserved_keys += total.saturating_sub(*observed);
    }
}

fn weaker(a: Provenance, b: Provenance) -> Provenance {
    let rank = |p: Provenance| match p {
        Provenance::Write => 0,
        Provenance::PreValue => 1,
        Provenance::ObservedRead => 2,
        Provenance::ReRead => 3,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// Renders the human-readable verdict, including the div0 marker when present (§6.6).
pub fn verdict_text(outcome: &Outcome, counters: &ArithmeticCounters) -> String {
    match outcome {
        Outcome::True => "satisfied".to_string(),
        Outcome::False => {
            if counters.overflow_violations > 0 {
                format!(
                    "violated (requires_no_overflow failed at {} site(s))",
                    counters.overflow_violations
                )
            } else {
                "violated".to_string()
            }
        }
        Outcome::SatisfiedButDiv0 => format!(
            "satisfied (div0 observed {} time(s))",
            counters.division_by_zero_observed
        ),
        Outcome::Unknown(reason) => format!("unknown ({reason})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BindingManifest;
    use crate::resolve::{NoReRead, ReadRecord, WriteRecord};
    use crate::types::compile;

    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }

    fn slot(value: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = value;
        s
    }

    fn word(value: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&value.to_be_bytes());
        w
    }

    const TWO_SLOTS: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "a": { "kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256 },
            "b": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 }
        }
    }"#;

    struct Fixture {
        bindings: BTreeMap<String, Binding>,
        writes: Vec<WriteRecord>,
        reads: Vec<ReadRecord>,
    }

    fn fixture() -> Fixture {
        Fixture {
            bindings: BindingManifest::from_json(TWO_SLOTS)
                .expect("parses")
                .resolve()
                .expect("resolves"),
            writes: Vec::new(),
            reads: Vec::new(),
        }
    }

    fn run(fixture: &Fixture, source: &str) -> (Outcome, ArithmeticCounters) {
        let checked = compile(source).unwrap_or_else(|e| panic!("compile {source}: {e}"));
        let resolver = Resolver::new(&fixture.bindings, &fixture.writes, &fixture.reads, 1);
        let ctx = EvalContext {
            bindings: &fixture.bindings,
            resolver: &resolver,
            block: BlockContext::default(),
            tx_index: 1,
        };
        let mut reader = NoReRead;
        let (outcome, counters, _coverage) =
            evaluate(checked.expr(), &ctx, &mut reader, ReReadBudget::new(8));
        (outcome, counters)
    }

    fn with_values(a: u64, b: u64) -> Fixture {
        let mut f = fixture();
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(1),
            old_value: word(0),
            new_value: word(a),
        });
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(2),
            old_value: word(0),
            new_value: word(b),
        });
        f
    }

    // ---- the four outcomes --------------------------------------------

    #[test]
    fn a_true_predicate_is_a_clean_pass() {
        let f = with_values(5, 5);
        let (outcome, counters) = run(&f, "a == b");
        assert_eq!(outcome, Outcome::True);
        assert!(outcome.is_clean_pass());
        assert!(outcome.is_signal());
        assert!(!outcome.is_violation());
        assert!(counters.is_default());
    }

    #[test]
    fn a_false_predicate_is_a_violation() {
        let f = with_values(5, 6);
        let (outcome, _) = run(&f, "a == b");
        assert_eq!(outcome, Outcome::False);
        assert!(outcome.is_violation());
        assert!(!outcome.is_clean_pass());
    }

    #[test]
    fn an_unevaluable_predicate_is_unknown_and_not_a_signal() {
        // No writes, no reads, no reader: nothing can be resolved.
        let f = fixture();
        let (outcome, _) = run(&f, "a == b");
        assert!(matches!(outcome, Outcome::Unknown(_)), "got {outcome:?}");
        assert!(!outcome.is_violation(), "Unknown must never be a finding");
        assert!(!outcome.is_clean_pass(), "Unknown must never be a pass");
        assert!(!outcome.is_signal(), "Unknown is no signal");
    }

    // ---- §3 item 3: div0 degrades a pass ------------------------------

    #[test]
    fn division_by_zero_degrades_a_pass_and_is_counted() {
        // `a / b <= 10` with b == 0: EVM DIV gives 0, and 0 <= 10 holds. A clean pass
        // here would hide the chance that the contract is broken.
        let f = with_values(100, 0);
        let (outcome, counters) = run(&f, "a / b <= 10");
        assert_eq!(counters.division_by_zero_observed, 1);
        assert_eq!(outcome, Outcome::SatisfiedButDiv0);
        assert!(!outcome.is_clean_pass(), "div0 must not be a clean pass");
        assert!(
            !outcome.is_signal(),
            "div0-degraded satisfaction is no signal"
        );
    }

    #[test]
    fn modulo_by_zero_is_counted_the_same_way() {
        let f = with_values(100, 0);
        let (outcome, counters) = run(&f, "a % b <= 10");
        assert_eq!(counters.division_by_zero_observed, 1);
        assert_eq!(outcome, Outcome::SatisfiedButDiv0);
    }

    #[test]
    fn a_div0_violation_still_stands_as_a_violation() {
        // Arithmetic degeneracy does not erase a violation (§3 item 3).
        let f = with_values(100, 0);
        let (outcome, counters) = run(&f, "a / b > 10");
        assert_eq!(counters.division_by_zero_observed, 1);
        assert_eq!(outcome, Outcome::False);
        assert!(outcome.is_violation());
    }

    #[test]
    fn the_div0_marker_appears_in_the_verdict_text() {
        let f = with_values(100, 0);
        let (outcome, counters) = run(&f, "a / b <= 10");
        let text = verdict_text(&outcome, &counters);
        assert!(
            text.contains("div0"),
            "verdict text must name the marker: {text}"
        );
    }

    // ---- §3 item 2: requires_no_overflow ------------------------------

    #[test]
    fn requires_no_overflow_passes_when_the_sum_fits() {
        let f = with_values(10, 20);
        let (outcome, counters) = run(&f, "requires_no_overflow(a + b)");
        assert_eq!(outcome, Outcome::True);
        assert_eq!(counters.overflow_checked_sites, 1);
        assert_eq!(counters.overflow_violations, 0);
    }

    #[test]
    fn requires_no_overflow_fails_when_the_sum_wraps() {
        // a and b are both max, so a + b wraps to max - 1.
        let mut f = fixture();
        for (index, s) in [1u8, 2u8].iter().enumerate() {
            f.writes.push(WriteRecord {
                tx_index: 0,
                address: addr(0xaa),
                slot: slot(*s),
                old_value: word(0),
                new_value: [0xffu8; 32],
            });
            let _ = index;
        }
        let (outcome, counters) = run(&f, "requires_no_overflow(a + b)");
        assert_eq!(
            outcome,
            Outcome::False,
            "a wrap is a violation, not an error"
        );
        assert_eq!(counters.overflow_checked_sites, 1);
        assert_eq!(counters.overflow_violations, 1);
    }

    #[test]
    fn requires_no_overflow_does_not_change_the_value_used_elsewhere() {
        // The operand still evaluates wrapping for every other use, so
        // `requires_no_overflow(a + b) || (a + b == 0)` can be true when the sum wraps
        // to zero.
        let mut f = fixture();
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(1),
            old_value: word(0),
            new_value: {
                let mut w = [0u8; 32];
                w[0] = 0xff;
                w
            },
        });
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(2),
            old_value: word(0),
            new_value: {
                let mut w = [0u8; 32];
                w[0] = 0x01;
                w
            },
        });
        // a = 0xff00..0, b = 0x0100..0 -> sum wraps to 0.
        let (outcome, _) = run(&f, "a + b == 0");
        assert_eq!(
            outcome,
            Outcome::True,
            "wrapping value is what the contract computes"
        );
    }

    // ---- wrapping arithmetic through the evaluator -------------------

    #[test]
    fn subtraction_wraps_rather_than_failing() {
        let f = with_values(0, 1);
        // 0 - 1 == 2^256 - 1, which is > 1000.
        let (outcome, _) = run(&f, "a - b > 1000");
        assert_eq!(outcome, Outcome::True);
    }

    // ---- short-circuit logic -----------------------------------------

    #[test]
    fn logical_and_short_circuits_on_false() {
        // The right side is unevaluable (no binding), but `false && x` is false.
        let f = with_values(1, 2);
        let (outcome, _) = run(&f, "a == 2 && missing == 0");
        assert_eq!(
            outcome,
            Outcome::False,
            "short-circuit must not be poisoned"
        );
    }

    #[test]
    fn logical_or_short_circuits_on_true() {
        let f = with_values(1, 2);
        let (outcome, _) = run(&f, "a == 1 || missing == 0");
        assert_eq!(outcome, Outcome::True);
    }

    #[test]
    fn an_unevaluable_left_operand_poisons_the_conjunction() {
        let f = with_values(1, 2);
        let (outcome, _) = run(&f, "missing == 0 && a == 1");
        assert!(matches!(outcome, Outcome::Unknown(_)));
    }

    // ---- block environment -------------------------------------------

    #[test]
    fn block_timestamp_is_readable() {
        let f = with_values(1, 2);
        let checked = compile("block.timestamp > 0").expect("compiles");
        let resolver = Resolver::new(&f.bindings, &f.writes, &f.reads, 1);
        let ctx = EvalContext {
            bindings: &f.bindings,
            resolver: &resolver,
            block: BlockContext {
                number: Int256::from_u64(100),
                timestamp: Int256::from_u64(1_700_000_000),
            },
            tx_index: 1,
        };
        let mut reader = NoReRead;
        let (outcome, _, _) = evaluate(checked.expr(), &ctx, &mut reader, ReReadBudget::new(4));
        assert_eq!(outcome, Outcome::True);
    }

    // ---- old() / delta() ---------------------------------------------

    #[test]
    fn delta_requires_a_write_at_the_current_transaction() {
        let f = with_values(100, 200);
        // Both writes are at tx 0; evaluated at tx 1, delta() is undefined.
        let (outcome, _) = run(&f, "delta(a) == 0");
        assert!(matches!(outcome, Outcome::Unknown(_)), "got {outcome:?}");
    }

    #[test]
    fn delta_is_the_difference_across_one_transaction() {
        // a: 5 -> 9 in tx 0, so delta(a) == 4 when evaluated at tx 0.
        let mut f = fixture();
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(1),
            old_value: word(5),
            new_value: word(9),
        });
        f.writes.push(WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot(2),
            old_value: word(0),
            new_value: word(0),
        });

        let checked = compile("delta(a) == 4").expect("compiles");
        let resolver = Resolver::new(&f.bindings, &f.writes, &f.reads, 0);
        let ctx = EvalContext {
            bindings: &f.bindings,
            resolver: &resolver,
            block: BlockContext::default(),
            tx_index: 0,
        };
        let mut reader = NoReRead;
        let (outcome, _, _) = evaluate(checked.expr(), &ctx, &mut reader, ReReadBudget::new(4));
        assert_eq!(outcome, Outcome::True, "delta(a) must be 9 - 5");
    }

    // ---- §5: no path panics ------------------------------------------

    #[test]
    fn evaluating_a_bound_but_never_touched_slot_is_unknown_not_a_panic() {
        let f = fixture();
        let (outcome, _) = run(&f, "a > 0");
        assert!(matches!(outcome, Outcome::Unknown(_)));
    }
}
