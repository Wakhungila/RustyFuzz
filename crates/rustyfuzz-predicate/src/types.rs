//! Type checking (§3) and 256-bit wrapping arithmetic (§3 items 1-3).
//!
//! Two responsibilities, deliberately in one module because they share a rule: the
//! predicate models what the contract does, not ideal mathematics. A type error is
//! reported before evaluation; an arithmetic edge case is reported *through* the
//! evaluation, because `a / 0` is legal EVM and must not be a type error.
//!
//! # The three sorts
//!
//! `Int`, `Bool`, `Slot`. Only `Int` and `Bool` are first-class in expressions;
//! `Slot` exists to name a storage location and never appears in arithmetic.

use crate::expr::{BinOp, BlockField, Expr, Symbol};
use std::fmt;

/// The sort of an expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Int,
    Bool,
}

impl fmt::Display for Sort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Sort::Int => "int",
            Sort::Bool => "bool",
        })
    }
}

/// Type errors. All are detected before any evaluation happens (§5 items 7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeError {
    #[error("predicate must evaluate to bool, but it evaluates to {actual}")]
    NotBoolean { actual: Sort },
    #[error("operator `{op}` cannot take {left} and {right}")]
    OperandMismatch {
        op: &'static str,
        left: Sort,
        right: Sort,
    },
    #[error("operator `{op}` expects {expected}, found {actual}")]
    UnaryMismatch {
        op: &'static str,
        expected: Sort,
        actual: Sort,
    },
}

/// Checks that `expr` is a well-formed boolean predicate and returns its sort.
///
/// Returns `Ok(Sort::Bool)` only when the whole expression is a predicate.
pub fn check(expr: &Expr) -> Result<Sort, TypeError> {
    let sort = sort_of(expr)?;
    if sort != Sort::Bool {
        return Err(TypeError::NotBoolean { actual: sort });
    }
    Ok(sort)
}

/// Infers the sort of an expression, rejecting ill-typed operators.
pub fn sort_of(expr: &Expr) -> Result<Sort, TypeError> {
    Ok(match expr {
        Expr::Int(_) => Sort::Int,
        Expr::Bool(_) => Sort::Bool,
        // A bare symbol is an integer-valued read; the binder resolves it later.
        Expr::Symbol(_) => Sort::Int,
        Expr::Old(_) | Expr::Delta(_) => Sort::Int,
        Expr::Sum(_) | Expr::Count(_) => Sort::Int,
        Expr::BlockEnv(BlockField::Number | BlockField::Timestamp) => Sort::Int,
        Expr::RequiresNoOverflow(inner) => {
            let inner_sort = sort_of(inner)?;
            if inner_sort != Sort::Int {
                return Err(TypeError::UnaryMismatch {
                    op: "requires_no_overflow",
                    expected: Sort::Int,
                    actual: inner_sort,
                });
            }
            Sort::Bool
        }
        Expr::Neg(inner) => {
            let inner_sort = sort_of(inner)?;
            if inner_sort != Sort::Int {
                return Err(TypeError::UnaryMismatch {
                    op: "-",
                    expected: Sort::Int,
                    actual: inner_sort,
                });
            }
            Sort::Int
        }
        Expr::Not(inner) => {
            let inner_sort = sort_of(inner)?;
            if inner_sort != Sort::Bool {
                return Err(TypeError::UnaryMismatch {
                    op: "!",
                    expected: Sort::Bool,
                    actual: inner_sort,
                });
            }
            Sort::Bool
        }
        Expr::Binary(op, left, right) => {
            let left_sort = sort_of(left)?;
            let right_sort = sort_of(right)?;
            if left_sort != right_sort && compares_against_bool_literal(*op, left, right) {
                // Int-vs-boolean-literal comparison, e.g. `verify(...) == false`.
                Sort::Bool
            } else {
                classify_binary(*op, left_sort, right_sort)?
            }
        }
    })
}

/// True when one side is a literal `true`/`false` and the other is not a boolean.
///
/// Motivated by real code: a proof verifier's answer arrives as an ABI word, so the
/// natural way to write "this forgery does not verify" is `verify(...) == false`. At the
/// ABI level that word is an integer, so requiring a separate boolean sort would make
/// the most common property in this domain inexpressible.
///
/// The allowance is deliberately narrow: it applies **only** to `==` and `!=`, and
/// **only** when one side is a boolean *literal*. Two non-literal values of different
/// sorts remain a type error, so `flag == count` is still rejected and the rule that a
/// boolean value cannot be silently coerced to an integer still holds.
fn compares_against_bool_literal(op: BinOp, left: &Expr, right: &Expr) -> bool {
    if !matches!(op, BinOp::Eq | BinOp::NotEq) {
        return false;
    }
    match (left, right) {
        (Expr::Bool(_), other) | (other, Expr::Bool(_)) => {
            // A boolean literal against a symbol whose value is an ABI word is the case
            // real code needs: `verify(...) == false`. A boolean literal against an
            // integer *literal* is not: `1 == true` has no defensible reading, so it
            // stays a type error.
            !matches!(other, Expr::Bool(_) | Expr::Int(_))
        }
        _ => false,
    }
}

fn classify_binary(op: BinOp, left: Sort, right: Sort) -> Result<Sort, TypeError> {
    let mismatch = || TypeError::OperandMismatch {
        op: op.as_str(),
        left,
        right,
    };
    if op.is_comparison() {
        // Comparisons need both sides to agree. `1 == true` is a category error,
        // not a coercion opportunity.
        return if left == right {
            Ok(Sort::Bool)
        } else {
            Err(mismatch())
        };
    }
    if op.is_logical() {
        return if left == Sort::Bool && right == Sort::Bool {
            Ok(Sort::Bool)
        } else {
            Err(mismatch())
        };
    }
    // Arithmetic.
    if left == Sort::Int && right == Sort::Int {
        Ok(Sort::Int)
    } else {
        Err(mismatch())
    }
}

/// A 256-bit unsigned value, used both for literals and for evaluated results.
///
/// Kept as bytes rather than a wider integer so the wrapping behaviour is explicit
/// in the code that implements it, instead of an emergent property of a big-int
/// library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Int256(pub [u8; 32]);

impl Int256 {
    pub const ZERO: Int256 = Int256([0u8; 32]);
    pub const ONE: Int256 = {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Int256(bytes)
    };
    /// 2^256 - 1.
    pub const MAX: Int256 = Int256([0xffu8; 32]);

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Int256(bytes)
    }

    pub fn is_zero(self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrapping addition, matching EVM `ADD`.
    pub fn wrapping_add(self, other: Self) -> Self {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let acc = u16::from(self.0[i]) + u16::from(other.0[i]) + carry;
            out[i] = (acc & 0xFF) as u8;
            carry = acc >> 8;
        }
        Int256(out)
    }

    /// Wrapping subtraction, matching EVM `SUB`.
    ///
    /// There is no underflow error: `0 - 1 == 2^256 - 1` (§3 item 1).
    pub fn wrapping_sub(self, other: Self) -> Self {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let acc = i16::from(self.0[i]) - i16::from(other.0[i]) - borrow;
            if acc < 0 {
                out[i] = (acc + 256) as u8;
                borrow = 1;
            } else {
                out[i] = acc as u8;
                borrow = 0;
            }
        }
        Int256(out)
    }

    /// Wrapping multiplication, matching EVM `MUL`.
    ///
    /// Shift-and-add over the bits of `other`, keeping only the low 256 bits. This
    /// is O(256) worst case per call and has no index arithmetic that can underflow,
    /// which an earlier limb-based version did.
    pub fn wrapping_mul(self, other: Self) -> Self {
        let mut result = Int256::ZERO;
        // Iterate `other` from its least-significant bit upward.
        for byte_index in (0..32).rev() {
            let byte = other.0[byte_index];
            if byte == 0 {
                continue;
            }
            for bit in 0..8u32 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                // Weight of this bit position, counted from the least-significant end.
                let shift = bit + ((31 - byte_index) as u32) * 8;
                result = result.wrapping_add(self.shl(shift));
            }
        }
        result
    }

    /// Shifts left by `bits`, discarding anything that leaves the 256-bit range.
    ///
    /// Bytes are big-endian, so index 31 is least significant and a left shift moves
    /// each byte toward *higher* indices. The carry into byte `i` comes from the top
    /// bits of byte `i + 1`, which is the byte one place less significant.
    fn shl(self, bits: u32) -> Self {
        if bits >= 256 {
            return Int256::ZERO;
        }
        let byte_shift = (bits / 8) as usize;
        let bit_shift = bits % 8;
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let src = i + byte_shift;
            if src >= 32 {
                continue;
            }
            let mut value = u16::from(self.0[src]) << bit_shift;
            if bit_shift > 0 && src + 1 < 32 {
                value |= u16::from(self.0[src + 1]) >> (8 - bit_shift);
            }
            *slot = (value & 0xFF) as u8;
        }
        Int256(out)
    }

    /// EVM `DIV`: truncating, and `x / 0 == 0`.
    pub fn evm_div(self, other: Self) -> Self {
        if other.is_zero() {
            return Int256::ZERO;
        }
        let mut quotient = [0u8; 32];
        let mut remainder = Int256::ZERO;
        for (byte_index, source) in self.0.iter().enumerate() {
            for bit in (0..8).rev() {
                remainder = remainder.shl1();
                let incoming = (source >> bit) & 1;
                remainder.0[31] |= incoming;
                if remainder >= other {
                    remainder = remainder.wrapping_sub(other);
                    quotient[byte_index] |= 1 << bit;
                }
            }
        }
        Int256(quotient)
    }

    /// EVM `MOD`: `x % 0 == 0`.
    pub fn evm_rem(self, other: Self) -> Self {
        if other.is_zero() {
            return Int256::ZERO;
        }
        let mut remainder = Int256::ZERO;
        for i in 0..32 {
            for bit in (0..8).rev() {
                remainder = remainder.shl1();
                let incoming = (self.0[i] >> bit) & 1;
                remainder.0[31] |= incoming;
                if remainder >= other {
                    remainder = remainder.wrapping_sub(other);
                }
            }
        }
        remainder
    }

    /// Shifts left by one, discarding the top bit (wrapping).
    fn shl1(self) -> Self {
        let mut out = [0u8; 32];
        let mut carry = 0u8;
        for i in (0..32).rev() {
            out[i] = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 7;
        }
        Int256(out)
    }
}

impl fmt::Display for Int256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("0");
        }
        // Decimal rendering via repeated division. Only used for human-readable
        // evidence, never on a hot path.
        let mut digits = Vec::new();
        let mut current = *self;
        let ten = Int256::from_u64(10);
        while !current.is_zero() {
            let quotient = current.evm_div(ten);
            let remainder = current.wrapping_sub(quotient.wrapping_mul(ten)).0[31];
            digits.push(b'0' + remainder);
            current = quotient;
        }
        digits.reverse();
        f.write_str(&String::from_utf8_lossy(&digits))
    }
}

/// Counters that arithmetic produced while evaluating.
///
/// `division_by_zero_observed` is **not** merely diagnostic: a non-zero value
/// degrades a pass to `Satisfied(div0 observed)` (§3 item 3). The other counter is
/// carried so a reviewer can tell how much the verdict depends on
/// `requires_no_overflow` checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArithmeticCounters {
    pub division_by_zero_observed: u64,
    pub overflow_checked_sites: u64,
    pub overflow_violations: u64,
}

impl ArithmeticCounters {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Whether a value fits in 256 bits, for `requires_no_overflow`.
///
/// `Int256` cannot represent "wider than 256 bits", so the check is performed on a
/// widened intermediate during evaluation rather than on the wrapped result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Widened {
    Fits(Int256),
    Overflowed,
}

impl Widened {
    /// Widened addition: overflow only when the sum exceeds 2^256 - 1.
    pub fn add(a: Int256, b: Int256) -> Self {
        let sum = a.wrapping_add(b);
        if sum < a {
            Widened::Overflowed
        } else {
            Widened::Fits(sum)
        }
    }

    pub fn sub(a: Int256, b: Int256) -> Self {
        if b > a {
            Widened::Overflowed
        } else {
            Widened::Fits(a.wrapping_sub(b))
        }
    }

    pub fn mul(a: Int256, b: Int256) -> Self {
        let product = a.wrapping_mul(b);
        // Recover a factor and compare: if b != 0 then product / b must equal a.
        if a.is_zero() || b.is_zero() {
            return Widened::Fits(Int256::ZERO);
        }
        if product.evm_div(b) == a {
            Widened::Fits(product)
        } else {
            Widened::Overflowed
        }
    }
}

/// A type-and-arithmetic checked predicate, ready to bind and evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedPredicate {
    expr: Expr,
    /// Distinct symbols referenced, in first-appearance order, for binding.
    symbols: Vec<Symbol>,
}

impl CheckedPredicate {
    pub fn expr(&self) -> &Expr {
        &self.expr
    }

    /// Every distinct symbol the predicate references.
    ///
    /// The binder must resolve all of these before evaluation; a missing binding is
    /// `Error::UnboundSymbol` at load time, not a runtime surprise (§5 item 1).
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }
}

/// Parses *and* type-checks in one step.
pub fn compile(source: &str) -> Result<CheckedPredicate, CompileError> {
    let expr = crate::parse(source)?;
    check(&expr)?;
    let mut symbols = Vec::new();
    collect_symbols(&expr, &mut symbols);
    Ok(CheckedPredicate { expr, symbols })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error(transparent)]
    Parse(#[from] crate::ParseError),
    #[error(transparent)]
    Type(#[from] TypeError),
}

fn collect_symbols(expr: &Expr, out: &mut Vec<Symbol>) {
    let push = |symbol: &Symbol, out: &mut Vec<Symbol>| {
        if !out.contains(symbol) {
            out.push(symbol.clone());
        }
    };
    match expr {
        Expr::Symbol(s) | Expr::Old(s) | Expr::Delta(s) | Expr::Sum(s) | Expr::Count(s) => {
            push(s, out)
        }
        Expr::RequiresNoOverflow(inner) | Expr::Neg(inner) | Expr::Not(inner) => {
            collect_symbols(inner, out)
        }
        Expr::Binary(_, left, right) => {
            collect_symbols(left, out);
            collect_symbols(right, out);
        }
        Expr::Int(_) | Expr::Bool(_) | Expr::BlockEnv(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::compile;
    use super::*;

    fn int(hex: &str) -> Int256 {
        crate::parse(hex)
            .ok()
            .and_then(|e| match e {
                Expr::Int(lit) => Some(Int256(*lit.value_bytes())),
                _ => None,
            })
            .expect("literal must parse")
    }

    // ---- types (§3) ----------------------------------------------------

    #[test]
    fn accepts_bool_predicates_and_rejects_int_expressions() {
        assert!(compile("a == b").is_ok());
        assert!(compile("a && b").is_err(), "a and b are ints, not bools");
        // A bare integer is not a predicate.
        match compile("a") {
            Err(CompileError::Type(TypeError::NotBoolean { actual })) => {
                assert_eq!(actual, Sort::Int)
            }
            other => panic!("expected NotBoolean, got {other:?}"),
        }
    }

    #[test]
    fn comparison_requires_matching_sorts() {
        // `1 == true` is a category error, not a coercion.
        let error = compile("1 == true").unwrap_err();
        assert!(
            matches!(error, CompileError::Type(TypeError::OperandMismatch { .. })),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_symbol_may_be_compared_against_a_bool_literal_but_an_int_literal_may_not() {
        // Real code needs `verify(...) == false`, where the symbol's value is an ABI
        // word. The allowance must not spill over into `1 == true`, which has no
        // defensible reading.
        assert!(
            compile("verifierAnswer == false").is_ok(),
            "a symbol against a bool literal must be allowed"
        );
        assert!(
            compile("verifierAnswer != true").is_ok(),
            "!= must be allowed too"
        );
        assert!(
            compile("1 == true").is_err(),
            "an int literal against a bool literal must stay a type error"
        );
        // Ordering against a bool literal is never meaningful.
        assert!(compile("verifierAnswer < true").is_err());
    }

    #[test]
    fn logical_operators_require_booleans_on_both_sides() {
        assert!(compile("(a == b) && (c == d)").is_ok());
        let error = compile("(a == b) && c").unwrap_err();
        assert!(
            matches!(error, CompileError::Type(TypeError::OperandMismatch { .. })),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn arithmetic_rejects_booleans() {
        let error = compile("(a == b) + 1 > 2").unwrap_err();
        assert!(
            matches!(error, CompileError::Type(TypeError::OperandMismatch { .. })),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn requires_no_overflow_takes_an_int_and_yields_bool() {
        assert!(compile("requires_no_overflow(a + b)").is_ok());
        // A comparison operand is rejected by the *parser*, not the type checker,
        // because the grammar gives `requires_no_overflow` an `arith` operand
        // (§2). Non-boolean operands can therefore never reach this check.
        let error = compile("requires_no_overflow(a == b)").unwrap_err();
        assert!(
            matches!(error, CompileError::Parse(_)),
            "expected a parse error for a comparison operand, got {error:?}"
        );
    }

    #[test]
    fn unary_not_requires_a_boolean() {
        assert!(compile("!(a == b)").is_ok());
        let error = compile("!a").unwrap_err();
        assert!(
            matches!(
                error,
                CompileError::Type(TypeError::UnaryMismatch { op: "!", .. })
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn negation_requires_an_int() {
        assert!(compile("-a < 0").is_ok());
        let error = compile("-(a == b) < 0").unwrap_err();
        assert!(
            matches!(
                error,
                CompileError::Type(TypeError::UnaryMismatch { op: "-", .. })
            ),
            "unexpected error: {error}"
        );
    }

    // ---- symbol collection ----------------------------------------------

    #[test]
    fn collects_distinct_symbols_in_first_appearance_order() {
        let checked = compile("sum(balances) == totalSupply + totalSupply").expect("valid");
        let names: Vec<String> = checked.symbols().iter().map(|s| s.to_string()).collect();
        assert_eq!(names, vec!["balances", "totalSupply"]);
    }

    #[test]
    fn block_environment_is_not_a_symbol() {
        let checked = compile("block.timestamp > 0").expect("valid");
        assert!(checked.symbols().is_empty());
    }

    // ---- wrapping arithmetic (§3 item 1) --------------------------------

    #[test]
    fn addition_wraps_at_256_bits() {
        let max = Int256::MAX;
        assert_eq!(max.wrapping_add(Int256::ONE), Int256::ZERO);
        assert!(max.wrapping_add(Int256::ONE).is_zero());
    }

    #[test]
    fn subtraction_has_no_underflow_error() {
        // §3 item 1: 0 - 1 == 2^256 - 1, matching EVM SUB.
        assert_eq!(Int256::ZERO.wrapping_sub(Int256::ONE), Int256::MAX);
    }

    #[test]
    fn multiplication_is_exact_when_it_fits() {
        let a = Int256::from_u64(1_000_000);
        let b = Int256::from_u64(1_000);
        assert_eq!(a.wrapping_mul(b), Int256::from_u64(1_000_000_000));
    }

    #[test]
    fn multiplication_wraps_at_256_bits() {
        // (2^256 - 1) * 2 == 2^256 - 2, because the top bit falls off.
        let double = Int256::MAX.wrapping_mul(Int256::from_u64(2));
        assert_eq!(double, Int256::MAX.wrapping_sub(Int256::ONE));
    }

    #[test]
    fn division_truncates_and_zero_divisor_yields_zero() {
        // §3 item 3: x / 0 == 0, EVM DIV.
        assert_eq!(
            Int256::from_u64(7).evm_div(Int256::from_u64(2)),
            Int256::from_u64(3)
        );
        assert_eq!(Int256::from_u64(7).evm_div(Int256::ZERO), Int256::ZERO);
        assert_eq!(Int256::ZERO.evm_div(Int256::ZERO), Int256::ZERO);
    }

    #[test]
    fn modulo_zero_divisor_yields_zero() {
        assert_eq!(
            Int256::from_u64(7).evm_rem(Int256::from_u64(3)),
            Int256::from_u64(1)
        );
        assert_eq!(Int256::from_u64(7).evm_rem(Int256::ZERO), Int256::ZERO);
    }

    #[test]
    fn wide_values_survive_division() {
        let big = int("0x100000000000000000000000000000000");
        let divisor = int("0x10000000000000000000000000000000");
        assert_eq!(big.evm_div(divisor), Int256::from_u64(16));
    }

    // ---- widened arithmetic for requires_no_overflow -------------------

    #[test]
    fn widened_add_detects_overflow() {
        assert_eq!(Widened::add(Int256::MAX, Int256::ONE), Widened::Overflowed);
        assert_eq!(
            Widened::add(Int256::ONE, Int256::ONE),
            Widened::Fits(Int256::from_u64(2))
        );
    }

    #[test]
    fn widened_sub_detects_underflow() {
        assert_eq!(Widened::sub(Int256::ZERO, Int256::ONE), Widened::Overflowed);
    }

    #[test]
    fn widened_mul_detects_overflow() {
        assert_eq!(
            Widened::mul(Int256::MAX, Int256::from_u64(2)),
            Widened::Overflowed
        );
        assert_eq!(
            Widened::mul(Int256::ZERO, Int256::MAX),
            Widened::Fits(Int256::ZERO)
        );
    }

    // ---- display ------------------------------------------------------

    #[test]
    fn int256_displays_as_decimal() {
        assert_eq!(Int256::ZERO.to_string(), "0");
        assert_eq!(Int256::from_u64(255).to_string(), "255");
        assert_eq!(Int256::MAX.to_string(), {
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                .to_string()
        });
    }
}
