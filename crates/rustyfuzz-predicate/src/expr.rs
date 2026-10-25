//! The predicate AST, its symbols and its parse errors.
//!
//! Split from the parser so type checking and evaluation depend on the shape of
//! the language without depending on how it is read.

use crate::{MAX_NESTING_DEPTH, MAX_PREDICATE_BYTES};
use std::fmt;

/// A parsed, typed predicate expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Integer literal, 256-bit.
    Int(U256Lit),
    /// Boolean literal.
    Bool(bool),
    /// `symbol` or `symbol.symbol`.
    Symbol(Symbol),
    /// `old(sym)` — the value before the current transaction.
    Old(Symbol),
    /// `delta(sym)` — `new - old` for the current transaction.
    Delta(Symbol),
    /// `sum(sym)` — sum over a mapping's key set.
    Sum(Symbol),
    /// `count(sym)` — cardinality of a mapping's key set.
    Count(Symbol),
    /// `block.number` or `block.timestamp`, read-only.
    BlockEnv(BlockField),
    /// `requires_no_overflow(expr)`.
    RequiresNoOverflow(Box<Expr>),
    /// Unary negation, which wraps (§3 item 1).
    Neg(Box<Expr>),
    /// Logical negation.
    Not(Box<Expr>),
    /// Binary arithmetic or comparison.
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    And,
    Or,
}

impl BinOp {
    /// True for operators that yield `Bool` from two `Int` operands.
    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            BinOp::Eq | BinOp::NotEq | BinOp::Lt | BinOp::LtEq | BinOp::Gt | BinOp::GtEq
        )
    }

    /// True for operators that yield `Bool` from two `Bool` operands.
    pub fn is_logical(self) -> bool {
        matches!(self, BinOp::And | BinOp::Or)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Rem => "%",
            BinOp::Eq => "==",
            BinOp::NotEq => "!=",
            BinOp::Lt => "<",
            BinOp::LtEq => "<=",
            BinOp::Gt => ">",
            BinOp::GtEq => ">=",
            BinOp::And => "&&",
            BinOp::Or => "||",
        }
    }
}

/// Block environment field, readable but never settable (§9 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockField {
    Number,
    Timestamp,
}

/// A dotted symbol such as `totalSupply` or `balances.alice`.
///
/// Kept as owned segments rather than a joined string so the binder can match on
/// structure instead of re-splitting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(pub Vec<String>);

impl Symbol {
    pub fn root(&self) -> &str {
        self.0.first().map(String::as_str).unwrap_or("")
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// 256-bit unsigned literal, kept as the raw hex/decimal text plus its value.
///
/// The text is retained so error messages and finding evidence quote what the
/// author actually wrote rather than a normalised form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U256Lit {
    pub(crate) text: String,
    pub(crate) value: [u8; 32],
}

impl U256Lit {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn value_bytes(&self) -> &[u8; 32] {
        &self.value
    }
}

/// Errors from lexing or parsing. Every variant carries a byte offset so a caller
/// can point at the offending character (§5 items 10 and 7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("predicate exceeds {MAX_PREDICATE_BYTES} bytes ({0} bytes)")]
    TooLong(usize),
    #[error("expression nests deeper than {MAX_NESTING_DEPTH} levels")]
    TooDeep,
    #[error("unexpected end of input at byte {0}")]
    UnexpectedEnd(usize),
    #[error("unexpected character {ch:?} at byte {offset}")]
    UnexpectedChar { ch: char, offset: usize },
    #[error("expected {expected} at byte {offset}")]
    Expected {
        expected: &'static str,
        offset: usize,
    },
    #[error("integer literal at byte {offset} exceeds 256 bits")]
    IntegerOverflow { offset: usize },
    #[error("empty predicate")]
    Empty,
}
