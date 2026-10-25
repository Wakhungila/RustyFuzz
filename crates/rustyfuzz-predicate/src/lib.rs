//! Bounded predicate IR for RustyFuzz invariants.
//!
//! Implements §2 (expression grammar) and §3 (types) of
//! `docs/design/PREDICATE_IR.md`. This module is the **syntax** layer only:
//! parsing into a typed AST. Evaluation, slot binding and the oracle trait are
//! separate components (see §8 of the design).
//!
//! # Why hand-written
//!
//! The grammar is deliberately tiny (see §1 non-goals: no loops, no recursion, no
//! user-defined functions). A generated parser would add a build-time dependency
//! and a code generator for roughly 300 lines of recursive descent, and would make
//! the "no unbounded constructs" property harder to audit than easier.
//!
//! # The bound that matters
//!
//! Parsing is the one place where an untrusted string enters the system — a
//! predicate may come from a manifest or from an LLM proposal. Every recursive
//! production therefore carries an explicit depth budget, and input length is
//! capped before tokenisation. Exceeding either is a typed error, never a panic
//! and never unbounded work.

pub mod binding;
pub mod expr;
pub mod types;

pub use binding::{
    extract_bits, mapping_slot, Binding, BindingError, BindingKind, BindingManifest,
};
pub use expr::{BinOp, BlockField, Expr, ParseError, Symbol, U256Lit};
pub use types::{
    compile, ArithmeticCounters, CheckedPredicate, CompileError, Int256, Sort, TypeError, Widened,
};

/// Maximum accepted predicate length in bytes.
///
/// A predicate that needs more than this is not a predicate, it is a program, and
/// §1 of the design forbids those.
pub const MAX_PREDICATE_BYTES: usize = 8 * 1024;

/// Maximum expression nesting depth.
///
/// 64 is far more than any real invariant needs (`sum a == b` nests twice) and far
/// less than what would let a hostile input exhaust the stack.
pub const MAX_NESTING_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Int { text: String, value: [u8; 32] },
    Ident(String),
    True,
    False,
    LParen,
    RParen,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    AndAnd,
    OrOr,
    Bang,
    Dot,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpannedToken {
    token: Token,
    offset: usize,
}

/// Parses a predicate string into a typed AST.
///
/// Does not type-check: that is [`crate::types`], kept separate so a syntax error
/// and a type error stay distinguishable in reports.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    if input.len() > MAX_PREDICATE_BYTES {
        return Err(ParseError::TooLong(input.len()));
    }
    let tokens = lex(input)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let expr = parser.parse_or()?;
    if matches!(parser.peek(), Token::Eof) {
        Ok(expr)
    } else {
        Err(ParseError::Expected {
            expected: "end of input",
            offset: parser.offset(),
        })
    }
}

fn lex(input: &str) -> Result<Vec<SpannedToken>, ParseError> {
    let bytes: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        let offset = i;
        let two = if i + 1 < bytes.len() {
            Some((bytes[i], bytes[i + 1]))
        } else {
            None
        };
        // Two-character operators first so `==` never lexes as two `=`.
        if let Some(token) = match two {
            Some(('=', '=')) => Some(Token::EqEq),
            Some(('!', '=')) => Some(Token::NotEq),
            Some(('<', '=')) => Some(Token::LtEq),
            Some(('>', '=')) => Some(Token::GtEq),
            Some(('&', '&')) => Some(Token::AndAnd),
            Some(('|', '|')) => Some(Token::OrOr),
            _ => None,
        } {
            tokens.push(SpannedToken { token, offset });
            i += 2;
            continue;
        }
        if ch.is_ascii_digit() {
            let start = i;
            if ch == '0' && i + 1 < bytes.len() && (bytes[i + 1] == 'x' || bytes[i + 1] == 'X') {
                i += 2;
                let digits_start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if i == digits_start {
                    return Err(ParseError::UnexpectedChar { ch: 'x', offset });
                }
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let text: String = bytes[start..i].iter().collect();
            let value = parse_int_literal(&text, offset)?;
            tokens.push(SpannedToken {
                token: Token::Int { text, value },
                offset,
            });
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '_') {
                i += 1;
            }
            let word: String = bytes[start..i].iter().collect();
            let token = match word.as_str() {
                "true" => Token::True,
                "false" => Token::False,
                _ => Token::Ident(word),
            };
            tokens.push(SpannedToken { token, offset });
            continue;
        }
        let token = match ch {
            '(' => Token::LParen,
            ')' => Token::RParen,
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '/' => Token::Slash,
            '%' => Token::Percent,
            '<' => Token::Lt,
            '>' => Token::Gt,
            '!' => Token::Bang,
            '.' => Token::Dot,
            other => return Err(ParseError::UnexpectedChar { ch: other, offset }),
        };
        tokens.push(SpannedToken { token, offset });
        i += 1;
    }
    tokens.push(SpannedToken {
        token: Token::Eof,
        offset: input.len(),
    });
    if tokens.len() == 1 {
        return Err(ParseError::Empty);
    }
    Ok(tokens)
}

/// Parses a decimal or `0x` hex literal into 32 big-endian bytes.
///
/// Overflow is reported as a typed error rather than wrapping: a literal that does
/// not fit in 256 bits is an authoring mistake, and silently truncating it would
/// change what the predicate means.
fn parse_int_literal(text: &str, offset: usize) -> Result<[u8; 32], ParseError> {
    let mut value = [0u8; 32];
    let (digits, radix) =
        if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (rest, 16u32)
        } else {
            (text, 10u32)
        };
    for ch in digits.chars() {
        let digit = ch
            .to_digit(radix)
            .ok_or(ParseError::UnexpectedChar { ch, offset })? as u16;
        let mut carry = digit;
        for byte in value.iter_mut().rev() {
            let acc = u16::from(*byte) * radix as u16 + carry;
            *byte = (acc & 0xFF) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(ParseError::IntegerOverflow { offset });
        }
    }
    Ok(value)
}

struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        self.tokens
            .get(self.pos)
            .map(|t| &t.token)
            .unwrap_or(&Token::Eof)
    }

    fn offset(&self) -> usize {
        self.tokens
            .get(self.pos)
            .map(|t| t.offset)
            .unwrap_or_else(|| self.tokens.last().map(|t| t.offset).unwrap_or(0))
    }

    fn advance(&mut self) -> Token {
        let token = self
            .tokens
            .get(self.pos)
            .map(|t| t.token.clone())
            .unwrap_or(Token::Eof);
        self.pos += 1;
        token
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(ParseError::TooDeep);
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // or_expr := and_expr ("||" and_expr)*
    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::OrOr) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        self.leave();
        Ok(left)
    }

    // and_expr := not_expr ("&&" not_expr)*
    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Token::AndAnd) {
            self.advance();
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // not_expr := "!" not_expr | comparison
    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Token::Bang) {
            self.enter()?;
            self.advance();
            let inner = self.parse_not()?;
            self.leave();
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_comparison()
    }

    // comparison := arith (cmp_op arith)?
    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_arith()?;
        let op = match self.peek() {
            Token::EqEq => Some(BinOp::Eq),
            Token::NotEq => Some(BinOp::NotEq),
            Token::Lt => Some(BinOp::Lt),
            Token::LtEq => Some(BinOp::LtEq),
            Token::Gt => Some(BinOp::Gt),
            Token::GtEq => Some(BinOp::GtEq),
            _ => None,
        };
        let Some(op) = op else {
            return Ok(left);
        };
        self.advance();
        let right = self.parse_arith()?;
        Ok(Expr::Binary(op, Box::new(left), Box::new(right)))
    }

    // arith := term (("+"|"-") term)*
    fn parse_arith(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_term()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_term()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // term := unary (("*"|"/"|"%") unary)*
    fn parse_term(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Rem,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // unary := "-" unary | primary
    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Token::Minus) {
            self.enter()?;
            self.advance();
            let inner = self.parse_unary()?;
            self.leave();
            return Ok(Expr::Neg(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let result = match self.peek().clone() {
            Token::Int { text, value } => {
                self.advance();
                Ok(Expr::Int(U256Lit { text, value }))
            }
            Token::True => {
                self.advance();
                Ok(Expr::Bool(true))
            }
            Token::False => {
                self.advance();
                Ok(Expr::Bool(false))
            }
            Token::LParen => {
                self.advance();
                let inner = self.parse_or()?;
                match self.advance() {
                    Token::RParen => Ok(inner),
                    _ => Err(ParseError::Expected {
                        expected: "`)`",
                        offset: self.offset(),
                    }),
                }
            }
            Token::Ident(name) => {
                self.advance();
                self.parse_ident_tail(name)
            }
            _ => Err(ParseError::Expected {
                expected: "expression",
                offset: self.offset(),
            }),
        };
        self.leave();
        result
    }

    /// Handles what follows an identifier: a call (`sum(...)`), a dotted path, or a
    /// bare symbol.
    fn parse_ident_tail(&mut self, name: String) -> Result<Expr, ParseError> {
        // `requires_no_overflow` takes an arithmetic expression, not a symbol, so it
        // must be routed before the symbol-call path below.
        if name == "requires_no_overflow" {
            if !matches!(self.peek(), Token::LParen) {
                return Err(ParseError::Expected {
                    expected: "`(` after requires_no_overflow",
                    offset: self.offset(),
                });
            }
            self.advance();
            let inner = self.parse_arith()?;
            match self.advance() {
                Token::RParen => {}
                _ => {
                    return Err(ParseError::Expected {
                        expected: "`)`",
                        offset: self.offset(),
                    })
                }
            }
            return Ok(Expr::RequiresNoOverflow(Box::new(inner)));
        }

        // Function-like forms.
        if matches!(self.peek(), Token::LParen) {
            self.advance();
            let arg = self.parse_symbol()?;
            match self.advance() {
                Token::RParen => {}
                _ => {
                    return Err(ParseError::Expected {
                        expected: "`)`",
                        offset: self.offset(),
                    })
                }
            }
            return match name.as_str() {
                "old" => Ok(Expr::Old(arg)),
                "delta" => Ok(Expr::Delta(arg)),
                "sum" => Ok(Expr::Sum(arg)),
                "count" => Ok(Expr::Count(arg)),
                // `requires_no_overflow` takes an arithmetic expression, not a symbol.
                other => Err(ParseError::Expected {
                    expected: match other {
                        "requires_no_overflow" => "arithmetic expression",
                        _ => "a known function (old, delta, sum, count)",
                    },
                    offset: self.offset(),
                }),
            };
        }

        // Dotted path.
        let mut segments = vec![name];
        while matches!(self.peek(), Token::Dot) {
            self.advance();
            match self.advance() {
                Token::Ident(next) => segments.push(next),
                _ => {
                    return Err(ParseError::Expected {
                        expected: "identifier after `.`",
                        offset: self.offset(),
                    })
                }
            }
        }

        // `block.number` / `block.timestamp` are read-only environment reads.
        if segments.len() == 2 && segments[0] == "block" {
            return match segments[1].as_str() {
                "number" => Ok(Expr::BlockEnv(BlockField::Number)),
                "timestamp" => Ok(Expr::BlockEnv(BlockField::Timestamp)),
                _ => Err(ParseError::Expected {
                    expected: "`block.number` or `block.timestamp`",
                    offset: self.offset(),
                }),
            };
        }

        Ok(Expr::Symbol(Symbol(segments)))
    }

    fn parse_symbol(&mut self) -> Result<Symbol, ParseError> {
        let mut segments = Vec::new();
        match self.advance() {
            Token::Ident(name) => segments.push(name),
            _ => {
                return Err(ParseError::Expected {
                    expected: "symbol",
                    offset: self.offset(),
                })
            }
        }
        while matches!(self.peek(), Token::Dot) {
            self.advance();
            match self.advance() {
                Token::Ident(next) => segments.push(next),
                _ => {
                    return Err(ParseError::Expected {
                        expected: "identifier after `.`",
                        offset: self.offset(),
                    })
                }
            }
        }
        Ok(Symbol(segments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(text: &str) -> Expr {
        Expr::Symbol(Symbol(text.split('.').map(str::to_string).collect()))
    }

    #[test]
    fn parses_the_worked_example_from_the_design() {
        // §6: sum(userBalances) == totalSupply
        let expr = parse("sum(userBalances) == totalSupply").expect("must parse");
        assert_eq!(
            expr,
            Expr::Binary(
                BinOp::Eq,
                Box::new(Expr::Sum(Symbol(vec!["userBalances".into()]))),
                Box::new(sym("totalSupply")),
            )
        );
    }

    #[test]
    fn parses_requires_no_overflow_over_arithmetic() {
        // §3 item 2: the operand is an expression, not a symbol.
        let expr = parse("requires_no_overflow(totalSupply + amount)").expect("must parse");
        match expr {
            Expr::RequiresNoOverflow(inner) => {
                assert_eq!(
                    *inner,
                    Expr::Binary(
                        BinOp::Add,
                        Box::new(sym("totalSupply")),
                        Box::new(sym("amount"))
                    )
                );
            }
            other => panic!("expected RequiresNoOverflow, got {other:?}"),
        }
    }

    #[test]
    fn multiplication_binds_tighter_than_addition() {
        let expr = parse("a + b * c").expect("must parse");
        assert_eq!(
            expr,
            Expr::Binary(
                BinOp::Add,
                Box::new(sym("a")),
                Box::new(Expr::Binary(
                    BinOp::Mul,
                    Box::new(sym("b")),
                    Box::new(sym("c"))
                )),
            )
        );
    }

    #[test]
    fn comparison_binds_looser_than_arithmetic() {
        let expr = parse("a + 1 < b * 2").expect("must parse");
        match expr {
            Expr::Binary(BinOp::Lt, lhs, rhs) => {
                assert!(matches!(*lhs, Expr::Binary(BinOp::Add, _, _)));
                assert!(matches!(*rhs, Expr::Binary(BinOp::Mul, _, _)));
            }
            other => panic!("expected Lt at the root, got {other:?}"),
        }
    }

    #[test]
    fn logical_operators_chain_left_to_right() {
        let expr = parse("a == 1 && b == 2 || c == 3").expect("must parse");
        match expr {
            Expr::Binary(BinOp::Or, lhs, _) => {
                assert!(matches!(*lhs, Expr::Binary(BinOp::And, _, _)));
            }
            other => panic!("expected Or at the root, got {other:?}"),
        }
    }

    #[test]
    fn parses_block_environment_reads() {
        assert_eq!(
            parse("block.timestamp").expect("must parse"),
            Expr::BlockEnv(BlockField::Timestamp)
        );
        assert_eq!(
            parse("block.number").expect("must parse"),
            Expr::BlockEnv(BlockField::Number)
        );
    }

    #[test]
    fn rejects_unknown_block_field() {
        let error = parse("block.gaslimit").unwrap_err();
        assert!(
            matches!(error, ParseError::Expected { expected, .. } if expected.contains("block.number")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_dotted_symbols_and_keeps_the_structure() {
        let expr = parse("balances.alice").expect("must parse");
        match expr {
            Expr::Symbol(s) => {
                assert_eq!(s.root(), "balances");
                assert_eq!(s.0, vec!["balances".to_string(), "alice".to_string()]);
            }
            other => panic!("expected Symbol, got {other:?}"),
        }
    }

    #[test]
    fn parses_hex_and_decimal_literals_to_the_same_value() {
        let hex = parse("0xff").expect("must parse");
        let dec = parse("255").expect("must parse");
        match (hex, dec) {
            (Expr::Int(a), Expr::Int(b)) => {
                assert_eq!(a.value_bytes(), b.value_bytes());
                // The raw text is preserved so evidence quotes the author's form.
                assert_eq!(a.text(), "0xff");
                assert_eq!(b.text(), "255");
            }
            other => panic!("expected two int literals, got {other:?}"),
        }
    }

    #[test]
    fn rejects_integer_literals_wider_than_256_bits() {
        // 2^256 does not fit; silently truncating would change the predicate's meaning.
        let too_big = format!("1{}", "0".repeat(78));
        let error = parse(&too_big).unwrap_err();
        assert!(
            matches!(error, ParseError::IntegerOverflow { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn accepts_the_largest_representable_literal() {
        // 2^256 - 1 in hex must be accepted.
        let max = format!("0x{}", "f".repeat(64));
        assert!(parse(&max).is_ok());
    }

    #[test]
    fn rejects_nesting_beyond_the_budget() {
        let deep = format!("{}a{}", "(".repeat(200), ")".repeat(200));
        let error = parse(&deep).unwrap_err();
        assert!(
            matches!(error, ParseError::TooDeep),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_input_longer_than_the_budget() {
        let long = "a".repeat(MAX_PREDICATE_BYTES + 1);
        assert!(matches!(parse(&long), Err(ParseError::TooLong(_))));
    }

    #[test]
    fn rejects_empty_and_whitespace_only_input() {
        assert!(matches!(parse(""), Err(ParseError::Empty)));
        assert!(matches!(parse("   \n\t "), Err(ParseError::Empty)));
    }

    #[test]
    fn reports_a_byte_offset_for_a_bad_character() {
        let error = parse("a @ b").unwrap_err();
        match error {
            ParseError::UnexpectedChar { ch, offset } => {
                assert_eq!(ch, '@');
                assert_eq!(offset, 2);
            }
            other => panic!("expected UnexpectedChar, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_trailing_operator_instead_of_panicking() {
        // §5: no path panics, and a malformed predicate is a typed error.
        assert!(parse("a +").is_err());
        assert!(parse("sum(").is_err());
        assert!(parse("!").is_err());
    }

    #[test]
    fn rejects_an_unknown_function_call() {
        let error = parse("explode(a)").unwrap_err();
        assert!(
            matches!(error, ParseError::Expected { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_trailing_tokens_after_a_complete_expression() {
        let error = parse("a == b c").unwrap_err();
        assert!(
            matches!(error, ParseError::Expected { expected, .. } if expected == "end of input"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_unary_minus_and_not() {
        assert!(matches!(parse("-a"), Ok(Expr::Neg(_))));
        assert!(matches!(parse("!(a == b)"), Ok(Expr::Not(_))));
    }

    #[test]
    fn division_by_zero_is_syntactically_fine() {
        // §3 item 3: `a / 0` parses. The evaluator returns 0 and counts it; the
        // parser must not reject arithmetic that the language allows.
        assert!(parse("a / 0").is_ok());
    }
}
