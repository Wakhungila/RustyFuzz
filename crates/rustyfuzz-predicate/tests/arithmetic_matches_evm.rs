//! Cross-checks `Int256` against independently computed EVM semantics.
//!
//! The expected values in `tests/data/arith_cases.txt` were generated with Python
//! arbitrary-precision integers, so they are not derived from this implementation.
//! A shared bug between generator and implementation is impossible here because the
//! generator is not Rust.
//!
//! 306 cases: 300 random 256-bit pairs plus the boundaries where wrapping is most
//! likely to be wrong — `0/1`, `1/0`, `max/2`, `max/max`, `2^255` doubled, `0/max`,
//! and each of those against a zero divisor.

use rustyfuzz_predicate::Int256;

fn parse_hex(text: &str) -> Int256 {
    let mut bytes = [0u8; 32];
    let trimmed = text.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    let padded = format!("{trimmed:0>64}");
    for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("ascii hex");
        bytes[index] = u8::from_str_radix(pair, 16).expect("valid hex");
    }
    Int256(bytes)
}

#[test]
fn arithmetic_matches_independently_computed_evm_results() {
    let data = include_str!("data/arith_cases.txt");
    let mut checked = 0usize;
    for (line_number, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            7,
            "malformed case on line {}",
            line_number + 1
        );

        let a = parse_hex(fields[0]);
        let b = parse_hex(fields[1]);

        assert_eq!(
            a.wrapping_add(b),
            parse_hex(fields[2]),
            "add mismatch on line {}",
            line_number + 1
        );
        assert_eq!(
            a.wrapping_sub(b),
            parse_hex(fields[3]),
            "sub mismatch on line {}",
            line_number + 1
        );
        assert_eq!(
            a.wrapping_mul(b),
            parse_hex(fields[4]),
            "mul mismatch on line {}",
            line_number + 1
        );
        assert_eq!(
            a.evm_div(b),
            parse_hex(fields[5]),
            "div mismatch on line {}",
            line_number + 1
        );
        assert_eq!(
            a.evm_rem(b),
            parse_hex(fields[6]),
            "rem mismatch on line {}",
            line_number + 1
        );
        checked += 1;
    }
    assert!(checked >= 300, "expected at least 300 cases, ran {checked}");
}

#[test]
fn zero_divisor_yields_zero_not_a_panic() {
    // §3 item 3: EVM DIV/MOD return 0 rather than trapping. The evaluator counts
    // this and degrades a pass; the arithmetic itself must stay total.
    let value = Int256::from_u64(12345);
    assert!(value.evm_div(Int256::ZERO).is_zero());
    assert!(value.evm_rem(Int256::ZERO).is_zero());
    assert!(Int256::ZERO.evm_div(Int256::ZERO).is_zero());
}
