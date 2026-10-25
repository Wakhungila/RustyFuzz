//! Cross-checks Solidity mapping slot derivation against an independent reference.
//!
//! `tests/data/mapping_cases.txt` was generated with Python's `pycryptodome`
//! Keccak-256, so the expected slots come from a different implementation and a
//! different language than the `sha3` crate used here. A shared bug is impossible.
//!
//! Format: `<kind> <base_slot_hex> <key> <expected_slot_hex>` where `kind` is
//! `addr` (20-byte address key, left-padded) or `uint` (uint256 key).

use rustyfuzz_predicate::mapping_slot;

fn word(hex: &str) -> [u8; 32] {
    let hex = hex.trim_start_matches("0x");
    let trimmed = hex.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    let padded = format!("{trimmed:0>64}");
    let mut out = [0u8; 32];
    for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("ascii");
        out[index] = u8::from_str_radix(pair, 16).expect("hex");
    }
    out
}

#[test]
fn mapping_slots_match_an_independent_keccak_reference() {
    let data = include_str!("data/mapping_cases.txt");
    let mut checked = 0usize;

    for (line_number, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            4,
            "malformed case on line {}",
            line_number + 1
        );

        let base = word(fields[1]);
        let key = match fields[0] {
            "addr" => {
                let bytes = word(fields[2]);
                // An address key occupies the low 20 bytes; the reference generator
                // produced exactly that, so assert the padding instead of assuming it.
                assert_eq!(&bytes[..12], &[0u8; 12], "address key not left-padded");
                bytes
            }
            "uint" => word(fields[2]),
            other => panic!("unknown key kind `{other}` on line {}", line_number + 1),
        };
        let expected = word(fields[3]);

        assert_eq!(
            mapping_slot(&key, &base),
            expected,
            "mapping slot mismatch on line {} ({} base={} key={})",
            line_number + 1,
            fields[0],
            fields[1],
            fields[2]
        );
        checked += 1;
    }

    assert!(checked >= 40, "expected at least 40 cases, ran {checked}");
}
