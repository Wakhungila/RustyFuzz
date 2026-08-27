//! Reusable deterministic fixtures for RustyFuzz tests.
//!
//! Rule: production crates must never depend on this crate; it sits on top of
//! their public APIs. Fixtures are deterministic by construction (fixed
//! addresses, fixed seeds) so failures are reproducible.

/// Deterministic address builder: `repeat_byte(byte)` repeated to fill 20
/// bytes (EVM addresses).
pub fn evm_address(byte: u8) -> [u8; 20] {
    [byte; 20]
}

/// Deterministic 32-byte storage slot from an index (index big-endian in the
/// final word).
pub fn storage_slot(index: u64) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..].copy_from_slice(&index.to_be_bytes());
    slot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic() {
        assert_eq!(evm_address(0x11), evm_address(0x11));
        assert_ne!(evm_address(0x11), evm_address(0x22));
        assert_eq!(&storage_slot(7)[24..], &7u64.to_be_bytes());
        assert!(storage_slot(7)[..24].iter().all(|b| *b == 0));
    }
}
