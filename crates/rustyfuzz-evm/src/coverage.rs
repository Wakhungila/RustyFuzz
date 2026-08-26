//! EVM coverage-path hashing shared by executor feedback and corpus metadata.

fn bucket_hitcount(hit: u8) -> u8 {
    match hit {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Stable path hash over hit-count-bucketed coverage bytes.
///
/// Moved verbatim from the monolith's `EvmCoverageFeedback` in Stage 2E; the
/// monolith calls through to this function so persisted hashes are identical.
pub fn stable_path_hash(coverage: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for (idx, hit) in coverage.iter().copied().enumerate() {
        let bucket = bucket_hitcount(hit);
        if bucket == 0 {
            continue;
        }
        hash ^= idx as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= bucket as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
