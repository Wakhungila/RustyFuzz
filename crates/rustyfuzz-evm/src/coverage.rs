//! EVM coverage-path hashing shared by executor feedback and corpus metadata.
//!
//! # Why this is not a simple scan
//!
//! The coverage map is 256 KiB. Deriving a path signature by walking the whole
//! map once per transaction costs ~177 µs on the reference machine — more than
//! executing the transaction itself. Because it is paid per *transaction*, not
//! per campaign, it silently dominated throughput (79% of measured execution
//! time on a small target).
//!
//! The map is written only by the inspector, one hit at a time, so the set of
//! touched indices is known as the transaction runs. Recording them makes the
//! signature cost proportional to the edges a transaction actually covers
//! instead of the size of the map, while producing byte-identical results.

use std::cell::RefCell;

thread_local! {
    /// Indices written since the last [`begin_transaction`].
    ///
    /// Thread-local because each fuzzing worker owns its own coverage map and
    /// never shares it; there is no cross-thread state to synchronize.
    static TOUCHED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
}

#[inline]
pub(crate) fn bucket_hitcount(hit: u8) -> u8 {
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
/// This is the reference definition and the compatibility contract: persisted
/// corpus hashes and replay verification use it. The incremental path in
/// [`transaction_path_hash`] must agree with it exactly, which the unit tests
/// below pin.
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

/// Prepares the thread-local touched log for a new transaction.
pub fn begin_transaction() {
    TOUCHED.with(|touched| touched.borrow_mut().clear());
}

/// Records that `index` was hit in the current transaction.
///
/// Called by the inspector on the first hit of each edge. Duplicates are
/// tolerated: the hash path deduplicates before mixing.
#[inline(always)]
pub fn record_touched(index: usize) {
    TOUCHED.with(|touched| touched.borrow_mut().push(index as u32));
}

/// Path hash for the current transaction, computed over touched indices only.
///
/// Equals [`stable_path_hash`] over the same map bytes, in the same ascending
/// index order, at a fraction of the cost.
pub fn transaction_path_hash(coverage: &[u8]) -> u64 {
    let mut touched = TOUCHED.with(|touched| {
        let mut touched = touched.borrow().clone();
        touched.sort_unstable();
        touched.dedup();
        touched
    });
    touched.sort_unstable();
    touched.dedup();

    let mut hash = 0xcbf29ce484222325u64;
    for index in touched {
        let Some(&hit) = coverage.get(index as usize) else {
            continue;
        };
        let bucket = bucket_hitcount(hit);
        if bucket == 0 {
            continue;
        }
        hash ^= index as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= bucket as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Number of distinct edges covered by the current transaction.
pub fn transaction_edge_count() -> usize {
    TOUCHED.with(|touched| {
        let mut touched = touched.borrow().clone();
        touched.sort_unstable();
        touched.dedup();
        touched.len()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulate the inspector writing through a raw slice plus the touched log.
    fn write_hits(coverage: &mut [u8], hits: &[(usize, u8)]) {
        begin_transaction();
        for &(index, count) in hits {
            for _ in 0..count {
                let slot = &mut coverage[index];
                if *slot == 0 {
                    record_touched(index);
                }
                *slot = slot.saturating_add(1);
            }
        }
    }

    #[test]
    fn incremental_hash_matches_full_scan() {
        let mut coverage = vec![0u8; 1024];
        write_hits(&mut coverage, &[(7, 1), (300, 5), (1023, 9), (300, 2)]);
        assert_eq!(
            transaction_path_hash(&coverage),
            stable_path_hash(&coverage)
        );
        assert_eq!(transaction_edge_count(), 3);
    }

    #[test]
    fn begin_transaction_resets_the_log() {
        let mut coverage = vec![0u8; 256];
        write_hits(&mut coverage, &[(10, 1), (200, 3)]);
        assert_eq!(transaction_edge_count(), 2);

        begin_transaction();
        // A campaign clears the map per input; clearing it here keeps the
        // comparison with the full-scan definition meaningful.
        coverage.fill(0);

        assert_eq!(transaction_edge_count(), 0);
        // Matches the full-scan definition, which returns the FNV offset basis
        // (not zero) when nothing was touched.
        assert_eq!(
            transaction_path_hash(&coverage),
            stable_path_hash(&coverage)
        );
    }

    #[test]
    fn empty_transaction_matches_full_scan_definition() {
        let coverage = vec![0u8; 64];
        begin_transaction();
        assert_eq!(
            transaction_path_hash(&coverage),
            stable_path_hash(&coverage)
        );
    }

    #[test]
    fn out_of_range_touched_index_is_ignored() {
        // A raw slice can shrink between record and read in tests; a stale index
        // must not panic in the feedback loop.
        let mut coverage = vec![0u8; 8];
        write_hits(&mut coverage, &[(4, 1)]);
        record_touched(9999);
        assert_eq!(
            transaction_path_hash(&coverage),
            stable_path_hash(&coverage)
        );
    }
}
