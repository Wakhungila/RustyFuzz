//! Concolic hint generation/application statistics shared by solver and mutator.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct ConcolicHintStats {
    generated: AtomicU64,
    deduplicated: AtomicU64,
    applied: AtomicU64,
    successful: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConcolicHintStatsSnapshot {
    pub generated: u64,
    pub deduplicated: u64,
    pub applied: u64,
    pub successful: u64,
}

impl ConcolicHintStats {
    pub fn record_generated(&self, count: u64) {
        self.generated.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_deduplicated(&self, count: u64) {
        self.deduplicated.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_applied(&self) {
        self.applied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_successful(&self) {
        self.successful.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConcolicHintStatsSnapshot {
        ConcolicHintStatsSnapshot {
            generated: self.generated.load(Ordering::Relaxed),
            deduplicated: self.deduplicated.load(Ordering::Relaxed),
            applied: self.applied.load(Ordering::Relaxed),
            successful: self.successful.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_accumulate_into_snapshot() {
        let stats = ConcolicHintStats::default();
        stats.record_generated(5);
        stats.record_deduplicated(2);
        stats.record_applied();
        stats.record_successful();
        let snap = stats.snapshot();
        assert_eq!(
            snap,
            ConcolicHintStatsSnapshot {
                generated: 5,
                deduplicated: 2,
                applied: 1,
                successful: 1
            }
        );
    }
}
