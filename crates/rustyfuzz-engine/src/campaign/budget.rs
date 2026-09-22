//! Execution budget for bounded campaigns.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn campaign_shutdown_grace() -> u64 {
    std::env::var("RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
}

/// Bounds a campaign by execution count and wall-clock deadline.
///
/// The deadline reserves a shutdown grace window so in-flight work can finish.
/// `reserve_execution` must be called before every execution; it is the only
/// admission control into the fuzz loop.
pub struct CampaignBudget {
    pub max_execs: Option<u64>,
    deadline: Option<Instant>,
    reserved_execs: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetCheckpoint {
    pub max_execs: Option<u64>,
    pub consumed: u64,
    pub remaining: Option<Duration>,
}

impl CampaignBudget {
    pub fn checkpoint(&self) -> BudgetCheckpoint {
        BudgetCheckpoint {
            max_execs: self.max_execs,
            consumed: self.reserved(),
            remaining: self
                .deadline
                .map(|d| d.saturating_duration_since(Instant::now())),
        }
    }

    pub fn restore(saved: BudgetCheckpoint) -> Result<Self, &'static str> {
        if saved.max_execs.is_some_and(|limit| saved.consumed > limit) {
            return Err("checkpoint budget exceeds execution limit");
        }
        let deadline = saved
            .remaining
            .map(|d| {
                Instant::now()
                    .checked_add(d)
                    .ok_or("checkpoint duration overflows deadline")
            })
            .transpose()?;
        Ok(Self {
            max_execs: saved.max_execs,
            deadline,
            reserved_execs: AtomicU64::new(saved.consumed),
        })
    }
    /// Conservative equal share when the caller has no worker index. Any
    /// remainder is unused; use `for_worker` to distribute the entire budget.
    pub fn new(max_execs: Option<u64>, duration_secs: Option<u64>, workers: usize) -> Self {
        Self::with_limit(
            max_execs.map(|execs| execs / workers.max(1) as u64),
            duration_secs,
        )
    }

    /// Exact partition for a stable zero-based worker index. Across all workers
    /// the quotas sum to the requested global limit, including zero. Invalid
    /// topology is rejected. These quotas are process-local and are not a
    /// durable accounting mechanism across worker restarts.
    pub fn for_worker(
        max_execs: Option<u64>,
        duration_secs: Option<u64>,
        workers: usize,
        worker_index: usize,
    ) -> Option<Self> {
        if workers == 0 || worker_index >= workers {
            return None;
        }
        let quota = max_execs.map(|limit| {
            limit / workers as u64 + u64::from((worker_index as u64) < limit % workers as u64)
        });
        Some(Self::with_limit(quota, duration_secs))
    }

    fn with_limit(max_execs: Option<u64>, duration_secs: Option<u64>) -> Self {
        let shutdown_grace = campaign_shutdown_grace();
        Self {
            max_execs,
            deadline: duration_secs.map(|secs| {
                Instant::now() + Duration::from_secs(secs.saturating_sub(shutdown_grace))
            }),
            reserved_execs: AtomicU64::new(0),
        }
    }

    pub fn reserve_execution(&self) -> bool {
        if self.time_exhausted() {
            return false;
        }
        let Some(max_execs) = self.max_execs else {
            self.reserved_execs.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        loop {
            let current = self.reserved_execs.load(Ordering::Relaxed);
            if current >= max_execs {
                return false;
            }
            if self
                .reserved_execs
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub fn exhausted(&self) -> bool {
        self.time_exhausted()
            || self
                .max_execs
                .is_some_and(|max_execs| self.reserved_execs.load(Ordering::Relaxed) >= max_execs)
    }

    pub fn reserved(&self) -> u64 {
        self.reserved_execs.load(Ordering::Relaxed)
    }

    pub fn time_exhausted(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_budget_admits_only_unconsumed_executions() {
        let budget = CampaignBudget::new(Some(10), None, 1);
        for _ in 0..7 {
            assert!(budget.reserve_execution());
        }
        let restored = CampaignBudget::restore(budget.checkpoint()).unwrap();
        for _ in 0..3 {
            assert!(restored.reserve_execution());
        }
        assert!(!restored.reserve_execution());
        assert_eq!(restored.reserved(), 10);
    }

    #[test]
    fn unlimited_budget_still_checkpoints_execution_count() {
        let budget = CampaignBudget::new(None, None, 1);
        for _ in 0..3 {
            assert!(budget.reserve_execution());
        }
        assert_eq!(
            CampaignBudget::restore(budget.checkpoint())
                .unwrap()
                .reserved(),
            3
        );
    }

    #[test]
    fn budget_reserves_up_to_per_worker_share() {
        let budget = CampaignBudget::new(Some(10), None, 4);
        // Without worker identity the remainder must remain unused.
        let mut reserved = 0;
        while budget.reserve_execution() {
            reserved += 1;
        }
        assert_eq!(reserved, 2);
        assert!(budget.exhausted());
    }

    #[test]
    fn unlimited_budget_never_exhausts_by_count() {
        let budget = CampaignBudget::new(None, None, 1);
        assert!(budget.reserve_execution());
        assert!(!budget.exhausted());
    }

    #[test]
    fn worker_quotas_preserve_global_limit() {
        for limit in [0, 1, 3, 10, 101, u64::MAX] {
            for workers in [1, 2, 4, 16] {
                let quotas: Vec<_> = (0..workers)
                    .map(|index| {
                        CampaignBudget::for_worker(Some(limit), None, workers, index)
                            .unwrap()
                            .max_execs
                            .unwrap()
                    })
                    .collect();
                assert_eq!(
                    quotas.iter().map(|v| *v as u128).sum::<u128>(),
                    limit as u128
                );
                assert!(quotas.iter().max().unwrap() - quotas.iter().min().unwrap() <= 1);
            }
        }
        assert!(CampaignBudget::for_worker(Some(1), None, 0, 0).is_none());
        assert!(CampaignBudget::for_worker(Some(1), None, 2, 2).is_none());
    }

    #[test]
    fn zero_budget_admits_no_execution() {
        let budget = CampaignBudget::new(Some(0), None, 1);
        assert!(!budget.reserve_execution());
        assert!(budget.exhausted());
        assert_eq!(budget.reserved(), 0);
    }

    #[test]
    fn concurrent_reservations_do_not_overshoot() {
        let budget = CampaignBudget::new(Some(1003), None, 1);
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let mut count = 0;
                        while budget.reserve_execution() {
                            count += 1;
                        }
                        count
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum::<u64>()
        });
        assert_eq!(admitted, 1003);
        assert_eq!(budget.reserved(), admitted);
    }

    #[test]
    fn past_deadline_rejects_reservations() {
        let mut budget = CampaignBudget::new(None, Some(0), 1);
        // duration 0 minus grace saturates to an immediate/past deadline.
        budget.deadline = Some(Instant::now() - Duration::from_secs(1));
        assert!(!budget.reserve_execution());
        assert!(budget.exhausted());
    }
}
