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

impl CampaignBudget {
    pub fn new(max_execs: Option<u64>, duration_secs: Option<u64>, workers: usize) -> Self {
        let max_execs = max_execs.map(|execs| {
            let workers = workers.max(1) as u64;
            execs.div_ceil(workers).max(1)
        });
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
    fn budget_reserves_up_to_per_worker_share() {
        let budget = CampaignBudget::new(Some(10), None, 4);
        // 10/4 workers -> ceil = 3 per worker share.
        let mut reserved = 0;
        while budget.reserve_execution() {
            reserved += 1;
        }
        assert_eq!(reserved, 3);
        assert!(budget.exhausted());
    }

    #[test]
    fn unlimited_budget_never_exhausts_by_count() {
        let budget = CampaignBudget::new(None, None, 1);
        assert!(budget.reserve_execution());
        assert!(!budget.exhausted());
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
