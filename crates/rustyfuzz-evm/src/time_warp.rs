//! Deterministic block-environment advance between transactions.
//!
//! # Why this exists
//!
//! A fuzzer that keeps `block.timestamp` and `block.number` constant across a
//! whole sequence cannot reach an entire class of real bugs:
//!
//! - vesting cliffs and unlock schedules (`require(block.timestamp >= start + duration)`)
//! - TWAP / oracle staleness windows
//! - interest accrual (`elapsed = now - lastUpdate`)
//! - auction deadlines, timelocks, cooldowns, epochs, `permit` expiries
//!
//! The harness cloned `BlockEnv` per input but never advanced it, so every
//! transaction in a sequence observed the same block. Time-dependent state
//! transitions were therefore unreachable by construction.
//!
//! # Determinism
//!
//! The advance is a pure function of the fuzz input and the transaction index, so
//! replaying the same input reproduces exactly the same block environments. No
//! wall clock is consulted. This is what allows a time-dependent finding to be
//! replayed by the verifier and re-executed against pinned fork state.

use revm::context::BlockEnv;
use revm::primitives::U256;

/// Per-transaction time advance derived from an input sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWarp {
    /// Seconds added per transaction.
    pub seconds_per_tx: u64,
    /// Blocks added per transaction.
    pub blocks_per_tx: u64,
}

impl TimeWarp {
    /// No advance: every transaction sees the original block context.
    pub const NONE: Self = Self {
        seconds_per_tx: 0,
        blocks_per_tx: 0,
    };

    /// Default exploration policy.
    ///
    /// A fuzzed sequence is short (typically 3–8 transactions), so a 12-second
    /// slot time spans at most a minute or two — not enough to clear an hourly
    /// timelock, a daily cooldown, or a weekly epoch. Real time-dependent bugs
    /// live at those scales.
    ///
    /// One hour per transaction lets an 8-transaction sequence span eight hours,
    /// which reaches same-day vesting cliffs, hourly funding epochs, cooldown
    /// expiries and daily accrual while staying well inside plausible chain
    /// history. Longer horizons (weeks, months) are reachable by raising this in
    /// configuration; the value is recorded with the campaign so a finding stays
    /// replayable.
    pub const DEFAULT: Self = Self {
        seconds_per_tx: 3_600,
        blocks_per_tx: 1,
    };

    pub fn is_noop(&self) -> bool {
        self.seconds_per_tx == 0 && self.blocks_per_tx == 0
    }

    /// Builds a policy from configuration, clamping to sane bounds.
    ///
    /// A multi-year jump in one step is legal in principle but makes most
    /// arithmetic in a target either overflow to a revert or skip every
    /// intermediate state, so the advance is capped at one year per transaction.
    pub fn from_seconds(seconds_per_tx: u64, blocks_per_tx: u64) -> Self {
        const MAX_SECONDS_PER_TX: u64 = 365 * 24 * 60 * 60;
        Self {
            seconds_per_tx: seconds_per_tx.min(MAX_SECONDS_PER_TX),
            blocks_per_tx,
        }
    }

    /// Applies the advance for transaction `tx_index` to `env`.
    ///
    /// Index 0 receives no advance: the first transaction must observe the exact
    /// forked state, or a replay would not match the pinned block.
    pub fn apply(&self, env: &mut BlockEnv, tx_index: usize) {
        if tx_index == 0 || self.is_noop() {
            return;
        }
        let steps = tx_index as u64;
        if self.seconds_per_tx != 0 {
            let delta = self.seconds_per_tx.saturating_mul(steps);
            env.timestamp = env.timestamp.saturating_add(U256::from(delta));
        }
        if self.blocks_per_tx != 0 {
            let delta = self.blocks_per_tx.saturating_mul(steps);
            env.number = env.number.saturating_add(U256::from(delta));
        }
    }
}

impl Default for TimeWarp {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(number: u64, timestamp: u64) -> BlockEnv {
        BlockEnv {
            number: U256::from(number),
            timestamp: U256::from(timestamp),
            ..Default::default()
        }
    }

    #[test]
    fn first_transaction_observes_the_forked_block() {
        let warp = TimeWarp::DEFAULT;
        let mut block = env(100, 1_700_000_000);
        warp.apply(&mut block, 0);
        assert_eq!(block.number, U256::from(100));
        assert_eq!(block.timestamp, U256::from(1_700_000_000u64));
    }

    #[test]
    fn advance_is_linear_in_transaction_index() {
        let warp = TimeWarp::from_seconds(12, 1);
        let mut block = env(100, 1_700_000_000);
        warp.apply(&mut block, 3);
        assert_eq!(block.number, U256::from(103));
        assert_eq!(block.timestamp, U256::from(1_700_000_036u64));
    }

    #[test]
    fn replay_produces_identical_environments() {
        let warp = TimeWarp::from_seconds(7, 2);
        let first: Vec<_> = (0..5)
            .map(|tx| {
                let mut block = env(50, 1_000);
                warp.apply(&mut block, tx);
                (block.number, block.timestamp)
            })
            .collect();
        let second: Vec<_> = (0..5)
            .map(|tx| {
                let mut block = env(50, 1_000);
                warp.apply(&mut block, tx);
                (block.number, block.timestamp)
            })
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn noop_policy_leaves_the_environment_untouched() {
        let mut block = env(7, 42);
        TimeWarp::NONE.apply(&mut block, 9);
        assert_eq!(block.number, U256::from(7));
        assert_eq!(block.timestamp, U256::from(42u64));
    }

    #[test]
    fn advance_is_capped_and_saturating() {
        let warp = TimeWarp::from_seconds(u64::MAX, u64::MAX);
        assert_eq!(warp.seconds_per_tx, 365 * 24 * 60 * 60);
        let mut block = env(0, 0);
        // Must not panic or wrap.
        warp.apply(&mut block, 1_000_000);
        assert!(block.timestamp > U256::ZERO);
    }
}
