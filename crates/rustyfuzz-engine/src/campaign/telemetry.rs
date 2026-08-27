//! Campaign execution telemetry.

use crate::concolic_stats::{ConcolicHintStats, ConcolicHintStatsSnapshot};
use log;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CAMPAIGN_TELEMETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Per-strategy attempt/mutated counters for named mutation strategies.
///
/// Stage 3.6: additive observability only — recording happens around the
/// existing dispatch and never influences RNG draws or strategy selection.
#[derive(Debug, Default)]
pub struct StrategyCounters {
    inner: Mutex<BTreeMap<String, StrategyCounts>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StrategyCounts {
    pub attempted: u64,
    pub mutated: u64,
}

impl StrategyCounters {
    pub fn record_attempted(&self, strategy: &str) {
        let mut counts = self.inner.lock();
        counts.entry(strategy.to_string()).or_default().attempted += 1;
    }

    pub fn record_mutated(&self, strategy: &str) {
        let mut counts = self.inner.lock();
        counts.entry(strategy.to_string()).or_default().mutated += 1;
    }

    pub fn snapshot(&self) -> BTreeMap<String, StrategyCounts> {
        self.inner.lock().clone()
    }
}

pub struct CampaignTelemetry {
    start: Instant,
    executions: AtomicU64,
    mutated_inputs: AtomicU64,
    seed_replays: AtomicU64,
    pub artifacts: AtomicU64,
    oracle_findings: AtomicU64,
    state_novelty: AtomicU64,
    best_score: AtomicU64,
    max_coverage_edges: AtomicU64,
    mutation_strategies: Mutex<BTreeMap<String, u64>>,
    pub concolic_hint_stats: Arc<ConcolicHintStats>,
    last_report: Mutex<(Instant, u64)>,
}

pub struct ExecutionTelemetryRecord<'a> {
    pub core_id: usize,
    pub tx_count: usize,
    pub findings: usize,
    pub campaign_score: u64,
    pub corpus_size: usize,
    pub coverage_edges: usize,
    pub state_novelty_score: u64,
    pub mutation_strategies: &'a [String],
}

impl Default for CampaignTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl CampaignTelemetry {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            executions: AtomicU64::new(0),
            mutated_inputs: AtomicU64::new(0),
            seed_replays: AtomicU64::new(0),
            artifacts: AtomicU64::new(0),
            oracle_findings: AtomicU64::new(0),
            state_novelty: AtomicU64::new(0),
            best_score: AtomicU64::new(0),
            max_coverage_edges: AtomicU64::new(0),
            mutation_strategies: Mutex::new(BTreeMap::new()),
            concolic_hint_stats: Arc::new(ConcolicHintStats::default()),
            last_report: Mutex::new((now, 0)),
        }
    }

    pub fn record_execution(&self, record: ExecutionTelemetryRecord<'_>) {
        let ExecutionTelemetryRecord {
            core_id,
            tx_count,
            findings,
            campaign_score,
            corpus_size,
            coverage_edges,
            state_novelty_score,
            mutation_strategies,
        } = record;
        let total = self.executions.fetch_add(1, Ordering::Relaxed) + 1;
        if mutation_strategies
            .iter()
            .any(|strategy| strategy != "seed_or_imported")
        {
            self.mutated_inputs.fetch_add(1, Ordering::Relaxed);
        } else {
            self.seed_replays.fetch_add(1, Ordering::Relaxed);
        }
        if findings > 0 {
            self.oracle_findings
                .fetch_add(findings as u64, Ordering::Relaxed);
        }
        if state_novelty_score > 0 {
            self.state_novelty
                .fetch_add(state_novelty_score, Ordering::Relaxed);
        }
        self.best_score.fetch_max(campaign_score, Ordering::Relaxed);
        self.max_coverage_edges
            .fetch_max(coverage_edges as u64, Ordering::Relaxed);
        if !mutation_strategies.is_empty() {
            let mut counts = self.mutation_strategies.lock();
            for strategy in mutation_strategies {
                *counts.entry(strategy.clone()).or_default() += 1;
            }
        }

        let now = Instant::now();
        let mut last = self.last_report.lock();
        let elapsed = now.duration_since(last.0);
        if elapsed < CAMPAIGN_TELEMETRY_INTERVAL {
            return;
        }

        let delta_execs = total.saturating_sub(last.1);
        let interval_execs_per_sec = delta_execs as f64 / elapsed.as_secs_f64().max(0.001);
        let total_execs_per_sec =
            total as f64 / now.duration_since(self.start).as_secs_f64().max(0.001);
        let mutation_mix = {
            let counts = self.mutation_strategies.lock();
            counts
                .iter()
                .map(|(strategy, count)| format!("{strategy}:{count}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let concolic: ConcolicHintStatsSnapshot = self.concolic_hint_stats.snapshot();
        log::info!(
            "RustyFuzz telemetry: core={}, executions={}, mutated_inputs={}, seed_replays={}, execs_per_sec_30s={:.3}, execs_per_sec_avg={:.3}, corpus_size={}, coverage_edges_last={}, state_novelty_count={}, oracle_findings={}, persisted_artifacts={}, best_score={}, txs_last={}, score_last={}, mutation_strategy_mix=[{}], concolic_hints={{generated:{},deduplicated:{},applied:{},successful:{}}}",
            core_id,
            total,
            self.mutated_inputs.load(Ordering::Relaxed),
            self.seed_replays.load(Ordering::Relaxed),
            interval_execs_per_sec,
            total_execs_per_sec,
            corpus_size,
            coverage_edges,
            self.state_novelty.load(Ordering::Relaxed),
            self.oracle_findings.load(Ordering::Relaxed),
            self.artifacts.load(Ordering::Relaxed),
            self.best_score.load(Ordering::Relaxed),
            tx_count,
            campaign_score,
            mutation_mix,
            concolic.generated,
            concolic.deduplicated,
            concolic.applied,
            concolic.successful
        );
        *last = (now, total);
    }

    pub fn record_artifact(&self) {
        self.artifacts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn execution_count(&self) -> u64 {
        self.executions.load(Ordering::Relaxed)
    }

    pub fn artifact_count(&self) -> u64 {
        self.artifacts.load(Ordering::Relaxed)
    }

    pub fn coverage_edges(&self) -> u64 {
        self.max_coverage_edges.load(Ordering::Relaxed)
    }

    pub fn mutated_inputs(&self) -> u64 {
        self.mutated_inputs.load(Ordering::Relaxed)
    }

    pub fn seed_replays(&self) -> u64 {
        self.seed_replays.load(Ordering::Relaxed)
    }

    pub fn executions(&self) -> u64 {
        self.executions.load(Ordering::Relaxed)
    }

    pub fn artifacts(&self) -> u64 {
        self.artifacts.load(Ordering::Relaxed)
    }
}
