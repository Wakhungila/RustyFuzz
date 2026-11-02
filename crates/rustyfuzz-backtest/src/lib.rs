//! Backtest scoring rubric.
//!
//! The rule this crate exists to enforce: **a false positive cannot count.**
//!
//! A case contributes to the rediscovery rate only when the evidence is
//! end-to-end reproducible. Everything else is excluded from the numerator and
//! reported in its own bucket, so a table can never be inflated by findings that
//! did not survive verification.
//!
//! Counting rule (deliberately strict):
//!
//! | PoC outcome  | replays | counts toward rediscovery |
//! |--------------|---------|---------------------------|
//! | `Pass`       | yes     | **yes**                   |
//! | `Pass`       | no      | no — demoted to `Inconclusive` |
//! | `Fail`       | any     | no — counted as a false positive |
//! | `Inconclusive` | any   | no — counted as unmeasured |
//!
//! `Fail` and `Inconclusive` are both excluded from the numerator but are *not*
//! the same thing: `Fail` is evidence of a wrong answer, `Inconclusive` is absence
//! of evidence. Collapsing them would let a tool hide false positives by calling
//! them unmeasured, so they are tracked separately and reported separately.

use serde::{Deserialize, Serialize};

/// Outcome of running the generated proof-of-concept against the target's own
/// test suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PocOutcome {
    /// The PoC compiled, executed, and demonstrated the violation.
    Pass,
    /// The PoC ran and did **not** demonstrate the violation. This is a false
    /// positive and is counted as such.
    Fail,
    /// The PoC could not be produced or could not be evaluated (missing source,
    /// missing compiler, no ABI, unevaluable predicate). This is an absence of
    /// evidence, not evidence against.
    Inconclusive,
}

impl PocOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            PocOutcome::Pass => "pass",
            PocOutcome::Fail => "fail",
            PocOutcome::Inconclusive => "inconclusive",
        }
    }
}

/// Per-case classification after applying the counting rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseResult {
    /// Matches the case's known vulnerability, replayed deterministically, PoC passes.
    Rediscovered,
    /// A violation that is *not* the known one, but replayed and PoC-verified.
    NovelFinding,
    /// The fuzzer produced nothing reproducible for a case that has a known bug.
    Missed,
    /// Could not be measured, or the evidence was insufficient to classify.
    Inconclusive,
}

impl CaseResult {
    /// True only for results that may enter the rediscovery numerator.
    pub fn counts_toward_rediscovery(self) -> bool {
        matches!(self, CaseResult::Rediscovered)
    }

    /// True for results that are positive evidence of a wrong answer.
    pub fn is_false_positive(self) -> bool {
        matches!(self, CaseResult::Missed)
    }
}

/// Raw observations for one backtest case, before the rubric is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseObservation {
    /// Stable case identifier (matches the corpus file name).
    pub case_id: String,
    /// The known vulnerability was reported as found by the fuzzer.
    pub reported_finding: bool,
    /// The minimized sequence replayed deterministically in a fresh process.
    pub replay_ok: bool,
    /// Outcome of compiling and running the generated PoC.
    pub poc: PocOutcome,
    /// Whether the case carries a known ground truth to compare against.
    pub has_ground_truth: bool,
    /// Reason the case could not be measured, when it could not be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<String>,
    /// Milliseconds from campaign start to the first finding, when one was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_to_first_finding_ms: Option<u64>,
}

/// A case after the rubric has classified it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredCase {
    pub case_id: String,
    pub result: CaseResult,
    pub poc: PocOutcome,
    pub time_to_first_finding_ms: Option<u64>,
    /// Why the case was classified this way. Always populated for
    /// `Inconclusive` and `Missed`, so a reader never has to guess.
    pub reason: String,
}

impl CaseObservation {
    /// Applies the counting rule to one case.
    ///
    /// The order of checks matters and is intentional:
    ///
    /// 1. An explicit "could not measure" reason wins: no evidence exists, so
    ///    nothing downstream may claim anything about this case.
    /// 2. A reported finding that does not replay is `Missed` (false positive),
    ///    not `Inconclusive`: the tool made a claim and the claim failed.
    /// 3. A reported finding whose PoC did not pass is likewise `Missed`.
    /// 4. Only a finding that replays *and* has a passing PoC can be a
    ///    rediscovery or a novel finding.
    /// 5. No finding on a case with ground truth is `Missed`; on a case without
    ///    ground truth it is `Inconclusive`, because "found nothing" is not the
    ///    same as "known to have missed".
    pub fn score(&self) -> ScoredCase {
        let result = if self.inconclusive_reason.is_some() {
            CaseResult::Inconclusive
        } else if self.reported_finding {
            if !self.replay_ok {
                CaseResult::Missed
            } else {
                match self.poc {
                    PocOutcome::Pass => {
                        if self.has_ground_truth {
                            CaseResult::Rediscovered
                        } else {
                            CaseResult::NovelFinding
                        }
                    }
                    // A finding that replays but whose PoC does not demonstrate
                    // the violation is still a wrong answer.
                    PocOutcome::Fail => CaseResult::Missed,
                    // No PoC could be produced: the claim is unproven, so it must
                    // not count, and it must not be counted as a false positive
                    // either.
                    PocOutcome::Inconclusive => CaseResult::Inconclusive,
                }
            }
        } else if self.has_ground_truth {
            CaseResult::Missed
        } else {
            CaseResult::Inconclusive
        };

        let reason = match result {
            CaseResult::Rediscovered => {
                "reported finding replayed deterministically and the PoC demonstrated the violation"
                    .to_string()
            }
            CaseResult::NovelFinding => {
                "replayed and PoC-verified violation with no ground truth to compare against"
                    .to_string()
            }
            CaseResult::Missed => {
                if let Some(reason) = &self.inconclusive_reason {
                    reason.clone()
                } else if self.reported_finding && !self.replay_ok {
                    "reported finding did not replay deterministically".to_string()
                } else if self.reported_finding {
                    "reported finding replayed but the PoC did not demonstrate the violation"
                        .to_string()
                } else {
                    "no finding was reported for a case with known ground truth".to_string()
                }
            }
            CaseResult::Inconclusive => self
                .inconclusive_reason
                .clone()
                .or_else(|| {
                    (self.reported_finding && self.poc == PocOutcome::Inconclusive)
                        .then(|| "finding replayed but no PoC could be produced".to_string())
                })
                .unwrap_or_else(|| "no ground truth and no finding".to_string()),
        };

        ScoredCase {
            case_id: self.case_id.clone(),
            result,
            poc: self.poc,
            time_to_first_finding_ms: self.time_to_first_finding_ms,
            reason,
        }
    }
}

/// Aggregate report for a backtest run.
///
/// Every denominator that matters is reported alongside the rate, so a reader can
/// see how many cases each number was computed from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestReport {
    pub schema_version: u32,
    /// Total cases considered.
    pub total_cases: usize,
    /// Cases that entered the rediscovery numerator.
    pub rediscovered: usize,
    pub novel_findings: usize,
    pub missed: usize,
    pub inconclusive: usize,
    /// `rediscovered / total_cases`, or `None` when there are no cases.
    pub rediscovery_rate: Option<f64>,
    /// False positives per case: `missed / total_cases`.
    ///
    /// Reported as a rate over all cases rather than over claimed findings,
    /// because a tool that claims nothing should not be rewarded with a
    /// zero false-positive rate on a non-zero denominator.
    pub false_positive_rate: Option<f64>,
    /// Fraction of cases that could not be measured at all.
    pub unmeasured_rate: Option<f64>,
    pub median_time_to_first_finding_ms: Option<u64>,
    pub cases: Vec<ScoredCase>,
    /// True when `--strict` was requested and any case was `Inconclusive`.
    pub strict_failure: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RubricError {
    #[error("{count} case(s) are Inconclusive and --strict was requested: {cases:?}")]
    StrictViolation { count: usize, cases: Vec<String> },
}

impl BacktestReport {
    /// Builds the aggregate report from already-scored cases.
    pub fn from_scored(cases: Vec<ScoredCase>, strict: bool) -> Self {
        let total_cases = cases.len();
        let rediscovered = cases
            .iter()
            .filter(|case| case.result == CaseResult::Rediscovered)
            .count();
        let novel_findings = cases
            .iter()
            .filter(|case| case.result == CaseResult::NovelFinding)
            .count();
        let missed = cases
            .iter()
            .filter(|case| case.result == CaseResult::Missed)
            .count();
        let inconclusive = cases
            .iter()
            .filter(|case| case.result == CaseResult::Inconclusive)
            .count();

        let rate =
            |numerator: usize| (total_cases > 0).then(|| numerator as f64 / total_cases as f64);

        let mut times: Vec<u64> = cases
            .iter()
            .filter_map(|case| case.time_to_first_finding_ms)
            .collect();
        times.sort_unstable();
        let median_time_to_first_finding_ms = (!times.is_empty()).then(|| times[times.len() / 2]);

        let strict_failure = strict && inconclusive > 0;

        Self {
            schema_version: 1,
            total_cases,
            rediscovered,
            novel_findings,
            missed,
            inconclusive,
            rediscovery_rate: rate(rediscovered),
            false_positive_rate: rate(missed),
            unmeasured_rate: rate(inconclusive),
            median_time_to_first_finding_ms,
            cases,
            strict_failure,
        }
    }

    /// Convenience: score raw observations and aggregate.
    pub fn from_observations(observations: &[CaseObservation], strict: bool) -> Self {
        Self::from_scored(
            observations.iter().map(CaseObservation::score).collect(),
            strict,
        )
    }

    /// Enforces `--strict`: any `Inconclusive` case fails the run.
    pub fn enforce_strict(&self) -> Result<(), RubricError> {
        if !self.strict_failure {
            return Ok(());
        }
        let cases = self
            .cases
            .iter()
            .filter(|case| case.result == CaseResult::Inconclusive)
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>();
        Err(RubricError::StrictViolation {
            count: cases.len(),
            cases,
        })
    }

    /// Renders the summary table. Rendered from the numbers, never hand-written.
    pub fn summary_table(&self) -> String {
        let mut out = String::new();
        out.push_str("| metric | value |\n|---|---|\n");
        out.push_str(&format!("| total cases | {} |\n", self.total_cases));
        out.push_str(&format!("| rediscovered | {} |\n", self.rediscovered));
        out.push_str(&format!("| novel findings | {} |\n", self.novel_findings));
        out.push_str(&format!("| missed (false positives) | {} |\n", self.missed));
        out.push_str(&format!("| inconclusive | {} |\n", self.inconclusive));
        let fmt = |value: Option<f64>| match value {
            Some(value) => format!("{:.3}", value),
            None => "n/a".to_string(),
        };
        out.push_str(&format!(
            "| rediscovery rate | {} |\n",
            fmt(self.rediscovery_rate)
        ));
        out.push_str(&format!(
            "| false-positive rate | {} |\n",
            fmt(self.false_positive_rate)
        ));
        out.push_str(&format!(
            "| unmeasured rate | {} |\n",
            fmt(self.unmeasured_rate)
        ));
        out.push_str(&format!(
            "| median time to first finding (ms) | {} |\n",
            self.median_time_to_first_finding_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(case_id: &str, finding: bool, replay: bool, poc: PocOutcome) -> CaseObservation {
        CaseObservation {
            case_id: case_id.to_string(),
            reported_finding: finding,
            replay_ok: replay,
            poc,
            has_ground_truth: true,
            inconclusive_reason: None,
            time_to_first_finding_ms: finding.then_some(1_000),
        }
    }

    /// The headline requirement: one Pass and one Inconclusive must yield 1/N,
    /// never 2/N.
    #[test]
    fn pass_plus_inconclusive_yields_one_over_n() {
        let observations = vec![
            obs("case-pass", true, true, PocOutcome::Pass),
            obs("case-inconclusive", true, true, PocOutcome::Inconclusive),
        ];
        let report = BacktestReport::from_observations(&observations, false);

        assert_eq!(report.total_cases, 2);
        assert_eq!(report.rediscovered, 1);
        assert_eq!(report.inconclusive, 1);
        assert_eq!(
            report.rediscovery_rate,
            Some(0.5),
            "rediscovery must be 1/N, not 2/N"
        );
    }

    /// A false positive must land in its own bucket, not vanish.
    #[test]
    fn failed_poc_is_counted_as_a_false_positive() {
        let observations = vec![
            obs("case-pass", true, true, PocOutcome::Pass),
            obs("case-fail", true, true, PocOutcome::Fail),
        ];
        let report = BacktestReport::from_observations(&observations, false);

        assert_eq!(report.rediscovered, 1);
        assert_eq!(report.missed, 1);
        assert_eq!(report.false_positive_rate, Some(0.5));
        assert_eq!(report.rediscovery_rate, Some(0.5));
    }

    /// A finding that does not replay cannot count, whatever the PoC says.
    #[test]
    fn non_replaying_finding_cannot_count() {
        let observations = vec![obs("case-noreplay", true, false, PocOutcome::Pass)];
        let report = BacktestReport::from_observations(&observations, false);

        assert_eq!(report.rediscovered, 0);
        assert_eq!(report.missed, 1);
        assert_eq!(report.rediscovery_rate, Some(0.0));
    }

    /// Explicit "could not measure" wins over everything else.
    #[test]
    fn explicit_reason_forces_inconclusive() {
        let mut case = obs("case-no-rpc", true, true, PocOutcome::Pass);
        case.inconclusive_reason = Some("RPC unavailable".to_string());
        let scored = case.score();

        assert_eq!(scored.result, CaseResult::Inconclusive);
        assert_eq!(scored.reason, "RPC unavailable");
    }

    /// No finding on a ground-truth case is a miss; no finding on a case without
    /// ground truth is merely unmeasured.
    #[test]
    fn absence_of_finding_distinguishes_ground_truth_from_unknown() {
        let with_truth = obs("case-known", false, false, PocOutcome::Inconclusive);
        assert_eq!(with_truth.score().result, CaseResult::Missed);

        let mut unknown = obs("case-unknown", false, false, PocOutcome::Inconclusive);
        unknown.has_ground_truth = false;
        assert_eq!(unknown.score().result, CaseResult::Inconclusive);
    }

    /// Novel findings count separately and never as rediscoveries.
    #[test]
    fn novel_finding_is_reported_but_not_counted_as_rediscovery() {
        let mut case = obs("case-novel", true, true, PocOutcome::Pass);
        case.has_ground_truth = false;
        let report = BacktestReport::from_observations(&[case], false);

        assert_eq!(report.rediscovered, 0);
        assert_eq!(report.novel_findings, 1);
        assert_eq!(report.rediscovery_rate, Some(0.0));
    }

    #[test]
    fn strict_mode_fails_on_any_inconclusive_case() {
        let observations = vec![
            obs("case-pass", true, true, PocOutcome::Pass),
            obs("case-inconclusive", true, true, PocOutcome::Inconclusive),
        ];

        let lenient = BacktestReport::from_observations(&observations, false);
        assert!(lenient.enforce_strict().is_ok());

        let strict = BacktestReport::from_observations(&observations, true);
        assert!(strict.strict_failure);
        let error = strict.enforce_strict().unwrap_err();
        match error {
            RubricError::StrictViolation { count, cases } => {
                assert_eq!(count, 1);
                assert_eq!(cases, vec!["case-inconclusive".to_string()]);
            }
        }
    }

    #[test]
    fn empty_run_reports_no_rates_rather_than_zero() {
        let report = BacktestReport::from_observations(&[], false);
        assert_eq!(report.total_cases, 0);
        assert_eq!(report.rediscovery_rate, None);
        assert_eq!(report.false_positive_rate, None);
    }

    #[test]
    fn summary_table_reports_every_bucket() {
        let observations = vec![
            obs("a", true, true, PocOutcome::Pass),
            obs("b", true, true, PocOutcome::Fail),
            obs("c", false, false, PocOutcome::Inconclusive),
        ];
        let table = BacktestReport::from_observations(&observations, false).summary_table();

        for expected in [
            "total cases | 3",
            "rediscovered | 1",
            "missed (false positives) | 2",
            "unmeasured rate",
        ] {
            assert!(
                table.contains(expected),
                "table missing `{expected}`:\n{table}"
            );
        }
    }
}
