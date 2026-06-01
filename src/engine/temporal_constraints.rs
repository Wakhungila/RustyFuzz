use crate::engine::formal_spec::{FormalSpecification, TemporalConstraint, TemporalConstraintKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalViolation {
    pub constraint_id: String,
    pub kind: String,
    pub tx_indices: Vec<usize>,
    pub functions: Vec<String>,
    pub reason: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default)]
pub struct TemporalConstraintChecker {
    constraints: Vec<TemporalConstraint>,
    function_call_sequence: Vec<(usize, String)>, // (tx_index, selector)
    violations: Vec<TemporalViolation>,
    called_once: HashMap<String, usize>, // selector -> tx_index
}

impl TemporalConstraintChecker {
    pub fn new(spec: Option<&FormalSpecification>) -> Self {
        let constraints = spec
            .map(|s| s.temporal_constraints.clone())
            .unwrap_or_default();

        Self {
            constraints,
            function_call_sequence: Vec::new(),
            violations: Vec::new(),
            called_once: HashMap::new(),
        }
    }

    pub fn record_function_call(&mut self, tx_index: usize, selector: &str) {
        self.function_call_sequence
            .push((tx_index, selector.to_string()));

        // Record one-time-only calls
        self.called_once
            .entry(selector.to_string())
            .or_insert(tx_index);
    }

    pub fn check_constraints(&mut self) -> Vec<TemporalViolation> {
        let constraints = self.constraints.clone();
        for constraint in &constraints {
            match constraint.kind {
                TemporalConstraintKind::MustPrecede => self.check_must_precede(constraint),
                TemporalConstraintKind::CannotFollow => self.check_cannot_follow(constraint),
                TemporalConstraintKind::RequireInterval => self.check_require_interval(constraint),
                TemporalConstraintKind::OneTimeOnly => self.check_one_time_only(constraint),
            }
        }
        self.violations.clone()
    }

    fn check_must_precede(&mut self, constraint: &TemporalConstraint) {
        // constraint.functions[0] must be called before constraint.functions[1]
        if constraint.functions.len() < 2 {
            return;
        }

        let first_func = &constraint.functions[0];
        let second_func = &constraint.functions[1];

        let first_call = self
            .function_call_sequence
            .iter()
            .position(|(_, sel)| sel == first_func);
        let second_call = self
            .function_call_sequence
            .iter()
            .position(|(_, sel)| sel == second_func);

        if let (Some(first_idx), Some(second_idx)) = (first_call, second_call) {
            if first_idx > second_idx {
                let (tx1, _) = self.function_call_sequence[first_idx];
                let (tx2, _) = self.function_call_sequence[second_idx];
                self.violations.push(TemporalViolation {
                    constraint_id: constraint.id.clone(),
                    kind: "must_precede".to_string(),
                    tx_indices: vec![tx2, tx1],
                    functions: vec![first_func.clone(), second_func.clone()],
                    reason: format!("{} must be called before {}", first_func, second_func),
                    severity: "high".to_string(),
                });
            }
        } else if second_call.is_some() && first_call.is_none() {
            self.violations.push(TemporalViolation {
                constraint_id: constraint.id.clone(),
                kind: "must_precede".to_string(),
                tx_indices: vec![],
                functions: vec![first_func.clone(), second_func.clone()],
                reason: format!("{} is called but {} is not", second_func, first_func),
                severity: "critical".to_string(),
            });
        }
    }

    fn check_cannot_follow(&mut self, constraint: &TemporalConstraint) {
        // constraint.functions[1] cannot be called after constraint.functions[0]
        if constraint.functions.len() < 2 {
            return;
        }

        let first_func = &constraint.functions[0];
        let second_func = &constraint.functions[1];

        let mut first_seen = false;
        for (tx_idx, (_, sel)) in self.function_call_sequence.iter().enumerate() {
            if sel == first_func {
                first_seen = true;
            } else if sel == second_func && first_seen {
                self.violations.push(TemporalViolation {
                    constraint_id: constraint.id.clone(),
                    kind: "cannot_follow".to_string(),
                    tx_indices: vec![tx_idx],
                    functions: vec![first_func.clone(), second_func.clone()],
                    reason: format!("{} cannot be called after {}", second_func, first_func),
                    severity: "high".to_string(),
                });
            }
        }
    }

    fn check_require_interval(&mut self, constraint: &TemporalConstraint) {
        // Functions must be called within N blocks
        let max_gap = constraint.max_gap_blocks.unwrap_or(10);
        if constraint.functions.len() < 2 {
            return;
        }

        let first_func = &constraint.functions[0];
        let second_func = &constraint.functions[1];

        if let (Some(first_idx), Some(second_idx)) = (
            self.function_call_sequence
                .iter()
                .position(|(_, sel)| sel == first_func),
            self.function_call_sequence
                .iter()
                .position(|(_, sel)| sel == second_func),
        ) {
            let gap = (second_idx as u64).abs_diff(first_idx as u64);
            if gap > max_gap {
                self.violations.push(TemporalViolation {
                    constraint_id: constraint.id.clone(),
                    kind: "require_interval".to_string(),
                    tx_indices: vec![first_idx, second_idx],
                    functions: vec![first_func.clone(), second_func.clone()],
                    reason: format!(
                        "{} and {} must be called within {} blocks (gap was {})",
                        first_func, second_func, max_gap, gap
                    ),
                    severity: "medium".to_string(),
                });
            }
        }
    }

    fn check_one_time_only(&mut self, constraint: &TemporalConstraint) {
        // Each function can only be called once per sequence
        for selector in &constraint.functions {
            let call_count = self
                .function_call_sequence
                .iter()
                .filter(|(_, sel)| sel == selector)
                .count();
            if call_count > 1 {
                let indices: Vec<_> = self
                    .function_call_sequence
                    .iter()
                    .enumerate()
                    .filter_map(|(_idx, (tx_idx, sel))| {
                        if sel == selector {
                            Some(*tx_idx as usize)
                        } else {
                            None
                        }
                    })
                    .collect();
                self.violations.push(TemporalViolation {
                    constraint_id: constraint.id.clone(),
                    kind: "one_time_only".to_string(),
                    tx_indices: indices,
                    functions: vec![selector.clone()],
                    reason: format!(
                        "{} can only be called once, but was called {} times",
                        selector, call_count
                    ),
                    severity: "high".to_string(),
                });
            }
        }
    }

    pub fn violations(&self) -> &[TemporalViolation] {
        &self.violations
    }

    pub fn detect_initialization_patterns(&self) -> Vec<String> {
        // Flag common initialization-related selectors to help identify must-precede constraints
        let mut init_patterns = Vec::new();
        for (tx_idx, (_, sel)) in self.function_call_sequence.iter().enumerate() {
            if sel.contains("initialize") || sel.contains("init") || sel.contains("setup") {
                if tx_idx > 0 {
                    init_patterns.push(format!(
                        "Potential initialization selector '{}' called at non-zero index {}",
                        sel, tx_idx
                    ));
                }
            }
        }
        init_patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_must_precede_violation() {
        let constraint = TemporalConstraint {
            id: "init-first".to_string(),
            kind: TemporalConstraintKind::MustPrecede,
            functions: vec!["initialize".to_string(), "deposit".to_string()],
            max_gap_blocks: None,
        };

        let spec = {
            let mut s = FormalSpecification::empty();
            s.temporal_constraints = vec![constraint];
            s
        };

        let mut checker = TemporalConstraintChecker::new(Some(&spec));
        checker.record_function_call(0, "deposit");
        checker.record_function_call(1, "initialize");

        let violations = checker.check_constraints();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, "must_precede");
    }

    #[test]
    fn detects_cannot_follow_violation() {
        let constraint = TemporalConstraint {
            id: "no-unpause-after-pause".to_string(),
            kind: TemporalConstraintKind::CannotFollow,
            functions: vec!["pause".to_string(), "unpause".to_string()],
            max_gap_blocks: None,
        };

        let spec = {
            let mut s = FormalSpecification::empty();
            s.temporal_constraints = vec![constraint];
            s
        };

        let mut checker = TemporalConstraintChecker::new(Some(&spec));
        checker.record_function_call(0, "pause");
        checker.record_function_call(1, "unpause");

        let violations = checker.check_constraints();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, "cannot_follow");
    }

    #[test]
    fn detects_one_time_only_violation() {
        let constraint = TemporalConstraint {
            id: "initialize-once".to_string(),
            kind: TemporalConstraintKind::OneTimeOnly,
            functions: vec!["initialize".to_string()],
            max_gap_blocks: None,
        };

        let spec = {
            let mut s = FormalSpecification::empty();
            s.temporal_constraints = vec![constraint];
            s
        };

        let mut checker = TemporalConstraintChecker::new(Some(&spec));
        checker.record_function_call(0, "initialize");
        checker.record_function_call(1, "initialize");

        let violations = checker.check_constraints();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, "one_time_only");
    }
}
