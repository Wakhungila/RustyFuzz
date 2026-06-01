use crate::engine::formal_spec::{FormalSpecification, StateMachineSpec};
use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionViolation {
    pub tx_index: usize,
    pub from_state: String,
    pub to_state: String,
    pub function_called: String,
    pub reason: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default)]
pub struct StateTransitionChecker {
    state_machine: Option<StateMachineSpec>,
    current_state: String,
    state_history: Vec<(usize, String)>,
    violations: Vec<StateTransitionViolation>,
}

impl StateTransitionChecker {
    pub fn new(spec: Option<&FormalSpecification>) -> Self {
        let (sm, initial_state) = spec
            .and_then(|s| {
                s.state_machine
                    .as_ref()
                    .map(|sm| (Some(sm.clone()), sm.initial_state.clone()))
            })
            .unwrap_or((None, "Unknown".to_string()));

        Self {
            state_machine: sm,
            current_state: initial_state,
            state_history: Vec::new(),
            violations: Vec::new(),
        }
    }

    pub fn infer_state_from_storage(&mut self, storage_diffs: &[(Address, B256, U256, U256)]) {
        // Heuristic: slot writes often correspond to state transitions
        // Common pattern: slot 0 stores state (for simple contracts)
        if let Some((_, slot, _old, new)) = storage_diffs.first() {
            if *slot == B256::ZERO && *new != U256::ZERO {
                let state_name = self.state_from_value(*new);
                self.current_state = state_name;
            }
        }
    }

    fn state_from_value(&self, value: U256) -> String {
        let val = if value > U256::from(u32::MAX) {
            u32::MAX
        } else {
            value.as_limbs()[0] as u32
        };
        match val {
            0 => "Uninitialized".to_string(),
            1 => "Initialized".to_string(),
            2 => "Active".to_string(),
            3 => "Paused".to_string(),
            4 => "Closed".to_string(),
            _ => format!("State({})", val),
        }
    }

    pub fn check_transition(
        &mut self,
        tx_index: usize,
        function_selector: &str,
        new_state: &str,
    ) -> Option<StateTransitionViolation> {
        let old_state = self.current_state.clone();
        self.current_state = new_state.to_string();
        self.state_history.push((tx_index, new_state.to_string()));

        if let Some(sm) = &self.state_machine {
            let is_allowed = sm.transitions.iter().any(|t| {
                t.from == old_state
                    && t.to == new_state
                    && (t.trigger_selector.is_none()
                        || t.trigger_selector
                            .as_ref()
                            .map_or(true, |sel| sel == function_selector))
            });

            let is_forbidden = sm
                .forbidden_transitions
                .iter()
                .any(|t| t.0 == old_state && t.1 == new_state);

            if is_forbidden || (!is_allowed && !sm.transitions.is_empty()) {
                let violation = StateTransitionViolation {
                    tx_index,
                    from_state: old_state.clone(),
                    to_state: new_state.to_string(),
                    function_called: function_selector.to_string(),
                    reason: if is_forbidden {
                        "Forbidden transition".to_string()
                    } else {
                        "Undefined transition in state machine".to_string()
                    },
                    severity: if is_forbidden {
                        "critical".to_string()
                    } else {
                        "high".to_string()
                    },
                };
                self.violations.push(violation.clone());
                return Some(violation);
            }
        }
        None
    }

    pub fn violations(&self) -> &[StateTransitionViolation] {
        &self.violations
    }

    pub fn state_history(&self) -> &[(usize, String)] {
        &self.state_history
    }

    pub fn find_skipped_states(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        if let Some(sm) = &self.state_machine {
            for window in self.state_history.windows(2) {
                let from = &window[0].1;
                let to = &window[1].1;
                let allowed = sm
                    .transitions
                    .iter()
                    .any(|t| &t.from == from && &t.to == to);
                if !allowed {
                    result.push((from.clone(), to.clone()));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::formal_spec::{FormalSpecification, StateMachineSpec, StateTransition};

    #[test]
    fn detects_forbidden_state_transitions() {
        let mut spec = FormalSpecification::empty();
        spec.state_machine = Some(StateMachineSpec {
            states: vec![
                "Init".to_string(),
                "Active".to_string(),
                "Paused".to_string(),
            ],
            initial_state: "Init".to_string(),
            transitions: vec![
                StateTransition {
                    from: "Init".to_string(),
                    to: "Active".to_string(),
                    trigger_selector: None,
                    guard_conditions: vec![],
                },
                StateTransition {
                    from: "Active".to_string(),
                    to: "Paused".to_string(),
                    trigger_selector: None,
                    guard_conditions: vec![],
                },
            ],
            forbidden_transitions: vec![("Paused".to_string(), "Active".to_string())],
        });

        let mut checker = StateTransitionChecker::new(Some(&spec));
        checker.check_transition(0, "initialize", "Active");
        let violation = checker.check_transition(1, "pause", "Paused");
        assert!(violation.is_none()); // Allowed
        let violation = checker.check_transition(2, "unpause", "Active");
        assert!(violation.is_some()); // Forbidden
        assert_eq!(violation.unwrap().reason, "Forbidden transition");
    }

    #[test]
    fn tracks_state_history() {
        let checker = StateTransitionChecker::new(None);
        let mut checker = checker;
        checker.check_transition(0, "func1", "State1");
        checker.check_transition(1, "func2", "State2");
        checker.check_transition(2, "func3", "State3");

        assert_eq!(checker.state_history().len(), 3);
        assert_eq!(checker.state_history()[0].1, "State1");
        assert_eq!(checker.state_history()[2].1, "State3");
    }
}
