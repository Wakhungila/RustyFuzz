use crate::engine::formal_spec::{StateMachineSpec, StateTransition};
use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredStateMachine {
    pub states: Vec<String>,
    pub state_slot: Option<B256>, // Where state is stored
    pub transitions: Vec<InferredTransition>,
    pub state_values: HashMap<String, U256>, // Mapping of state name to its value
    pub confidence: u64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredTransition {
    pub from_state: String,
    pub to_state: String,
    pub trigger_selectors: Vec<String>,
    pub storage_reads: Vec<B256>,
    pub storage_writes: Vec<B256>,
}

#[allow(dead_code)]
pub struct StateMachineInference {
    inferred_machine: Option<InferredStateMachine>,
    state_transitions: Vec<(u64, String, String)>, // (block, from_state, to_state)
    storage_access_patterns: HashMap<B256, Vec<String>>, // slot -> operations
}

impl StateMachineInference {
    pub fn new() -> Self {
        Self {
            inferred_machine: None,
            state_transitions: Vec::new(),
            storage_access_patterns: HashMap::new(),
        }
    }

    pub fn infer_from_execution_trace(
        &mut self,
        storage_diffs: &[(Address, B256, U256, U256)],
        function_calls: &[String],
    ) -> Option<InferredStateMachine> {
        // Heuristic 1: Detect state slot (usually slot 0 or a specific constant)
        let potential_state_slots = Self::identify_state_slots(storage_diffs);

        let mut best_machine = None;
        let mut best_confidence = 0u64;

        for slot in potential_state_slots {
            if let Some(machine) = self.infer_for_slot(slot, storage_diffs, function_calls) {
                if machine.confidence > best_confidence {
                    best_confidence = machine.confidence;
                    best_machine = Some(machine);
                }
            }
        }

        self.inferred_machine = best_machine.clone();
        best_machine
    }

    fn identify_state_slots(storage_diffs: &[(Address, B256, U256, U256)]) -> Vec<B256> {
        let mut slots = HashSet::new();

        // Common state storage slots
        slots.insert(B256::ZERO); // slot 0 - often used for state

        // Look for slots with small value changes (likely state enums)
        for (_, slot, old_val, new_val) in storage_diffs {
            if old_val != new_val && new_val < &U256::from(100) {
                slots.insert(*slot);
            }
        }

        slots.into_iter().collect()
    }

    fn infer_for_slot(
        &self,
        slot: B256,
        storage_diffs: &[(Address, B256, U256, U256)],
        function_calls: &[String],
    ) -> Option<InferredStateMachine> {
        let mut states = HashMap::new();
        let mut transitions = Vec::new();
        let mut evidence = Vec::new();
        let mut state_sequence = Vec::new();

        // Extract state values from storage diffs
        for (_, s, old, new) in storage_diffs {
            if s == &slot {
                state_sequence.push((old.clone(), new.clone()));
                states.entry(Self::state_name(new)).or_insert(*new);
            }
        }

        if states.len() < 2 {
            return None; // Need at least 2 states
        }

        // Infer transitions from sequence
        for window in state_sequence.windows(2) {
            let from_state = Self::state_name(&window[0].1);
            let to_state = Self::state_name(&window[1].1);

            transitions.push(InferredTransition {
                from_state,
                to_state,
                trigger_selectors: function_calls.to_vec(),
                storage_reads: vec![slot],
                storage_writes: vec![slot],
            });
        }

        evidence.push(format!("Inferred state slot: 0x{:x}", slot));
        evidence.push(format!("State values: {:?}", states));
        evidence.push(format!("Transitions: {}", transitions.len()));

        let confidence = (states.len() as u64 * 20) + (transitions.len() as u64 * 30);

        let mut state_vals = HashMap::new();
        for (state, val) in states {
            state_vals.insert(state, val);
        }

        Some(InferredStateMachine {
            states: state_vals.keys().cloned().collect(),
            state_slot: Some(slot),
            transitions,
            state_values: state_vals,
            confidence: confidence.min(100),
            evidence,
        })
    }

    fn state_name(value: &U256) -> String {
        let val = if *value > U256::from(u32::MAX) {
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
            5 => "Liquidating".to_string(),
            _ => format!("State{}", val),
        }
    }

    pub fn to_formal_spec(&self) -> Option<StateMachineSpec> {
        self.inferred_machine.as_ref().map(|machine| {
            let transitions: Vec<StateTransition> = machine
                .transitions
                .iter()
                .map(|t| StateTransition {
                    from: t.from_state.clone(),
                    to: t.to_state.clone(),
                    trigger_selector: t.trigger_selectors.first().cloned(),
                    guard_conditions: vec![],
                })
                .collect();

            StateMachineSpec {
                states: machine.states.clone(),
                initial_state: "Uninitialized".to_string(),
                transitions,
                forbidden_transitions: vec![],
            }
        })
    }

    pub fn detect_suspicious_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();

        if let Some(machine) = &self.inferred_machine {
            // Pattern 1: Too many states (likely not a simple state machine)
            if machine.states.len() > 10 {
                patterns.push(format!(
                    "Unusually large state space ({} states) - may not be a traditional state machine",
                    machine.states.len()
                ));
            }

            // Pattern 2: Single transition to many states (fan-out)
            let mut transition_out: HashMap<_, u32> = HashMap::new();
            for t in &machine.transitions {
                *transition_out.entry(&t.from_state).or_insert(0) += 1;
            }

            for (state, count) in transition_out {
                if count > 5 {
                    patterns.push(format!(
                        "State '{}' has {} outgoing transitions (suspicious fan-out)",
                        state, count
                    ));
                }
            }

            // Pattern 3: State that's never reached
            let mut in_degree: HashMap<_, u32> = HashMap::new();
            for s in &machine.states {
                in_degree.insert(s.clone(), 0);
            }
            for t in &machine.transitions {
                *in_degree.get_mut(&t.to_state).unwrap() += 1;
            }

            for (state, degree) in in_degree {
                if degree == 0 && state != "Uninitialized" {
                    patterns.push(format!("State '{}' is unreachable", state));
                }
            }
        }

        patterns
    }
}

impl Default for StateMachineInference {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_simple_state_machine() {
        let mut inference = StateMachineInference::new();

        let storage_diffs = vec![
            (Address::ZERO, B256::ZERO, U256::from(0), U256::from(1)),
            (Address::ZERO, B256::ZERO, U256::from(1), U256::from(2)),
            (Address::ZERO, B256::ZERO, U256::from(2), U256::from(3)),
        ];

        let machine =
            inference.infer_from_execution_trace(&storage_diffs, &["initialize".to_string()]);

        assert!(machine.is_some());
        let m = machine.unwrap();
        assert_eq!(m.states.len(), 3);
        assert!(m.confidence > 0);
    }

    #[test]
    fn converts_to_formal_spec() {
        let machine = InferredStateMachine {
            states: vec!["Init".to_string(), "Active".to_string()],
            state_slot: Some(B256::ZERO),
            transitions: vec![InferredTransition {
                from_state: "Init".to_string(),
                to_state: "Active".to_string(),
                trigger_selectors: vec!["initialize".to_string()],
                storage_reads: vec![],
                storage_writes: vec![],
            }],
            state_values: {
                let mut m = HashMap::new();
                m.insert("Init".to_string(), U256::from(0));
                m.insert("Active".to_string(), U256::from(1));
                m
            },
            confidence: 85,
            evidence: vec![],
        };

        let mut inference = StateMachineInference::new();
        inference.inferred_machine = Some(machine);

        let spec = inference.to_formal_spec();
        assert!(spec.is_some());
        assert_eq!(spec.unwrap().states.len(), 2);
    }
}
