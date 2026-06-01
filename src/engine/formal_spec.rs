use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormalSpecification {
    pub contract: Option<Address>,
    pub architectural_invariants: Vec<ArchitecturalInvariant>,
    pub state_machine: Option<StateMachineSpec>,
    pub permission_model: Option<PermissionModelSpec>,
    pub temporal_constraints: Vec<TemporalConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchitecturalInvariant {
    pub id: String,
    pub description: String,
    pub kind: InvariantKind,
    pub severity: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    AdminCannotTransferUserFunds,
    OnlyGovernanceCanUpgrade,
    ReservesAlwaysIncreasing,
    FeesNeverExceed,
    NoUnauthorizedStateChange,
    EconomicSanity,
    SlippageProtectionExists,
    CircuitBreakerExists,
    RateLimitEnforced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMachineSpec {
    pub states: Vec<String>,
    pub initial_state: String,
    pub transitions: Vec<StateTransition>,
    pub forbidden_transitions: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateTransition {
    pub from: String,
    pub to: String,
    pub trigger_selector: Option<String>,
    #[serde(default)]
    pub guard_conditions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionModelSpec {
    pub roles: Vec<Role>,
    pub function_permissions: Vec<FunctionPermission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub allowed_functions: Vec<String>,
    #[serde(default)]
    pub max_privileges: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionPermission {
    pub selector: String,
    pub required_roles: Vec<String>,
    #[serde(default)]
    pub mutually_exclusive_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporalConstraint {
    pub id: String,
    pub kind: TemporalConstraintKind,
    pub functions: Vec<String>,
    pub max_gap_blocks: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemporalConstraintKind {
    MustPrecede,     // first function must be called before second
    CannotFollow,    // second function cannot be called after first
    RequireInterval, // functions must be called within N blocks
    OneTimeOnly,     // function can only be called once per sequence
}

impl FormalSpecification {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)?;
        toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse formal spec: {}", e))
    }

    pub fn empty() -> Self {
        Self {
            contract: None,
            architectural_invariants: Vec::new(),
            state_machine: None,
            permission_model: None,
            temporal_constraints: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: Self) {
        if other.contract.is_some() {
            self.contract = other.contract;
        }
        self.architectural_invariants
            .extend(other.architectural_invariants);
        if other.state_machine.is_some() {
            self.state_machine = other.state_machine;
        }
        if other.permission_model.is_some() {
            self.permission_model = other.permission_model;
        }
        self.temporal_constraints.extend(other.temporal_constraints);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_formal_spec_from_toml() {
        let toml = r#"
contract = "0x0000000000000000000000000000000000000001"

[[architectural_invariants]]
id = "no-admin-transfer"
description = "Admin cannot transfer user funds"
kind = "admin_cannot_transfer_user_funds"
severity = "critical"

[[temporal_constraints]]
id = "init-before-use"
kind = "must_precede"
functions = ["initialize()", "deposit(uint256)"]
"#;
        let spec: FormalSpecification = toml::from_str(toml).expect("parse failed");
        assert_eq!(spec.architectural_invariants.len(), 1);
        assert_eq!(spec.temporal_constraints.len(), 1);
    }
}
