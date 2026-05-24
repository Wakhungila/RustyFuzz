use crate::engine::target_profile::ProtocolType;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct StateMachineStep {
    pub action: String,
    pub required_preconditions: Vec<String>,
    pub expected_state_effects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolStateMachine {
    pub name: String,
    pub protocol: ProtocolType,
    pub steps: Vec<StateMachineStep>,
    pub rejection_rules: Vec<String>,
}

impl ProtocolStateMachine {
    pub fn is_sequence_shape_valid(&self, actions: &[String]) -> bool {
        if actions.is_empty() || actions.len() > self.steps.len() {
            return false;
        }
        actions
            .iter()
            .zip(self.steps.iter())
            .all(|(actual, expected)| action_matches(actual, &expected.action))
    }
}

pub fn state_machines_for_protocols(protocols: &[ProtocolType]) -> Vec<ProtocolStateMachine> {
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for protocol in protocols {
        for machine in state_machines_for_protocol(protocol) {
            if names.insert(machine.name.clone()) {
                out.push(machine);
            }
        }
    }
    if out.is_empty() {
        out.push(generic_machine());
    }
    out
}

pub fn state_machines_for_protocol(protocol: &ProtocolType) -> Vec<ProtocolStateMachine> {
    match protocol {
        ProtocolType::Erc4626Vault => vec![vault_machine()],
        ProtocolType::AmmDexPool => vec![amm_machine()],
        ProtocolType::LendingBorrowing => vec![lending_machine()],
        ProtocolType::GovernanceTimelock => vec![governance_machine()],
        ProtocolType::BridgeMessagePassing => vec![bridge_machine()],
        ProtocolType::StakingRewards => vec![rewards_machine()],
        ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable => {
            vec![access_control_machine()]
        }
        _ => vec![generic_machine()],
    }
}

fn step(
    action: &str,
    required_preconditions: &[&str],
    expected_state_effects: &[&str],
) -> StateMachineStep {
    StateMachineStep {
        action: action.to_string(),
        required_preconditions: required_preconditions
            .iter()
            .map(|s| s.to_string())
            .collect(),
        expected_state_effects: expected_state_effects
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn vault_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "vault-inflation".to_string(),
        protocol: ProtocolType::Erc4626Vault,
        steps: vec![
            step(
                "deposit",
                &["attacker asset balance"],
                &["attacker shares increase"],
            ),
            step(
                "donate",
                &["asset transfer path"],
                &["total assets increase without shares"],
            ),
            step(
                "deposit",
                &["victim asset balance"],
                &["victim shares minted"],
            ),
            step(
                "redeem",
                &["attacker shares"],
                &["attacker assets returned"],
            ),
        ],
        rejection_rules: vec![
            "reject redeem before attacker owns shares".to_string(),
            "reject victim deposit before vault has attacker-seeded shares".to_string(),
        ],
    }
}

fn amm_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "amm-price-manipulation".to_string(),
        protocol: ProtocolType::AmmDexPool,
        steps: vec![
            step("approve", &["attacker token balance"], &["allowance set"]),
            step("swap", &["pool reserves"], &["price/reserve movement"]),
            step(
                "dependent_action",
                &["manipulated price"],
                &["economic state changes"],
            ),
            step(
                "swap",
                &["remaining token balance"],
                &["partial price restoration"],
            ),
        ],
        rejection_rules: vec![
            "reject swap before approval when token requires allowance".to_string()
        ],
    }
}

fn lending_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "lending-bad-debt".to_string(),
        protocol: ProtocolType::LendingBorrowing,
        steps: vec![
            step(
                "supply",
                &["collateral token balance"],
                &["collateral increases"],
            ),
            step(
                "borrow",
                &["collateral above threshold"],
                &["debt increases"],
            ),
            step("price_move", &["oracle path"], &["health factor changes"]),
            step(
                "liquidate",
                &["liquidator actor"],
                &["debt/collateral shifts"],
            ),
            step(
                "withdraw",
                &["remaining collateral"],
                &["collateral leaves protocol"],
            ),
        ],
        rejection_rules: vec![
            "reject borrow before collateral".to_string(),
            "reject liquidation without debt".to_string(),
        ],
    }
}

fn governance_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "governance-timelock".to_string(),
        protocol: ProtocolType::GovernanceTimelock,
        steps: vec![
            step("propose", &["proposal threshold"], &["proposal created"]),
            step("vote", &["voter power"], &["votes recorded"]),
            step("queue", &["proposal passed"], &["eta set"]),
            step("execute", &["delay elapsed"], &["target call executed"]),
        ],
        rejection_rules: vec![
            "reject execute before queue".to_string(),
            "reject execute before delay unless testing bypass".to_string(),
        ],
    }
}

fn bridge_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "bridge-finalization".to_string(),
        protocol: ProtocolType::BridgeMessagePassing,
        steps: vec![
            step("send", &["message payload"], &["message hash recorded"]),
            step("prove", &["proof material"], &["message proven"]),
            step("finalize", &["message proven"], &["message consumed"]),
            step(
                "finalize",
                &["message already consumed"],
                &["replay rejected"],
            ),
        ],
        rejection_rules: vec!["reject finalize without proof unless testing bypass".to_string()],
    }
}

fn rewards_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "staking-rewards".to_string(),
        protocol: ProtocolType::StakingRewards,
        steps: vec![
            step(
                "stake",
                &["staking token balance"],
                &["stake balance increases"],
            ),
            step(
                "accrue",
                &["time or block movement"],
                &["claimable rewards increase"],
            ),
            step("claim", &["claimable rewards"], &["rewards paid"]),
            step("unstake", &["stake balance"], &["stake balance decreases"]),
            step("claim", &["already claimed"], &["double claim rejected"]),
        ],
        rejection_rules: vec!["reject claim before stake/accrual unless testing bypass".to_string()],
    }
}

fn access_control_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "access-control-sensitive-call".to_string(),
        protocol: ProtocolType::AccessControlHeavy,
        steps: vec![
            step(
                "sensitive_call",
                &["non-admin actor"],
                &["no privileged write expected"],
            ),
            step(
                "sensitive_call",
                &["role-like actor"],
                &["privileged write if authorized"],
            ),
        ],
        rejection_rules: vec!["confirmed finding requires unauthorized state mutation".to_string()],
    }
}

fn generic_machine() -> ProtocolStateMachine {
    ProtocolStateMachine {
        name: "generic-stateful-sequence".to_string(),
        protocol: ProtocolType::Unknown,
        steps: vec![step(
            "call",
            &["funded caller"],
            &["state transition or revert evidence"],
        )],
        rejection_rules: vec![
            "generic reverts are not exploit evidence without invariant pressure".to_string(),
        ],
    }
}

fn action_matches(actual: &str, expected: &str) -> bool {
    let actual = actual.to_ascii_lowercase();
    let expected = expected.to_ascii_lowercase();
    actual == expected || actual.contains(&expected) || expected.contains(&actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_machine_rejects_out_of_order_shape() {
        let machine = vault_machine();
        assert!(machine.is_sequence_shape_valid(&[
            "deposit".to_string(),
            "donate".to_string(),
            "deposit".to_string(),
            "redeem".to_string(),
        ]));
        assert!(!machine.is_sequence_shape_valid(&["redeem".to_string(), "deposit".to_string(),]));
    }

    #[test]
    fn protocol_list_generates_unique_machines() {
        let machines = state_machines_for_protocols(&[
            ProtocolType::Erc4626Vault,
            ProtocolType::Erc4626Vault,
            ProtocolType::AmmDexPool,
        ]);
        assert_eq!(machines.len(), 2);
        assert!(machines.iter().any(|m| m.name == "vault-inflation"));
        assert!(machines.iter().any(|m| m.name == "amm-price-manipulation"));
    }
}
