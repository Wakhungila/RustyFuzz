use crate::common::types::SingletonTx;
use crate::evm::fork_db::ForkDb;
use revm::database::CacheDB;
use revm::primitives::{Address, U256};
use revm::state::AccountInfo;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActorType {
    Attacker,
    Victim,
    Whale,
    Depositor,
    Borrower,
    Liquidator,
    Trader,
    GovernanceProposer,
    GovernanceVoter,
    Keeper,
    PrivilegedCandidate,
    RandomUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub role: ActorType,
    pub address: Address,
    pub synthetic: bool,
    pub initial_balance: U256,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorSet {
    pub actors: Vec<Actor>,
    pub observed_callers: Vec<Address>,
}

impl ActorSet {
    pub fn by_role(&self, role: ActorType) -> Option<&Actor> {
        self.actors.iter().find(|actor| actor.role == role)
    }

    pub fn address_for(&self, role: ActorType) -> Address {
        self.by_role(role)
            .map(|actor| actor.address)
            .or_else(|| self.actors.first().map(|actor| actor.address))
            .unwrap_or_else(|| Address::repeat_byte(0x13))
    }

    pub fn fund_synthetic_actors(&self, db: &mut CacheDB<ForkDb>) {
        for actor in self.actors.iter().filter(|actor| actor.synthetic) {
            db.insert_account_info(
                actor.address,
                AccountInfo {
                    balance: actor.initial_balance,
                    ..AccountInfo::default()
                },
            );
        }
    }

    pub fn apply_roles_to_sequence(&self, txs: &mut [SingletonTx]) -> BTreeMap<usize, ActorType> {
        let mut assigned = BTreeMap::new();
        let len = txs.len();
        for (idx, tx) in txs.iter_mut().enumerate() {
            let role = role_for_position(idx, len);
            tx.caller = self.address_for(role);
            tx.is_victim = role == ActorType::Victim;
            assigned.insert(idx, role);
        }
        assigned
    }
}

#[derive(Debug, Clone)]
pub struct ActorModelConfig {
    pub fuzzer_address: Address,
    pub synthetic_balance: U256,
    pub preserve_single_fuzzer_fallback: bool,
}

impl Default for ActorModelConfig {
    fn default() -> Self {
        Self {
            fuzzer_address: Address::repeat_byte(0x13),
            synthetic_balance: U256::from(10u128.pow(30)),
            preserve_single_fuzzer_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActorModel {
    config: ActorModelConfig,
}

impl ActorModel {
    pub fn new(config: ActorModelConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self, observed_callers: impl IntoIterator<Item = Address>) -> ActorSet {
        let observed = observed_callers.into_iter().collect::<BTreeSet<_>>();
        let observed_vec = observed.iter().copied().collect::<Vec<_>>();
        let mut actors = Vec::new();
        let roles = [
            ActorType::Attacker,
            ActorType::Victim,
            ActorType::Whale,
            ActorType::Depositor,
            ActorType::Borrower,
            ActorType::Liquidator,
            ActorType::Trader,
            ActorType::GovernanceProposer,
            ActorType::GovernanceVoter,
            ActorType::Keeper,
            ActorType::PrivilegedCandidate,
            ActorType::RandomUser,
        ];

        for (idx, role) in roles.into_iter().enumerate() {
            let observed_address = observed_vec.get(idx).copied();
            let address = observed_address.unwrap_or_else(|| synthetic_actor_address(role));
            actors.push(Actor {
                role,
                address,
                synthetic: observed_address.is_none(),
                initial_balance: self.config.synthetic_balance,
                explanation: if observed_address.is_some() {
                    "historical caller reused for role model".to_string()
                } else {
                    format!("synthetic {:?} actor", role)
                },
            });
        }

        if self.config.preserve_single_fuzzer_fallback
            && !actors
                .iter()
                .any(|actor| actor.address == self.config.fuzzer_address)
        {
            actors.push(Actor {
                role: ActorType::RandomUser,
                address: self.config.fuzzer_address,
                synthetic: true,
                initial_balance: self.config.synthetic_balance,
                explanation: "legacy single fuzzer address fallback".to_string(),
            });
        }

        ActorSet {
            actors,
            observed_callers: observed_vec,
        }
    }
}

pub fn synthetic_actor_address(role: ActorType) -> Address {
    let byte = match role {
        ActorType::Attacker => 0xa1,
        ActorType::Victim => 0xb1,
        ActorType::Whale => 0xc1,
        ActorType::Depositor => 0xd1,
        ActorType::Borrower => 0xe1,
        ActorType::Liquidator => 0xf1,
        ActorType::Trader => 0x71,
        ActorType::GovernanceProposer => 0x72,
        ActorType::GovernanceVoter => 0x73,
        ActorType::Keeper => 0x74,
        ActorType::PrivilegedCandidate => 0x75,
        ActorType::RandomUser => 0x76,
    };
    Address::repeat_byte(byte)
}

fn role_for_position(idx: usize, len: usize) -> ActorType {
    if len >= 4 {
        match idx {
            0 => ActorType::Attacker,
            1 => ActorType::Victim,
            2 => ActorType::Attacker,
            _ => ActorType::Liquidator,
        }
    } else if idx == 0 {
        ActorType::Attacker
    } else {
        ActorType::RandomUser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::database_interface::DatabaseRef;

    #[test]
    fn generates_role_specific_actors_with_fallback() {
        let actors = ActorModel::default().generate([]);
        assert!(actors.by_role(ActorType::Attacker).is_some());
        assert!(actors
            .actors
            .iter()
            .any(|actor| actor.address == Address::repeat_byte(0x13)));
    }

    #[test]
    fn reuses_observed_historical_callers() {
        let observed = Address::repeat_byte(0x99);
        let actors = ActorModel::default().generate([observed]);
        assert_eq!(
            actors.by_role(ActorType::Attacker).unwrap().address,
            observed
        );
        assert!(!actors.by_role(ActorType::Attacker).unwrap().synthetic);
    }

    #[test]
    fn funds_synthetic_actors() {
        let actors = ActorModel::default().generate([]);
        let mut db = CacheDB::new(ForkDb::empty());
        actors.fund_synthetic_actors(&mut db);
        let attacker = actors.by_role(ActorType::Attacker).unwrap();
        let info = db.basic_ref(attacker.address).unwrap().unwrap();
        assert_eq!(info.balance, attacker.initial_balance);
    }

    #[test]
    fn assigns_different_callers_to_sequence() {
        let actors = ActorModel::default().generate([]);
        let target = Address::repeat_byte(0x44);
        let mut txs = vec![
            SingletonTx {
                input: vec![1],
                caller: Address::ZERO,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            },
            SingletonTx {
                input: vec![2],
                caller: Address::ZERO,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            },
            SingletonTx {
                input: vec![3],
                caller: Address::ZERO,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            },
            SingletonTx {
                input: vec![4],
                caller: Address::ZERO,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            },
        ];
        let assigned = actors.apply_roles_to_sequence(&mut txs);
        assert_eq!(assigned.get(&0), Some(&ActorType::Attacker));
        assert_eq!(assigned.get(&1), Some(&ActorType::Victim));
        assert_ne!(txs[0].caller, txs[1].caller);
        assert!(txs[1].is_victim);
    }
}
