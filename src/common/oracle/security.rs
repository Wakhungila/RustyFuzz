use crate::common::oracle::{VulnType, VulnerabilityOracle};
use crate::common::types::{ChainState, Snapshot, Waypoint};
use revm::primitives::{Address, B256, U256};
use std::collections::HashMap;

/// StaleViewOracle: Detects Read-only Reentrancy by identifying cases where
/// a view function returns inconsistent values during a single execution sequence.
pub struct StaleViewOracle;

impl VulnerabilityOracle for StaleViewOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed_outputs: HashMap<(Address, Vec<u8>), Vec<u8>> = HashMap::new();
        let mut state_changed = false;

        for waypoint in &after.waypoints {
            match waypoint {
                Waypoint::StorageWrite { .. } | Waypoint::TransientStorageWrite { .. } => {
                    state_changed = true;
                }
                Waypoint::StaticCall {
                    target,
                    data,
                    output,
                    ..
                } => {
                    let key = (Address::from_slice(target.as_slice()), data.clone());
                    if let Some(previous_output) = observed_outputs.get(&key) {
                        if previous_output != output && state_changed {
                            log::error!(
                                "CRITICAL: Read-Only Reentrancy detected at target {}",
                                key.0
                            );
                            return Some(VulnType::ReadOnlyReentrancy);
                        }
                    }
                    observed_outputs.insert(key, output.clone());
                }
                _ => {}
            }
        }
        None
    }
}

/// ReentrancyOracle: Detects state-change violations within reentrant call depths.
pub struct ReentrancyOracle;

impl VulnerabilityOracle for ReentrancyOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        for waypoint in &after.waypoints {
            if let Waypoint::Arithmetic { op, lhs, rhs, .. } = waypoint {
                if after.depth > 1 {
                    let overflowed = match *op {
                        0x01 => lhs.overflowing_add(*rhs).1,
                        0x02 => lhs.overflowing_mul(*rhs).1,
                        _ => false,
                    };
                    if overflowed {
                        return Some(VulnType::Reentrancy);
                    }
                }
            }
        }

        for (addr, acc_after) in &db_after.cache.accounts {
            if let Some(acc_before) = db_before.cache.accounts.get(addr) {
                if acc_after.storage != acc_before.storage && after.depth > 1 {
                    return Some(VulnType::Reentrancy);
                }
            }
        }
        None
    }
}

/// PanicOracle: Monitors for EVM Panic errors (0x4e487b71).
pub struct PanicOracle;

impl VulnerabilityOracle for PanicOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall { output, .. } = waypoint {
                if output.len() >= 36 && output[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
                    let code = U256::from_be_slice(&output[4..36]).to::<u64>();
                    if code != 0x01 {
                        return Some(VulnType::UnintendedPanic(code));
                    }
                }
            }
        }
        None
    }
}

/// PrecisionLossOracle: Detects arithmetic rounding that leads to value leakage.
pub struct PrecisionLossOracle;

impl VulnerabilityOracle for PrecisionLossOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::Arithmetic {
                op,
                lhs,
                rhs,
                taint_source,
                ..
            } = waypoint
            {
                if (*op == 0x04 || *op == 0x05) && !rhs.is_zero() {
                    let result = lhs.wrapping_div(*rhs);
                    if taint_source.is_some() && result.is_zero() && !lhs.is_zero() {
                        return Some(VulnType::PrecisionLossExploit);
                    }
                }
            }
        }
        None
    }
}

/// StateRootOracle: Detects massive unexpected state changes signaling a systemic exploit.
pub struct StateRootOracle;

impl VulnerabilityOracle for StateRootOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        let changed_accounts = db_after
            .cache
            .accounts
            .iter()
            .filter(|(addr, acc)| {
                db_before
                    .cache
                    .accounts
                    .get(*addr)
                    .is_none_or(|prev| prev.info != acc.info)
            })
            .count();

        if changed_accounts > 50 && db_before.cache.accounts.len() > 10 {
            return Some(VulnType::SystemicStateCorruption);
        }
        None
    }
}

/// AccessControlOracle: Detects if the fuzzer managed to set itself as owner or admin.
pub struct AccessControlOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for AccessControlOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        // EIP-1967 admin slot: keccak256("eip1967.proxy.admin") - 1
        let eip1967_admin_slot: B256 =
            hex::decode("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let fuzzer_bytes = B256::from(self.address_to_32bytes(self.fuzzer_address));

        let ChainState::Evm(db) = &*state;
        for (_addr, acc) in &db.cache.accounts {
            for (slot, value) in &acc.storage {
                let value_b256 = B256::from(value.to_be_bytes::<32>());
                let slot_matches_eip1967 = *slot == U256::from_be_bytes(eip1967_admin_slot.0);

                if value_b256 == fuzzer_bytes
                    && (slot_matches_eip1967 || self.is_owner_slot(slot, &after.waypoints, _addr))
                {
                    return Some(VulnType::PrivilegeEscalation);
                }
            }
        }
        None
    }
}

impl AccessControlOracle {
    fn address_to_32bytes(&self, addr: Address) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[12..32].copy_from_slice(addr.as_slice());
        b
    }

    fn is_owner_slot(&self, slot: &U256, waypoints: &[Waypoint], _contract_addr: &Address) -> bool {
        if *slot == U256::ZERO {
            let slot_bytes = slot.to_be_bytes::<32>().to_vec();
            return waypoints.iter().any(|waypoint| {
                matches!(
                    waypoint,
                    Waypoint::Dataflow {
                        address,
                        slot,
                        influenced: true,
                    } if address == _contract_addr && slot == &slot_bytes
                )
            });
        }

        let target_slot = B256::from(slot.to_be_bytes::<32>());
        for waypoint in waypoints {
            if let Waypoint::MappingDerivation {
                base_slot,
                derived_slot,
                ..
            } = waypoint
            {
                if *base_slot == U256::ZERO && *derived_slot == target_slot {
                    return true;
                }
            }
        }
        false
    }
}
