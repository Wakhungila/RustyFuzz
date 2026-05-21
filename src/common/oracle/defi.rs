use crate::common::oracle::{VulnType, VulnerabilityOracle};
use crate::common::types::{ChainState, Snapshot, Waypoint};
use crate::evm::registry::GlobalAccountRegistry;
use parking_lot::RwLock;
use revm::primitives::{Address, B256, U256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// CrossContractConsistencyOracle: Detects desynchronization between related protocol components.
pub struct CrossContractConsistencyOracle {
    pub contract_a: Address,
    pub contract_b: Address,
    pub slot_a: U256,
    pub slot_b: U256,
}

impl VulnerabilityOracle for CrossContractConsistencyOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        let ChainState::Evm(db) = &*state;
        let val_a = db
            .cache
            .accounts
            .get(&self.contract_a)
            .and_then(|a| a.storage.get(&self.slot_a))
            .cloned()
            .unwrap_or(U256::ZERO);
        let val_b = db
            .cache
            .accounts
            .get(&self.contract_b)
            .and_then(|a| a.storage.get(&self.slot_b))
            .cloned()
            .unwrap_or(U256::ZERO);
        if val_a != val_b {
            return Some(VulnType::CrossContractDesync);
        }
        None
    }
}

/// AccountingDeltaOracle: Tracks multi-step accounting consistency.
pub struct AccountingDeltaOracle {
    pub target_contract: Address,
    pub internal_accounting_slot: U256,
    pub external_token: Address,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl VulnerabilityOracle for AccountingDeltaOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        let registry = self.account_registry.read();
        let balance_slot = registry.erc20_balance_slots.get(&self.external_token)?;

        let ext_before = db_before
            .cache
            .accounts
            .get(&self.external_token)?
            .storage
            .get(balance_slot)
            .cloned()
            .unwrap_or(U256::ZERO);
        let ext_after = db_after
            .cache
            .accounts
            .get(&self.external_token)?
            .storage
            .get(balance_slot)
            .cloned()
            .unwrap_or(U256::ZERO);
        let ext_delta = if ext_after > ext_before {
            ext_after - ext_before
        } else {
            ext_before - ext_after
        };

        let int_before = db_before
            .cache
            .accounts
            .get(&self.target_contract)?
            .storage
            .get(&self.internal_accounting_slot)
            .cloned()
            .unwrap_or(U256::ZERO);
        let int_after = db_after
            .cache
            .accounts
            .get(&self.target_contract)?
            .storage
            .get(&self.internal_accounting_slot)
            .cloned()
            .unwrap_or(U256::ZERO);
        let int_delta = if int_after > int_before {
            int_after - int_before
        } else {
            int_before - int_after
        };

        if int_delta != ext_delta
            && ((int_delta > ext_delta && int_delta - ext_delta > U256::from(1))
                || (ext_delta > int_delta && ext_delta - int_delta > U256::from(1)))
        {
            return Some(VulnType::AccountingDesync);
        }
        None
    }
}

/// StatePersistenceOracle: Ensures critical state flags maintain integrity across sequences.
pub struct StatePersistenceOracle {
    pub target_contract: Address,
    pub critical_slot: U256,
    pub expected_persistent_value: U256,
}

impl VulnerabilityOracle for StatePersistenceOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        let ChainState::Evm(db) = &*state;
        if let Some(acc) = db.cache.accounts.get(&self.target_contract) {
            let actual = acc
                .storage
                .get(&self.critical_slot)
                .cloned()
                .unwrap_or(U256::ZERO);
            if actual != self.expected_persistent_value && after.depth > 1 {
                return Some(VulnType::PersistenceFailure);
            }
        }
        None
    }
}

/// FlashLoanAttackOracle: Detects profitable sequences wrapped in flashloan cycles.
pub struct FlashLoanAttackOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for FlashLoanAttackOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::FlashloanExecution {
                lender,
                amount: _,
                fee,
                ..
            } = waypoint
            {
                let state = after.state.read();
                let ChainState::Evm(db) = &*state;
                if let Some(acc) = db.cache.accounts.get(&self.fuzzer_address) {
                    let profit = acc.info.balance;
                    if profit > *fee {
                        log::info!(
                            "FLASHLOAN EXPLOIT: Profit of {} realized via lender {}",
                            profit,
                            lender
                        );
                        return Some(VulnType::FlashLoanProfit);
                    }
                }
            }
        }
        None
    }
}

/// PriceOracleManipulationOracle: Detects intra-sequence price deviations.
pub struct PriceOracleManipulationOracle {
    pub threshold_bps: u64,
}

impl VulnerabilityOracle for PriceOracleManipulationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed: HashMap<Address, U256> = HashMap::new();
        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall {
                target,
                data,
                output,
                ..
            } = waypoint
            {
                if data.len() < 4 || output.len() < 32 {
                    continue;
                }
                let val = if data[0..4] == [0xfe, 0xaf, 0x96, 0x8c] {
                    Some(U256::from_be_slice(&output[0..32]))
                } else {
                    None
                };
                if let Some(curr) = val {
                    if let Some(prev) = observed.get(target) {
                        let diff = if curr > *prev {
                            curr - *prev
                        } else {
                            *prev - curr
                        };
                        if !prev.is_zero()
                            && (diff * U256::from(10000)) / *prev > U256::from(self.threshold_bps)
                        {
                            return Some(VulnType::PriceManipulation);
                        }
                    }
                    observed.insert(*target, curr);
                }
            }
        }
        None
    }
}

pub struct ERC4626InflationOracle {
    pub vault: Address,
}

impl VulnerabilityOracle for ERC4626InflationOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        let vault_before = db_before.cache.accounts.get(&self.vault)?;
        let vault_after = db_after.cache.accounts.get(&self.vault)?;

        let supply_before = vault_before
            .storage
            .get(&U256::ZERO)
            .cloned()
            .unwrap_or(U256::ZERO);
        let assets_before = vault_before
            .storage
            .get(&U256::from(1))
            .cloned()
            .unwrap_or(U256::ZERO);
        let supply_after = vault_after
            .storage
            .get(&U256::ZERO)
            .cloned()
            .unwrap_or(U256::ZERO);
        let assets_after = vault_after
            .storage
            .get(&U256::from(1))
            .cloned()
            .unwrap_or(U256::ZERO);

        if !supply_after.is_zero() {
            let price_after = (assets_after * U256::from(10u128.pow(18))) / supply_after;
            let price_before = if supply_before.is_zero() {
                U256::ZERO
            } else {
                (assets_before * U256::from(10u128.pow(18))) / supply_before
            };
            if !price_before.is_zero() && price_after > (price_before * U256::from(2)) {
                return Some(VulnType::VaultInflation);
            }
        }
        None
    }
}

/// PriceManipulationOracle: Detects intra-sequence price deviations across common oracle interfaces.
pub struct PriceManipulationOracle {
    pub threshold_bps: u64,
}

impl VulnerabilityOracle for PriceManipulationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed_oracle_values: HashMap<Address, U256> = HashMap::new();

        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall {
                target,
                data,
                output,
                ..
            } = waypoint
            {
                if data.len() < 4 || output.len() < 32 {
                    continue;
                }
                let selector = &data[0..4];
                let val = if selector == [0xfe, 0xaf, 0x96, 0x8c] {
                    Some(U256::from_be_slice(&output[0..32]))
                } else if selector == [0x8a, 0x8a, 0x57, 0x20] && output.len() >= 64 {
                    Some(U256::from_be_slice(&output[32..64]))
                } else if selector == [0x35, 0x70, 0x38, 0x93] {
                    Some(U256::from_be_slice(&output[0..32]))
                } else {
                    None
                };

                if let Some(current_val) = val {
                    let addr = Address::from_slice(target.as_slice());
                    if let Some(prev_val) = observed_oracle_values.get(&addr) {
                        if !prev_val.is_zero() {
                            let diff = if current_val > *prev_val {
                                current_val - *prev_val
                            } else {
                                *prev_val - current_val
                            };
                            let bps = (diff * U256::from(10000)) / *prev_val;
                            if bps > U256::from(self.threshold_bps) {
                                return Some(VulnType::PriceOracleManipulation);
                            }
                        }
                    }
                    observed_oracle_values.insert(addr, current_val);
                }
            }
        }
        None
    }
}

/// UniswapV3InvariantOracle: Monitors the core concentrated liquidity invariant.
pub struct UniswapV3InvariantOracle {
    pub pool_address: Address,
}

impl VulnerabilityOracle for UniswapV3InvariantOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        let ChainState::Evm(db) = &*state;
        let pool = db.cache.accounts.get(&self.pool_address)?;

        let global_liquidity = pool
            .storage
            .get(&U256::from(4))
            .cloned()
            .unwrap_or(U256::ZERO);

        let ticks_touched: HashSet<i32> = after
            .waypoints
            .iter()
            .filter_map(|w| {
                if let Waypoint::MappingDerivation { base_slot, key, .. } = w {
                    if *base_slot == U256::from(5) {
                        return Some(key.to::<i32>());
                    }
                }
                None
            })
            .collect();

        if ticks_touched.is_empty() {
            return None;
        }

        let mut calculated_liquidity: i128 = 0;
        let slot0 = pool.storage.get(&U256::ZERO).cloned().unwrap_or(U256::ZERO);
        let current_tick = self.extract_tick_from_slot0(slot0);

        for (slot, value) in &pool.storage {
            if let Some(tick_index) = self.get_tick_index_for_slot(slot, &after.waypoints) {
                let liquidity_net = (value & U256::from(u128::MAX)).to::<i128>();
                if tick_index <= current_tick {
                    calculated_liquidity = calculated_liquidity.saturating_add(liquidity_net);
                }
            }
        }

        if U256::from(calculated_liquidity.unsigned_abs()) != global_liquidity {
            return Some(VulnType::UniswapV3LiquidityAsymmetry);
        }
        None
    }
}

impl UniswapV3InvariantOracle {
    fn extract_tick_from_slot0(&self, slot0: U256) -> i32 {
        let tick_bits: U256 = (slot0 >> 160) & U256::from(0xFFFFFF);
        tick_bits.to::<i32>()
    }

    fn get_tick_index_for_slot(&self, slot: &U256, waypoints: &[Waypoint]) -> Option<i32> {
        let target_slot = B256::from(slot.to_be_bytes::<32>());
        for waypoint in waypoints {
            if let Waypoint::MappingDerivation {
                base_slot,
                key,
                derived_slot,
            } = waypoint
            {
                if *base_slot == U256::from(5) && *derived_slot == target_slot {
                    return Some(key.to::<i32>());
                }
            }
        }
        None
    }
}

/// PrecisionOracle: Detects KyberSwap-style rounding bugs.
pub struct PrecisionOracle {
    pub target_contract: Address,
}

impl VulnerabilityOracle for PrecisionOracle {
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
                    let remainder = lhs.wrapping_rem(*rhs);
                    if taint_source.is_some()
                        && !remainder.is_zero()
                        && result.is_zero()
                        && *lhs > U256::ZERO
                    {
                        return Some(VulnType::RoundingLeakage);
                    }
                }
            }
        }
        None
    }
}

/// ProfitOracle: Detects zero-day exploits by monitoring the fuzzer's own ETH and ERC20 balances.
pub struct ProfitOracle {
    pub fuzzer_address: Address,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl VulnerabilityOracle for ProfitOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        let bal_before = db_before
            .cache
            .accounts
            .get(&self.fuzzer_address)
            .map(|a| a.info.balance)
            .unwrap_or(U256::ZERO);
        let bal_after = db_after
            .cache
            .accounts
            .get(&self.fuzzer_address)
            .map(|a| a.info.balance)
            .unwrap_or(U256::ZERO);

        if bal_after > bal_before {
            return Some(VulnType::FlashLoanProfit);
        }

        let registry = self.account_registry.read();
        for (token_addr, balance_slot) in &registry.erc20_balance_slots {
            if let Some(token_acc_after) = db_after.cache.accounts.get(token_addr) {
                if let Some(token_acc_before) = db_before.cache.accounts.get(token_addr) {
                    let erc20_bal_after = token_acc_after
                        .storage
                        .get(balance_slot)
                        .cloned()
                        .unwrap_or(U256::ZERO);
                    let erc20_bal_before = token_acc_before
                        .storage
                        .get(balance_slot)
                        .cloned()
                        .unwrap_or(U256::ZERO);
                    if erc20_bal_after > erc20_bal_before {
                        return Some(VulnType::FlashLoanProfit);
                    }
                }
            }
        }
        None
    }
}

/// SolvencyOracle: Monitors that a protocol holds sufficient assets to cover its liabilities.
pub struct SolvencyOracle {
    pub protocol_address: Address,
    pub token_thresholds: HashMap<Address, U256>,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl VulnerabilityOracle for SolvencyOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_after = after.state.read();

        let ChainState::Evm(db_after) = &*state_after;
        if let Some(acc) = db_after.cache.accounts.get(&self.protocol_address) {
            let eth_threshold = self
                .token_thresholds
                .get(&Address::ZERO)
                .cloned()
                .unwrap_or(U256::ZERO);
            if acc.info.balance < eth_threshold {
                return Some(VulnType::InvariantViolation(
                    "Protocol ETH Insolvency".into(),
                ));
            }
        }

        for (token_addr, threshold) in &self.token_thresholds {
            if *token_addr == Address::ZERO {
                continue;
            }
            if let Some(token_acc) = db_after.cache.accounts.get(token_addr) {
                let registry = self.account_registry.read();
                if let Some(slot) = registry.erc20_balance_slots.get(token_addr) {
                    let balance = token_acc.storage.get(slot).cloned().unwrap_or(U256::ZERO);
                    if balance < *threshold {
                        return Some(VulnType::InvariantViolation(format!(
                            "Insolvent in token {}",
                            token_addr
                        )));
                    }
                }
            }
        }
        None
    }
}

/// RebalanceDeltaOracle: Monitors economic invariants during and after asset rebalancing.
pub struct RebalanceDeltaOracle {
    pub target_contract: Address,
    pub rebalance_slot: U256,
}

impl VulnerabilityOracle for RebalanceDeltaOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
            (&*state_before, &*state_after);
        let val_before = db_before
            .cache
            .accounts
            .get(&self.target_contract)
            .and_then(|a| a.storage.get(&self.rebalance_slot))
            .cloned()
            .unwrap_or(U256::ZERO);
        let val_after = db_after
            .cache
            .accounts
            .get(&self.target_contract)
            .and_then(|a| a.storage.get(&self.rebalance_slot))
            .cloned()
            .unwrap_or(U256::ZERO);

        if val_after < val_before {
            let loss = val_before - val_after;
            if loss > U256::from(10u128.pow(18)) {
                return Some(VulnType::RebalanceValueLoss);
            }
        }
        None
    }
}
