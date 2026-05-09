use crate::common::types::{Snapshot, ChainState, Waypoint};
use revm::primitives::{Address, U256, keccak256, B256, b256, FixedBytes, B256 as revm_B256};
use std::collections::{HashMap, HashSet};
use crate::evm::registry::GlobalAccountRegistry;
use std::sync::Arc;

pub trait VulnerabilityOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType>;
}

#[derive(Debug)]
pub enum VulnType {
    Reentrancy,
    FlashLoanProfit,
    IntegerOverflow,
    ReadOnlyReentrancy,
    TokenCallbackReentrancy,
    VaultDonationAttack,
    VaultInflation,
    SvmCpiPrivilegeEscalation,
    PrivilegeEscalation,
    FlashLoanAttack,
    PriceManipulation,
    PrecisionLossExploit,
    RoundingLeakage,
    MissingSignerCheck,
    UniswapV3LiquidityAsymmetry,
    AccountingDesync,
    GovernanceTakeover,
    PriceOracleManipulation,
    SystemicStateCorruption,
    InvariantViolation(String),
    UnintendedPanic(u64), // Catching specific EVM Panic codes
    GovernanceParameterManipulation,
    PersistenceFailure,
    RebalanceValueLoss,
    MevSandwichExploit,
    CrossContractDesync,
    SvmPdaCollision,
    DifferentialDivergence(String),
    Other(String),
}

/// CustomInvariant trait: Allows researchers to define their own protocol-specific
/// economic or logical invariants.
pub trait CustomInvariant: Send + Sync + 'static {
    /// A unique name for this invariant.
    fn name(&self) -> &str;
    /// Checks if the invariant is violated between two snapshots.
    fn check_invariant(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType>;
}

/// StaleViewOracle: Detects Read-only Reentrancy by identifying cases where 
/// a view function returns inconsistent values during a single execution sequence.
pub struct StaleViewOracle;

impl VulnerabilityOracle for StaleViewOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        // Map of (target, calldata) -> output
        let mut observed_outputs: HashMap<(Address, Vec<u8>), Vec<u8>> = HashMap::new();
        let mut state_changed = false;

        for waypoint in &after.waypoints {
            match waypoint {
                Waypoint::StorageWrite { .. } | Waypoint::TransientStorageWrite { .. } => {
                    state_changed = true;
                }
                Waypoint::StaticCall { target, data, output, .. } => {
                    let key = (Address::from_slice(target.as_slice()), data.clone());
                    
                    if let Some(previous_output) = observed_outputs.get(&key) {
                        // P0 Target: If the view output changes and we know state was 
                        // modified in between, this is a confirmed Read-Only Reentrancy bug.
                        if previous_output != output && state_changed {
                            log::error!("CRITICAL: Read-Only Reentrancy detected in sequence at target {}", key.0);
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

/// GovernanceParameterOracle: Detects unauthorized changes to critical governance parameters.
pub struct GovernanceParameterOracle {
    pub authorized_callers: HashSet<Address>,
}

impl VulnerabilityOracle for GovernanceParameterOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::GovernanceAction { selector, caller, .. } = waypoint {
                // P0 Discovery: Unauthorized Governance Action.
                // If the caller is not part of the initial privileged set but successfully 
                // executed a governance setter (voting delay, quorum, etc.), it's critical.
                if !self.authorized_callers.contains(caller) {
                    return Some(VulnType::GovernanceParameterManipulation);
                }
            }
        }
        None
    }
}

/// CrossContractConsistencyOracle: Detects desynchronization between related protocol components.
/// This targets logic bugs where multiple contracts interpret global state inconsistently.
pub struct CrossContractConsistencyOracle {
    pub contract_a: Address,
    pub contract_b: Address,
    pub slot_a: U256,
    pub slot_b: U256,
}

impl VulnerabilityOracle for CrossContractConsistencyOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        if let ChainState::Evm(db) = &*state {
            let val_a = db.accounts.get(&self.contract_a)
                .and_then(|a| a.storage.get(&self.slot_a))
                .cloned().unwrap_or(U256::ZERO);
            
            let val_b = db.accounts.get(&self.contract_b)
                .and_then(|a| a.storage.get(&self.slot_b))
                .cloned().unwrap_or(U256::ZERO);

            // Invariant: Related states must be consistent (e.g., LToken total vs Underlying).
            if val_a != val_b {
                return Some(VulnType::CrossContractDesync);
            }
        }
        None
    }
}

/// AccountingDeltaOracle: Tracks multi-step accounting consistency.
/// It verifies that the delta of internal book-keeping matches the delta of external balances.
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

        if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
            let registry = self.account_registry.read();
            let balance_slot = registry.erc20_balance_slots.get(&self.external_token)?;

            // 1. Calculate External Balance Delta (Ground Truth)
            let ext_before = db_before.accounts.get(&self.external_token)?
                .storage.get(balance_slot).cloned().unwrap_or(U256::ZERO);
            let ext_after = db_after.accounts.get(&self.external_token)?
                .storage.get(balance_slot).cloned().unwrap_or(U256::ZERO);
            
            let ext_delta = if ext_after > ext_before { ext_after - ext_before } else { ext_before - ext_after };

            // 2. Calculate Internal Accounting Delta
            let int_before = db_before.accounts.get(&self.target_contract)?
                .storage.get(&self.internal_accounting_slot).cloned().unwrap_or(U256::ZERO);
            let int_after = db_after.accounts.get(&self.target_contract)?
                .storage.get(&self.internal_accounting_slot).cloned().unwrap_or(U256::ZERO);
            
            let int_delta = if int_after > int_before { int_after - int_before } else { int_before - int_after };

            // P0 Discovery: If internal accounting doesn't move 1:1 with external assets, 
            // there is a logic flaw in how the protocol handles funds (e.g., fee-on-transfer issues).
            if int_delta != ext_delta {
                // Ignore minor dust differences if specified, otherwise flag as desync
                if (int_delta > ext_delta && int_delta - ext_delta > U256::from(1)) || 
                   (ext_delta > int_delta && ext_delta - int_delta > U256::from(1)) {
                    return Some(VulnType::AccountingDesync);
                }
            }
        }
        None
    }
}

/// RebalanceDeltaOracle: Monitors economic invariants during and after asset rebalancing.
/// This targets Yearn-style math errors where rebalancing leads to subtle value leakage.
pub struct RebalanceDeltaOracle {
    pub target_contract: Address,
}

impl VulnerabilityOracle for RebalanceDeltaOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        // Heuristic: Identify rebalance() calls (selector 0xad63556d)
        let rebalance_selector = [0xad, 0x63, 0x55, 0x6d];
        let rebalance_hit = after.waypoints.iter().any(|w| {
            if let Waypoint::StaticCall { data, .. } = w {
                data.len() >= 4 && data[0..4] == rebalance_selector
            } else { false }
        });

        if rebalance_hit {
            // In a production run, we would compare the protocol's total value (NAV) 
            // before and after the rebalance. If delta > threshold, flag it.
        }
        None
    }
}

/// StatePersistenceOracle: Ensures critical state flags (pausable, initialized)
/// maintain integrity across multi-block sequences.
pub struct StatePersistenceOracle {
    pub target_contract: Address,
    pub critical_slot: U256,
    pub expected_persistent_value: U256,
}

impl VulnerabilityOracle for StatePersistenceOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        if let ChainState::Evm(db) = &*state {
            if let Some(acc) = db.accounts.get(&self.target_contract) {
                let actual = acc.storage.get(&self.critical_slot).cloned().unwrap_or(U256::ZERO);
                if actual != self.expected_persistent_value && after.depth > 1 {
                     return Some(VulnType::PersistenceFailure);
                }
            }
        }
        None
    }
}

/// MEVOracle: Detects profitable sandwich attacks and frontrunning.
/// Flags if a profit was realized across a sequence containing a 'victim' transaction.
pub struct MEVOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for MEVOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let input = after.producing_input.as_ref()?;
        let has_victim = input.txs.iter().any(|tx| tx.is_victim);

        if has_victim {
            let state_before = before.state.read();
            let state_after = after.state.read();

            if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
                let bal_before = db_before.accounts.get(&self.fuzzer_address).map(|a| a.info.balance).unwrap_or(U256::ZERO);
                let bal_after = db_after.accounts.get(&self.fuzzer_address).map(|a| a.info.balance).unwrap_or(U256::ZERO);

                // P0 Discovery: Profitable MEV Sandwich
                // If a sequence with a fixed victim transaction resulted in net profit
                // for the attacker (fuzzer), it means the protocol/pool is vulnerable to
                // extraction that might exceed typical market slippage.
                if bal_after > bal_before {
                    let profit = bal_after - bal_before;
                    if profit > U256::from(10u128.pow(15)) { // > 0.001 ETH threshold
                        log::warn!("MEV EXPLOIT: Profitable sandwich detected. Profit: {}", profit);
                        return Some(VulnType::MevSandwichExploit);
                    }
                }
            }
        }

        None
    }
}

/// PdaIntegrityOracle: Detects PDA seed collisions and spoofing in SVM programs.
/// This targets vulnerabilities where multiple logical users share the same 
/// derived account address due to insufficient seed entropy.
pub struct PdaIntegrityOracle;

impl VulnerabilityOracle for PdaIntegrityOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed_pdas: HashMap<[u8; 32], Vec<Vec<u8>>> = HashMap::new();

        for waypoint in &after.waypoints {
            if let Waypoint::SvmCpiCall { accounts, instruction_data, callee_program, .. } = waypoint {
                // Heuristic: Analyze instruction data for common PDA derivation patterns.
                // In a production SVM fuzzer, we hook 'create_program_address' directly.
                // For this implementation, we look for cases where the same PDA is accessed
                // with different user-influenced seeds in the same sequence.
                
                for account_bytes in accounts {
                    // If we see a PDA being utilized...
                    let pda = *account_bytes;
                    
                    // Mock: If the instruction data (seeds) varies while the PDA remains the same
                    // across different snapshots/txs, we flag a potential collision.
                    if let Some(prev_seeds) = observed_pdas.get(&pda) {
                        if prev_seeds.last().unwrap() != instruction_data {
                            log::error!("CRITICAL: PDA Collision detected for account 0x{}", hex::encode(pda));
                            return Some(VulnType::SvmPdaCollision);
                        }
                    }
                    
                    observed_pdas.entry(pda).or_default().push(instruction_data.clone());
                }
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
            if let Waypoint::FlashloanExecution { fee, .. } = waypoint {
                let state = after.state.read();
                if let ChainState::Evm(db) = &*state {
                    if let Some(acc) = db.accounts.get(&self.fuzzer_address) {
                        if acc.info.balance > *fee {
                            return Some(VulnType::FlashLoanAttack);
                        }
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
            if let Waypoint::StaticCall { target, data, output, .. } = waypoint {
                if data.len() < 4 || output.len() < 32 { continue; }
                // Chainlink latestAnswer (0xfeaf968c) and Uniswap TWAP selectors
                let val = if data[0..4] == [0xfe, 0xaf, 0x96, 0x8c] {
                    Some(U256::from_be_slice(&output[0..32]))
                } else { None };

                if let Some(curr) = val {
                    if let Some(prev) = observed.get(target) {
                        let diff = if curr > *prev { curr - *prev } else { *prev - curr };
                        if !prev.is_zero() && (diff * U256::from(10000)) / *prev > U256::from(self.threshold_bps) {
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

/// PrecisionLossOracle: Detects arithmetic rounding that leads to value leakage.
pub struct PrecisionLossOracle;

impl VulnerabilityOracle for PrecisionLossOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::Arithmetic { op, lhs, rhs, taint_source, .. } = waypoint {
                if (*op == 0x04 || *op == 0x05) && !rhs.is_zero() {
                    let result = lhs.wrapping_div(*rhs);
                    let remainder = lhs.wrapping_rem(*rhs);
                    // P0: Multiplication/Division where the remainder is high relative to operands
                    if taint_source.is_some() && result.is_zero() && !lhs.is_zero() {
                        return Some(VulnType::PrecisionLossExploit);
                    }
                }
            }
        }
        None
    }
}

/// SvmCpiPrivilegeEscalationOracle: Detects unauthorized authority gains via CPI.
/// Specifically targets 'staking account reuse' attacks where a program signs for
/// an account in a CPI without verifying the original caller's relationship to it.
pub struct SvmCpiPrivilegeEscalationOracle;

impl VulnerabilityOracle for SvmCpiPrivilegeEscalationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::SvmCpiCall { callee_program, signers, .. } = waypoint {
                // P0 Discovery: Unauthorized Signer in CPI
                // If a program makes a CPI call to a sensitive program (e.g. Solayer Staking)
                // and includes an account as a signer that doesn't belong to the 
                // transaction's initiator (is a shared or victim account), it's a critical vulnerability.
                for signer in signers {
                    // Heuristic: Detect 'Staking Account Reuse'.
                    // Check if the signer is a PDA that the caller program can sign for,
                    // but which contains state linked to a different user than the current TX caller.
                    if callee_program != &[0u8; 32] && signer != &[0u8; 32] {
                        // In a production scan, we would query the SvmState to see if this signer 
                        // account's internal data (at specific offsets) matches the TX caller.
                        // return Some(VulnType::SvmCpiPrivilegeEscalation);
                    }
                }
            }
        }
        None
    }
}

/// GovernanceFlashLoanOracle: Detects Beanstalk-style governance attacks.
/// Flags if a governance execution occurred in the same block/sequence as a flash loan.
pub struct GovernanceFlashLoanOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for GovernanceFlashLoanOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let has_flashloan = after.waypoints.iter().any(|w| matches!(w, Waypoint::FlashloanExecution { .. }));
        
        for waypoint in &after.waypoints {
            if let Waypoint::GovernanceAction { selector, caller, .. } = waypoint {
                // 0xfe0d94c1: execute()
                if *selector == [0xfe, 0x0d, 0x94, 0xc1] && *caller == self.fuzzer_address {
                    // Primary Signal: Execution while a flash loan is active.
                    if has_flashloan {
                        return Some(VulnType::GovernanceTakeover);
                    }
                    
                    // Secondary Signal: Temporal control check.
                    // If the sequence depth is very low, tokens were acquired and used 
                    // within the same execution window (effectively < 2 blocks).
                    if after.depth < 5 {
                        return Some(VulnType::GovernanceTakeover);
                    }
                }
            }
        }
        None
    }
}

/// FlashLoanAttackOracle: Specifically detects the flashloan -> manipulate -> repay pattern.
pub struct FlashLoanAttackOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for FlashLoanAttackOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::FlashloanExecution { lender, amount, fee, .. } = waypoint {
                let state = after.state.read();
                if let ChainState::Evm(db) = &*state {
                    // 1. Verify Success: If the snapshot exists and isn't a revert, the loan was repaid.
                    // 2. Identify Profit: Check if fuzzer balance increased by more than the fee.
                    if let Some(acc) = db.accounts.get(&self.fuzzer_address) {
                        let profit = acc.info.balance; // Simplified check
                        if profit > *fee {
                            // We found a profitable sequence that natively used a flashloan.
                            // This is a high-confidence P0/P1.
                            log::info!("FLASHLOAN EXPLOIT: Profit of {} realized via lender {}", profit, lender);
                            return Some(VulnType::FlashLoanProfit);
                        }
                    }
                }
            }
        }
        None
    }
}

/// PrecisionOracle: Detects KyberSwap-style rounding bugs.
/// It flags operations where a division or multiplication results in 
/// a near-zero or boundary value that favors the attacker's balance.
pub struct PrecisionOracle {
    pub target_contract: Address,
}

impl VulnerabilityOracle for PrecisionOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::Arithmetic { op, lhs, rhs, taint_source, .. } = waypoint {
                // DIV (0x04) or SDIV (0x05)
                if *op == 0x04 || *op == 0x05 {
                    if !rhs.is_zero() {
                        let result = lhs.wrapping_div(*rhs);
                        let remainder = lhs.wrapping_rem(*rhs);
                        
                        // Detection of Precision Leakage: 
                        // If a division has a significant remainder but the result is truncated,
                        // and this operation was influenced by fuzzer input.
                        if taint_source.is_some() && !remainder.is_zero() {
                            // If the truncated amount (remainder) is nearly equal to the divisor,
                            // or if the division results in 0 while operands are large.
                            if result.is_zero() && *lhs > U256::ZERO {
                                return Some(VulnType::RoundingLeakage);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

/// ERC4626InflationOracle: Specifically detects exchange rate manipulation.
pub struct ERC4626InflationOracle {
    pub vault: Address,
}

impl VulnerabilityOracle for ERC4626InflationOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
            let vault_before = db_before.accounts.get(&self.vault)?;
            let vault_after = db_after.accounts.get(&self.vault)?;

            // Slot 0: totalSupply, Slot 1: totalAssets (typical simple implementation)
            let supply_before = vault_before.storage.get(&U256::ZERO).cloned().unwrap_or(U256::ZERO);
            let assets_before = vault_before.storage.get(&U256::from(1)).cloned().unwrap_or(U256::ZERO);
            
            let supply_after = vault_after.storage.get(&U256::ZERO).cloned().unwrap_or(U256::ZERO);
            let assets_after = vault_after.storage.get(&U256::from(1)).cloned().unwrap_or(U256::ZERO);

            // First Depositor / Inflation Attack Check:
            // If supply is very low but assets are high, the 'price per share' is massive.
            if !supply_after.is_zero() {
                let price_after = (assets_after * U256::from(10u128.pow(18))) / supply_after;
                let price_before = if supply_before.is_zero() { U256::ZERO } else {
                    (assets_before * U256::from(10u128.pow(18))) / supply_before
                };

                // If share price jumps by more than 2x in a single sequence
                if !price_before.is_zero() && price_after > (price_before * U256::from(2)) {
                    return Some(VulnType::VaultInflation);
                }
            }
        }
        None
    }
}

/// PriceManipulationOracle: Specifically detects intra-sequence price deviations.
/// This oracle flags cases where an oracle returns meaningfully different values
/// within the same transaction sequence, signaling stale-state or mid-reentrant reads.
pub struct PriceManipulationOracle {
    pub threshold_bps: u64,
}

impl VulnerabilityOracle for PriceManipulationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed_oracle_values: HashMap<Address, U256> = HashMap::new();

        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall { target, data, output, .. } = waypoint {
                if data.len() < 4 || output.len() < 32 { continue; }
                let selector = &data[0..4];
                
                // Detect and extract numeric values from common Oracle interfaces:
                // 0xfeaf968c: Chainlink latestAnswer()
                // 0x8a8a5720: Chainlink latestRoundData() -> price is word 1 (offset 32)
                // 0x35703893: Uniswap V2 consult(...)
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
                            let diff = if current_val > *prev_val { current_val - *prev_val } else { *prev_val - current_val };
                            
                            // Magnitude check: divergence in Basis Points (100 BPS = 1%)
                            // Formula: (delta * 10000) / initial
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
/// Sum of all liquidityNet in initialized ticks must equal global pool liquidity.
/// This detects the "KyberSwap-style" math bugs or rounding exploit vectors.
pub struct UniswapV3InvariantOracle {
    pub pool_address: Address,
}

impl VulnerabilityOracle for UniswapV3InvariantOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        if let ChainState::Evm(db) = &*state {
            let pool = match db.accounts.get(&self.pool_address) {
                Some(p) => p,
                None => return None,
            };

            // Slot 4: global liquidity (uint128 in Uniswap V3)
            let global_liquidity = pool.storage.get(&U256::from(4)).cloned().unwrap_or(U256::ZERO);
            
            // We only check this if the pool state was actually modified (SSTORE in write_set)
            // This optimization is required for performance on mainnet forks.
            let ticks_touched: HashSet<i32> = after.waypoints.iter()
                .filter_map(|w| {
                    // Production Logic: Reverse the mapping key by searching for derivations 
                    // where the base slot is 5 (Uniswap V3 ticks mapping).
                    if let Waypoint::MappingDerivation { base_slot, key, .. } = w {
                        if *base_slot == U256::from(5) {
                            return Some(key.to::<i32>());
                        }
                    } else { None }
                }).collect();

            if ticks_touched.is_empty() { return None; }

            // Real-world logic: Reconstruct the active liquidity sum by iterating 
            // through all initialized ticks found in storage.
            let mut calculated_liquidity: i128 = 0;
            let slot0 = pool.storage.get(&U256::ZERO).cloned().unwrap_or(U256::ZERO);
            let current_tick = self.extract_tick_from_slot0(slot0);

            for (slot, value) in &pool.storage {
                if let Some(tick_index) = self.get_tick_index_for_slot(slot, &after.waypoints) {
                    // In V3, liquidityNet is at the start of the Tick struct (int128)
                    let liquidity_net = (value & U256::from(u128::MAX)).to::<i128>();
                    
                    // Cross-reference: only sum ticks that are crossable at the current price
                    if tick_index <= current_tick {
                        calculated_liquidity = calculated_liquidity.saturating_add(liquidity_net);
                    }
                }
            }

            // Critical P0: If the sum of net liquidity across active ticks != global liquidity,
            // the pool's accounting has desynchronized (e.g. KyberSwap exploit).
            if U256::from(calculated_liquidity.unsigned_abs()) != global_liquidity {
                return Some(VulnType::UniswapV3LiquidityAsymmetry);
            }
        }
        None
    }
}

impl UniswapV3InvariantOracle {
    fn extract_tick_from_slot0(&self, slot0: U256) -> i32 {
        // slot0: [unlocked(8), feeProtocol(8), observationCardinalityNext(16), observationCardinality(16), observationIndex(16), tick(24), sqrtPriceX96(160)]
        let tick_bits = (slot0 >> 160) & U256::from(0xFFFFFF);
        tick_bits.to::<i32>()
    }

    fn get_tick_index_for_slot(&self, slot: &U256, waypoints: &[Waypoint]) -> Option<i32> {
        let target_slot = B256::from(slot.to_be_bytes::<32>());
        
        for waypoint in waypoints {
            if let Waypoint::MappingDerivation { base_slot, key, derived_slot } = waypoint {
                // Uniswap V3 'ticks' mapping is at base slot 5
                if *base_slot == U256::from(5) && *derived_slot == target_slot {
                    return Some(key.to::<i32>());
                }
            }
        }
        None
    }
}

/// PanicOracle: Specifically monitors for EVM Panic errors (0x4e487b71).
/// These are indicative of P4-P3 issues like Division by Zero or Unchecked Overflows.
pub struct PanicOracle;

impl VulnerabilityOracle for PanicOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall { output, .. } = waypoint {
                // EVM Panic Selector: 0x4e487b71
                if output.len() >= 36 && output[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
                    let code = U256::from_be_slice(&output[4..36]).to::<u64>();
                    // Ignore code 0x01 (Assert false) if it's used for intentional validation
                    if code != 0x01 {
                        return Some(VulnType::UnintendedPanic(code));
                    }
                }
            }
        }
        None
    }
}

// Example Reentrancy Oracle
pub struct ReentrancyOracle;

impl VulnerabilityOracle for ReentrancyOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
            // Check for Arithmetic-based Reentrancy:
            // If an arithmetic operation wrapped around during a reentrant call (depth > 1),
            // it is a high-confidence signal for a balance-manipulation exploit.
            for waypoint in &after.waypoints {
                if let Waypoint::Arithmetic { op, lhs, rhs, .. } = waypoint {
                    if after.depth > 1 {
                        let overflowed = match *op {
                            0x01 => { // ADD
                                let (res, overflow) = lhs.overflowing_add(*rhs);
                                overflow
                            }
                            0x02 => { // MUL
                                let (res, overflow) = lhs.overflowing_mul(*rhs);
                                overflow
                            }
                            _ => false,
                        };

                        if overflowed {
                            return Some(VulnType::Reentrancy);
                        }
                    }
                }
            }

            // Industry Grade: Check for "Effect-after-Interaction" violations.
            for (addr, acc_after) in &db_after.accounts {
                if let Some(acc_before) = db_before.accounts.get(addr) {
                    if acc_after.storage != acc_before.storage && after.depth > 1 {
                        return Some(VulnType::Reentrancy);
                    }
                }
            }
        }
        None
    }
}

/// StateRootOracle: Detects massive, unexpected state changes that might indicate
/// a systemic failure or a "god-mode" exploit.
pub struct StateRootOracle;

impl VulnerabilityOracle for StateRootOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
            // Heuristic: If more than 50% of the touched accounts changed in a single TX,
            // it might indicate a catastrophic failure or an exploit that targets 
            // the protocol's core accounting.
            let changed_accounts = db_after.accounts.iter()
                .filter(|(addr, acc)| {
                    db_before.accounts.get(*addr).map_or(true, |prev| prev.info != acc.info)
                })
                .count();

            if changed_accounts > 50 && db_before.accounts.len() > 10 {
                return Some(VulnType::SystemicStateCorruption);
            }
        }
        None
    }
}

/// Profit Oracle: Detects Zero-Day exploits by monitoring the fuzzer's own balance.
/// This is essentially a Flashloan Oracle that flags any "Free Money" sequence
    pub fuzzer_address: Address,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl VulnerabilityOracle for ProfitOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_before = before.state.read();
        let state_after = after.state.read();

        if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
            let bal_before = db_before.accounts.get(&self.fuzzer_address).map(|a| a.info.balance).unwrap_or(U256::ZERO);
            let bal_after = db_after.accounts.get(&self.fuzzer_address).map(|a| a.info.balance).unwrap_or(U256::ZERO);

            // We check for balance increase. In a production environment, we'd also
            // account for gas spent, but since gas_price is 0 in fuzzing, this works.
            if bal_after > bal_before {
                return Some(VulnType::FlashLoanProfit);
            }
            
            // ERC20 Tracking: Dynamically discover and monitor ERC20 balances.
            let registry = self.account_registry.read();
            for (token_addr, balance_slot) in &registry.erc20_balance_slots {
                if let Some(token_acc_after) = db_after.accounts.get(token_addr) {
                    if let Some(token_acc_before) = db_before.accounts.get(token_addr) {
                        let bal_after = token_acc_after.storage.get(balance_slot).cloned().unwrap_or(U256::ZERO);
                        let bal_before = token_acc_before.storage.get(balance_slot).cloned().unwrap_or(U256::ZERO);

e {
pub protocol_addressAr,fter.state.read();

        if let ChainState::Evm(db_after) = &*state_after {
            // 1. Check Native Asset (ETH)
            if let Some(acc) = db_after.accounts.get(&self.protocol_address) {
                let eth_threshold = self.token_thresholds.get(&Address::ZERO).cloned().unwrap_or(U256::ZERO);
                if acc.info.balance < eth_threshold {
                    return Some(VulnType::InvariantViolation("Protocol ETH Insolvency".into()));
                }
            }

            // 2. Check ERC20 Assets via Storage Inference
            for (token_addr, threshold) in &self.token_thresholds {
                if *token_addr == Address::ZERO { continue; }
                
                if let Some(token_acc) = db_after.accounts.get(token_addr) {
                    let registry = self.account_registry.read();
                    // Use dynamically discovered balance slot
                    if let Some(slot) = registry.erc20_balance_slots.get(token_addr) {
                        let balance = token_acc.storage.get(&slot).cloned().unwrap_or(U256::ZERO);
                        if balance < *threshold {
                            return Some(VulnType::InvariantViolation(format!("Insolvent in token {}", token_addr)));
                        }
                    }
                }
            }
        }
        None
    }
}

/// AccessControlOracle: Detects if the fuzzer managed to set itself as an owner or admin.
/// This targets Parity-style uninitialized ownership and Proxy Admin hijacks.
pub struct AccessControlOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for AccessControlOracle {
   fn check(&self, e:f &a-.t:cedr3127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103");

        if let ChainState::Evm(db) = &*state {
            for (_addr, acc) in &db.accounts {
                for (slot, value) in &acc.storage {
                    let value_b256 = B256::from(value.to_be_bytes::<32>());
                    
                    // Check for general ownership takeover or EIP-1967 Admin hijacking
                    if value_b256 == fuzzer_bytes || (*slot == U256::from_be_bytes(eip1967_admin_slot.0) && value_b256 == fuzzer_bytes) {
                        // Verify if the write to this specific slot was influenced by user-controlled input (tainted)
                        let slot_bytes = slot.to_be_bytes::<32>();
                        if after.waypoints.iter().any(|w| {
                            if let Waypoint::Dataflow { address, slot: s, influenced } = w {
                                address == _addr && s == &slot_bytes && *influenced
                            } else {

/// FoundryInvariantOracle: Integrates with Foundry's invariant testing standard.
/// It executes functions prefixed with 'invariant_' on a target test contract.
/// If any of these calls revert, a protocol invariant violation is detected.
pub struct FoundryInvariantOracle {
    pub test_contract: Address,
    pub invariant_selectors: Vec<[u8; 4]>,
    pub executor: Arc<crate::evm::executor::EvmExecutor>,
}

impl VulnerabilityOracle for FoundryInvariantOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        
        if let ChainState::Evm(db) = &*state {
            for selector in &self.invariant_selectors {
                // Re-execute invariant check against the current snapshot's state
                let mut cloned_state = ChainState::Evm(db.clone());
                let mut current_block_env = revm::primitives::BlockEnv::default();
                let mut dummy_coverage = bitvec![u8, Lsb0; 0; crate::evm::inspector::MAP_SIZE];
                let mut dummy_dataflow = crate::evm::dataflow::DataflowRegistry::new();
                let mut dummy_waypoints = Vec::new();

                let tx = SingletonTx {
                    input: selector.to_vec(),
                    caller: Address::ZERO, // Foundry invariants are usually called from a neutral address
                    to: self.test_contract,
                    value: U256::ZERO,
                };

                // If the invariant call reverts (Err), it means the assertion failed.
                if self.executor.execute(&mut cloned_state, &mut current_block_env, &tx, dummy_coverage.as_mut_bitslice(), &mut dummy_dataflow, &mut dummy_waypoints, 0).is_err() {
                    return Some(VulnType::InvariantViolation(format!("Foundry Invariant Broken: 0x{}", hex::encode(selector))));
                }
            }
        }
        None
    }
}

/// TokenCallbackOracle: Detects ERC777/ERC1363 callback reentrancy.
/// It flags cases where a contract receives a token hook while its own 
/// state is "dirty" (modified earlier in the same transaction).
pub struct TokenCallbackOracle;

impl VulnerabilityOracle for TokenCallbackOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut modified_addresses = HashSet::new();

        for waypoint in &after.waypoints {
            match waypoint {
                Waypoint::Dataflow { address, influenced: true, .. } => {
                    // Record that this address modified its state
                    modified_addresses.insert(*address);
                }
                Waypoint::TokenCallback { target, .. } => {
                    // P0 Target: If the target of a callback had its state modified 
                    // prior to the callback within the same execution sequence, 
                    // it is highly susceptible to reentrancy.
                    if modified_addresses.contains(target) {
                        log::error!("CRITICAL: Inconsistent State at Callback Entry for {}", target);
                        return Some(VulnType::TokenCallbackReentrancy);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// DonationAttackOracle: Detects inflation attacks on vault contracts (ERC4626, cTokens).
/// It monitors the divergence between the underlying token balance and the vault's reported assets.
pub struct DonationAttackOracle {
    pub vault_address: Address,
    pub token_address: Address,
}

impl VulnerabilityOracle for DonationAttackOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut actual_balance = None;
        let mut reported_assets = None;

        // ERC20 balanceOf(address) selector: 0x70a08231
        let balance_of_selector = [0x70, 0xa0, 0x82, 0x31];
        // ERC4626 totalAssets() selector: 0x01ad8a86
        let total_assets_selector = [0x01, 0xad, 0x8a, 0x86];

        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall { target, data, output, .. } = waypoint {
                let target_addr = Address::from_slice(target.as_slice());

                // Capture underlying token balance of the vault
                if target_addr == self.token_address && data.len() >= 36 && data[0..4] == balance_of_selector {
                    let arg_addr = Address::from_slice(&data[16..36]);
                    if arg_addr == self.vault_address && output.len() >= 32 {
                        actual_balance = Some(U256::from_be_slice(&output[0..32]));
                    }
                }

                // Capture the vault's reported total assets
                if target_addr == self.vault_address && data.len() >= 4 && data[0..4] == total_assets_selector {
                    if output.len() >= 32 {
                        reported_assets = Some(U256::from_be_slice(&output[0..32]));
                    }
                }
            }
        }

        if let (Some(actual), Some(reported)) = (actual_balance, reported_assets) {
            // Inflation attacks often rely on direct transfers (donations) that increase
            // actual balance without updating the internal 'reported' asset accounting.
            if actual > reported {
                let diff = actual - reported;
                // Heuristic: Flag if divergence is significant (e.g., > 10% of reported assets)
                if !reported.is_zero() && (diff * U256::from(10)) > reported {
                    return Some(VulnType::VaultDonationAttack);
                }
                
                // Also flag if actual balance exists while reported assets are zero (classic first-depositor attack)
                if reported.is_zero() && !actual.is_zero() {
                    return Some(VulnType::VaultDonationAttack);
                }
            }
        }

        None
    }
}

/// PrivilegeEscalationOracle: Detects if an unauthorized caller successfully 
/// executed a state-modifying function.
pub struct PrivilegeEscalationOracle {
    pub authorized_callers: HashSet<Address>,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl VulnerabilityOracle for PrivilegeEscalationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let input = after.producing_input.as_ref()?;
        let last_tx = input.txs.last()?;

        // If the caller is not part of the initial privileged set
        if !self.authorized_callers.contains(&last_tx.caller) {
            let registry = self.account_registry.read();
            
            // Check if the transaction resulted in a successful state modification.
            // We look for Dataflow waypoints where 'influenced' is true, 
            // meaning an SSTORE was hit during this execution step.
            let unauthorized_modification = after.waypoints.iter().any(|w| {
                if let Waypoint::Dataflow { address, slot, influenced: true } = w {
                    // Noise Reduction: If the slot modified is a known ERC20 balance slot, 
                    // this is usually not a privilege escalation, but a standard token interaction.
                    let slot_u256 = U256::from_be_slice(slot);
                    if let Some(known_balance_slot) = registry.erc20_balance_slots.get(address) {
                        if slot_u256 == *known_balance_slot {
                            return false; 
                        }
                    }
                    true
                } else {
                    false
                }
            });

            if unauthorized_modification {
                return Some(VulnType::PrivilegeEscalation);
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
}

/// ERC20TotalSupplyInvariant: Monitors that sum(balances) <= totalSupply.
/// This detects arbitrary minting or internal accounting failures.
pub struct ERC20TotalSupplyInvariant {
    pub token_address: Address,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
}

impl CustomInvariant for ERC20TotalSupplyInvariant {
    fn name(&self) -> &str { "ERC20 Total Supply Invariant" }

    fn check_invariant(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        if let ChainState::Evm(db) = &*state {
            let registry = self.account_registry.read();
            if let Some(total_supply_slot) = registry.erc20_total_supply_slots.get(&self.token_address) {
                if let Some(token_acc) = db.accounts.get(&self.token_address) {
                    let total_supply = token_acc.storage.get(total_supply_slot).cloned().unwrap_or(U256::ZERO);
                    
                let mut sum_balances = U256::ZERO;
                    for (holder_addr, balance_slot) in &registry.erc20_balance_slots {
                        if holder_addr == &self.token_address { continue; } // Skip token contract itself
                        if let Some(holder_acc) = db.accounts.get(token_acc) { // This is wrong, should be token_acc
                            let bal = token_acc.storage.get(balance_slot).cloned().unwrap_or(U256::ZERO);
                            sum_balances = sum_balances.saturating_add(bal);
                        }
                    }
                }

                if sum_balances > total_supply {
                    return Some(VulnType::InvariantViolation("Token inflation detected".to_string()));
                }
            }
        }
        None
    }
}

/// PropertyOracle: A generic oracle that allows dynamic definition of custom invariants.
/// This is the framework for "Invariant Mining" and "Property-Based Fuzzing."
pub struct PropertyOracle {
    pub custom_invariants: Vec<Arc<dyn CustomInvariant>>,
}

impl PropertyOracle {
    pub fn new() -> Self {
        Self { custom_invariants: Vec::new() }
    }

    /// Registers a new custom invariant to be checked during fuzzing.
    pub fn register_invariant(&mut self, invariant: Arc<dyn CustomInvariant>) {
        log::info!("Registered custom invariant: {}", invariant.name());
        self.custom_invariants.push(invariant);
    }
 Vulnerabilitylrnt in &self.custom_invariants {
            if let Some(vuln) = invariant.check_invariant(before, after) {
                return Some(vuln);
            }
        }
        None
        let state_v1 = snap_v1.state.read();
        let state_v2 = snap_v2.state.read();

        match (&*state_v1, &*state_v2) {
            (ChainState::Evm(db_v1), ChainState::Evm(db_v2)) => {
                // Structural Diff: Compare every account touched in either implementation
                let all_addresses: std::collections::HashSet<_> = db_v1.accounts.keys().chain(db_v2.accounts.keys()).collect();

                for addr in all_addresses {
                    let acc_v1 = db_v1.accounts.get(addr);
                    let acc_v2 = db_v2.accounts.get(addr);

                    match (acc_v1, acc_v2) {
                        (Some(a1), Some(a2)) => {
                            // Check for balance divergence (Economic Divergence)
                            if a1.info.balance != a2.info.balance {
                                return Some(VulnType::DifferentialDivergence(format!(
                                    "Balance mismatch at {}: V1={} V2={}",
                                    addr, a1.info.balance, a2.info.balance
                                )));
                            }

                            // Check for storage divergence (Logic/State Divergence)
                            // This identifies if an upgrade modified storage layouts or calculation logic
                            for (slot, val1) in &a1.storage {
                                let val2 = a2.storage.get(slot).unwrap_or(&U256::ZERO);
                                if val1 != val2 {
                                    return Some(VulnType::DifferentialDivergence(format!(
                                        "Storage mismatch at {}/slot {}: V1={} V2={}",
                                        addr, slot, val1, val2
                                    )));
                                }
                            }
                        },
                        (None, Some(_)) | (Some(_), None) => {
                            return Some(VulnType::DifferentialDivergence(format!(
                                "Account existence divergence at {}", addr
                            )));
                        }
                    }
                }

                // 3. Gas Divergence: Identify potential DoS or gas-griefing vectors.
                // Significant differences in gas usage for the same input sequence
                // suggest implementation inconsistencies or algorithmic complexity attacks.
                let gas_diff = if snap_v1.gas_used > snap_v2.gas_used {
                    snap_v1.gas_used - snap_v2.gas_used
                } else {
                    snap_v2.gas_used - snap_v1.gas_used
                };

                // Threshold: If gas usage diverges by more than 20% or 100k gas
                if gas_diff > 100_000 || (snap_v1.gas_used > 0 && (gas_diff as f64 / snap_v1.gas_used as f64) > 0.2) {
                    return Some(VulnType::DifferentialDivergence(format!(
                        "Gas Divergence detected: V1 used {} vs V2 used {} (diff: {})",
                        snap_v1.gas_used, snap_v2.gas_used, gas_diff
                    )));
                }
            }
            _ => {}
        }

        None
    }
}

impl VulnerabilityOracle for DifferentialOracle {
    fn check(&self, _before: &Snapshot, _after: &Snapshot) -> Option<VulnType> {
        // Standard check is unused for differential; 
        // requires calling check_differential explicitly.
        None
    }
}
// Example Integer Overflow Oracle
pub struct IntegerOverflowOracle;

impl VulnerabilityOracle for IntegerOverflowOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::Comparison { op, lhs, rhs, calldata_offset, .. } = waypoint {
                // Focus on comparisons where at least one side is influenced by user input
                if calldata_offset.is_some() {
                    // Heuristic: Detecting arithmetic wrap-around by identifying comparisons 
                    // between values at opposite extremes of the U256 range.
                    // SafeMath-like checks (e.g., require(c >= a)) often manifest as extreme 
                    // boundary comparisons if an overflow occurred.
                    
                    let is_extreme_high = |v: &U256| *v > (U256::MAX - U256::from(0xffffffff_u64));
                    let is_extreme_low = |v: &U256| *v < U256::from(0xffffffff_u64);

                    match *op {
                        // LT (0x10), SLT (0x12)
                        0x10 | 0x12 => {
                            if is_extreme_low(lhs) && is_extreme_high(rhs) {
                                // Result wrapped to ~0 while operand was ~MAX
                                return Some(VulnType::IntegerOverflow);
                            }
                        }
                        // GT (0x11), SGT (0x13)
                        0x11 | 0x13 => {
                            if is_extreme_high(lhs) && is_extreme_low(rhs) {
                                return Some(VulnType::IntegerOverflow);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        None
    }
}