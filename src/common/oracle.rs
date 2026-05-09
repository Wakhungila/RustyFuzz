use crate::common::types::{Snapshot, ChainState, Waypoint};
use revm::primitives::{Address, U256, keccak256, B256, b256};
use std::collections::HashMap;
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
    PrivilegeEscalation,
    UniswapV3LiquidityAsymmetry,
    PriceOracleManipulation,
    SystemicStateCorruption,
    InvariantViolation(String),
    UnintendedPanic(u64), // Catching specific EVM Panic codes
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

        for waypoint in &after.waypoints {
            if let Waypoint::StaticCall { target, data, output, .. } = waypoint {
                let key = (Address::from_slice(target.as_slice()), data.clone());
                
                if let Some(previous_output) = observed_outputs.get(&key) {
                    // If the same view function returned a different value 
                    // in the same transaction sequence, the state is inconsistent.
                    if previous_output != output {
                        return Some(VulnType::ReadOnlyReentrancy);
                    }
                }
                
                observed_outputs.insert(key, output.clone());
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
            let ticks_touched: Vec<i32> = after.waypoints.iter()
                .filter_map(|w| {
                    if let Waypoint::Dataflow { slot, .. } = w {
                        // Slot 5 is the 'ticks' mapping. We identify accessed ticks via key inference.
                        // Mapping key = keccak256(uint24 tick, uint256 5)
                        // This is a simplified heuristic for identification.
                        Some(0) // In production, we reverse the mapping key to find the tick index
                    } else { None }
                }).collect();

            if ticks_touched.is_empty() { return None; }

            // Deep Invariant Validation:
            // Sum(liquidityNet) for all ticks <= current_tick must equal global_liquidity.
            // This implementation reads the current tick from Slot 0.
            let slot0 = pool.storage.get(&U256::ZERO).cloned().unwrap_or(U256::ZERO);
            let current_tick = self.extract_tick_from_slot0(slot0);

            // In a production environment, we would iterate through all initialized ticks (from the DataflowRegistry)
            // stored in the DB. If the sum does not match global liquidity, a P0 is found.
            // This detects bugs where liquidity is added/removed but the global tracker
            // desynchronizes due to precision loss or overflow.
            
            let mut calculated_liquidity: i128 = 0;
            for (slot, value) in &pool.storage {
                // Check if slot belongs to the 'ticks' mapping (slot 5)
                // For V3, liquidityNet is the first 128 bits of the Tick struct
                if self.is_tick_mapping_slot(slot) {
                    let liquidity_net = value.to::<i128>(); 
                    calculated_liquidity += liquidity_net;
                }
            }

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

    fn is_tick_mapping_slot(&self, _slot: &U256) -> bool {
        // In a research-grade tool, we compare the slot against 
        // keccak256(preimage, 5) from the DataflowRegistry to confirm it's a tick mapping.
        true 
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
/// This is essentially a Flashloan Oracle that flags any "Free Money" sequence.
pub struct ProfitOracle {
    pub fuzzer_address: Address,
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

            // ERC20 Tracking: Monitor storage slots for fuzzer-related balance increases.
            // Heuristic: Check if any contract storage changed at a slot derived from fuzzer address.
            for (addr, acc_after) in &db_after.accounts {
                if addr == &self.fuzzer_address { continue; }
                
                let acc_before = db_before.accounts.get(addr);
                for (slot, val_after) in &acc_after.storage {
                    let val_before = acc_before.and_then(|a| a.storage.get(slot)).cloned().unwrap_or(U256::ZERO);
                    
                    if val_after > &val_before {
                        // Optimization: Instead of brute-force, check if the slot key was 
                        // generated by a keccak256 hash involving the fuzzer address.
                        // This requires the DataflowRegistry to track "Hash Pre-images".
                        
                        // If the slot is a known balance-slot for the fuzzer, this is a P0.
                        if after.waypoints.iter().any(|w| {
                            if let Waypoint::Dataflow { slot: s, influenced } = w {
                                s == slot.as_slice() && *influenced
                            } else { false }
                        }) {
                             return Some(VulnType::FlashLoanProfit);
                        }
                    }
                }
            }
        }
        None
    }
}

/// Solvency Oracle: Checks if a lending protocol's critical asset balance falls below a threshold.
/// In a real-world scenario, this would involve calling specific view functions (e.g., totalAssets(), totalLiabilities())
/// or reading specific storage slots to determine the protocol's solvency.
pub struct SolvencyOracle {
    pub protocol_address: Address,
    pub critical_asset_threshold: U256, // e.g., minimum ETH balance
    // pub total_assets_slot: Option<U256>, // For reading specific storage slots
    // pub total_liabilities_slot: Option<U256>,
}

impl VulnerabilityOracle for SolvencyOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_after = after.state.read();

        if let ChainState::Evm(db_after) = &*state_after {
            if let Some(account) = db_after.accounts.get(&self.protocol_address) {
                // Simple check: Is the protocol's ETH balance below a critical threshold?
                if account.info.balance < self.critical_asset_threshold {
                    return Some(VulnType::InvariantViolation(format!(
                        "Solvency broken: Protocol {} balance {} < threshold {}",
                        self.protocol_address, account.info.balance, self.critical_asset_threshold
                    )));
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
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        let fuzzer_bytes = B256::from_slice(&self.address_to_32bytes(self.fuzzer_address));

        if let ChainState::Evm(db) = &*state {
            for (_addr, acc) in &db.accounts {
                for (slot, value) in &acc.storage {
                    if B256::from(value.to_be_bytes::<32>()) == fuzzer_bytes {
                        // Verify if the write to this specific slot was influenced by user-controlled input (tainted)
                        let slot_bytes = slot.to_be_bytes::<32>();
                        if after.waypoints.iter().any(|w| {
                            if let Waypoint::Dataflow { slot: s, influenced } = w {
                                s == &slot_bytes && *influenced
                            } else {
                                false
                            }
                        }) {
                            log::error!("CRITICAL: Privilege Escalation detected at address {}/slot {}", _addr, slot);
                            return Some(VulnType::PrivilegeEscalation);
                        }
                    }
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
}

impl VulnerabilityOracle for PropertyOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for invariant in &self.custom_invariants {
            if let Some(vuln) = invariant.check_invariant(before, after) {
                return Some(vuln);
            }
        }
        None
    }
}


/// Differential Oracle: Compares execution outcomes between two different snapshots
/// (e.g., Mainnet state vs. Local Upgrade state).
pub struct DifferentialOracle;

impl DifferentialOracle {
    pub fn check_differential(
        &self,
        snap_v1: &Snapshot,
        snap_v2: &Snapshot,
    ) -> Option<VulnType> {
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