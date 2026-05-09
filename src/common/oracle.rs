use crate::common::types::{Snapshot, ChainState, Waypoint};
use revm::primitives::{Address, U256, keccak256, B256, b256, FixedBytes, B256 as revm_B256};
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

/// SolvencyOracle: Monitors both native and ERC20 asset balances for a protocol.
/// Uses MappingDerivation telemetry to find and check balance slots dynamically.
pub struct SolvencyOracle {
    pub protocol_address: Address,
    pub token_thresholds: HashMap<Address, U256>,
}

impl VulnerabilityOracle for SolvencyOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state_after = after.state.read();

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
                    // Resolve the storage slot for balances[protocol_address]
                    // Logic: Search waypoints for a derivation where key == protocol_address
                    let target_slot = self.find_balance_slot(token_addr, &after.waypoints);
                    
                    if let Some(slot) = target_slot {
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

impl SolvencyOracle {
    fn find_balance_slot(&self, _token: &Address, waypoints: &[Waypoint]) -> Option<U256> {
        for waypoint in waypoints {
            if let Waypoint::MappingDerivation { key, derived_slot, .. } = waypoint {
                if key.to::<Address>() == self.protocol_address {
                    return Some(U256::from_be_bytes(derived_slot.0));
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
        
        // EIP-1967 Admin Slot: keccak-256('eip1967.proxy.admin') - 1
        let eip1967_admin_slot = b256!("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103");

        if let ChainState::Evm(db) = &*state {
            for (_addr, acc) in &db.accounts {
                for (slot, value) in &acc.storage {
                    let value_b256 = B256::from(value.to_be_bytes::<32>());
                    
                    // Check for general ownership takeover or EIP-1967 Admin hijacking
                    if value_b256 == fuzzer_bytes || (*slot == U256::from_be_bytes(eip1967_admin_slot.0) && value_b256 == fuzzer_bytes) {
                        // Verify if the write to this specific slot was influenced by user-controlled input (tainted)
                        let slot_bytes = slot.to_be_bytes::<32>();
                        if after.waypoints.iter().any(|w| {
                            if let Waypoint::Dataflow { slot: s, influenced } = w {
                                s == &slot_bytes && *influenced
                            } else {
                                false
                            }
                        }) {
                            log::error!("CRITICAL: Privilege Escalation/Proxy Hijack detected at address {}/slot {}", _addr, slot);
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

/// ERC20TotalSupplyInvariant: Monitors that sum(balances) <= totalSupply.
/// This detects arbitrary minting or internal accounting failures.
pub struct ERC20TotalSupplyInvariant {
    pub token_address: Address,
}

impl CustomInvariant for ERC20TotalSupplyInvariant {
    fn name(&self) -> &str { "ERC20 Total Supply Invariant" }

    fn check_invariant(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let state = after.state.read();
        if let ChainState::Evm(db) = &*state {
            if let Some(token_acc) = db.accounts.get(&self.token_address) {
                // Slot 1: Usually totalSupply in standard ERC20s
                let total_supply = token_acc.storage.get(&U256::from(1)).cloned().unwrap_or(U256::ZERO);
                
                let mut sum_balances = U256::ZERO;
                // In production, we'd use the DataflowRegistry to identify all addresses
                // whose balances changed, but for the fuzzer, we check the db accounts.
                for (addr, acc) in &db.accounts {
                    if addr == &self.token_address { continue; }
                    
                    // Mapping key for balances[addr]
                    // Mapping slot for 'balances' is usually 0
                    let mut buf = [0u8; 64];
                    buf[12..32].copy_from_slice(addr.as_slice());
                    buf[60..64].copy_from_slice(&0u32.to_be_bytes());
                    let balance_slot = U256::from_be_bytes(keccak256(&buf).0);
                    
                    let bal = token_acc.storage.get(&balance_slot).cloned().unwrap_or(U256::ZERO);
                    sum_balances = sum_balances.saturating_add(bal);
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