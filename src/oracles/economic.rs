use alloy_primitives::{Address, U256, Bytes};
use std::collections::{HashMap, HashSet};
use crate::common::oracle::{VulnerabilityOracle, VulnType};
use crate::common::types::Snapshot;
use super::economic::{EconomicState, PriceAnalyzer};

/// Detects flashloan attacks by analyzing profitability without collateral
pub struct FlashLoanOracle {
    /// Known flashloan provider addresses (Aave, dYdX, Uniswap, etc.)
    pub providers: HashSet<Address>,
    /// Initial economic state before transaction sequence
    pub initial_state: EconomicState,
    /// Current economic state
    pub current_state: EconomicState,
}

impl FlashLoanOracle {
    pub fn new(initial_state: EconomicState) -> Self {
        let mut providers = HashSet::new();
        // Add known flashloan providers
        providers.insert(Address::from_slice(&hex::decode("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9").unwrap())); // Aave V2
        providers.insert(Address::from_slice(&hex::decode("87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2").unwrap())); // Aave V3
        providers.insert(Address::from_slice(&hex::decode("1C32bE1aC51a437986650e25df6ACcf33C6446e2").unwrap())); // dYdX
        
        Self {
            providers,
            initial_state,
            current_state: initial_state.clone(),
        }
    }

    /// Record a flashloan borrow event
    pub fn record_borrow(&mut self, token: Address, amount: U256, borrower: Address) {
        // Flashloans increase borrower balance temporarily
        let entry = self.current_state.balances.entry(token).or_insert_with(HashMap::new);
        let bal = entry.entry(borrower).or_insert(U256::ZERO);
        *bal = bal.saturating_add(amount);
    }

    /// Record a flashloan repay event
    pub fn record_repay(&mut self, token: Address, amount: U256, borrower: Address) {
        let entry = self.current_state.balances.entry(token).or_insert_with(HashMap::new);
        let bal = entry.entry(borrower).or_insert(U256::ZERO);
        *bal = bal.saturating_sub(amount);
    }

    /// Check if the transaction sequence resulted in profit indicative of flashloan attack
    fn detect_profit(&self, attacker: Address) -> Option<VulnType> {
        let report = self.current_state.calculate_profit(attacker, &self.initial_state);
        
        // Threshold: 0.1 ETH profit (adjustable)
        let threshold = U256::from(100_000_000_000_000_000u128);
        
        if report.is_significant(threshold) {
            return Some(VulnType::FlashLoanProfit);
        }
        None
    }
}

impl VulnerabilityOracle for FlashLoanOracle {
    fn check(&self, _before: &Snapshot, _after: &Snapshot) -> Option<VulnType> {
        // In real impl, we'd analyze the trace for flashloan patterns
        // For now, check economic state directly
        // Attacker address would be configured or detected as tx origin
        let dummy_attacker = Address::ZERO; // Replace with actual tx origin
        self.detect_profit(dummy_attacker)
    }
}

/// Detects price oracle manipulation attacks
pub struct PriceManipulationOracle {
    pub analyzer: PriceAnalyzer,
    /// Threshold for manipulation detection (in basis points, e.g., 500 = 5%)
    pub threshold_bps: u64,
    /// Known oracle contracts
    pub oracles: HashSet<Address>,
}

impl PriceManipulationOracle {
    pub fn new(threshold_bps: u64) -> Self {
        let mut oracles = HashSet::new();
        // Add known oracles (Chainlink, Uniswap TWAP, etc.)
        oracles.insert(Address::from_slice(&hex::decode("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419").unwrap())); // ETH/USD Chainlink
        
        Self {
            analyzer: PriceAnalyzer::new(),
            threshold_bps,
            oracles,
        }
    }

    /// Record initial price from oracle
    pub fn record_initial_price(&mut self, oracle: Address, price: U256) {
        self.analyzer.record_initial_price(oracle, price);
    }

    /// Check if current price deviates significantly from initial
    pub fn check_manipulation(&self, oracle: Address, current_price: U256) -> Option<VulnType> {
        if !self.oracles.contains(&oracle) {
            return None;
        }

        if self.analyzer.check_manipulation(oracle, current_price, self.threshold_bps) {
            Some(VulnType::PriceOracleManipulation)
        } else {
            None
        }
    }
}

impl VulnerabilityOracle for PriceManipulationOracle {
    fn check(&self, _before: &Snapshot, _after: &Snapshot) -> Option<VulnType> {
        // Real impl would extract price reads from trace
        // This is a framework for detection logic
        None
    }
}

/// Detects access control bypasses
pub struct AccessControlOracle {
    /// Functions that should be restricted: selector -> allowed roles
    pub protected_functions: HashMap<[u8; 4], HashSet<String>>,
    /// Current caller's roles (extracted from contract state)
    pub caller_roles: HashMap<Address, HashSet<String>>,
}

impl AccessControlOracle {
    pub fn new() -> Self {
        Self {
            protected_functions: HashMap::new(),
            caller_roles: HashMap::new(),
        }
    }

    /// Register a protected function
    pub fn add_protected_function(&mut self, selector: [u8; 4], required_roles: Vec<&str>) {
        let roles: HashSet<String> = required_roles.into_iter().map(String::from).collect();
        self.protected_functions.insert(selector, roles);
    }

    /// Record caller's roles (parsed from contract state or events)
    pub fn set_caller_roles(&mut self, caller: Address, roles: Vec<&str>) {
        let role_set: HashSet<String> = roles.into_iter().map(String::from).collect();
        self.caller_roles.insert(caller, role_set);
    }

    /// Check if a function call violated access control
    pub fn check_violation(&self, selector: [u8; 4], caller: Address, succeeded: bool) -> Option<VulnType> {
        if !succeeded {
            return None; // Reverted calls don't indicate bypass
        }

        if let Some(required_roles) = self.protected_functions.get(&selector) {
            if let Some(caller_roles) = self.caller_roles.get(&caller) {
                // Check if caller has ANY of the required roles
                let has_access = required_roles.iter().any(|r| caller_roles.contains(r));
                
                if !has_access {
                    return Some(VulnType::Other(format!("AccessControlBypass: selector={:?}", selector)));
                }
            } else {
                // Caller has no recorded roles, assume no access
                return Some(VulnType::Other(format!("AccessControlBypass: selector={:?}", selector)));
            }
        }
        None
    }
}

impl VulnerabilityOracle for AccessControlOracle {
    fn check(&self, _before: &Snapshot, _after: &Snapshot) -> Option<VulnType> {
        // Real impl would iterate through executed transactions and check each call
        None
    }
}

/// Composite oracle that runs all economic checks
pub struct EconomicOracleBundle {
    pub flashloan: FlashLoanOracle,
    pub price_manipulation: PriceManipulationOracle,
    pub access_control: AccessControlOracle,
}

impl EconomicOracleBundle {
    pub fn new(initial_state: EconomicState) -> Self {
        Self {
            flashloan: FlashLoanOracle::new(initial_state.clone()),
            price_manipulation: PriceManipulationOracle::new(500), // 5% threshold
            access_control: AccessControlOracle::new(),
        }
    }

    pub fn check_all(&self, before: &Snapshot, after: &Snapshot) -> Vec<VulnType> {
        let mut vulns = Vec::new();
        
        if let Some(v) = self.flashloan.check(before, after) {
            vulns.push(v);
        }
        if let Some(v) = self.price_manipulation.check(before, after) {
            vulns.push(v);
        }
        if let Some(v) = self.access_control.check(before, after) {
            vulns.push(v);
        }
        
        vulns
    }
}
