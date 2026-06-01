use alloy_primitives::{Address, U256};
use revm::state::AccountInfo;
use std::collections::HashMap;

/// Tracks economic state changes to detect profitable attacks
#[derive(Debug, Clone, Default)]
pub struct EconomicState {
    /// Token balances per address: Token -> Account -> Balance
    pub balances: HashMap<Address, HashMap<Address, U256>>,
    /// DEX Reserves: PairAddress -> (ReserveA, ReserveB)
    pub reserves: HashMap<Address, (U256, U256)>,
    /// Native balance (ETH) per address
    pub native_balances: HashMap<Address, U256>,
}

impl EconomicState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture state from EVM DB (simplified for demo, real impl iterates journal)
    pub fn capture_from_accounts(&mut self, accounts: &HashMap<Address, AccountInfo>) {
        self.native_balances.clear();
        for (addr, info) in accounts {
            self.native_balances.insert(*addr, info.balance);
        }
    }

    /// Record a token transfer event (called by oracle during trace analysis)
    pub fn record_transfer(&mut self, token: Address, from: Address, to: Address, amount: U256) {
        let entry = self.balances.entry(token).or_insert_with(HashMap::new);

        // Deduct from sender
        let from_bal = entry.entry(from).or_insert(U256::ZERO);
        *from_bal = from_bal.saturating_sub(amount);

        // Add to receiver
        let to_bal = entry.entry(to).or_insert(U256::ZERO);
        *to_bal = to_bal.saturating_add(amount);
    }

    /// Update DEX reserves (parsed from Swap events or state reads)
    pub fn update_reserves(&mut self, pair: Address, reserve_a: U256, reserve_b: U256) {
        self.reserves.insert(pair, (reserve_a, reserve_b));
    }

    /// Calculate net profit for a specific address (attacker)
    pub fn calculate_profit(
        &self,
        attacker: Address,
        initial_state: &EconomicState,
    ) -> ProfitReport {
        let mut report = ProfitReport::default();

        // Native ETH profit
        let current_eth = self
            .native_balances
            .get(&attacker)
            .copied()
            .unwrap_or(U256::ZERO);
        let initial_eth = initial_state
            .native_balances
            .get(&attacker)
            .copied()
            .unwrap_or(U256::ZERO);
        report.eth_profit = current_eth.saturating_sub(initial_eth);

        // Token profits
        for (token, current_balances) in &self.balances {
            let current = current_balances
                .get(&attacker)
                .copied()
                .unwrap_or(U256::ZERO);
            let initial = initial_state
                .balances
                .get(token)
                .and_then(|m| m.get(&attacker).copied())
                .unwrap_or(U256::ZERO);

            let profit = current.saturating_sub(initial);
            if profit > U256::ZERO {
                report.token_profits.insert(*token, profit);
            }
        }

        report
    }
}

#[derive(Debug, Default)]
pub struct ProfitReport {
    pub eth_profit: U256,
    pub token_profits: HashMap<Address, U256>,
}

impl ProfitReport {
    pub fn is_significant(&self, threshold_eth: U256) -> bool {
        if self.eth_profit >= threshold_eth {
            return true;
        }
        // Simplified: assume 1 token = 1 ETH for demo, real impl needs price oracle
        !self.token_profits.is_empty() && self.token_profits.values().any(|&v| v > U256::from(1000))
    }
}

/// Detects price manipulation by comparing spot vs expected price
#[derive(Debug)]
pub struct PriceAnalyzer {
    pub initial_prices: HashMap<Address, U256>, // Pair -> Price
}

impl PriceAnalyzer {
    pub fn new() -> Self {
        Self {
            initial_prices: HashMap::new(),
        }
    }

    pub fn record_initial_price(&mut self, pair: Address, price: U256) {
        self.initial_prices.entry(pair).or_insert(price);
    }

    pub fn check_manipulation(
        &self,
        pair: Address,
        current_price: U256,
        threshold_pct: u64,
    ) -> bool {
        if let Some(&initial) = self.initial_prices.get(&pair) {
            if initial == U256::ZERO {
                return false;
            }

            let diff = if current_price > initial {
                current_price - initial
            } else {
                initial - current_price
            };

            let pct_change = (diff * U256::from(10000)) / initial;
            pct_change > U256::from(threshold_pct * 100) // threshold_pct is basis points
        } else {
            false
        }
    }
}
