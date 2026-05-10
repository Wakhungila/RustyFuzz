use crate::common::types::{Snapshot, ChainState};
use crate::common::oracle::{VulnerabilityOracle, VulnType};
use revm::primitives::{Address, U256};

/// MEVOracle: Detects profitable sandwich attacks and frontrunning.
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

            let (ChainState::Evm(db_before), ChainState::Evm(db_after)) =
                (&*state_before, &*state_after);
                let bal_before = db_before
                    .cache.accounts
                    .get(&self.fuzzer_address)
                    .map(|a| a.info.balance)
                    .unwrap_or(U256::ZERO);
                let bal_after = db_after
                    .cache.accounts
                    .get(&self.fuzzer_address)
                    .map(|a| a.info.balance)
                    .unwrap_or(U256::ZERO);

                if bal_after > bal_before {
                    let profit = bal_after - bal_before;
                    if profit > U256::from(10u128.pow(15)) {
                        log::warn!("MEV EXPLOIT: Profitable sandwich detected. Profit: {}", profit);
                        return Some(VulnType::MevSandwichExploit);
                    }
                }
            }
        None
    }
}
