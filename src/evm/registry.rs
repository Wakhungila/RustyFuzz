use crate::common::types::ChainState;
use crate::evm::etherscan_abi_fetcher::EtherscanAbiFetcher;
use crate::evm::fuzz::AbiRegistry;
use crate::evm::trace::ExecutionTrace;
use alloy_dyn_abi::DynSolType;
use libafl_bolts::rands::Rand;
use revm::primitives::{Address, U256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZero;

#[derive(Default, Clone, Debug)]
pub struct GlobalAccountRegistry {
    pub contracts: HashSet<Address>,
    /// Directed Call Graph: Caller -> { Callee1, Callee2, ... }
    pub call_graph: HashMap<Address, HashSet<Address>>,
    pub erc20_balance_slots: HashMap<Address, U256>, // token_address -> balance_slot
    pub erc20_total_supply_slots: HashMap<Address, U256>, // token_address -> total_supply_slot
    pub etherscan_abi_fetcher: Option<EtherscanAbiFetcher>,
}

impl GlobalAccountRegistry {
    /// Scans the EVM state for accounts with code and adds them to the registry.
    pub fn discover_from_state(&mut self, state: &ChainState) {
        let ChainState::Evm(db) = state;
        for (addr, acc) in &db.cache.accounts {
            // Heuristic: If it has code, it's a potential fuzzing target
            if acc.info.code.as_ref().is_some_and(|c| !c.is_empty()) {
                let alloy_addr = Address::from_slice(addr.as_slice());
                self.contracts.insert(alloy_addr);
            }
        }
    }

    /// Automatically populates an AbiRegistry with common DeFi selectors for fast startup.
    pub fn auto_populate_abi(&self, registry: &mut AbiRegistry) {
        let common_sigs: BTreeMap<[u8; 4], Vec<DynSolType>> = [
            (
                [0xa9, 0x05, 0x9c, 0xbb],
                vec![DynSolType::Address, DynSolType::Uint(256)],
            ), // ERC20 transfer
            (
                [0x23, 0xb8, 0x72, 0xdd],
                vec![
                    DynSolType::Address,
                    DynSolType::Address,
                    DynSolType::Uint(256),
                ],
            ), // ERC20 transferFrom
            (
                [0x09, 0x5e, 0xa7, 0xb3],
                vec![DynSolType::Address, DynSolType::Uint(256)],
            ), // ERC20 approve
            (
                [0x81, 0x19, 0xc0, 0x65],
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Bytes,
                ],
            ), // Proxy initialize
            (
                [0xb6, 0xb5, 0x5f, 0x25],
                vec![DynSolType::Uint(256), DynSolType::Address],
            ), // Vault deposit
            ([0x2e, 0x1a, 0x7d, 0x4d], vec![DynSolType::Uint(256)]), // Vault withdraw
            ([0x42, 0x96, 0x69, 0x45], vec![DynSolType::Uint(256)]), // ERC721 safeMint
            ([0x36, 0x44, 0x2b, 0x24], vec![]), // Proxy upgradeToAndCall (partial)
            (
                [0x61, 0x7c, 0x03, 0xcb],
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Uint(256),
                    DynSolType::Uint(16),
                ],
            ), // Aave V3 supply
            (
                [0xa4, 0x15, 0xbb, 0x22],
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Uint(256),
                    DynSolType::Address,
                ],
            ), // Uniswap V3 swap
            ([0x01, 0xad, 0x8a, 0x86], vec![]), // totalAssets
            ([0x18, 0x16, 0x0d, 0xdd], vec![]), // totalSupply
            ([0x70, 0xa0, 0x82, 0x31], vec![DynSolType::Address]), // balanceOf
        ]
        .into_iter()
        .collect();

        for (sel, types) in common_sigs {
            registry.functions.entry(sel).or_insert(types);
        }
    }

    /// Updates the protocol graph based on an execution trace.
    /// This captures internal calls and contract creations (deployments).
    pub fn record_trace(&mut self, trace: &ExecutionTrace) {
        for call in &trace.calls {
            self.contracts.insert(call.target);
            self.contracts.insert(call.caller);

            self.call_graph
                .entry(call.caller)
                .or_default()
                .insert(call.target);
        }

        for create in &trace.creates {
            if let Some(deployed) = create.deployed_address {
                self.contracts.insert(deployed);
                self.call_graph
                    .entry(create.creator)
                    .or_default()
                    .insert(deployed);
            }
        }
    }

    /// Fetches and populates the ABI for a given contract from Etherscan.
    pub async fn fetch_and_populate_abi(
        &self,
        address: Address,
        abi_registry: &mut AbiRegistry,
    ) -> anyhow::Result<()> {
        if let Some(fetcher) = &self.etherscan_abi_fetcher {
            let abi = fetcher.fetch_abi(address).await?;
            for func in abi.functions() {
                abi_registry.functions.insert(
                    func.selector().0,
                    func.inputs
                        .iter()
                        .map(|p| DynSolType::parse(&p.ty).unwrap())
                        .collect(),
                );
            }
            log::info!("Fetched ABI for {} from Etherscan.", address);
        }
        Ok(())
    }

    /// Returns a potential "next step" for a given contract based on observed flows.
    pub fn get_downstream_targets(&self, contract: &Address) -> Vec<Address> {
        self.call_graph
            .get(contract)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn random_contract<R: Rand>(&self, rand: &mut R) -> Option<Address> {
        if self.contracts.is_empty() {
            return None;
        }
        let idx = rand.below(NonZero::new(self.contracts.len()).unwrap());
        self.contracts.iter().nth(idx).cloned()
    }
}
