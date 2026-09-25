use crate::common::types::{CallPhase, ChainState, SequenceExecutionResult};
use crate::evm::etherscan_abi_fetcher::EtherscanAbiFetcher;
use crate::evm::fuzz::AbiRegistry;
use crate::evm::trace::ExecutionTrace;
use alloy_dyn_abi::DynSolType;
use alloy_json_abi::JsonAbi;
use libafl_bolts::rands::Rand;
use revm::primitives::{Address, U256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZero;

fn populate_remote_abi(abi: &JsonAbi, abi_registry: &mut AbiRegistry) -> anyhow::Result<()> {
    let mut staged_functions = HashMap::new();

    for function in abi.functions() {
        let inputs = function
            .inputs
            .iter()
            .map(|parameter| DynSolType::parse(&parameter.ty))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                anyhow::anyhow!(
                    "remote ABI function `{}` contains an invalid type `{}`: {error}",
                    function.name,
                    function
                        .inputs
                        .iter()
                        .find(|parameter| DynSolType::parse(&parameter.ty).is_err())
                        .map_or_else(|| "<unknown>".to_string(), |parameter| parameter.ty.clone())
                )
            })?;
        staged_functions.insert(function.selector().0, inputs);
    }

    abi_registry.functions.extend(staged_functions);
    Ok(())
}

#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GlobalAccountRegistry {
    pub contracts: HashSet<Address>,
    /// Directed Call Graph: Caller -> { Callee1, Callee2, ... }
    pub call_graph: HashMap<Address, HashSet<Address>>,
    pub erc20_balance_slots: HashMap<Address, U256>, // token_address -> balance_slot
    pub erc20_total_supply_slots: HashMap<Address, U256>, // token_address -> total_supply_slot
    #[serde(skip)]
    pub etherscan_abi_fetcher: Option<EtherscanAbiFetcher>,
    pub target_models: HashMap<Address, TargetModel>,
}

#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TargetModel {
    pub observed_selectors: HashSet<[u8; 4]>,
    pub callers: HashSet<Address>,
    pub callees: HashSet<Address>,
    pub storage_reads: HashSet<U256>,
    pub storage_writes: HashSet<U256>,
    pub successful_calls: usize,
    pub reverting_calls: usize,
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
                "transfer(address,uint256)",
                vec![DynSolType::Address, DynSolType::Uint(256)],
            ),
            (
                "transferFrom(address,address,uint256)",
                vec![
                    DynSolType::Address,
                    DynSolType::Address,
                    DynSolType::Uint(256),
                ],
            ),
            (
                "approve(address,uint256)",
                vec![DynSolType::Address, DynSolType::Uint(256)],
            ),
            (
                "initialize(address,uint256,bytes)",
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Bytes,
                ],
            ),
            (
                "deposit(uint256,address)",
                vec![DynSolType::Uint(256), DynSolType::Address],
            ),
            ("deposit(uint256)", vec![DynSolType::Uint(256)]),
            ("withdraw(uint256)", vec![DynSolType::Uint(256)]),
            (
                "withdraw(uint256,address,address)",
                vec![
                    DynSolType::Uint(256),
                    DynSolType::Address,
                    DynSolType::Address,
                ],
            ),
            (
                "redeem(uint256,address,address)",
                vec![
                    DynSolType::Uint(256),
                    DynSolType::Address,
                    DynSolType::Address,
                ],
            ),
            ("safeMint(uint256)", vec![DynSolType::Uint(256)]),
            (
                "upgradeToAndCall(address,bytes)",
                vec![DynSolType::Address, DynSolType::Bytes],
            ),
            (
                "supply(address,uint256,address,uint16)",
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Address,
                    DynSolType::Uint(16),
                ],
            ),
            (
                "repay(address,uint256,uint256,address)",
                vec![
                    DynSolType::Address,
                    DynSolType::Uint(256),
                    DynSolType::Uint(256),
                    DynSolType::Address,
                ],
            ),
            (
                "swap(address,bool,int256,uint160,bytes)",
                vec![
                    DynSolType::Address,
                    DynSolType::Bool,
                    DynSolType::Int(256),
                    DynSolType::Uint(160),
                    DynSolType::Bytes,
                ],
            ),
            ("totalAssets()", vec![]),
            ("totalSupply()", vec![]),
            ("balanceOf(address)", vec![DynSolType::Address]),
            ("canMint(address)", vec![DynSolType::Address]),
        ]
        .into_iter()
        .map(|(signature, types)| {
            let hash = revm::primitives::keccak256(signature.as_bytes());
            ([hash[0], hash[1], hash[2], hash[3]], types)
        })
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

    pub fn observe_execution(&mut self, execution: &SequenceExecutionResult) {
        for call in execution
            .call_trace
            .iter()
            .filter(|call| call.phase == CallPhase::End)
        {
            self.contracts.insert(call.target);
            self.contracts.insert(call.caller);
            self.call_graph
                .entry(call.caller)
                .or_default()
                .insert(call.target);

            let model = self.target_models.entry(call.target).or_default();
            model.callers.insert(call.caller);
            if let Some(selector) = call.input.get(..4).and_then(|bytes| bytes.try_into().ok()) {
                model.observed_selectors.insert(selector);
            }
            if call.success {
                model.successful_calls += 1;
            } else {
                model.reverting_calls += 1;
            }
        }

        for edge in &execution.call_trace {
            if edge.phase == CallPhase::End {
                self.target_models
                    .entry(edge.caller)
                    .or_default()
                    .callees
                    .insert(edge.target);
            }
        }

        for read in &execution.storage_reads {
            self.target_models
                .entry(read.address)
                .or_default()
                .storage_reads
                .insert(U256::from_be_bytes(read.slot.0));
        }
        for write in &execution.storage_writes {
            self.target_models
                .entry(write.address)
                .or_default()
                .storage_writes
                .insert(U256::from_be_bytes(write.slot.0));
        }
    }

    pub fn model_for(&self, target: &Address) -> Option<&TargetModel> {
        self.target_models.get(target)
    }

    /// Fetches and populates the ABI for a given contract from Etherscan.
    pub async fn fetch_and_populate_abi(
        &self,
        address: Address,
        abi_registry: &mut AbiRegistry,
    ) -> anyhow::Result<()> {
        if let Some(fetcher) = &self.etherscan_abi_fetcher {
            let abi = fetcher.fetch_abi(address).await?;
            populate_remote_abi(&abi, abi_registry)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_abi_malformed_type_is_propagated_without_partial_registry_entry() {
        let function = alloy_json_abi::Function {
            name: "broken".to_string(),
            inputs: vec![alloy_json_abi::Param {
                ty: "not-a-solidity-type".to_string(),
                name: "value".to_string(),
                components: Vec::new(),
                internal_type: None,
            }],
            outputs: Vec::new(),
            state_mutability: alloy_json_abi::StateMutability::NonPayable,
        };
        let mut abi = JsonAbi::default();
        abi.functions.insert("broken".to_string(), vec![function]);
        let mut registry = AbiRegistry::default();
        let error = populate_remote_abi(&abi, &mut registry).expect_err("malformed ABI type");
        assert!(error.to_string().contains("not-a-solidity-type"));
        assert!(registry.functions.is_empty());
    }

    #[test]
    fn remote_abi_partial_failure_does_not_commit_staged_functions() {
        let valid_function = alloy_json_abi::Function {
            name: "a_valid".to_string(),
            inputs: vec![alloy_json_abi::Param {
                ty: "uint256".to_string(),
                name: "value".to_string(),
                components: Vec::new(),
                internal_type: None,
            }],
            outputs: Vec::new(),
            state_mutability: alloy_json_abi::StateMutability::NonPayable,
        };
        let invalid_function = alloy_json_abi::Function {
            name: "z_broken".to_string(),
            inputs: vec![alloy_json_abi::Param {
                ty: "not-a-solidity-type".to_string(),
                name: "value".to_string(),
                components: Vec::new(),
                internal_type: None,
            }],
            outputs: Vec::new(),
            state_mutability: alloy_json_abi::StateMutability::NonPayable,
        };
        let mut abi = JsonAbi::default();
        abi.functions
            .insert("a_valid".to_string(), vec![valid_function]);
        abi.functions
            .insert("z_broken".to_string(), vec![invalid_function]);

        let mut registry = AbiRegistry::default();
        let existing_selector = [0, 0, 0, 0];
        registry.functions.insert(existing_selector, Vec::new());

        let error = populate_remote_abi(&abi, &mut registry).expect_err("malformed ABI type");

        assert!(error.to_string().contains("not-a-solidity-type"));
        assert_eq!(registry.functions.len(), 1);
        assert!(registry.functions.contains_key(&existing_selector));
    }
}
