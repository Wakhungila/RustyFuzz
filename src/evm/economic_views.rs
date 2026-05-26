use crate::common::types::{ChainState, SingletonTx};
use crate::engine::economic_delta::{
    AmmReserveView, EconomicViewSnapshot, LendingHealthView, OracleAnswerView, ScalarView,
    TokenBalanceView,
};
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::executor::EvmExecutor;
use revm::context::BlockEnv;
use revm::primitives::{keccak256, Address, U256};
use std::collections::BTreeSet;

const VIEW_GAS_MAP_SIZE: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EconomicViewProbePlan {
    pub actors: Vec<Address>,
    pub tokens: Vec<Address>,
    pub vaults: Vec<Address>,
    pub pools: Vec<Address>,
    pub oracles: Vec<Address>,
    pub lending_protocols: Vec<Address>,
}

impl EconomicViewProbePlan {
    pub fn from_sequence(input: &crate::evm::fuzz::EvmInput, target: Option<Address>) -> Self {
        let mut actors = BTreeSet::new();
        let mut contracts = BTreeSet::new();
        if let Some(target) = target {
            contracts.insert(target);
        }
        for tx in &input.txs {
            actors.insert(tx.caller);
            if tx.to != Address::ZERO {
                contracts.insert(tx.to);
            }
        }
        let contracts = contracts.into_iter().collect::<Vec<_>>();
        Self {
            actors: actors.into_iter().collect(),
            tokens: contracts.clone(),
            vaults: contracts.clone(),
            pools: contracts.clone(),
            oracles: contracts.clone(),
            lending_protocols: contracts,
        }
    }
}

pub fn snapshot_economic_views(
    base_state: &ChainState,
    block_env: &BlockEnv,
    plan: &EconomicViewProbePlan,
    tx_index: usize,
) -> EconomicViewSnapshot {
    let caller = plan.actors.first().copied().unwrap_or(Address::ZERO);
    let mut snapshot = EconomicViewSnapshot {
        tx_index,
        actor: Some(caller),
        ..EconomicViewSnapshot::default()
    };

    for token in &plan.tokens {
        for owner in &plan.actors {
            if let Some(value) = call_u256(
                base_state,
                block_env,
                caller,
                *token,
                calldata_with_address("balanceOf(address)", *owner),
            ) {
                snapshot.token_balances.push(TokenBalanceView {
                    token: *token,
                    owner: *owner,
                    value,
                });
            }
        }
    }

    for vault in &plan.vaults {
        let total_assets = call_u256(
            base_state,
            block_env,
            caller,
            *vault,
            selector("totalAssets()").to_vec(),
        );
        let total_supply = call_u256(
            base_state,
            block_env,
            caller,
            *vault,
            selector("totalSupply()").to_vec(),
        );
        if let (Some(assets), Some(supply)) = (total_assets, total_supply) {
            if !supply.is_zero() {
                let value = assets
                    .saturating_mul(U256::from(10_000u64))
                    .checked_div(supply)
                    .unwrap_or(U256::ZERO);
                snapshot.vault_share_prices_bps.push(ScalarView {
                    contract: *vault,
                    value,
                });
            }
        }
    }

    for pool in &plan.pools {
        if let Some(output) = call_raw(
            base_state,
            block_env,
            caller,
            *pool,
            selector("getReserves()").to_vec(),
        ) {
            if output.len() >= 64 {
                snapshot.amm_reserves.push(AmmReserveView {
                    pool: *pool,
                    reserve0: word(&output, 0),
                    reserve1: word(&output, 32),
                });
            }
        }
    }

    for oracle in &plan.oracles {
        if let Some(answer) = call_u256(
            base_state,
            block_env,
            caller,
            *oracle,
            selector("latestAnswer()").to_vec(),
        ) {
            snapshot.oracle_answers.push(OracleAnswerView {
                oracle: *oracle,
                answer,
                updated_at: None,
            });
        } else if let Some(output) = call_raw(
            base_state,
            block_env,
            caller,
            *oracle,
            selector("latestRoundData()").to_vec(),
        ) {
            if output.len() >= 160 {
                snapshot.oracle_answers.push(OracleAnswerView {
                    oracle: *oracle,
                    answer: word(&output, 32),
                    updated_at: Some(word(&output, 96).to::<u64>()),
                });
            }
        }
    }

    for protocol in &plan.lending_protocols {
        for account in &plan.actors {
            if let Some(output) = call_raw(
                base_state,
                block_env,
                caller,
                *protocol,
                calldata_with_address("getUserAccountData(address)", *account),
            ) {
                if output.len() >= 192 {
                    snapshot.lending_health.push(LendingHealthView {
                        protocol: *protocol,
                        account: *account,
                        collateral: word(&output, 0),
                        debt: word(&output, 32),
                        health_factor: word(&output, 160),
                    });
                }
            }
        }
    }

    snapshot
}

fn call_u256(
    base_state: &ChainState,
    block_env: &BlockEnv,
    caller: Address,
    to: Address,
    calldata: Vec<u8>,
) -> Option<U256> {
    call_raw(base_state, block_env, caller, to, calldata)
        .filter(|output| output.len() >= 32)
        .map(|output| word(&output, 0))
}

fn call_raw(
    base_state: &ChainState,
    block_env: &BlockEnv,
    caller: Address,
    to: Address,
    calldata: Vec<u8>,
) -> Option<Vec<u8>> {
    let mut state = base_state.clone();
    let mut env = block_env.clone();
    let mut coverage = vec![0u8; VIEW_GAS_MAP_SIZE];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();
    let result = EvmExecutor::new()
        .execute_with_result(
            &mut state,
            &mut env,
            &SingletonTx {
                input: calldata,
                caller,
                to,
                value: U256::ZERO,
                is_victim: false,
            },
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .ok()?;
    if result.output.len() >= 32 {
        Some(result.output)
    } else {
        None
    }
}

fn calldata_with_address(signature: &str, address: Address) -> Vec<u8> {
    let mut calldata = selector(signature).to_vec();
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(address.as_slice());
    calldata
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes()).0[..4]
        .try_into()
        .expect("selector slice has four bytes")
}

fn word(output: &[u8], offset: usize) -> U256 {
    output
        .get(offset..offset + 32)
        .map(U256::from_be_slice)
        .unwrap_or(U256::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_plan_infers_actors_and_contracts_from_sequence() {
        let caller = Address::new([0x11; 20]);
        let target = Address::new([0x22; 20]);
        let input = crate::evm::fuzz::EvmInput {
            txs: vec![SingletonTx {
                input: vec![1, 2, 3, 4],
                caller,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let plan = EconomicViewProbePlan::from_sequence(&input, Some(target));
        assert_eq!(plan.actors, vec![caller]);
        assert!(plan.tokens.contains(&target));
        assert!(plan.vaults.contains(&target));
        assert!(plan.pools.contains(&target));
    }
}
