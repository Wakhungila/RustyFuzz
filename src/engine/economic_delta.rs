use crate::common::types::{SequenceExecutionResult, StorageDiff};
use crate::evm::fuzz::EvmInput;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBalanceObservation {
    pub token: Address,
    pub owner: Address,
    pub before: U256,
    pub after: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EconomicDeltaReport {
    pub attacker: Option<Address>,
    pub victim: Option<Address>,
    pub attacker_native_delta: i128,
    pub victim_native_delta: i128,
    pub token_deltas: Vec<TokenBalanceDelta>,
    pub storage_delta_summary: Vec<StorageDeltaSummary>,
    pub estimated_profit: U256,
    pub suspicious_value_extraction: bool,
    pub accounting_anomaly: bool,
    pub confidence: u64,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBalanceDelta {
    pub token: Address,
    pub owner: Address,
    pub delta: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDeltaSummary {
    pub address: Address,
    pub slot_count: usize,
    pub absolute_delta_score: U256,
}

#[derive(Debug, Clone, Default)]
pub struct EconomicDeltaEngine;

impl EconomicDeltaEngine {
    pub fn from_balance_observations(
        attacker: Address,
        victim: Option<Address>,
        observations: &[TokenBalanceObservation],
    ) -> EconomicDeltaReport {
        let mut report = EconomicDeltaReport {
            attacker: Some(attacker),
            victim,
            caveats: vec![
                "token balance observations supplied externally or by harness".to_string(),
            ],
            ..EconomicDeltaReport::default()
        };
        for obs in observations {
            let delta = signed_delta(obs.before, obs.after);
            if obs.owner == attacker && delta > 0 {
                report.estimated_profit = report
                    .estimated_profit
                    .saturating_add(U256::from(delta as u128));
            }
            if Some(obs.owner) == victim && delta < 0 {
                report.suspicious_value_extraction = true;
            }
            report.token_deltas.push(TokenBalanceDelta {
                token: obs.token,
                owner: obs.owner,
                delta,
            });
        }
        report.accounting_anomaly = report.token_deltas.iter().any(|delta| delta.delta != 0)
            && report.estimated_profit > U256::ZERO;
        report.confidence = if report.suspicious_value_extraction {
            85
        } else if report.estimated_profit > U256::ZERO {
            70
        } else {
            25
        };
        report
    }

    pub fn from_execution(
        input: &EvmInput,
        execution: &SequenceExecutionResult,
    ) -> EconomicDeltaReport {
        let attacker = input.txs.first().map(|tx| tx.caller);
        let victim = input.txs.iter().find(|tx| tx.is_victim).map(|tx| tx.caller);
        let storage_delta_summary = summarize_storage_deltas(&execution.storage_diffs);
        let large_delta_count = execution
            .storage_diffs
            .iter()
            .filter(|diff| absolute_delta(diff) >= U256::from(10u128.pow(18)))
            .count();
        let multi_actor = input
            .txs
            .iter()
            .map(|tx| tx.caller)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1;
        let accounting_anomaly = large_delta_count >= 2;
        let suspicious_value_extraction = multi_actor && accounting_anomaly;
        let confidence = match (
            suspicious_value_extraction,
            accounting_anomaly,
            large_delta_count,
        ) {
            (true, _, _) => 70,
            (_, true, _) => 55,
            (_, _, count) if count > 0 => 35,
            _ => 10,
        };
        EconomicDeltaReport {
            attacker,
            victim,
            storage_delta_summary,
            suspicious_value_extraction,
            accounting_anomaly,
            confidence,
            estimated_profit: if suspicious_value_extraction { U256::from(large_delta_count as u64) } else { U256::ZERO },
            caveats: vec!["storage-delta economic estimate is heuristic until token balance reads are available".to_string()],
            ..EconomicDeltaReport::default()
        }
    }

    pub fn score(report: &EconomicDeltaReport) -> u64 {
        let profit_score = if report.estimated_profit > U256::ZERO {
            150
        } else {
            0
        };
        let extraction_score = if report.suspicious_value_extraction {
            250
        } else {
            0
        };
        let accounting_score = if report.accounting_anomaly { 120 } else { 0 };
        (profit_score + extraction_score + accounting_score + report.confidence).min(700)
    }
}

fn summarize_storage_deltas(diffs: &[StorageDiff]) -> Vec<StorageDeltaSummary> {
    let mut by_address: BTreeMap<Address, (usize, U256)> = BTreeMap::new();
    for diff in diffs {
        let entry = by_address.entry(diff.address).or_insert((0, U256::ZERO));
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(absolute_delta(diff));
    }
    by_address
        .into_iter()
        .map(
            |(address, (slot_count, absolute_delta_score))| StorageDeltaSummary {
                address,
                slot_count,
                absolute_delta_score,
            },
        )
        .collect()
}

fn absolute_delta(diff: &StorageDiff) -> U256 {
    if diff.new_value >= diff.old_value {
        diff.new_value - diff.old_value
    } else {
        diff.old_value - diff.new_value
    }
}

fn signed_delta(before: U256, after: U256) -> i128 {
    if after >= before {
        u256_to_i128(after - before)
    } else {
        -u256_to_i128(before - after)
    }
}

fn u256_to_i128(value: U256) -> i128 {
    let capped = value.min(U256::from(i128::MAX as u128));
    capped.to::<u128>() as i128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ExecutionStatus, SingletonTx, TxExecutionResult};
    use revm::primitives::B256;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    #[test]
    fn token_delta_reports_attacker_profit() {
        let report = EconomicDeltaEngine::from_balance_observations(
            addr(0xaa),
            Some(addr(0xbb)),
            &[
                TokenBalanceObservation {
                    token: addr(0x11),
                    owner: addr(0xaa),
                    before: U256::from(1),
                    after: U256::from(10),
                },
                TokenBalanceObservation {
                    token: addr(0x11),
                    owner: addr(0xbb),
                    before: U256::from(10),
                    after: U256::from(1),
                },
            ],
        );
        assert_eq!(report.estimated_profit, U256::from(9));
        assert!(report.suspicious_value_extraction);
        assert!(EconomicDeltaEngine::score(&report) >= 400);
    }

    #[test]
    fn execution_delta_flags_large_multi_actor_storage_movement() {
        let target = addr(0xcc);
        let input = EvmInput {
            txs: vec![
                SingletonTx {
                    input: vec![],
                    caller: addr(0xaa),
                    to: target,
                    value: U256::ZERO,
                    is_victim: false,
                },
                SingletonTx {
                    input: vec![],
                    caller: addr(0xbb),
                    to: target,
                    value: U256::ZERO,
                    is_victim: true,
                },
            ],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 1,
                output: Vec::new(),
                coverage_hash: 0,
                coverage_edges: 0,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 1,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![
                StorageDiff {
                    tx_index: 0,
                    address: target,
                    slot: B256::ZERO,
                    old_value: U256::ZERO,
                    new_value: U256::from(10u128.pow(18)),
                    pc: 0,
                },
                StorageDiff {
                    tx_index: 1,
                    address: target,
                    slot: B256::repeat_byte(1),
                    old_value: U256::ZERO,
                    new_value: U256::from(10u128.pow(18)),
                    pc: 0,
                },
            ],
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };
        let report = EconomicDeltaEngine::from_execution(&input, &execution);
        assert!(report.accounting_anomaly);
        assert!(report.suspicious_value_extraction);
    }
}
