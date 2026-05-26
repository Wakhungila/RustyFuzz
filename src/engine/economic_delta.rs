use crate::common::types::{CallKind, CallPhase, SequenceExecutionResult, StorageDiff, Waypoint};
use crate::evm::fuzz::EvmInput;
use revm::primitives::{keccak256, Address, B256, U256};
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
    #[serde(default)]
    pub semantic_deltas: Vec<SemanticValueDelta>,
    #[serde(default)]
    pub reserve_deltas: Vec<ReserveDelta>,
    #[serde(default)]
    pub flashloan_signals: Vec<FlashLoanSignal>,
    #[serde(default)]
    pub price_impact: Option<PriceImpactEstimate>,
    #[serde(default)]
    pub normalized_profit: Option<NormalizedProfit>,
    pub storage_delta_summary: Vec<StorageDeltaSummary>,
    pub estimated_profit: U256,
    pub suspicious_value_extraction: bool,
    pub accounting_anomaly: bool,
    #[serde(default)]
    pub flashloan_pressure: bool,
    #[serde(default)]
    pub price_impact_pressure: bool,
    #[serde(default)]
    pub debt_or_collateral_pressure: bool,
    #[serde(default)]
    pub share_price_pressure: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticValueDelta {
    pub tx_index: usize,
    pub address: Address,
    pub slot: B256,
    pub before: U256,
    pub after: U256,
    pub delta: i128,
    pub kind: EconomicStateKind,
    pub confidence: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EconomicStateKind {
    NativeBalance,
    TokenBalance,
    ShareBalance,
    Debt,
    Collateral,
    Reserve,
    Allowance,
    OraclePrice,
    UnknownAccounting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReserveDelta {
    pub pool: Address,
    pub tx_index: usize,
    pub slot_a: B256,
    pub slot_b: B256,
    pub reserve_a_before: U256,
    pub reserve_a_after: U256,
    pub reserve_b_before: U256,
    pub reserve_b_after: U256,
    pub product_before: U256,
    pub product_after: U256,
    pub product_change_bps: i128,
    pub price_change_bps: Option<i128>,
    pub confidence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlashLoanSignal {
    pub tx_index: usize,
    pub lender: Address,
    pub token: Address,
    pub amount: U256,
    pub fee: U256,
    pub is_repaid: bool,
    pub net_unrepaid: U256,
    pub confidence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceImpactEstimate {
    pub source: String,
    pub max_price_change_bps: i128,
    pub max_product_change_bps: i128,
    pub confidence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedProfit {
    pub raw_profit: U256,
    pub denominator: U256,
    pub profit_bps: u64,
    pub confidence: u64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EconomicViewSnapshot {
    pub tx_index: usize,
    pub actor: Option<Address>,
    pub token_balances: Vec<TokenBalanceView>,
    pub vault_share_prices_bps: Vec<ScalarView>,
    pub amm_reserves: Vec<AmmReserveView>,
    pub lending_health: Vec<LendingHealthView>,
    pub oracle_answers: Vec<OracleAnswerView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBalanceView {
    pub token: Address,
    pub owner: Address,
    pub value: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalarView {
    pub contract: Address,
    pub value: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmmReserveView {
    pub pool: Address,
    pub reserve0: U256,
    pub reserve1: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LendingHealthView {
    pub protocol: Address,
    pub account: Address,
    pub collateral: U256,
    pub debt: U256,
    pub health_factor: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleAnswerView {
    pub oracle: Address,
    pub answer: U256,
    pub updated_at: Option<u64>,
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
            report.semantic_deltas.push(SemanticValueDelta {
                tx_index: 0,
                address: obs.token,
                slot: synthetic_balance_slot(obs.owner),
                before: obs.before,
                after: obs.after,
                delta,
                kind: EconomicStateKind::TokenBalance,
                confidence: 90,
                reason: "externally observed token balance delta".to_string(),
            });
        }
        report.accounting_anomaly = report.token_deltas.iter().any(|delta| delta.delta != 0)
            && report.estimated_profit > U256::ZERO;
        report.normalized_profit = normalize_profit(
            report.estimated_profit,
            observations
                .iter()
                .map(|obs| obs.before.max(obs.after))
                .max()
                .unwrap_or(U256::ZERO),
            90,
            "token balance observations",
        );
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
        let selector_context = selector_context_by_tx(input);
        let semantic_deltas =
            semantic_deltas_from_storage(&execution.storage_diffs, &selector_context);
        let reserve_deltas =
            reserve_deltas_from_storage(&execution.storage_diffs, &selector_context);
        let flashloan_signals = flashloan_signals_from_waypoints(execution);
        let native_delta = attacker
            .map(|attacker| native_delta_for_actor(input, execution, attacker))
            .unwrap_or_default();
        let victim_native_delta = victim
            .map(|victim| native_delta_for_actor(input, execution, victim))
            .unwrap_or_default();
        let positive_native_profit = native_delta.max(0) as u128;
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
        let flashloan_pressure = flashloan_signals.iter().any(|signal| {
            signal.amount > U256::ZERO && (!signal.is_repaid || signal.net_unrepaid > U256::ZERO)
        }) || (!flashloan_signals.is_empty()
            && (positive_native_profit > 0 || reserve_deltas.iter().any(is_large_reserve_move)));
        let price_impact = price_impact_from_reserves(&reserve_deltas, execution);
        let price_impact_pressure = price_impact
            .as_ref()
            .is_some_and(|impact| impact.max_price_change_bps.unsigned_abs() >= 500);
        let debt_or_collateral_pressure = semantic_deltas.iter().any(|delta| {
            matches!(
                delta.kind,
                EconomicStateKind::Debt | EconomicStateKind::Collateral
            ) && delta.delta != 0
        });
        let share_price_pressure = semantic_deltas
            .iter()
            .any(|delta| matches!(delta.kind, EconomicStateKind::ShareBalance) && delta.delta != 0)
            && reserve_deltas.iter().any(is_large_reserve_move);
        let accounting_anomaly = large_delta_count >= 2
            || debt_or_collateral_pressure
            || share_price_pressure
            || price_impact_pressure;
        let suspicious_value_extraction =
            (multi_actor && accounting_anomaly) || positive_native_profit > 0 || flashloan_pressure;
        let estimated_profit = if positive_native_profit > 0 {
            U256::from(positive_native_profit)
        } else if suspicious_value_extraction {
            U256::from(large_delta_count as u64)
        } else {
            U256::ZERO
        };
        let denominator = storage_delta_summary
            .iter()
            .map(|summary| summary.absolute_delta_score)
            .max()
            .unwrap_or(U256::ZERO);
        let normalized_profit = normalize_profit(
            estimated_profit,
            denominator,
            if positive_native_profit > 0 { 85 } else { 45 },
            if positive_native_profit > 0 {
                "native value flow"
            } else {
                "storage delta proxy"
            },
        );
        let confidence = economic_confidence(EconomicConfidenceSignals {
            suspicious_value_extraction,
            accounting_anomaly,
            flashloan_pressure,
            price_impact_pressure,
            debt_or_collateral_pressure,
            share_price_pressure,
            direct_profit: positive_native_profit > 0,
            large_delta_count,
        });
        let mut caveats = vec![
            "storage-derived share/debt/reserve classifications are heuristic unless balance/ABI reads confirm them".to_string(),
        ];
        if positive_native_profit == 0 {
            caveats.push("no directly observed native/token profit; estimated profit may be a pressure signal only".to_string());
        }
        if !flashloan_signals.is_empty() {
            caveats.push("flashloan evidence came from execution waypoints and should be confirmed by replay trace".to_string());
        }
        EconomicDeltaReport {
            attacker,
            victim,
            attacker_native_delta: native_delta,
            victim_native_delta,
            semantic_deltas,
            reserve_deltas,
            flashloan_signals,
            price_impact,
            normalized_profit,
            storage_delta_summary,
            suspicious_value_extraction,
            accounting_anomaly,
            flashloan_pressure,
            price_impact_pressure,
            debt_or_collateral_pressure,
            share_price_pressure,
            confidence,
            estimated_profit,
            caveats,
            ..EconomicDeltaReport::default()
        }
    }

    pub fn from_view_snapshots(
        before: &EconomicViewSnapshot,
        after: &EconomicViewSnapshot,
    ) -> EconomicDeltaReport {
        economic_view_delta(before, after)
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
        let flashloan_score = if report.flashloan_pressure { 180 } else { 0 };
        let price_score = if report.price_impact_pressure { 160 } else { 0 };
        let debt_score = if report.debt_or_collateral_pressure {
            140
        } else {
            0
        };
        let share_score = if report.share_price_pressure { 140 } else { 0 };
        let normalized_score = report
            .normalized_profit
            .as_ref()
            .map(|profit| profit.profit_bps.min(2_000) / 10)
            .unwrap_or(0);
        (profit_score
            + extraction_score
            + accounting_score
            + flashloan_score
            + price_score
            + debt_score
            + share_score
            + normalized_score
            + report.confidence)
            .min(1_200)
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

pub fn economic_view_delta(
    before: &EconomicViewSnapshot,
    after: &EconomicViewSnapshot,
) -> EconomicDeltaReport {
    let attacker = before.actor.or(after.actor);
    let mut report = EconomicDeltaReport {
        attacker,
        caveats: vec!["economic proof derived from concrete view-call snapshots".to_string()],
        ..EconomicDeltaReport::default()
    };

    for before_balance in &before.token_balances {
        let Some(after_balance) = after.token_balances.iter().find(|candidate| {
            candidate.token == before_balance.token && candidate.owner == before_balance.owner
        }) else {
            continue;
        };
        let delta = signed_delta(before_balance.value, after_balance.value);
        if Some(before_balance.owner) == attacker && delta > 0 {
            report.estimated_profit = report
                .estimated_profit
                .saturating_add(U256::from(delta as u128));
            report.suspicious_value_extraction = true;
        }
        report.token_deltas.push(TokenBalanceDelta {
            token: before_balance.token,
            owner: before_balance.owner,
            delta,
        });
        report.semantic_deltas.push(SemanticValueDelta {
            tx_index: after.tx_index,
            address: before_balance.token,
            slot: synthetic_balance_slot(before_balance.owner),
            before: before_balance.value,
            after: after_balance.value,
            delta,
            kind: EconomicStateKind::TokenBalance,
            confidence: 95,
            reason: "concrete balanceOf view delta".to_string(),
        });
    }

    for before_price in &before.vault_share_prices_bps {
        let Some(after_price) = after
            .vault_share_prices_bps
            .iter()
            .find(|candidate| candidate.contract == before_price.contract)
        else {
            continue;
        };
        let delta = signed_delta(before_price.value, after_price.value);
        if delta.unsigned_abs() >= 500 {
            report.share_price_pressure = true;
            report.accounting_anomaly = true;
        }
        report.semantic_deltas.push(SemanticValueDelta {
            tx_index: after.tx_index,
            address: before_price.contract,
            slot: synthetic_balance_slot(before_price.contract),
            before: before_price.value,
            after: after_price.value,
            delta,
            kind: EconomicStateKind::ShareBalance,
            confidence: 90,
            reason: "concrete vault share-price view delta".to_string(),
        });
    }

    for before_reserve in &before.amm_reserves {
        let Some(after_reserve) = after
            .amm_reserves
            .iter()
            .find(|candidate| candidate.pool == before_reserve.pool)
        else {
            continue;
        };
        let product_before = before_reserve
            .reserve0
            .saturating_mul(before_reserve.reserve1);
        let product_after = after_reserve
            .reserve0
            .saturating_mul(after_reserve.reserve1);
        let product_change_bps = view_bps_change(product_before, product_after);
        let price_change_bps = ratio_bps(before_reserve.reserve1, before_reserve.reserve0)
            .zip(ratio_bps(after_reserve.reserve1, after_reserve.reserve0))
            .map(|(before, after)| view_bps_change(before, after))
            .unwrap_or_default();
        if product_change_bps.unsigned_abs() >= 100 || price_change_bps.unsigned_abs() >= 500 {
            report.price_impact_pressure = true;
            report.accounting_anomaly = true;
        }
        report.reserve_deltas.push(ReserveDelta {
            pool: before_reserve.pool,
            tx_index: after.tx_index,
            slot_a: synthetic_balance_slot(before_reserve.pool),
            slot_b: synthetic_balance_slot(after_reserve.pool),
            reserve_a_before: before_reserve.reserve0,
            reserve_a_after: after_reserve.reserve0,
            reserve_b_before: before_reserve.reserve1,
            reserve_b_after: after_reserve.reserve1,
            product_before,
            product_after,
            product_change_bps,
            price_change_bps: Some(price_change_bps),
            confidence: 95,
        });
    }

    for before_health in &before.lending_health {
        let Some(after_health) = after.lending_health.iter().find(|candidate| {
            candidate.protocol == before_health.protocol
                && candidate.account == before_health.account
        }) else {
            continue;
        };
        if after_health.debt > before_health.debt
            && after_health.health_factor < before_health.health_factor
        {
            report.debt_or_collateral_pressure = true;
            report.accounting_anomaly = true;
        }
        if after_health.debt > after_health.collateral && after_health.debt > before_health.debt {
            report.suspicious_value_extraction = true;
        }
    }

    for before_answer in &before.oracle_answers {
        let Some(after_answer) = after
            .oracle_answers
            .iter()
            .find(|candidate| candidate.oracle == before_answer.oracle)
        else {
            continue;
        };
        if view_bps_change(before_answer.answer, after_answer.answer).unsigned_abs() >= 500 {
            report.price_impact_pressure = true;
        }
        if before_answer.updated_at == after_answer.updated_at
            && before_answer.answer != after_answer.answer
        {
            report.accounting_anomaly = true;
        }
    }

    report.normalized_profit = normalize_profit(
        report.estimated_profit,
        before
            .token_balances
            .iter()
            .map(|balance| balance.value)
            .max()
            .unwrap_or(U256::ZERO),
        95,
        "concrete view-call snapshots",
    );
    report.confidence =
        if report.suspicious_value_extraction && report.estimated_profit > U256::ZERO {
            95
        } else if report.accounting_anomaly {
            85
        } else if report.estimated_profit > U256::ZERO {
            80
        } else {
            35
        };
    report
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

fn view_bps_change(before: U256, after: U256) -> i128 {
    if before.is_zero() {
        return if after.is_zero() { 0 } else { i128::MAX };
    }
    let before_i = u256_to_i128(before).max(1);
    let after_i = u256_to_i128(after);
    ((after_i - before_i) * 10_000) / before_i
}

fn synthetic_balance_slot(owner: Address) -> B256 {
    keccak256(owner)
}

fn selector_context_by_tx(input: &EvmInput) -> BTreeMap<usize, SelectorContext> {
    input
        .txs
        .iter()
        .enumerate()
        .map(|(idx, tx)| (idx, SelectorContext::from_calldata(&tx.input)))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectorContext {
    Deposit,
    Withdraw,
    Mint,
    Redeem,
    Borrow,
    Repay,
    Liquidate,
    Donate,
    Swap,
    Approve,
    Transfer,
    Unknown,
}

impl SelectorContext {
    fn from_calldata(calldata: &[u8]) -> Self {
        let Some(selector) = calldata.get(0..4) else {
            return Self::Unknown;
        };
        match selector {
            [0xd0, 0xe3, 0x0d, 0xb0] => Self::Deposit,   // deposit()
            [0xb6, 0xb5, 0x5f, 0x25] => Self::Deposit,   // deposit(uint256,address)
            [0x2e, 0x1a, 0x7d, 0x4d] => Self::Withdraw,  // withdraw(uint256)
            [0xba, 0x08, 0x7f, 0x8b] => Self::Redeem,    // redeem(uint256,address,address)
            [0x94, 0xbf, 0x80, 0x4d] => Self::Mint,      // mint(uint256,address)
            [0xc5, 0xeb, 0xea, 0xec] => Self::Borrow,    // borrow(uint256)
            [0x57, 0x3a, 0x53, 0x97] => Self::Repay,     // repay(uint256)
            [0x00, 0xa7, 0x18, 0xa9] => Self::Liquidate, // liquidate(address,address,uint256,uint256)
            [0x09, 0x5e, 0xa7, 0xb3] => Self::Approve,   // approve(address,uint256)
            [0xa9, 0x05, 0x9c, 0xbb] => Self::Transfer,  // transfer(address,uint256)
            [0x23, 0xb8, 0x72, 0xdd] => Self::Transfer,  // transferFrom(address,address,uint256)
            [0x38, 0xed, 0x17, 0x39] => Self::Swap,      // swapExactTokensForTokens
            [0x7f, 0xf3, 0x6a, 0xb5] => Self::Swap,      // swap(uint256,uint256,address,bytes)
            [0x83, 0x42, 0x1d, 0x72] => Self::Donate,    // donateToReserves(uint256,uint256)
            _ => Self::Unknown,
        }
    }
}

fn semantic_deltas_from_storage(
    diffs: &[StorageDiff],
    context: &BTreeMap<usize, SelectorContext>,
) -> Vec<SemanticValueDelta> {
    diffs
        .iter()
        .filter_map(|diff| {
            let selector = context
                .get(&diff.tx_index)
                .copied()
                .unwrap_or(SelectorContext::Unknown);
            let (kind, confidence, reason) = match selector {
                SelectorContext::Deposit | SelectorContext::Mint => (
                    EconomicStateKind::ShareBalance,
                    55,
                    "vault deposit/mint touched accounting storage",
                ),
                SelectorContext::Withdraw | SelectorContext::Redeem => (
                    EconomicStateKind::ShareBalance,
                    55,
                    "vault withdraw/redeem touched accounting storage",
                ),
                SelectorContext::Borrow => (
                    EconomicStateKind::Debt,
                    65,
                    "borrow selector touched debt-like storage",
                ),
                SelectorContext::Repay => (
                    EconomicStateKind::Debt,
                    60,
                    "repay selector touched debt-like storage",
                ),
                SelectorContext::Liquidate => (
                    EconomicStateKind::Collateral,
                    65,
                    "liquidation selector touched collateral/debt storage",
                ),
                SelectorContext::Donate => (
                    EconomicStateKind::Reserve,
                    70,
                    "donation selector touched reserve storage",
                ),
                SelectorContext::Swap => (
                    EconomicStateKind::Reserve,
                    60,
                    "swap selector touched reserve storage",
                ),
                SelectorContext::Approve => (
                    EconomicStateKind::Allowance,
                    65,
                    "approval selector touched allowance-like storage",
                ),
                SelectorContext::Transfer => (
                    EconomicStateKind::TokenBalance,
                    50,
                    "token transfer selector touched balance-like storage",
                ),
                SelectorContext::Unknown => {
                    if absolute_delta(diff) >= U256::from(10u128.pow(18)) {
                        (
                            EconomicStateKind::UnknownAccounting,
                            25,
                            "large unclassified accounting storage movement",
                        )
                    } else {
                        return None;
                    }
                }
            };
            Some(SemanticValueDelta {
                tx_index: diff.tx_index,
                address: diff.address,
                slot: diff.slot,
                before: diff.old_value,
                after: diff.new_value,
                delta: signed_delta(diff.old_value, diff.new_value),
                kind,
                confidence,
                reason: reason.to_string(),
            })
        })
        .collect()
}

fn reserve_deltas_from_storage(
    diffs: &[StorageDiff],
    context: &BTreeMap<usize, SelectorContext>,
) -> Vec<ReserveDelta> {
    let mut by_pool_tx: BTreeMap<(Address, usize), Vec<&StorageDiff>> = BTreeMap::new();
    for diff in diffs {
        let selector = context
            .get(&diff.tx_index)
            .copied()
            .unwrap_or(SelectorContext::Unknown);
        if matches!(selector, SelectorContext::Swap | SelectorContext::Donate)
            || absolute_delta(diff) >= U256::from(10u128.pow(18))
        {
            by_pool_tx
                .entry((diff.address, diff.tx_index))
                .or_default()
                .push(diff);
        }
    }

    let mut out = Vec::new();
    for ((pool, tx_index), mut diffs) in by_pool_tx {
        diffs.sort_by_key(|diff| diff.slot);
        for pair in diffs.windows(2) {
            let a = pair[0];
            let b = pair[1];
            if a.old_value.is_zero()
                || b.old_value.is_zero()
                || a.new_value.is_zero()
                || b.new_value.is_zero()
            {
                continue;
            }
            let product_before = saturating_product(a.old_value, b.old_value);
            let product_after = saturating_product(a.new_value, b.new_value);
            let product_change_bps = signed_bps_change(product_before, product_after);
            let price_before = ratio_bps(a.old_value, b.old_value);
            let price_after = ratio_bps(a.new_value, b.new_value);
            let price_change_bps = price_before
                .zip(price_after)
                .map(|(before, after)| signed_bps_change(before, after));
            out.push(ReserveDelta {
                pool,
                tx_index,
                slot_a: a.slot,
                slot_b: b.slot,
                reserve_a_before: a.old_value,
                reserve_a_after: a.new_value,
                reserve_b_before: b.old_value,
                reserve_b_after: b.new_value,
                product_before,
                product_after,
                product_change_bps,
                price_change_bps,
                confidence: if price_change_bps.is_some_and(|change| change.unsigned_abs() >= 500) {
                    70
                } else {
                    45
                },
            });
        }
    }
    out
}

fn flashloan_signals_from_waypoints(execution: &SequenceExecutionResult) -> Vec<FlashLoanSignal> {
    execution
        .tx_results
        .iter()
        .flat_map(|result| {
            result
                .waypoints
                .iter()
                .map(move |waypoint| (result.tx_index, waypoint))
        })
        .filter_map(|(tx_index, waypoint)| match waypoint {
            Waypoint::FlashloanExecution {
                lender,
                token,
                amount,
                fee,
                is_repaid,
            } => Some(FlashLoanSignal {
                tx_index,
                lender: *lender,
                token: *token,
                amount: *amount,
                fee: *fee,
                is_repaid: *is_repaid,
                net_unrepaid: if *is_repaid {
                    U256::ZERO
                } else {
                    amount.saturating_add(*fee)
                },
                confidence: if *is_repaid { 70 } else { 90 },
            }),
            _ => None,
        })
        .collect()
}

fn native_delta_for_actor(
    input: &EvmInput,
    execution: &SequenceExecutionResult,
    actor: Address,
) -> i128 {
    let paid = input
        .txs
        .iter()
        .filter(|tx| tx.caller == actor)
        .fold(U256::ZERO, |acc, tx| acc.saturating_add(tx.value));
    let received = execution
        .call_trace
        .iter()
        .filter(|call| {
            call.target == actor
                && call.success
                && call.value > U256::ZERO
                && call.phase == CallPhase::Start
                && matches!(call.kind, CallKind::Call | CallKind::Transaction)
        })
        .fold(U256::ZERO, |acc, call| acc.saturating_add(call.value));
    signed_delta(paid, received)
}

fn price_impact_from_reserves(
    reserve_deltas: &[ReserveDelta],
    execution: &SequenceExecutionResult,
) -> Option<PriceImpactEstimate> {
    let mut max_price = reserve_deltas
        .iter()
        .filter_map(|delta| delta.price_change_bps)
        .max_by_key(|change| change.unsigned_abs())
        .unwrap_or_default();
    let mut max_product = reserve_deltas
        .iter()
        .map(|delta| delta.product_change_bps)
        .max_by_key(|change| change.unsigned_abs())
        .unwrap_or_default();
    let mut source = "reserve storage movement".to_string();

    for waypoint in execution
        .tx_results
        .iter()
        .flat_map(|result| result.waypoints.iter())
    {
        if let Waypoint::MevSignal {
            slippage_harvested,
            is_sandwich,
            ..
        } = waypoint
        {
            if *is_sandwich || *slippage_harvested > U256::ZERO {
                max_price = max_price.max(750);
                max_product = max_product.max(250);
                source = "MEV/slippage waypoint".to_string();
            }
        }
    }

    if max_price == 0 && max_product == 0 {
        return None;
    }
    Some(PriceImpactEstimate {
        source,
        max_price_change_bps: max_price,
        max_product_change_bps: max_product,
        confidence: if max_price.unsigned_abs() >= 1_000 {
            80
        } else {
            55
        },
    })
}

fn normalize_profit(
    raw_profit: U256,
    denominator: U256,
    confidence: u64,
    method: &str,
) -> Option<NormalizedProfit> {
    if raw_profit.is_zero() {
        return None;
    }
    let denominator = denominator.max(raw_profit);
    let profit_bps = if denominator.is_zero() {
        0
    } else {
        raw_profit
            .saturating_mul(U256::from(10_000u64))
            .checked_div(denominator)
            .unwrap_or(U256::ZERO)
            .min(U256::from(u64::MAX))
            .to::<u64>()
    };
    Some(NormalizedProfit {
        raw_profit,
        denominator,
        profit_bps,
        confidence,
        method: method.to_string(),
    })
}

struct EconomicConfidenceSignals {
    suspicious_value_extraction: bool,
    accounting_anomaly: bool,
    flashloan_pressure: bool,
    price_impact_pressure: bool,
    debt_or_collateral_pressure: bool,
    share_price_pressure: bool,
    direct_profit: bool,
    large_delta_count: usize,
}

fn economic_confidence(signals: EconomicConfidenceSignals) -> u64 {
    let mut confidence: u64 = 10;
    if signals.large_delta_count > 0 {
        confidence = confidence.max(35);
    }
    if signals.accounting_anomaly {
        confidence = confidence.max(55);
    }
    if signals.suspicious_value_extraction {
        confidence = confidence.max(70);
    }
    if signals.direct_profit {
        confidence = confidence.max(82);
    }
    if signals.flashloan_pressure {
        confidence = confidence.max(75);
    }
    if signals.price_impact_pressure {
        confidence = confidence.max(72);
    }
    if signals.debt_or_collateral_pressure || signals.share_price_pressure {
        confidence = confidence.max(68);
    }
    confidence.min(95)
}

fn is_large_reserve_move(delta: &ReserveDelta) -> bool {
    delta
        .price_change_bps
        .is_some_and(|change| change.unsigned_abs() >= 500)
        || delta.product_change_bps.unsigned_abs() >= 250
}

fn saturating_product(a: U256, b: U256) -> U256 {
    a.checked_mul(b).unwrap_or(U256::MAX)
}

fn signed_bps_change(before: U256, after: U256) -> i128 {
    if before.is_zero() {
        return 0;
    }
    let magnitude = if after >= before {
        after - before
    } else {
        before - after
    };
    let bps = magnitude
        .saturating_mul(U256::from(10_000u64))
        .checked_div(before)
        .unwrap_or(U256::ZERO)
        .min(U256::from(i128::MAX as u128));
    let signed = bps.to::<u128>() as i128;
    if after >= before {
        signed
    } else {
        -signed
    }
}

fn ratio_bps(numerator: U256, denominator: U256) -> Option<U256> {
    if denominator.is_zero() {
        return None;
    }
    Some(
        numerator
            .saturating_mul(U256::from(10_000u64))
            .checked_div(denominator)
            .unwrap_or(U256::ZERO),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{
        CallKind, CallObservation, CallPhase, ExecutionStatus, SingletonTx, TxExecutionResult,
        Waypoint,
    };
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

    #[test]
    fn execution_delta_tracks_flashloan_pressure() {
        let target = addr(0xcc);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![],
                caller: addr(0xaa),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
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
                waypoints: vec![Waypoint::FlashloanExecution {
                    lender: addr(0x44),
                    token: addr(0x11),
                    amount: U256::from(1_000_000u64),
                    fee: U256::from(900u64),
                    is_repaid: false,
                }],
            }],
            total_gas_used: 1,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let report = EconomicDeltaEngine::from_execution(&input, &execution);
        assert!(report.flashloan_pressure);
        assert_eq!(report.flashloan_signals.len(), 1);
        assert!(EconomicDeltaEngine::score(&report) >= 250);
    }

    #[test]
    fn execution_delta_estimates_reserve_price_impact() {
        let target = addr(0xcc);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: hex::decode("38ed1739").unwrap(),
                caller: addr(0xaa),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
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
                storage_diffs: vec![
                    StorageDiff {
                        tx_index: 0,
                        address: target,
                        slot: B256::ZERO,
                        old_value: U256::from(1_000u64),
                        new_value: U256::from(500u64),
                        pc: 0,
                    },
                    StorageDiff {
                        tx_index: 0,
                        address: target,
                        slot: B256::repeat_byte(1),
                        old_value: U256::from(1_000u64),
                        new_value: U256::from(2_000u64),
                        pc: 0,
                    },
                ],
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
                    old_value: U256::from(1_000u64),
                    new_value: U256::from(500u64),
                    pc: 0,
                },
                StorageDiff {
                    tx_index: 0,
                    address: target,
                    slot: B256::repeat_byte(1),
                    old_value: U256::from(1_000u64),
                    new_value: U256::from(2_000u64),
                    pc: 0,
                },
            ],
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let report = EconomicDeltaEngine::from_execution(&input, &execution);
        assert!(report.price_impact_pressure);
        assert!(!report.reserve_deltas.is_empty());
        assert!(
            report
                .price_impact
                .unwrap()
                .max_price_change_bps
                .unsigned_abs()
                >= 500
        );
    }

    #[test]
    fn execution_delta_tracks_native_profit_and_normalizes_it() {
        let target = addr(0xcc);
        let attacker = addr(0xaa);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![],
                caller: attacker,
                to: target,
                value: U256::from(1u64),
                is_victim: false,
            }],
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
            storage_diffs: Vec::new(),
            call_trace: vec![CallObservation {
                tx_index: 0,
                depth: 1,
                caller: target,
                target: attacker,
                value: U256::from(10u64),
                input: Vec::new(),
                output: Vec::new(),
                gas_limit: 1,
                gas_used: 1,
                success: true,
                kind: CallKind::Call,
                phase: CallPhase::Start,
                created_address: None,
                result: None,
            }],
            oracle_observations: Vec::new(),
        };

        let report = EconomicDeltaEngine::from_execution(&input, &execution);
        assert_eq!(report.attacker_native_delta, 9);
        assert_eq!(report.estimated_profit, U256::from(9u64));
        assert!(report.normalized_profit.is_some());
        assert!(report.suspicious_value_extraction);
    }

    #[test]
    fn execution_delta_classifies_lending_storage_pressure() {
        let target = addr(0xcc);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: hex::decode("c5ebeaec").unwrap(),
                caller: addr(0xaa),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let diff = StorageDiff {
            tx_index: 0,
            address: target,
            slot: B256::ZERO,
            old_value: U256::ZERO,
            new_value: U256::from(5_000u64),
            pc: 0,
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
                storage_diffs: vec![diff.clone()],
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 1,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![diff],
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let report = EconomicDeltaEngine::from_execution(&input, &execution);
        assert!(report.debt_or_collateral_pressure);
        assert!(report
            .semantic_deltas
            .iter()
            .any(|delta| matches!(delta.kind, EconomicStateKind::Debt)));
    }

    #[test]
    fn concrete_view_delta_proves_profit_and_share_price_pressure() {
        let attacker = addr(0xaa);
        let token = addr(0x10);
        let vault = addr(0x20);
        let before = EconomicViewSnapshot {
            tx_index: 0,
            actor: Some(attacker),
            token_balances: vec![TokenBalanceView {
                token,
                owner: attacker,
                value: U256::from(100u64),
            }],
            vault_share_prices_bps: vec![ScalarView {
                contract: vault,
                value: U256::from(10_000u64),
            }],
            ..EconomicViewSnapshot::default()
        };
        let after = EconomicViewSnapshot {
            tx_index: 1,
            actor: Some(attacker),
            token_balances: vec![TokenBalanceView {
                token,
                owner: attacker,
                value: U256::from(150u64),
            }],
            vault_share_prices_bps: vec![ScalarView {
                contract: vault,
                value: U256::from(10_700u64),
            }],
            ..EconomicViewSnapshot::default()
        };

        let report = economic_view_delta(&before, &after);
        assert_eq!(report.estimated_profit, U256::from(50u64));
        assert!(report.suspicious_value_extraction);
        assert!(report.share_price_pressure);
        assert!(report.accounting_anomaly);
        assert!(report.confidence >= 90);
    }
}
