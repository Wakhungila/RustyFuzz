use crate::common::types::{ExecutionStatus, SequenceExecutionResult, SingletonTx, StorageAccess};
use crate::evm::fuzz::{AbiRegistry, EvmInput, MutationProvenance};
use alloy_dyn_abi::DynSolValue;
use revm::primitives::{keccak256, Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionDependencyGraph {
    pub nodes: Vec<TransactionDependencyNode>,
    pub edges: Vec<TransactionDependencyEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionDependencyNode {
    pub tx_index: usize,
    pub selector: Option<[u8; 4]>,
    pub caller: Address,
    pub target: Address,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionDependencyEdge {
    pub from_tx: usize,
    pub to_tx: usize,
    pub kind: DependencyEdgeKind,
    pub confidence: u64,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyEdgeKind {
    ReadsAfterWrites,
    WritesAfterReads,
    SameSlot,
    SameToken,
    CallerRole,
    ApprovalAllowance,
    BalanceShareSupply,
    OraclePriceState,
    Temporal,
    Economic,
}

impl TransactionDependencyGraph {
    pub fn from_execution(input: &EvmInput, execution: &SequenceExecutionResult) -> Self {
        let nodes = input
            .txs
            .iter()
            .enumerate()
            .map(|(idx, tx)| TransactionDependencyNode {
                tx_index: idx,
                selector: selector_for_calldata(&tx.input),
                caller: tx.caller,
                target: tx.to,
                status: execution
                    .tx_results
                    .iter()
                    .find(|result| result.tx_index == idx)
                    .map(|result| result.status.clone())
                    .unwrap_or(ExecutionStatus::Halt("not executed".to_string())),
            })
            .collect();

        let mut edges = Vec::new();
        add_storage_edges(execution, &mut edges);
        add_selector_flow_edges(input, &mut edges);
        dedup_edges(&mut edges);

        Self { nodes, edges }
    }

    pub fn score_boost(&self) -> u64 {
        self.edges
            .iter()
            .map(|edge| match edge.kind {
                DependencyEdgeKind::ApprovalAllowance
                | DependencyEdgeKind::Temporal
                | DependencyEdgeKind::Economic => edge.confidence / 2,
                DependencyEdgeKind::ReadsAfterWrites | DependencyEdgeKind::SameSlot => {
                    edge.confidence / 3
                }
                _ => edge.confidence / 4,
            })
            .sum::<u64>()
            .min(150)
    }
}

pub fn generate_flow_template_inputs(
    target: Address,
    caller: Address,
    abi_registry: &AbiRegistry,
) -> Vec<EvmInput> {
    let mut flows = Vec::new();
    let templates = [
        flow_erc20_approve_transfer_from(target, caller),
        flow_erc4626_deposit_withdraw(target, caller),
        flow_amm_approve_swap_reverse(target, caller),
        flow_lending_deposit_borrow_liquidate(target, caller),
        flow_governance_propose_vote_queue_execute(target, caller),
        flow_bridge_send_prove_finalize(target, caller),
        flow_staking_stake_claim_unstake(target, caller),
    ];

    for template in templates {
        let known_selector_count = template
            .txs
            .iter()
            .filter_map(|tx| selector_for_calldata(&tx.input))
            .filter(|selector| {
                abi_registry.functions.is_empty() || abi_registry.functions.contains_key(selector)
            })
            .count();

        if known_selector_count == 0 {
            continue;
        }
        flows.push(template);
    }

    flows
}

pub fn dependency_sequence_score(input: &EvmInput) -> u64 {
    let provenance_boost = input
        .mutation_provenance
        .iter()
        .filter(|entry| entry.strategy.starts_with("dependency_"))
        .count() as u64
        * 35;
    let flow_boost = known_ordered_flow_score(input);

    (provenance_boost + flow_boost).min(180)
}

fn add_storage_edges(
    execution: &SequenceExecutionResult,
    edges: &mut Vec<TransactionDependencyEdge>,
) {
    for write in &execution.storage_writes {
        for read in execution
            .storage_reads
            .iter()
            .filter(|read| same_slot(write, read) && read.tx_index > write.tx_index)
        {
            edges.push(TransactionDependencyEdge {
                from_tx: write.tx_index,
                to_tx: read.tx_index,
                kind: DependencyEdgeKind::ReadsAfterWrites,
                confidence: 85,
                explanation: format!(
                    "tx {} wrote {}:{} before tx {} read it",
                    write.tx_index,
                    write.address,
                    hex::encode(write.slot),
                    read.tx_index
                ),
            });
        }
    }

    for read in &execution.storage_reads {
        for write in execution
            .storage_writes
            .iter()
            .filter(|write| same_slot(read, write) && write.tx_index > read.tx_index)
        {
            edges.push(TransactionDependencyEdge {
                from_tx: read.tx_index,
                to_tx: write.tx_index,
                kind: DependencyEdgeKind::WritesAfterReads,
                confidence: 65,
                explanation: format!(
                    "tx {} read {}:{} before tx {} wrote it",
                    read.tx_index,
                    read.address,
                    hex::encode(read.slot),
                    write.tx_index
                ),
            });
        }
    }

    for earlier in &execution.storage_writes {
        for later in execution
            .storage_writes
            .iter()
            .filter(|later| same_slot(earlier, later) && later.tx_index > earlier.tx_index)
        {
            edges.push(TransactionDependencyEdge {
                from_tx: earlier.tx_index,
                to_tx: later.tx_index,
                kind: DependencyEdgeKind::SameSlot,
                confidence: 70,
                explanation: format!(
                    "tx {} and tx {} wrote the same slot {}:{}",
                    earlier.tx_index,
                    later.tx_index,
                    earlier.address,
                    hex::encode(earlier.slot)
                ),
            });
        }
    }
}

fn add_selector_flow_edges(input: &EvmInput, edges: &mut Vec<TransactionDependencyEdge>) {
    for (idx, pair) in input.txs.windows(2).enumerate() {
        let left = selector_for_calldata(&pair[0].input);
        let right = selector_for_calldata(&pair[1].input);
        let Some((kind, confidence, explanation)) = classify_selector_edge(left, right) else {
            continue;
        };

        edges.push(TransactionDependencyEdge {
            from_tx: idx,
            to_tx: idx + 1,
            kind,
            confidence,
            explanation,
        });
    }
}

fn classify_selector_edge(
    left: Option<[u8; 4]>,
    right: Option<[u8; 4]>,
) -> Option<(DependencyEdgeKind, u64, String)> {
    let left = left?;
    let right = right?;
    let approve = function_selector("approve(address,uint256)");
    let transfer_from = function_selector("transferFrom(address,address,uint256)");
    let deposit = function_selector("deposit(uint256,address)");
    let withdraw = function_selector("withdraw(uint256,address,address)");
    let mint = function_selector("mint(uint256,address)");
    let redeem = function_selector("redeem(uint256,address,address)");
    let propose = function_selector("propose(address[],uint256[],bytes[],string)");
    let vote = function_selector("castVote(uint256,uint8)");
    let queue = function_selector("queue(uint256)");
    let execute = function_selector("execute(uint256)");

    if left == approve && right == transfer_from {
        return Some((
            DependencyEdgeKind::ApprovalAllowance,
            95,
            "approve enables later transferFrom allowance path".to_string(),
        ));
    }
    if matches!((left, right), (l, r) if (l == deposit || l == mint) && (r == withdraw || r == redeem))
    {
        return Some((
            DependencyEdgeKind::BalanceShareSupply,
            90,
            "vault deposit/mint sets up later withdraw/redeem".to_string(),
        ));
    }
    if matches!((left, right), (l, r) if (l == propose && r == vote) || (l == vote && r == queue) || (l == queue && r == execute))
    {
        return Some((
            DependencyEdgeKind::Temporal,
            88,
            "governance transaction order matches proposal lifecycle".to_string(),
        ));
    }

    None
}

fn known_ordered_flow_score(input: &EvmInput) -> u64 {
    input
        .txs
        .windows(2)
        .filter_map(|pair| {
            classify_selector_edge(
                selector_for_calldata(&pair[0].input),
                selector_for_calldata(&pair[1].input),
            )
        })
        .map(|(_, confidence, _)| confidence / 2)
        .sum::<u64>()
        .min(150)
}

fn same_slot(left: &StorageAccess, right: &StorageAccess) -> bool {
    left.address == right.address && left.slot == right.slot
}

fn dedup_edges(edges: &mut Vec<TransactionDependencyEdge>) {
    edges.sort_by(|a, b| {
        (a.from_tx, a.to_tx, &a.kind, b.confidence).cmp(&(
            b.from_tx,
            b.to_tx,
            &b.kind,
            a.confidence,
        ))
    });
    edges.dedup_by(|a, b| a.from_tx == b.from_tx && a.to_tx == b.to_tx && a.kind == b.kind);
}

fn flow_erc20_approve_transfer_from(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_erc20_approve_transfer_from",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata(
                    "approve(address,uint256)",
                    vec![addr_word(target), uint_word(1_000_000)],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "transferFrom(address,address,uint256)",
                    vec![addr_word(caller), addr_word(target), uint_word(1)],
                ),
            ),
        ],
    )
}

fn flow_erc4626_deposit_withdraw(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_erc4626_deposit_withdraw",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata(
                    "deposit(uint256,address)",
                    vec![uint_word(1_000_000_000_000_000_000u128), addr_word(caller)],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "withdraw(uint256,address,address)",
                    vec![uint_word(1), addr_word(caller), addr_word(caller)],
                ),
            ),
        ],
    )
}

fn flow_amm_approve_swap_reverse(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_amm_swap_roundtrip",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata(
                    "approve(address,uint256)",
                    vec![addr_word(target), uint_word(1_000_000)],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "swap(address,bool,int256,uint160,bytes)",
                    vec![
                        addr_word(caller),
                        bool_word(true),
                        uint_word(1_000),
                        uint_word(0),
                        bytes_word(&[]),
                    ],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "swap(address,bool,int256,uint160,bytes)",
                    vec![
                        addr_word(caller),
                        bool_word(false),
                        uint_word(1_000),
                        uint_word(0),
                        bytes_word(&[]),
                    ],
                ),
            ),
        ],
    )
}

fn flow_lending_deposit_borrow_liquidate(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_lending_collateral_borrow_liquidate",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata(
                    "supply(address,uint256,address,uint16)",
                    vec![
                        addr_word(target),
                        uint_word(1_000_000),
                        addr_word(caller),
                        uint_word(0),
                    ],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "borrow(address,uint256,uint256,uint16,address)",
                    vec![
                        addr_word(target),
                        uint_word(1_000),
                        uint_word(2),
                        uint_word(0),
                        addr_word(caller),
                    ],
                ),
            ),
            tx(
                target,
                caller,
                calldata(
                    "liquidationCall(address,address,address,uint256,bool)",
                    vec![
                        addr_word(target),
                        addr_word(target),
                        addr_word(caller),
                        uint_word(1),
                        bool_word(false),
                    ],
                ),
            ),
        ],
    )
}

fn flow_governance_propose_vote_queue_execute(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_governance_lifecycle",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                function_selector("propose(address[],uint256[],bytes[],string)").to_vec(),
            ),
            tx(
                target,
                caller,
                calldata("castVote(uint256,uint8)", vec![uint_word(1), uint_word(1)]),
            ),
            tx(
                target,
                caller,
                calldata("queue(uint256)", vec![uint_word(1)]),
            ),
            tx(
                target,
                caller,
                calldata("execute(uint256)", vec![uint_word(1)]),
            ),
        ],
    )
}

fn flow_bridge_send_prove_finalize(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_bridge_send_prove_finalize",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata("send(bytes)", vec![bytes_word(&[1, 2, 3])]),
            ),
            tx(
                target,
                caller,
                calldata("prove(bytes)", vec![bytes_word(&[1, 2, 3])]),
            ),
            tx(
                target,
                caller,
                calldata("finalize(bytes)", vec![bytes_word(&[1, 2, 3])]),
            ),
            tx(target, caller, calldata("claim()", vec![])),
        ],
    )
}

fn flow_staking_stake_claim_unstake(target: Address, caller: Address) -> EvmInput {
    flow_input(
        "dependency_flow_staking_stake_claim_unstake",
        target,
        caller,
        vec![
            tx(
                target,
                caller,
                calldata("stake(uint256)", vec![uint_word(1_000_000)]),
            ),
            tx(target, caller, calldata("claim()", vec![])),
            tx(
                target,
                caller,
                calldata("unstake(uint256)", vec![uint_word(1)]),
            ),
        ],
    )
}

fn flow_input(
    strategy: &str,
    _target: Address,
    _caller: Address,
    txs: Vec<SingletonTx>,
) -> EvmInput {
    EvmInput {
        txs,
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: vec![MutationProvenance {
            strategy: strategy.to_string(),
            tx_index: None,
            selector: None,
            detail: "ordered dependency-aware flow template".to_string(),
        }],
    }
}

fn tx(target: Address, caller: Address, input: Vec<u8>) -> SingletonTx {
    SingletonTx {
        input,
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    }
}

fn calldata(signature: &str, values: Vec<DynSolValue>) -> Vec<u8> {
    let mut out = function_selector(signature).to_vec();
    out.extend_from_slice(&DynSolValue::Tuple(values).abi_encode());
    out
}

fn addr_word(address: Address) -> DynSolValue {
    DynSolValue::Address(address)
}

fn uint_word(value: u128) -> DynSolValue {
    DynSolValue::Uint(U256::from(value), 256)
}

fn bool_word(value: bool) -> DynSolValue {
    DynSolValue::Bool(value)
}

fn bytes_word(value: &[u8]) -> DynSolValue {
    DynSolValue::Bytes(value.to_vec())
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

fn selector_for_calldata(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata.get(0..4)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ExecutionStatus, StorageAccess, TxExecutionResult};
    use revm::primitives::B256;

    #[test]
    fn dependency_graph_creates_edges_from_storage_reads_and_writes() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let slot = B256::from([0x11; 32]);
        let input = EvmInput {
            txs: vec![
                tx(
                    target,
                    caller,
                    calldata("stake(uint256)", vec![uint_word(1)]),
                ),
                tx(
                    target,
                    caller,
                    calldata("unstake(uint256)", vec![uint_word(1)]),
                ),
            ],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![empty_result(0), empty_result(1)],
            total_gas_used: 0,
            final_coverage_hash: 0,
            storage_reads: vec![StorageAccess {
                tx_index: 1,
                address: target,
                slot,
                value: Some(U256::from(1)),
                pc: 2,
            }],
            storage_writes: vec![StorageAccess {
                tx_index: 0,
                address: target,
                slot,
                value: Some(U256::from(1)),
                pc: 1,
            }],
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let graph = TransactionDependencyGraph::from_execution(&input, &execution);

        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == DependencyEdgeKind::ReadsAfterWrites));
        assert!(graph.score_boost() > 0);
    }

    #[test]
    fn flow_templates_produce_ordered_multi_transaction_sequences() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let abi = AbiRegistry::default();

        let flows = generate_flow_template_inputs(target, caller, &abi);

        assert!(flows.iter().any(|flow| flow.txs.len() >= 2));
        let erc20 = flows
            .iter()
            .find(|flow| {
                flow.mutation_provenance
                    .iter()
                    .any(|entry| entry.strategy.contains("erc20"))
            })
            .expect("erc20 flow");
        assert_eq!(
            selector_for_calldata(&erc20.txs[0].input),
            Some(function_selector("approve(address,uint256)"))
        );
        assert_eq!(
            selector_for_calldata(&erc20.txs[1].input),
            Some(function_selector("transferFrom(address,address,uint256)"))
        );
        assert!(dependency_sequence_score(erc20) > 0);
    }

    fn empty_result(tx_index: usize) -> TxExecutionResult {
        TxExecutionResult {
            tx_index,
            status: ExecutionStatus::Success,
            gas_used: 0,
            output: Vec::new(),
            coverage_hash: 0,
            coverage_edges: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            waypoints: Vec::new(),
        }
    }
}
