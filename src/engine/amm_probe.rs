//! Engine-side reserve probing for the AMM oracle.
//!
//! The AMM pack flags a swap only when `getReserves()` observations on the
//! pool bracket it in the same sequence and the reserve product breaks. A
//! fuzzer that has to *happen* to call `getReserves` before and after every
//! swap will almost never satisfy that, so the engine probes the pool itself
//! (non-committing) around any transaction whose calldata contains a V2 swap
//! and injects the reads as observations. Probes never change fuzz state.

use revm::context::BlockEnv;
use revm::primitives::{Address, Bytes, TxKind, U256};
use rustyfuzz_evm::execution::{CallKind, CallObservation, CallPhase};
use rustyfuzz_evm::foundry::execute_with_cheatcodes;

use crate::engine::sim_defi::Db;

pub const GET_RESERVES: [u8; 4] = [0x09, 0x02, 0xf1, 0xac];
pub const V2_SWAP: [u8; 4] = [0x02, 0x2c, 0x0d, 0x9f];
const PROBE_CALLER: Address = Address::new([0x1d; 20]);

/// Whether the calldata mentions the V2 swap selector at the top level or
/// inside a wrapped call list (a direct call or an attacker `run`).
pub fn tx_mentions_v2_swap(input: &[u8]) -> bool {
    input.windows(4).any(|w| w == V2_SWAP)
}

/// Non-committing `getReserves()` on `pool`; the raw return data when the call
/// succeeds with at least two words.
pub fn probe_reserves(db: &mut Db, block: &BlockEnv, pool: Address) -> Option<Vec<u8>> {
    let run = execute_with_cheatcodes(
        db,
        block,
        PROBE_CALLER,
        TxKind::Call(pool),
        Bytes::from(GET_RESERVES.to_vec()),
        U256::ZERO,
        pool,
        false,
    )
    .ok()?;
    match run.result {
        revm::context::result::ExecutionResult::Success { output, .. } if output.data().len() >= 64 => {
            Some(output.data().to_vec())
        }
        _ => None,
    }
}

/// Contracts that look like V2 pools (both selectors present in their code)
/// and actually answer `getReserves()`.
pub fn discover_pools(db: &mut Db, block: &BlockEnv) -> Vec<Address> {
    let contains = |hay: &[u8], needle: &[u8; 4]| hay.windows(4).any(|w| w == needle);
    let mut candidates: Vec<Address> = db
        .cache
        .accounts
        .iter()
        .filter_map(|(addr, account)| {
            let code = account.info.code.as_ref()?.original_bytes();
            (contains(&code, &GET_RESERVES) && contains(&code, &V2_SWAP)).then_some(*addr)
        })
        .collect();
    candidates.sort();
    candidates.retain(|pool| probe_reserves(db, block, *pool).is_some());
    candidates
}

/// A `getReserves()` read as the oracle expects to see it.
/// A V2-style swap may never lower the reserve product (the fee only raises
/// it). Returns `(k_before, k_after)` when a successful swap lowered it.
pub fn k_regression(pre: &[u8], post: &[u8]) -> Option<(U256, U256)> {
    use revm::primitives::U256 as W;
    if pre.len() < 64 || post.len() < 64 {
        return None;
    }
    let k = |o: &[u8]| W::from_be_slice(&o[..32]).checked_mul(W::from_be_slice(&o[32..64]));
    let (before, after) = (k(pre)?, k(post)?);
    (!before.is_zero() && after < before).then_some((before, after))
}

pub fn observation(tx_index: usize, pool: Address, output: Vec<u8>) -> CallObservation {
    CallObservation {
        tx_index,
        depth: 1,
        caller: PROBE_CALLER,
        target: pool,
        value: U256::ZERO,
        input: GET_RESERVES.to_vec(),
        output,
        gas_limit: 0,
        gas_used: 0,
        success: true,
        kind: CallKind::StaticCall,
        phase: CallPhase::End,
        created_address: None,
        result: Some("engine reserve probe".to_string()),
    }
}

/// Wraps `result.call_trace` of one transaction with the before/after reads.
pub fn bracket_trace(
    trace: &mut Vec<CallObservation>,
    tx_index: usize,
    reads: Vec<(Address, Vec<u8>, Option<Vec<u8>>)>,
) {
    let mut before: Vec<CallObservation> = Vec::new();
    let mut after: Vec<CallObservation> = Vec::new();
    for (pool, pre, post) in reads {
        let Some(post) = post else { continue };
        before.push(observation(tx_index, pool, pre));
        after.push(observation(tx_index, pool, post));
    }
    trace.splice(0..0, before);
    trace.extend(after);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::sim_defi::{deploy_mock_token, deploy_v2_pair, transact, encode_call, deploy_atomic_attacker};
    use revm::database::CacheDB;
    use rustyfuzz_evm::fork_db::ForkDb;

    const T0: Address = Address::new([0x10; 20]);
    const T1: Address = Address::new([0x11; 20]);
    const PAIR: Address = Address::new([0x20; 20]);

    #[test]
    fn discovers_real_pairs_not_tokens_and_probes_without_committing() {
        let mut db = CacheDB::new(ForkDb::empty());
        deploy_mock_token(&mut db, T0);
        deploy_mock_token(&mut db, T1);
        let e18 = U256::from(10u128.pow(18));
        deploy_v2_pair(&mut db, PAIR, T0, T1, e18 * U256::from(1000), e18 * U256::from(500)).unwrap();
        let (_a, _) = deploy_atomic_attacker(&mut db, &[T0, T1], e18).unwrap();
        let block = BlockEnv::default();
        assert_eq!(discover_pools(&mut db, &block), vec![PAIR]);
        let out = probe_reserves(&mut db, &block, PAIR).unwrap();
        assert_eq!(U256::from_be_slice(&out[..32]), e18 * U256::from(1000));
        assert_eq!(U256::from_be_slice(&out[32..64]), e18 * U256::from(500));
        // Probing again is stable: nothing was committed by the probes.
        assert_eq!(probe_reserves(&mut db, &block, PAIR).unwrap(), out);
        let _ = (transact, encode_call);
    }

    #[test]
    fn swap_selector_is_found_in_direct_and_wrapped_calldata() {
        assert!(tx_mentions_v2_swap(&[0x02, 0x2c, 0x0d, 0x9f, 0, 0]));
        let wrapped = [vec![0xaa; 40], V2_SWAP.to_vec(), vec![0xbb; 8]].concat();
        assert!(tx_mentions_v2_swap(&wrapped));
        assert!(!tx_mentions_v2_swap(&[1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn bracket_trace_orders_reads_around_the_transaction() {
        let mut trace = vec![observation(3, PAIR, vec![9; 64])];
        bracket_trace(&mut trace, 3, vec![(PAIR, vec![1; 64], Some(vec![2; 64]))]);
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0].output, vec![1; 64]);
        assert_eq!(trace[1].output, vec![9; 64]);
        assert_eq!(trace[2].output, vec![2; 64]);
    }
}
