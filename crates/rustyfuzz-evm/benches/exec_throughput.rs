//! Reproducible in-process throughput benchmark for the execution hot path.
//!
//! `perf` is unavailable in the reference environment (`perf_event_paranoid=4`),
//! so this harness is the authoritative before/after number. It measures the
//! same public entry point campaigns use (`EvmExecutor::execute_with_result`)
//! against a warm, offline cache whose size is configurable, because the
//! dominant cost identified in review was per-transaction state cloning that
//! grows with cache size.
//!
//! Run with:
//!   cargo bench -p rustyfuzz-evm --bench exec_throughput
//!
//! Every reported number is a measurement, never an estimate. Medians of
//! repeated trials are printed so a diff between two builds on the same machine
//! is meaningful.

use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, B256, U256},
    state::{AccountInfo, Bytecode},
};
use rustyfuzz_evm::{
    execution::ChainState, inspector::MAP_SIZE, DataflowRegistry, EvmExecutor, ForkDb, SingletonTx,
};
use std::time::{Duration, Instant};

/// Transactions executed per input sequence.
///
/// The campaign harness clones the base snapshot once per *input*, then runs
/// every transaction of that input against the accumulating state. Measuring a
/// single transaction per clone hides the per-transaction copy cost that
/// dominated the old executor, so a sequence is used and cost is reported per
/// execution amortised over it.
const TXS_PER_INPUT: usize = 8;

/// Bytecode of the synthetic target.
///
/// Real protocols execute thousands of opcodes per transaction with frequent
/// storage access. This loop reads two slots, writes one, and branches, which
/// exercises the inspector's per-opcode path the same way production bytecode
/// does, without needing a solc round-trip.
fn target_code() -> Vec<u8> {
    let mut code = Vec::new();
    let loop_start = code.len();
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0      (slot 0)
    code.push(0x54); // SLOAD
    code.extend_from_slice(&[0x60, 0x01]); // PUSH1 1      (slot 1)
    code.push(0x54); // SLOAD
    code.push(0x01); // ADD
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0
    code.push(0x55); // SSTORE
    code.extend_from_slice(&[0x60, 0x02]); // PUSH1 2
    code.push(0x54); // SLOAD
    code.push(0x01); // ADD
    code.push(0x80); // DUP1
    code.extend_from_slice(&[0x60, 0x02]); // PUSH1 2
    code.push(0x55); // SSTORE
    code.extend_from_slice(&[0x60, 0x08]); // PUSH1 8 (max iterations)
    code.push(0x11); // GT
    let jumpi_at = code.len();
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 <exit, patched>
    code.push(0x57); // JUMPI
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 <loop, patched>
    code.push(0x56); // JUMP
    let exit_at = code.len();
    code.push(0x00); // STOP

    code[jumpi_at + 1] = exit_at as u8;
    code[jumpi_at + 3] = loop_start as u8;
    code
}

fn target_address() -> Address {
    Address::repeat_byte(0x22)
}

fn caller_address() -> Address {
    Address::repeat_byte(0x11)
}

struct Fixture {
    state: ChainState,
    env: BlockEnv,
    tx: SingletonTx,
}

/// Build a warm cache.
///
/// `extra_accounts` and `slots_per_account` only inflate cached state; they are
/// never touched by execution. That isolates state-copy cost from execution
/// cost, which is exactly what the review's first finding claims dominates.
fn fixture(extra_accounts: usize, slots_per_account: usize) -> Fixture {
    let backend = ForkDb::new_offline("0x1");
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut db = CacheDB::new(backend);

    db.insert_account_info(
        caller_address(),
        AccountInfo {
            balance: U256::from(10u128.pow(24)),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target_address(),
        AccountInfo::default().with_code(Bytecode::new_raw(target_code().into())),
    );

    for account_idx in 0..extra_accounts {
        let mut addr_bytes = [0u8; 20];
        addr_bytes[0] = 0xAB;
        addr_bytes[16..].copy_from_slice(&(account_idx as u32).to_be_bytes());
        let address = Address::from(addr_bytes);
        let info = AccountInfo {
            balance: U256::from(1_000_000_000u128),
            nonce: 1,
            code_hash: B256::repeat_byte(0x77),
            ..Default::default()
        };
        db.insert_account_info(address, info);
        if let Some(account) = db.cache.accounts.get_mut(&address) {
            for slot in 0..slots_per_account {
                account
                    .storage
                    .insert(U256::from(slot), U256::from(slot + 1));
            }
        }
    }

    let mut env = BlockEnv {
        number: U256::from(1u64),
        timestamp: U256::from(1_700_000_000u64),
        basefee: 1_000_000_000,
        gas_limit: 30_000_000,
        ..Default::default()
    };
    env.set_blob_excess_gas_and_price(0, 3_338_477);

    Fixture {
        state: ChainState::Evm(db),
        env,
        tx: SingletonTx {
            caller: caller_address(),
            to: target_address(),
            input: vec![0xAA; 68],
            value: U256::ZERO,
            is_victim: false,
        },
    }
}

fn cached_slots(state: &ChainState) -> usize {
    let ChainState::Evm(db) = state;
    db.cache
        .accounts
        .values()
        .map(|account| account.storage.len())
        .sum()
}

/// Fixture shapes used by every table: (label, accounts, slots/account, iterations).
const CONFIGS: [(&str, usize, usize, usize); 4] = [
    ("bare", 0, 0, 300),
    ("warm-1k", 100, 10, 300),
    ("warm-10k", 500, 20, 150),
    ("warm-50k", 1000, 50, 60),
];

struct Measurement {
    label: String,
    cached_slots: usize,
    per_exec_us: f64,
    execs_per_sec: f64,
}

/// Current production shape: one base-state clone per input sequence, one
/// dataflow registry per input, every transaction against accumulating state.
fn measure_current(label: &str, accounts: usize, slots: usize, iterations: usize) -> Measurement {
    let fixture = fixture(accounts, slots);
    let cached = cached_slots(&fixture.state);
    let executor = EvmExecutor::exploration();
    let mut coverage = vec![0u8; MAP_SIZE];

    for _ in 0..3usize.min(iterations) {
        let mut state = fixture.state.clone();
        let mut env = fixture.env.clone();
        let mut dataflow = DataflowRegistry::new();
        for tx_idx in 0..TXS_PER_INPUT {
            let mut waypoints = Vec::new();
            executor
                .execute_with_result(
                    &mut state,
                    &mut env,
                    &fixture.tx,
                    &mut coverage,
                    &mut dataflow,
                    &mut waypoints,
                    tx_idx,
                )
                .expect("warm-up execution must succeed");
        }
    }

    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..iterations {
            let mut state = fixture.state.clone();
            let mut env = fixture.env.clone();
            let mut dataflow = DataflowRegistry::new();
            for tx_idx in 0..TXS_PER_INPUT {
                let mut waypoints = Vec::new();
                executor
                    .execute_with_result(
                        &mut state,
                        &mut env,
                        &fixture.tx,
                        &mut coverage,
                        &mut dataflow,
                        &mut waypoints,
                        tx_idx,
                    )
                    .expect("measured execution must succeed");
            }
        }
        samples.push(started.elapsed());
    }
    samples.sort();
    let executions_per_sample = iterations * TXS_PER_INPUT;
    let median = samples[samples.len() / 2];
    Measurement {
        label: label.to_string(),
        cached_slots: cached,
        per_exec_us: median.as_secs_f64() * 1e6 / executions_per_sample as f64,
        execs_per_sec: executions_per_sample as f64 / median.as_secs_f64(),
    }
}

/// Pre-change shape: an additional full cache copy for every transaction.
///
/// This reproduces the removed cost inside the same binary and the same run, so
/// the comparison cannot be attributed to machine or compiler differences.
fn measure_previous_shape(
    label: &str,
    accounts: usize,
    slots: usize,
    iterations: usize,
) -> Measurement {
    let fixture = fixture(accounts, slots);
    let cached = cached_slots(&fixture.state);
    let executor = EvmExecutor::exploration();
    let mut coverage = vec![0u8; MAP_SIZE];

    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..iterations {
            let mut state = fixture.state.clone();
            let mut env = fixture.env.clone();
            let mut dataflow = DataflowRegistry::new();
            for tx_idx in 0..TXS_PER_INPUT {
                // The removed per-transaction deep copy.
                let mut per_tx_state = state.clone();
                let mut waypoints = Vec::new();
                executor
                    .execute_with_result(
                        &mut per_tx_state,
                        &mut env,
                        &fixture.tx,
                        &mut coverage,
                        &mut dataflow,
                        &mut waypoints,
                        tx_idx,
                    )
                    .expect("previous-shape execution must succeed");
                state = per_tx_state;
            }
        }
        samples.push(started.elapsed());
    }
    samples.sort();
    // The median is a single sample's elapsed time, so normalise by the number
    // of executions in one sample.
    let executions_per_sample = iterations * TXS_PER_INPUT;
    let median = samples[samples.len() / 2];
    Measurement {
        label: label.to_string(),
        cached_slots: cached,
        per_exec_us: median.as_secs_f64() * 1e6 / executions_per_sample as f64,
        execs_per_sec: executions_per_sample as f64 / median.as_secs_f64(),
    }
}

/// Attribute the fixed per-execution cost that does not depend on cache size.
///
/// The "bare" fixture shows ~220us per execution with no cached state at all,
/// which cannot be EVM work for this target. These three measurements split
/// that constant into the coverage post-processing that runs on every
/// transaction and the execution itself.
fn fixed_cost_probe() {
    use rustyfuzz_evm::coverage::stable_path_hash;

    let fixture = fixture(0, 0);
    let executor = EvmExecutor::exploration();
    let reps = 300;

    // (a) The removed cost for comparison: a full scan of the map per tx.
    let mut map = vec![0u8; MAP_SIZE];
    for slot in map.iter_mut().take(64) {
        *slot = 3;
    }
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        for _ in 0..reps {
            let hash = stable_path_hash(&map);
            let edges = map.iter().filter(|&&hit| hit != 0).count();
            std::hint::black_box((hash, edges));
        }
        best = best.min(started.elapsed());
    }
    println!(
        "{:<34} {:>10.2} us",
        "full map scan (removed path)",
        best.as_secs_f64() * 1e6 / reps as f64
    );

    // (a2) The replacement: touched-index signature over an equivalent map.
    let mut touched_map = vec![0u8; MAP_SIZE];
    rustyfuzz_evm::coverage::begin_transaction();
    for (index, slot) in touched_map.iter_mut().take(64).enumerate() {
        *slot = 3;
        rustyfuzz_evm::coverage::record_touched(index);
    }
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        for _ in 0..reps {
            let hash = rustyfuzz_evm::coverage::transaction_path_hash(&touched_map);
            let edges = rustyfuzz_evm::coverage::transaction_edge_count();
            std::hint::black_box((hash, edges));
        }
        best = best.min(started.elapsed());
    }
    println!(
        "{:<34} {:>10.2} us",
        "touched-index signature",
        best.as_secs_f64() * 1e6 / reps as f64
    );

    // (b) A single execution with a freshly zeroed map (what a campaign sees).
    let mut coverage = vec![0u8; MAP_SIZE];
    let mut env = fixture.env.clone();
    let mut state = fixture.state.clone();
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();
    executor
        .execute_with_result(
            &mut state,
            &mut env,
            &fixture.tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("probe execution must succeed");

    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        for idx in 0..reps {
            let mut state = fixture.state.clone();
            let mut env = fixture.env.clone();
            let mut map = vec![0u8; MAP_SIZE];
            let mut df = DataflowRegistry::new();
            let mut wp = Vec::new();
            executor
                .execute_with_result(
                    &mut state,
                    &mut env,
                    &fixture.tx,
                    &mut map,
                    &mut df,
                    &mut wp,
                    idx,
                )
                .expect("probe execution must succeed");
        }
        best = best.min(started.elapsed());
    }
    println!(
        "{:<34} {:>10.2} us",
        "one execution (fresh map)",
        best.as_secs_f64() * 1e6 / reps as f64
    );

    // (c) Allocating the map alone, to separate allocation from hashing.
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        for _ in 0..reps {
            let map = vec![0u8; MAP_SIZE];
            std::hint::black_box(&map);
        }
        best = best.min(started.elapsed());
    }
    println!(
        "{:<34} {:>10.2} us",
        "allocate+zero the map",
        best.as_secs_f64() * 1e6 / reps as f64
    );
    println!();
}

fn main() {
    println!("rustyfuzz-evm execution throughput");
    println!("==================================");
    println!(
        "coverage map: {MAP_SIZE} bytes; {TXS_PER_INPUT} txs per input, one base-state clone per input\n"
    );

    fixed_cost_probe();

    // Isolate the copy itself. If this single copy is many times the cost of
    // executing a whole input, the next structural target is sharing rather
    // than copying the base state.
    println!("base-state clone cost only:");
    println!(
        "{:<12} {:>12} {:>14} {:>16}",
        "fixture", "cached slots", "us/copy", "copies/sec"
    );
    println!("{}", "-".repeat(58));
    for (label, accounts, slots, _) in CONFIGS {
        let fixture = fixture(accounts, slots);
        let cached = cached_slots(&fixture.state);
        let reps = 100;
        let mut best = Duration::MAX;
        let _warm = fixture.state.clone();
        for _ in 0..3 {
            let started = Instant::now();
            for _ in 0..reps {
                let copy = fixture.state.clone();
                std::hint::black_box(&copy);
            }
            best = best.min(started.elapsed());
        }
        let per_copy_us = best.as_secs_f64() * 1e6 / reps as f64;
        println!(
            "{:<12} {:>12} {:>14.2} {:>16.0}",
            label,
            cached,
            per_copy_us,
            1e6 / per_copy_us
        );
    }

    println!("\nthroughput, previous shape (per-transaction copy):");
    println!(
        "{:<10} {:>12} {:>14} {:>16}",
        "fixture", "cached slots", "us/exec", "execs/sec"
    );
    println!("{}", "-".repeat(56));
    let previous: Vec<Measurement> = CONFIGS
        .iter()
        .map(|(label, accounts, slots, iterations)| {
            measure_previous_shape(label, *accounts, *slots, *iterations)
        })
        .collect();
    for m in &previous {
        println!(
            "{:<10} {:>12} {:>14.2} {:>16.0}",
            m.label, m.cached_slots, m.per_exec_us, m.execs_per_sec
        );
    }

    println!("\nthroughput, current (one copy per input):");
    println!(
        "{:<10} {:>12} {:>14} {:>16}",
        "fixture", "cached slots", "us/exec", "execs/sec"
    );
    println!("{}", "-".repeat(56));
    let current: Vec<Measurement> = CONFIGS
        .iter()
        .map(|(label, accounts, slots, iterations)| {
            measure_current(label, *accounts, *slots, *iterations)
        })
        .collect();
    for m in &current {
        println!(
            "{:<10} {:>12} {:>14.2} {:>16.0}",
            m.label, m.cached_slots, m.per_exec_us, m.execs_per_sec
        );
    }

    println!("\nspeedup (current vs previous shape, same binary):");
    println!(
        "{:<10} {:>12} {:>14} {:>16}",
        "fixture", "cached slots", "x faster", "execs/sec"
    );
    println!("{}", "-".repeat(56));
    for (before, after) in previous.iter().zip(current.iter()) {
        println!(
            "{:<10} {:>12} {:>14.2} {:>16.0}",
            after.label,
            after.cached_slots,
            after.execs_per_sec / before.execs_per_sec,
            after.execs_per_sec
        );
    }

    println!("\nJSON:");
    println!("{{");
    println!("  \"map_size\": {MAP_SIZE},");
    println!("  \"txs_per_input\": {TXS_PER_INPUT},");
    println!("  \"fixtures\": [");
    for (idx, (before, after)) in previous.iter().zip(current.iter()).enumerate() {
        let comma = if idx + 1 == current.len() { "" } else { "," };
        println!(
            "    {{\"name\": \"{}\", \"cached_slots\": {}, \"previous_execs_per_sec\": {:.0}, \"current_execs_per_sec\": {:.0}, \"speedup\": {:.2}}}{}",
            after.label,
            after.cached_slots,
            before.execs_per_sec,
            after.execs_per_sec,
            after.execs_per_sec / before.execs_per_sec,
            comma
        );
    }
    println!("  ]");
    println!("}}");
}
