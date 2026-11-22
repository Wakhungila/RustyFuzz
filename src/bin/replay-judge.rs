//! Oracle-independent replay judge (benchmark item 16).
//!
//! Replays RustyFuzz campaign inputs on a fresh copy of the fixture state and
//! reads the Daedaluzz `__bugs[id]` mapping slots straight from contract
//! storage. No RustyFuzz oracle, invariant or finding is consulted, so the
//! confirmed-bug set cannot be inflated by the fuzzer's own heuristics.
use clap::Parser;
use revm::primitives::{keccak256, Address, U256};
use revm::Database;
use rusty_fuzz::common::types::ChainState;
use rusty_fuzz::engine::executable_fixture::ExecutableFixture;
use rusty_fuzz::evm::fork::{create_in_memory_fork_db_from_fixture, create_offline_fallback_block_env};
use rusty_fuzz::evm::fuzz::EvmInput;
use rustyfuzz_evm::dataflow::DataflowRegistry;
use rustyfuzz_evm::executor::EvmExecutor;
use rustyfuzz_evm::inspector::MAP_SIZE;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    /// Maze fixture JSON.
    #[arg(long)]
    fixture: PathBuf,
    /// Invariants manifest (only used to learn the bug ids 1..N, never to judge).
    #[arg(long)]
    invariants: PathBuf,
    /// Directory containing `inputs/<id>.json` (a run's `inputs/inputs`).
    #[arg(long)]
    inputs: PathBuf,
    /// Number of bug ids to probe if the manifest cannot be parsed.
    #[arg(long, default_value_t = 0)]
    max_bug_id: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let state = ExecutableFixture::load_for_fuzz(&args.fixture)?;
    let target: Address = state.target;
    let mut base_db = create_in_memory_fork_db_from_fixture(&state);
    // Mirror campaign setup for `--attacker-harness`: inputs reference these accounts.
    rusty_fuzz::engine::attacker_harness::deploy_reentrancy_attacker(&mut base_db, target)
        .map_err(|e| anyhow::anyhow!("attacker deploy: {e}"))?;
    rusty_fuzz::engine::sim_defi::setup_flashloan(&mut base_db, rusty_fuzz::engine::sim_defi::DEFAULT_FEE_BPS)
        .map_err(|e| anyhow::anyhow!("flashloan setup: {e}"))?;
    let block_env0 = create_offline_fallback_block_env(0);

    let mut ids: BTreeSet<u64> = BTreeSet::new();
    if let Ok(raw) = std::fs::read_to_string(&args.invariants) {
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        if let Some(syms) = v.get("symbols").and_then(|s| s.as_object()) {
            for name in syms.keys() {
                if let Some(n) = name.strip_prefix('b').and_then(|n| n.parse::<u64>().ok()) {
                    ids.insert(n);
                }
            }
        }
    }
    for n in 1..=args.max_bug_id {
        ids.insert(n);
    }

    let executor = EvmExecutor::new();
    let mut confirmed: BTreeSet<u64> = BTreeSet::new();
    let mut replayed = 0usize;
    let mut failed = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&args.inputs)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false) && !p.to_string_lossy().ends_with(".meta.json"))
        .collect();
    entries.sort();
    for path in entries {
        let input: EvmInput = match serde_json::from_slice(&std::fs::read(&path)?) {
            Ok(i) => i,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        // Root-based inputs only: a snapshot-based input needs its parent state.
        if input.base_snapshot_id != 0 {
            failed += 1;
            continue;
        }
        let mut db = base_db.clone();
        let mut block_env = block_env0.clone();
        let mut dataflow = DataflowRegistry::new();
        let mut coverage = vec![0u8; MAP_SIZE];
        let mut ok = true;
        for (idx, tx) in input.txs.iter().enumerate() {
            let mut cs = ChainState::Evm(db.clone());
            let mut wp = Vec::new();
            match executor.execute_with_result(&mut cs, &mut block_env, tx, &mut coverage, &mut dataflow, &mut wp, idx) {
                Err(_) => {
                    ok = false;
                    break;
                }
                Ok(r) => {
                    if std::env::var("JUDGE_DUMP").is_ok() {
                        println!("  reads={:?} writes={:?}", r.storage_reads, r.storage_writes);
                        println!("  tx{} status={:?} gas={} diffs={} writes={}", idx, r.status, r.gas_used, r.storage_diffs.len(), r.storage_writes.len());
                    }
                }
            }
            let ChainState::Evm(n) = cs;
            db = n;
        }
        if !ok {
            failed += 1;
            continue;
        }
        replayed += 1;
        if std::env::var("JUDGE_DUMP").is_ok() {
            if let Some(acc) = db.cache.accounts.get(&target) {
                let nz: Vec<_> = acc.storage.iter().filter(|(_, v)| !v.is_zero()).collect();
                println!("{} nonzero_slots={} {:?}", path.display(), nz.len(), nz.iter().take(4).collect::<Vec<_>>());
            }
        }
        for id in &ids {
            let mut buf = [0u8; 64];
            buf[24..32].copy_from_slice(&id.to_be_bytes());
            // base slot 0 occupies bytes 32..64 (already zero)
            let slot = U256::from_be_bytes(keccak256(buf).0);
            if std::env::var("JUDGE_DUMP").is_ok() && *id == 16 {
                use revm::DatabaseRef;
                println!("  b16 slot={:#x} storage={:?} storage_ref={:?}", slot, db.storage(target, slot), db.storage_ref(target, slot));
            }
            if let Ok(v) = db.storage(target, slot) {
                if !v.is_zero() {
                    confirmed.insert(*id);
                }
            }
        }
    }
    println!(
        "judge replayed={} skipped={} confirmed={} ids={:?}",
        replayed,
        failed,
        confirmed.len(),
        confirmed
    );
    Ok(())
}
