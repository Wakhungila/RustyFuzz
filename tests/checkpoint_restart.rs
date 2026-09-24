#![cfg(unix)]
use revm::primitives::Address;
use rusty_fuzz::{
    config::HardenedDefiConfig,
    engine::{
        checkpoint::{CheckpointConfig, CheckpointEnvelope},
        fuzz_engine::{run_fuzz_campaign, Config},
        promotion::PromotionConfig,
    },
};
use std::os::unix::process::ExitStatusExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// A real campaign in a subprocess, not a checkpoint serializer stand-in.
#[test]
fn checkpoint_campaign_worker() {
    let Some(root) = std::env::var_os("RUSTYFUZZ_RESTART_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let resume = std::env::var_os("RUSTYFUZZ_RESTART_TEST_RESUME").is_some();
    let config = Config {
        rpc_url: "offline-test".into(),
        fork_block: 1,
        target_contract: Some(Address::repeat_byte(0x11)),
        corpus_dir: root.join("corpus").display().to_string(),
        report_dir: root.join("reports").display().to_string(),
        foundry_harness: None,
        mainnet_seed_bundle: None,
        // SSTORE(calldataload(0)); SLOAD; return the resulting word.
        in_memory_bytecode: Some(hex::decode("60003560005560005460005260206000f3").unwrap()),
        cores: None,
        require_seed_bundle: false,
        require_rpc_fork: false,
        allow_synthetic_fallback: true,
        hardened_defi: HardenedDefiConfig {
            single_process: true,
            deterministic: true,
            rng_seed: Some(42),
            checkpoint: Some(CheckpointConfig {
                directory: root.join("checkpoint"),
                resume,
                every_execs: 4,
            }),
            ..Default::default()
        },
        target_invariant_manifest: None,
        abi_path: None,
        max_execs: Some(100_000),
        duration_secs: None,
        artifact_limit: Some(0),
        campaign_id: Some("restart".to_string()),
        paths_are_isolated: true,

        min_finding_confidence: 0,

        promotion: PromotionConfig {
            enabled: false,
            ..Default::default()
        },
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_fuzz_campaign(config))
        .unwrap();
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(root: &Path, resume: bool) -> Process {
    let log = fs::File::create(root.join(if resume { "resume.log" } else { "start.log" })).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "checkpoint_campaign_worker", "--nocapture"])
        .env("RUSTYFUZZ_RESTART_TEST_ROOT", root)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    if resume {
        command.env("RUSTYFUZZ_RESTART_TEST_RESUME", "1");
    }
    Process(command.spawn().unwrap())
}
fn read(path: &Path) -> CheckpointEnvelope {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn wait_for(child: &mut Process, root: &Path, path: &Path, minimum: u64) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if path.exists() && read(path).budget_consumed >= minimum {
            return;
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "campaign exited before checkpoint: {status}; start={} resume={}",
                fs::read_to_string(root.join("start.log")).unwrap_or_default(),
                fs::read_to_string(root.join("resume.log")).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "campaign checkpoint timed out; logs at {}",
            root.display()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn kill(child: &mut Process) {
    child.0.kill().unwrap(); // std::process::Child::kill sends SIGKILL on Unix.
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    println!("child terminated by signal={}", status.signal().unwrap());
}

#[test]
fn sigkill_resumes_real_campaign_from_checkpoint() {
    let root = std::env::temp_dir().join(format!(
        "rustyfuzz-restart-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("checkpoint/checkpoint.json");
    let mut first = start(&root, false);
    wait_for(&mut first, &root, &path, 8);
    kill(&mut first);
    // Read AFTER death: this is the last committed checkpoint, not an earlier poll.
    let before = read(&path);
    assert!(before.completed_execs >= 8);
    assert_eq!(before.schema_version, 2);
    assert_eq!(before.config_schema_version, 2);

    assert!(before.coverage.iter().any(|byte| *byte != 0));
    assert!(!before.corpus_ids.is_empty());
    println!(
        "last checkpoint: consumed={}, completed={}, corpus={}, covered_slots={}",
        before.budget_consumed,
        before.completed_execs,
        before.corpus_ids.len(),
        before.coverage.iter().filter(|b| **b != 0).count()
    );
    let provenance_path = root
        .join("corpus/execution_provenance")
        .join(format!("{:020}.json", before.completed_execs));
    let provenance: rusty_fuzz::engine::provenance::ExecutionProvenanceRecord =
        serde_json::from_slice(&fs::read(&provenance_path).unwrap()).unwrap();
    assert_eq!(provenance.schema_version, 2);
    assert_eq!(provenance.execution_index, before.completed_execs);
    assert_eq!(provenance.budget_consumed, before.budget_consumed);
    assert_eq!(provenance.input_id, provenance.input.semantic_input_hash());
    assert_eq!(
        provenance.execution.tx_results.len(),
        provenance.input.txs.len()
    );
    println!(
        "sample provenance: {}",
        serde_json::to_string(&serde_json::json!({
            "schema_version": provenance.schema_version,
            "execution_index": provenance.execution_index,
            "budget_consumed": provenance.budget_consumed,
            "input_id": provenance.input_id,
            "tx_count": provenance.input.txs.len(),
            "tx_statuses": provenance.execution.tx_results.iter()
                .map(|result| format!("{:?}", result.status)).collect::<Vec<_>>(),
            "total_gas_used": provenance.execution.total_gas_used,
            "coverage_edges": provenance.coverage_edges,
            "state_novelty_score": provenance.state_novelty_score,
            "campaign_score": provenance.campaign_score.total,
            "finding_count": provenance.findings.len(),
            "mutation_strategies": provenance.mutation_strategies,
        }))
        .unwrap()
    );
    let mut second = start(&root, true);
    wait_for(&mut second, &root, &path, before.budget_consumed + 1);
    assert!(!root.join("checkpoint/resume.json").exists());
    wait_for(&mut second, &root, &path, before.budget_consumed + 4);
    kill(&mut second);
    let after = read(&path);
    assert!(after.completed_execs > before.completed_execs);
    assert!(after.budget_consumed > before.budget_consumed);
    assert!(after
        .coverage
        .iter()
        .zip(&before.coverage)
        .all(|(a, b)| a >= b));
    for id in &before.corpus_ids {
        assert!(after.corpus_ids.contains(id));
    }
    println!(
        "continued campaign: consumed={}, completed={}, corpus={}, covered_slots={}",
        after.budget_consumed,
        after.completed_execs,
        after.corpus_ids.len(),
        after.coverage.iter().filter(|b| **b != 0).count()
    );
    fs::remove_dir_all(&root).unwrap();
}
