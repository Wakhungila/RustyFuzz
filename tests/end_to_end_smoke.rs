use revm::primitives::Address;
use rusty_fuzz::config::HardenedDefiConfig;
use rusty_fuzz::engine::fuzz_engine::{run_fuzz_campaign, Config};
use rusty_fuzz::engine::promotion::{PromotionCampaignSummary, PromotionConfig};
use std::fs;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_root(name: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("rustyfuzz-{name}-{nonce}"))
}

#[tokio::test]
async fn synthetic_abi_smoke_campaign_does_not_promote_findings() {
    let root = unique_temp_root("smoke");
    fs::create_dir_all(&root).expect("temp root");
    let corpus_dir = root.join("corpus");
    let report_dir = root.join("reports");
    let target = Address::from_str("0x1111111111111111111111111111111111111111").expect("target");

    let hardened = HardenedDefiConfig {
        enabled: false,
        single_process: true,
        deterministic: true,
        rng_seed: Some(1),
        max_template_sequences: 1,
        ..Default::default()
    };

    let config = Config {
        rpc_url: "not-a-url".to_string(),
        fork_block: 1,
        target_contract: Some(target),
        in_memory_bytecode: None,
        cores: None,
        corpus_dir: corpus_dir.display().to_string(),
        report_dir: report_dir.display().to_string(),
        foundry_harness: None,
        mainnet_seed_bundle: None,
        require_seed_bundle: false,
        require_rpc_fork: false,
        allow_synthetic_fallback: true,
        hardened_defi: hardened,
        target_invariant_manifest: None,
        predicate_invariants: None,
        abi_path: None,
        max_execs: None,
        duration_secs: Some(1),
        artifact_limit: Some(1),
        campaign_id: Some("smoke".to_string()),
        paths_are_isolated: false,
        min_finding_confidence: 0,

        promotion: PromotionConfig {
            enabled: true,
            no_promotion: false,
            external_foundry_opt_in: true,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            strict_proof: true,
            no_synthetic_proof: true,
            require_foundry_poc: true,
            require_minimized: true,
            reject_heuristics: true,
            max_finding_noise: Some(0),
            poc_out: None,
            promotion_limit: Some(8),
        },
    };

    let canonical_root = root.join(".rustyfuzz/runs/smoke");
    let campaign_report_dir = canonical_root.join("reports");
    let previous_dir = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(&root).expect("set temp cwd");
    let result = run_fuzz_campaign(config).await;
    std::env::set_current_dir(previous_dir).expect("restore cwd");
    result.expect("smoke campaign");

    let finding_dir = campaign_report_dir.join("findings");
    assert!(
        !finding_dir.exists()
            || fs::read_dir(&finding_dir)
                .expect("finding dir")
                .filter_map(Result::ok)
                .all(|entry| !entry.path().join("finding.json").exists()),
        "synthetic fallback must not promote vulnerability findings"
    );
    let summary: PromotionCampaignSummary = serde_json::from_slice(
        &fs::read(campaign_report_dir.join("campaign_summary.json")).expect("summary json"),
    )
    .expect("campaign summary");
    assert_eq!(summary.promoted_findings, 0);
    assert_eq!(summary.confirmed_findings, 0);
    assert_eq!(summary.synthetic_non_production_findings, 0);
    let status: serde_json::Value = serde_json::from_slice(
        &fs::read(campaign_report_dir.join("campaign_status.json")).expect("status json"),
    )
    .expect("campaign status");
    assert_eq!(status["state"], "finalized");
    assert_eq!(status["summary"]["promoted_findings"], 0);
    let canonical_summary = canonical_root.join("reports/campaign_summary.json");
    let canonical_status = canonical_root.join("campaign_status.json");
    let terminal: serde_json::Value = serde_json::from_slice(
        &fs::read(canonical_root.join("terminal_status.json")).expect("terminal status"),
    )
    .expect("terminal status json");
    assert_eq!(
        terminal["final_summary_path"],
        "reports/campaign_summary.json"
    );
    assert!(!root.join("reports_smoke/campaign_summary.json").exists());
    assert!(!root.join("corpus_smoke").exists());
    let canonical_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(&canonical_summary).expect("canonical summary")).unwrap();
    let inventory = canonical_summary["evidence_inventory"].as_array().unwrap();
    assert!(!inventory.is_empty());
    assert!(inventory.iter().all(|entry| {
        let path = entry["path"].as_str().unwrap_or_default();
        !path.is_empty()
            && path != "config.json"
            && entry["digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:"))
    }));
    assert!(inventory.iter().any(|entry| {
        entry["path"]
            .as_str()
            .is_some_and(|path| path.starts_with("inputs/") || path.starts_with("reports/"))
    }));

    let canonical_status: serde_json::Value =
        serde_json::from_slice(&fs::read(&canonical_status).expect("canonical campaign status"))
            .expect("canonical status json");
    assert_eq!(canonical_status["campaign_id"], "smoke");
    assert_eq!(canonical_status["phase"], "terminal");

    let _ = fs::remove_dir_all(root);
}

/// A predicate that can never hold must produce a finding through the normal pipeline.
///
/// Structure matters here. Every test in this repo that asserts real execution runs the
/// campaign in a **child process** via `current_exe`, because the campaign spawns its own
/// worker process; running it in-process silently completes with zero executions, which
/// would make this test pass for the wrong reason or fail with no diagnosis. An earlier
/// version of this test did exactly that and reported `total_executions: 0`.
///
/// Two more things learned by getting them wrong:
///
/// * the target needs real bytecode or nothing runs. The bytecode below does
///   `SLOAD(0)`, add 1, `SSTORE(0)`, so slot 0 is definitely written and observable.
/// * the predicate must be impossible for a *resolved* value. An unwritten slot is
///   `Unknown`, which is no-signal, so a predicate over it would never fire and the test
///   would prove nothing.
#[test]
fn an_impossible_invariant_produces_a_finding_through_the_campaign() {
    let root = unique_temp_root("invariant-fires");
    fs::create_dir_all(&root).expect("temp root");
    let log_path = root.join("worker.log");
    let log = fs::File::create(&log_path).expect("worker log");

    let mut child = std::process::Command::new(std::env::current_exe().expect("test exe"))
        .args([
            "--exact",
            "invariant_campaign_worker",
            "--nocapture",
            "--ignored",
        ])
        .current_dir(&root)
        .env("RUSTYFUZZ_INVARIANT_TEST_ROOT", &root)
        .env("RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS", "0")
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn worker");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll worker") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            panic!(
                "invariant campaign worker timed out; log:\n{}",
                fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "invariant campaign worker failed; log:\n{}",
        fs::read_to_string(&log_path).unwrap_or_default()
    );

    // The summary must show the campaign actually executed something. Without this, a
    // passing "found nothing" result would be indistinguishable from a campaign that
    // never ran.
    let summary_path = root.join(".rustyfuzz/runs/invariant-fires/reports/campaign_summary.json");
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(&summary_path).expect("campaign summary"))
            .expect("summary json");
    let executions = summary["total_executions"].as_u64().unwrap_or(0);
    assert!(
        executions > 0,
        "the campaign must execute transactions for this test to mean anything; \
         summary shows total_executions={executions}"
    );

    // The violation must appear in the provenance trail with its predicate text.
    //
    // Scope, stated exactly: this run is a synthetic fork (no RPC), and
    // `campaign_artifact_reason` deliberately returns None for synthetic forks -- there is
    // no real chain state to attest a finding against, so no artifact is emitted and
    // `total_artifacts` stays 0. Requiring an artifact here would be requiring the tool to
    // do something it refuses on purpose. What this test therefore proves is that the
    // predicate layer runs inside the campaign and that its verdict reaches the recorded
    // evidence; promotion to a proof-carrying artifact is gated on a real fork and is
    // exercised by the live-target path, not here.
    let provenance_root = root.join(".rustyfuzz/runs/invariant-fires/inputs/execution_provenance");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&provenance_root).expect("provenance dir") {
        let path = entry.expect("entry").path();
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if text.contains("supply < supplyFrozen && supply > supplyFrozen") {
            violations.push(path);
        }
    }
    assert!(
        !violations.is_empty(),
        "the violated predicate must appear in the execution provenance; \
         {} has {} file(s) and none mention it",
        provenance_root.display(),
        fs::read_dir(&provenance_root)
            .map(|d| d.count())
            .unwrap_or(0)
    );

    // And it must be typed as an invariant violation, not merely present as text.
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(&violations[0]).expect("provenance json"))
            .expect("provenance is json");
    let finding = &provenance["findings"][0];
    assert_eq!(
        finding["vuln"]["InvariantViolation"], "supply < supplyFrozen && supply > supplyFrozen",
        "the finding must carry the predicate as its vulnerability class"
    );
    assert_eq!(finding["tx_index"], 0, "the violation happened at tx 0");

    let _ = fs::remove_dir_all(root);
}

/// Body of the child process for the test above. Does nothing unless the driver set the
/// environment variable, so a plain `cargo test` does not run a campaign as a side effect.
#[test]
#[ignore]
fn invariant_campaign_worker() {
    let Some(root) = std::env::var_os("RUSTYFUZZ_INVARIANT_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = Address::from_str("0x1111111111111111111111111111111111111111").expect("target");

    let invariants = root.join("invariants.json");
    fs::write(
        &invariants,
        serde_json::json!({
            "target": target.to_string(),
            "symbols": {
                "supply": { "kind": "slot", "slot": "0x0", "offset_bits": 0, "width_bits": 256 },
                // Same slot under a second name, so both sides resolve to one observed
                // value and the comparison is impossible rather than merely false.
                "supplyFrozen": { "kind": "slot", "slot": "0x0", "offset_bits": 0, "width_bits": 256 }
            },
            "invariants": [
                { "name": "alwaysFails", "predicate": "supply < supplyFrozen && supply > supplyFrozen" }
            ]
        })
        .to_string(),
    )
    .expect("write invariants");

    let config = Config {
        rpc_url: "offline-test".to_string(),
        fork_block: 1,
        target_contract: Some(target),
        // SLOAD(0), +1, SSTORE(0): guarantees slot 0 is written and observable.
        in_memory_bytecode: Some(vec![0x60, 0, 0x54, 0x60, 1, 1, 0x60, 0, 0x55, 0]),
        cores: None,
        corpus_dir: root.join("corpus").display().to_string(),
        report_dir: root.join("reports").display().to_string(),
        foundry_harness: None,
        mainnet_seed_bundle: None,
        require_seed_bundle: false,
        require_rpc_fork: false,
        allow_synthetic_fallback: true,
        hardened_defi: HardenedDefiConfig {
            single_process: true,
            deterministic: true,
            rng_seed: Some(7),
            ..Default::default()
        },
        target_invariant_manifest: None,
        predicate_invariants: Some(invariants.display().to_string()),
        abi_path: None,
        max_execs: Some(400),
        duration_secs: Some(10),
        artifact_limit: Some(4),
        campaign_id: Some("invariant-fires".to_string()),
        paths_are_isolated: true,
        min_finding_confidence: 0,
        promotion: PromotionConfig::default(),
    };

    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(run_fuzz_campaign(config))
        .expect("campaign with an impossible invariant");
}
