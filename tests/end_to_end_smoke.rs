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
