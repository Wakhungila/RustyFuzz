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
    let corpus_dir = root.join("corpus");
    let report_dir = root.join("reports");
    let target = Address::from_str("0x1111111111111111111111111111111111111111").expect("target");

    let mut hardened = HardenedDefiConfig::default();
    hardened.enabled = false;
    hardened.single_process = true;
    hardened.deterministic = true;
    hardened.rng_seed = Some(1);
    hardened.max_template_sequences = 1;

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
        min_finding_confidence: 0,
        promotion: PromotionConfig {
            enabled: true,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            promotion_limit: Some(8),
        },
    };

    run_fuzz_campaign(config).await.expect("smoke campaign");

    let finding_dir = report_dir.join("findings");
    assert!(
        !finding_dir.exists()
            || fs::read_dir(&finding_dir)
                .expect("finding dir")
                .filter_map(Result::ok)
                .all(|entry| !entry.path().join("finding.json").exists()),
        "synthetic fallback must not promote vulnerability findings"
    );
    assert!(
        report_dir.join("campaign_summary.json").exists(),
        "campaign summary JSON should exist"
    );
    let summary: PromotionCampaignSummary = serde_json::from_slice(
        &fs::read(report_dir.join("campaign_summary.json")).expect("summary json"),
    )
    .expect("campaign summary");
    assert_eq!(summary.promoted_findings, 0);
    assert_eq!(summary.confirmed_findings, 0);
    assert_eq!(summary.synthetic_non_production_findings, 0);

    let _ = fs::remove_dir_all(root);
}
