use revm::primitives::Address;
use rusty_fuzz::config::HardenedDefiConfig;
use rusty_fuzz::engine::fuzz_engine::{run_fuzz_campaign, Config};
use rusty_fuzz::engine::promotion::{
    FindingLifecycleStage, FindingPromotionRecord, PromotionCampaignSummary, PromotionConfig,
};
use rusty_fuzz::evm::corpus::CampaignArtifactRecord;
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
async fn synthetic_abi_smoke_campaign_persists_non_production_finding() {
    let root = unique_temp_root("smoke");
    let corpus_dir = root.join("corpus");
    let report_dir = root.join("reports");
    let target = Address::from_str("0x1111111111111111111111111111111111111111").expect("target");

    let mut hardened = HardenedDefiConfig::default();
    hardened.enabled = true;
    hardened.single_process = true;
    hardened.deterministic = true;
    hardened.rng_seed = Some(1);
    hardened.max_template_sequences = 8;

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
        abi_path: Some("tests/fixtures/smoke_vault.abi.json".to_string()),
        max_execs: Some(16),
        duration_secs: None,
        artifact_limit: Some(16),
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

    let artifact_dir = corpus_dir.join("campaign_artifacts");
    let records = fs::read_dir(&artifact_dir)
        .expect("artifact dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().extension().and_then(|ext| ext.to_str()) == Some("json")
                && entry.path().file_name().and_then(|name| name.to_str()) != Some("index")
        })
        .collect::<Vec<_>>();
    assert!(
        !records.is_empty(),
        "bounded smoke campaign should persist at least one artifact"
    );

    let record = records
        .iter()
        .filter_map(|entry| fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<CampaignArtifactRecord>(&bytes).ok())
        .find(|record| !record.findings.is_empty())
        .expect("smoke artifact with oracle evidence");
    assert!(
        record.reason.starts_with("synthetic-non-production"),
        "synthetic fallback artifacts must be explicitly non-production: {}",
        record.reason
    );
    assert!(
        !record.findings.is_empty(),
        "smoke artifact should include oracle evidence"
    );
    assert!(
        record.triage.confidence <= 35,
        "synthetic fallback confidence must stay low, got {}",
        record.triage.confidence
    );

    let finding_dir = report_dir.join("findings");
    let promoted = fs::read_dir(&finding_dir)
        .expect("finding dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("finding.json"))
        .find(|path| path.exists())
        .expect("promoted finding JSON");
    let promoted_record: FindingPromotionRecord =
        serde_json::from_slice(&fs::read(&promoted).expect("finding json"))
            .expect("promotion record");
    assert_ne!(
        promoted_record.lifecycle_stage,
        FindingLifecycleStage::Confirmed
    );
    assert!(promoted_record.synthetic_mode);
    assert!(promoted_record
        .caveats
        .iter()
        .any(|caveat| caveat.contains("synthetic fallback")));
    assert!(
        promoted_record
            .artifact_paths
            .get("replay")
            .is_some_and(|path| std::path::Path::new(path).exists()),
        "replay JSON should exist"
    );
    assert!(
        report_dir.join("campaign_summary.json").exists(),
        "campaign summary JSON should exist"
    );
    let summary: PromotionCampaignSummary = serde_json::from_slice(
        &fs::read(report_dir.join("campaign_summary.json")).expect("summary json"),
    )
    .expect("campaign summary");
    assert!(summary.promoted_findings > 0);
    assert_eq!(summary.confirmed_findings, 0);

    let _ = fs::remove_dir_all(root);
}
