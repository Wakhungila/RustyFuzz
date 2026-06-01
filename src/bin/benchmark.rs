use clap::Parser;
use revm::primitives::Address;
use rusty_fuzz::config::HardenedDefiConfig;
use rusty_fuzz::engine::fuzz_engine::{run_fuzz_campaign, Config as FuzzConfig};
use rusty_fuzz::engine::promotion::PromotionConfig;
use rusty_fuzz::evm::corpus::CampaignArtifactRecord;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
struct Args {
    /// Directory containing Daedaluzz-style JSON artifacts.
    artifacts_dir: PathBuf,
    /// Maximum executions per contract.
    #[arg(long, default_value_t = 50_000)]
    max_execs: u64,
    /// Directory where benchmark markdown and JSON reports are written.
    #[arg(long, default_value = "reports/benchmarks")]
    output_dir: PathBuf,
}

#[derive(Debug)]
struct ContractArtifact {
    name: String,
    runtime_bytecode: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkRow {
    contract: String,
    bugs_found: usize,
    coverage_edges: usize,
    seconds: f64,
    execs_per_sec: f64,
    crashes: usize,
    oracle_classes: BTreeMap<String, usize>,
    artifact_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    artifacts_dir: PathBuf,
    max_execs: u64,
    total_bugs_found: usize,
    total_crashes: usize,
    rows: Vec<BenchmarkRow>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let artifacts = load_artifacts(&args.artifacts_dir)?;
    let mut rows = Vec::new();

    for (idx, artifact) in artifacts.iter().enumerate() {
        let target = benchmark_address(idx);
        let work_dir = std::env::temp_dir()
            .join("rustyfuzz-daedaluzz")
            .join(format!("{}-{idx}", sanitize_name(&artifact.name)));
        let corpus_dir = work_dir.join("corpus");
        let report_dir = work_dir.join("reports");
        fs::create_dir_all(&corpus_dir)?;
        fs::create_dir_all(&report_dir)?;

        let mut hardened_defi = HardenedDefiConfig::default();
        hardened_defi.enabled = false;
        hardened_defi.single_process = true;

        let started = Instant::now();
        run_fuzz_campaign(FuzzConfig {
            rpc_url: "http://127.0.0.1:0".to_string(),
            fork_block: 0,
            target_contract: Some(target),
            corpus_dir: corpus_dir.display().to_string(),
            report_dir: report_dir.display().to_string(),
            foundry_harness: None,
            mainnet_seed_bundle: None,
            in_memory_bytecode: Some(artifact.runtime_bytecode.clone()),
            cores: None,
            require_seed_bundle: false,
            require_rpc_fork: false,
            allow_synthetic_fallback: true,
            hardened_defi,
            target_invariant_manifest: None,
            abi_path: None,
            max_execs: Some(args.max_execs),
            duration_secs: None,
            artifact_limit: Some(100),
            campaign_id: Some(format!("daedaluzz-{}", sanitize_name(&artifact.name))),
            min_finding_confidence: 0,
            promotion: PromotionConfig::default(),
        })
        .await?;

        let metrics = collect_campaign_metrics(&corpus_dir)?;
        let seconds = started.elapsed().as_secs_f64();
        rows.push(BenchmarkRow {
            contract: artifact.name.clone(),
            bugs_found: metrics.bugs_found,
            coverage_edges: metrics.coverage_edges,
            seconds,
            execs_per_sec: args.max_execs as f64 / seconds.max(0.001),
            crashes: metrics.crashes,
            oracle_classes: metrics.oracle_classes,
            artifact_ids: metrics.artifact_ids,
        });
    }

    print_markdown_table(&rows);
    write_reports(&args, rows.as_slice())?;
    if rows.iter().map(|row| row.bugs_found).sum::<usize>() == 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn load_artifacts(dir: &Path) -> anyhow::Result<Vec<ContractArtifact>> {
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let Some(runtime_bytecode) = artifact_runtime_bytecode(&value) else {
            continue;
        };
        let name = value
            .get("contractName")
            .or_else(|| value.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("contract")
                    .to_string()
            });
        artifacts.push(ContractArtifact {
            name,
            runtime_bytecode,
        });
    }
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(artifacts)
}

fn artifact_runtime_bytecode(value: &Value) -> Option<Vec<u8>> {
    let candidates = [
        &value["deployedBytecode"]["object"],
        &value["deployedBytecode"],
        &value["bytecode"]["object"],
        &value["bytecode"],
    ];
    candidates
        .iter()
        .filter_map(|candidate| candidate.as_str())
        .find_map(decode_hex_bytecode)
}

fn decode_hex_bytecode(raw: &str) -> Option<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("__") {
        return None;
    }
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.is_empty() {
        return None;
    }
    hex::decode(hex).ok().filter(|bytes| !bytes.is_empty())
}

#[derive(Default)]
struct CampaignMetrics {
    bugs_found: usize,
    coverage_edges: usize,
    crashes: usize,
    oracle_classes: BTreeMap<String, usize>,
    artifact_ids: Vec<String>,
}

fn collect_campaign_metrics(corpus_dir: &Path) -> anyhow::Result<CampaignMetrics> {
    let mut metrics = CampaignMetrics::default();
    let crashes_dir = corpus_dir.join("crashes");
    if crashes_dir.exists() {
        metrics.crashes = fs::read_dir(crashes_dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .count();
    }

    let mut bugs_found = 0usize;
    let artifacts_dir = corpus_dir.join("campaign_artifacts");
    if !artifacts_dir.exists() {
        return Ok(metrics);
    }
    let mut artifact_ids = BTreeSet::new();
    for entry in fs::read_dir(artifacts_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record: CampaignArtifactRecord = serde_json::from_slice(&fs::read(&path)?)?;
        bugs_found += record.findings.len();
        metrics.coverage_edges = metrics.coverage_edges.max(record.metadata.coverage_edges);
        artifact_ids.insert(record.input_id.clone());
        for finding in &record.findings {
            *metrics
                .oracle_classes
                .entry(format!("{:?}", finding.vuln))
                .or_default() += 1;
        }
    }
    metrics.bugs_found = bugs_found;
    metrics.artifact_ids = artifact_ids.into_iter().collect();
    Ok(metrics)
}

fn print_markdown_table(rows: &[BenchmarkRow]) {
    println!("| contract name | bugs found | coverage edges | exec/sec | crashes | time |");
    println!("|---|---:|---:|---:|---:|---:|");
    for row in rows {
        println!(
            "| {} | {} | {} | {:.2} | {} | {:.2}s |",
            row.contract, row.bugs_found, row.coverage_edges, row.execs_per_sec, row.crashes, row.seconds
        );
    }
}

fn write_reports(args: &Args, rows: &[BenchmarkRow]) -> anyhow::Result<()> {
    fs::create_dir_all(&args.output_dir)?;
    let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = BenchmarkReport {
        artifacts_dir: args.artifacts_dir.clone(),
        max_execs: args.max_execs,
        total_bugs_found: rows.iter().map(|row| row.bugs_found).sum(),
        total_crashes: rows.iter().map(|row| row.crashes).sum(),
        rows: rows.to_vec(),
    };

    let json_path = args.output_dir.join(format!("daedaluzz-{run_id}.json"));
    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)?;

    let markdown_path = args.output_dir.join(format!("daedaluzz-{run_id}.md"));
    let mut markdown = String::new();
    markdown.push_str("| contract name | bugs found | coverage edges | exec/sec | crashes | time |\n");
    markdown.push_str("|---|---:|---:|---:|---:|---:|\n");
    for row in rows {
        markdown.push_str(&format!(
            "| {} | {} | {} | {:.2} | {} | {:.2}s |\n",
            row.contract, row.bugs_found, row.coverage_edges, row.execs_per_sec, row.crashes, row.seconds
        ));
    }
    fs::write(&markdown_path, markdown)?;

    println!("Benchmark reports written: {}, {}", markdown_path.display(), json_path.display());
    Ok(())
}

fn benchmark_address(index: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xda;
    bytes[19] = index as u8;
    Address::from(bytes)
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}
