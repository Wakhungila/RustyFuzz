use clap::Parser;
use revm::primitives::Address;
use rusty_fuzz::config::HardenedDefiConfig;
use rusty_fuzz::engine::fuzz_engine::{run_fuzz_campaign, Config as FuzzConfig};
use rusty_fuzz::engine::promotion::{PromotionCampaignSummary, PromotionConfig};
use rusty_fuzz::evm::corpus::CampaignArtifactRecord;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
struct Args {
    /// Directory containing Daedaluzz-style JSON artifacts or Solidity sources.
    artifacts_dir: PathBuf,
    /// Maximum executions per contract.
    #[arg(long, default_value_t = 50_000)]
    max_execs: u64,
    /// Directory where benchmark markdown and JSON reports are written.
    #[arg(long, default_value = "reports/benchmarks")]
    output_dir: PathBuf,
    /// Per-contract wall-clock timeout in seconds.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,
    /// Internal mode: execute only one artifact index as a child process.
    #[arg(long, hide = true)]
    child_index: Option<usize>,
}

#[derive(Debug)]
struct ContractArtifact {
    name: String,
    runtime_bytecode: Vec<u8>,
    abi: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkRow {
    contract: String,
    bugs_found: usize,
    coverage_edges: usize,
    executions: u64,
    seconds: f64,
    execs_per_sec: f64,
    crashes: usize,
    oracle_classes: BTreeMap<String, usize>,
    artifact_ids: Vec<String>,
    timed_out: bool,
    executions_to_first_signal_upper_bound: Option<u64>,
    seconds_to_first_signal_upper_bound: Option<f64>,
    replay_failures: u64,
    confirmed_findings: u64,
    poc_count: u64,
    false_positive_rate_after_replay: f64,
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
    if let Some(child_index) = args.child_index {
        anyhow::ensure!(
            child_index < artifacts.len(),
            "--child-index {child_index} out of range for {} artifacts",
            artifacts.len()
        );
        run_benchmark_contract(&args, artifacts.len(), child_index, &artifacts[child_index])
            .await?;
        return Ok(());
    }

    println!(
        "Loaded {} benchmark artifact(s) from {}",
        artifacts.len(),
        args.artifacts_dir.display()
    );
    std::io::stdout().flush()?;
    let mut rows = Vec::new();

    for (idx, artifact) in artifacts.iter().enumerate() {
        let started = Instant::now();
        println!(
            "[{}/{}] starting {} (max_execs={}, timeout={}s)",
            idx + 1,
            artifacts.len(),
            artifact.name,
            args.max_execs,
            args.timeout_secs
        );
        std::io::stdout().flush()?;
        let timed_out = run_contract_child(&args, idx)?;
        let (_work_dir, corpus_dir, report_dir) = benchmark_paths(artifact, idx);
        let metrics = collect_campaign_metrics(&corpus_dir, &report_dir)?;
        let seconds = started.elapsed().as_secs_f64();
        let executions_to_first_signal = (metrics.bugs_found > 0).then_some(metrics.executions);
        let seconds_to_first_signal = (metrics.bugs_found > 0).then_some(seconds);
        let false_positive_rate_after_replay = if metrics.promoted_findings == 0 {
            0.0
        } else {
            metrics.replay_failures as f64 / metrics.promoted_findings as f64
        };
        println!(
            "[{}/{}] finished {}: bugs={}, confirmed={}, pocs={}, coverage_edges={}, executions={}, exec/sec={:.2}, timeout={}, elapsed={:.2}s",
            idx + 1,
            artifacts.len(),
            artifact.name,
            metrics.bugs_found,
            metrics.confirmed_findings,
            metrics.poc_count,
            metrics.coverage_edges,
            metrics.executions,
            metrics.executions as f64 / seconds.max(0.001),
            timed_out,
            seconds
        );
        std::io::stdout().flush()?;
        rows.push(BenchmarkRow {
            contract: artifact.name.clone(),
            bugs_found: metrics.bugs_found,
            coverage_edges: metrics.coverage_edges,
            executions: metrics.executions,
            seconds,
            execs_per_sec: metrics.executions as f64 / seconds.max(0.001),
            crashes: metrics.crashes,
            oracle_classes: metrics.oracle_classes,
            artifact_ids: metrics.artifact_ids,
            timed_out,
            executions_to_first_signal_upper_bound: executions_to_first_signal,
            seconds_to_first_signal_upper_bound: seconds_to_first_signal,
            replay_failures: metrics.replay_failures,
            confirmed_findings: metrics.confirmed_findings,
            poc_count: metrics.poc_count,
            false_positive_rate_after_replay,
        });
    }

    print_markdown_table(&rows);
    write_reports(&args, rows.as_slice())?;
    if rows.iter().map(|row| row.bugs_found).sum::<usize>() == 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_benchmark_contract(
    args: &Args,
    total: usize,
    idx: usize,
    artifact: &ContractArtifact,
) -> anyhow::Result<()> {
    println!(
        "[child {}/{}] running {}",
        idx + 1,
        total,
        artifact.name
    );
    std::io::stdout().flush()?;

    let target = benchmark_address(idx);
    let (work_dir, corpus_dir, report_dir) = benchmark_paths(artifact, idx);
    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&report_dir)?;
    let abi_path = if let Some(abi) = &artifact.abi {
        let path = work_dir.join("abi.json");
        fs::write(&path, serde_json::to_vec_pretty(abi)?)?;
        Some(path)
    } else {
        None
    };

    let mut hardened_defi = HardenedDefiConfig::default();
    hardened_defi.enabled = false;
    hardened_defi.single_process = true;

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
        abi_path: abi_path.as_ref().map(|path| path.display().to_string()),
        max_execs: Some(args.max_execs),
        duration_secs: None,
        artifact_limit: Some(100),
        campaign_id: Some(format!("daedaluzz-{}", sanitize_name(&artifact.name))),
        min_finding_confidence: 0,
        promotion: PromotionConfig::default(),
    })
    .await
}

fn run_contract_child(args: &Args, idx: usize) -> anyhow::Result<bool> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg(&args.artifacts_dir)
        .arg("--max-execs")
        .arg(args.max_execs.to_string())
        .arg("--output-dir")
        .arg(&args.output_dir)
        .arg("--timeout-secs")
        .arg(args.timeout_secs.to_string())
        .arg("--child-index")
        .arg(idx.to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| anyhow::anyhow!("failed to spawn benchmark child {idx}: {err:#}"))?;

    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(!status.success());
        }
        if Instant::now() >= deadline {
            eprintln!(
                "[{}/?] benchmark child timed out after {}s; killing pid {}",
                idx + 1,
                args.timeout_secs,
                child.id()
            );
            let _ = child.kill();
            let _ = child.wait();
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn benchmark_paths(artifact: &ContractArtifact, idx: usize) -> (PathBuf, PathBuf, PathBuf) {
    let work_dir = std::env::temp_dir()
        .join("rustyfuzz-daedaluzz")
        .join(format!("{}-{idx}", sanitize_name(&artifact.name)));
    let corpus_dir = work_dir.join("corpus");
    let report_dir = work_dir.join("reports");
    (work_dir, corpus_dir, report_dir)
}

fn load_artifacts(dir: &Path) -> anyhow::Result<Vec<ContractArtifact>> {
    let mut artifacts = Vec::new();
    for path in artifact_paths(dir)? {
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            if let Some(artifact) = load_json_artifact(&path)? {
                artifacts.push(artifact);
            }
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("sol")
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".foundry.sol"))
        {
            artifacts.extend(compile_solidity_artifacts(&path)?);
        }
    }
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(artifacts)
}

fn artifact_paths(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            for nested in fs::read_dir(&path)? {
                let nested = nested?.path();
                if nested.is_file() {
                    paths.push(nested);
                }
            }
        } else if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn load_json_artifact(path: &Path) -> anyhow::Result<Option<ContractArtifact>> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    let Some(runtime_bytecode) = artifact_runtime_bytecode(&value) else {
        return Ok(None);
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
    Ok(Some(ContractArtifact {
        name,
        runtime_bytecode,
        abi: value.get("abi").cloned(),
    }))
}

fn compile_solidity_artifacts(path: &Path) -> anyhow::Result<Vec<ContractArtifact>> {
    let output = Command::new("solc")
        .arg("--optimize")
        .arg("--combined-json")
        .arg("abi,bin-runtime")
        .arg(path)
        .output()
        .map_err(|err| anyhow::anyhow!("failed to start solc for {}: {err:#}", path.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "solc failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let mut artifacts = Vec::new();
    if let Some(contracts) = value.get("contracts").and_then(Value::as_object) {
        for (name, contract) in contracts {
            if let Some(runtime_bytecode) = artifact_runtime_bytecode(contract) {
                let contract_name = name
                    .rsplit(':')
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| {
                        path.file_stem()
                            .and_then(|stem| stem.to_str())
                            .unwrap_or("contract")
                    })
                    .to_string();
                artifacts.push(ContractArtifact {
                    name: format!(
                        "{}::{}",
                        path.file_stem()
                            .and_then(|stem| stem.to_str())
                            .unwrap_or("source"),
                        contract_name
                    ),
                    runtime_bytecode,
                    abi: contract.get("abi").cloned(),
                });
            }
        }
    }
    Ok(artifacts)
}

fn artifact_runtime_bytecode(value: &Value) -> Option<Vec<u8>> {
    let candidates = [
        &value["deployedBytecode"]["object"],
        &value["deployedBytecode"],
        &value["bin-runtime"],
        &value["bytecode"]["object"],
        &value["bytecode"],
        &value["bin"],
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
    executions: u64,
    crashes: usize,
    oracle_classes: BTreeMap<String, usize>,
    artifact_ids: Vec<String>,
    promoted_findings: u64,
    confirmed_findings: u64,
    replay_failures: u64,
    poc_count: u64,
}

fn collect_campaign_metrics(corpus_dir: &Path, report_dir: &Path) -> anyhow::Result<CampaignMetrics> {
    let mut metrics = CampaignMetrics::default();
    let summary_path = report_dir.join("campaign_summary.json");
    if summary_path.exists() {
        let summary: PromotionCampaignSummary =
            serde_json::from_slice(&fs::read(&summary_path)?)?;
        metrics.executions = summary.total_executions;
        metrics.coverage_edges = summary.coverage_edges as usize;
        metrics.promoted_findings = summary.promoted_findings;
        metrics.confirmed_findings = summary.confirmed_findings;
        metrics.replay_failures = summary.replay_failure_count;
        metrics.poc_count = summary.poc_count;
    }
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
    println!("| contract name | bugs found | confirmed | PoCs | coverage edges | executions | exec/sec | crashes | timed out | first signal <= | replay FP rate | time |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for row in rows {
        let first_signal = row
            .seconds_to_first_signal_upper_bound
            .map(|secs| format!("{secs:.2}s"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "| {} | {} | {} | {} | {} | {} | {:.2} | {} | {} | {} | {:.2} | {:.2}s |",
            row.contract,
            row.bugs_found,
            row.confirmed_findings,
            row.poc_count,
            row.coverage_edges,
            row.executions,
            row.execs_per_sec,
            row.crashes,
            row.timed_out,
            first_signal,
            row.false_positive_rate_after_replay,
            row.seconds
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
    markdown.push_str("| contract name | bugs found | confirmed | PoCs | coverage edges | executions | exec/sec | crashes | timed out | first signal <= | replay FP rate | time |\n");
    markdown.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in rows {
        let first_signal = row
            .seconds_to_first_signal_upper_bound
            .map(|secs| format!("{secs:.2}s"))
            .unwrap_or_else(|| "-".to_string());
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.2} | {} | {} | {} | {:.2} | {:.2}s |\n",
            row.contract,
            row.bugs_found,
            row.confirmed_findings,
            row.poc_count,
            row.coverage_edges,
            row.executions,
            row.execs_per_sec,
            row.crashes,
            row.timed_out,
            first_signal,
            row.false_positive_rate_after_replay,
            row.seconds
        ));
    }
    fs::write(&markdown_path, markdown)?;

    println!("Benchmark reports written: {}, {}", markdown_path.display(), json_path.display());
    std::io::stdout().flush()?;
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
