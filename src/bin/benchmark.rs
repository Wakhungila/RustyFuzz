use anyhow::Context;
use clap::Parser;
use revm::primitives::Address;
use rusty_fuzz::config::HardenedDefiConfig;
use rusty_fuzz::engine::fuzz_engine::{run_fuzz_campaign, Config as FuzzConfig};
use rusty_fuzz::engine::promotion::{PromotionCampaignSummary, PromotionConfig};
use rusty_fuzz::evm::corpus::CampaignArtifactRecord;
use rusty_fuzz::satori::fsutil::{
    redact_external_output, run_bounded_command_with_output_limit, sha256_hex,
    MAX_EXTERNAL_ARTIFACT_BYTES, MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use rustyfuzz_artifacts::fsutil::write_atomic;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_ARTIFACT_FILES: usize = 1_000;
const MAX_ARTIFACT_DEPTH: usize = 16;
const MAX_ARTIFACT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

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
    /// Internal shared identifier for isolated benchmark work directories.
    #[arg(long, hide = true)]
    work_run_id: Option<String>,
}

#[derive(Debug)]
struct ContractArtifact {
    name: String,
    runtime_bytecode: Vec<u8>,
    abi: Option<Value>,
    input_digest: String,
    fixture_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkReportDigests {
    input_digest: String,
    config_digest: String,
    manifest_digest: String,
    fixture_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkRow {
    contract: String,
    digests: BenchmarkReportDigests,
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
    config_digest: String,
    manifest_digest: String,
    max_execs: u64,
    total_bugs_found: usize,
    total_crashes: usize,
    rows: Vec<BenchmarkRow>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let run_id = benchmark_run_id(args.work_run_id.as_deref())?;
    let artifacts = load_artifacts(&args.artifacts_dir)?;
    if let Some(child_index) = args.child_index {
        anyhow::ensure!(
            child_index < artifacts.len(),
            "--child-index {child_index} out of range for {} artifacts",
            artifacts.len()
        );
        run_benchmark_contract(
            &args,
            &run_id,
            artifacts.len(),
            child_index,
            &artifacts[child_index],
        )
        .await?;
        return Ok(());
    }

    println!(
        "Loaded {} benchmark artifact(s) from {}",
        artifacts.len(),
        args.artifacts_dir.display()
    );
    std::io::stdout().flush()?;
    let config_digest = benchmark_config_digest(&args);
    let manifest_digest = benchmark_manifest_digest(&artifacts);
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
        let timed_out = run_contract_child(&args, &run_id, idx)?;
        let (_work_dir, corpus_dir, report_dir) = benchmark_paths(&run_id, artifact, idx)?;
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
            digests: BenchmarkReportDigests {
                input_digest: artifact.input_digest.clone(),
                config_digest: config_digest.clone(),
                manifest_digest: manifest_digest.clone(),
                fixture_digest: artifact.fixture_digest.clone(),
            },
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
    write_reports(
        &args,
        &run_id,
        &config_digest,
        &manifest_digest,
        rows.as_slice(),
    )?;
    if rows.iter().map(|row| row.bugs_found).sum::<usize>() == 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_benchmark_contract(
    args: &Args,
    run_id: &str,
    total: usize,
    idx: usize,
    artifact: &ContractArtifact,
) -> anyhow::Result<()> {
    println!("[child {}/{}] running {}", idx + 1, total, artifact.name);
    std::io::stdout().flush()?;

    let target = benchmark_address(idx);
    let (work_dir, corpus_dir, report_dir) =
        create_benchmark_work_paths(run_id, &artifact.name, idx)?;
    let abi_path = if let Some(abi) = &artifact.abi {
        let path = work_dir.join("abi.json");
        fs::write(&path, serde_json::to_vec_pretty(abi)?)?;
        Some(path)
    } else {
        None
    };

    let hardened_defi = HardenedDefiConfig {
        enabled: false,
        single_process: true,
        ..Default::default()
    };

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
        campaign_id: Some(benchmark_campaign_id(run_id, idx)),
        paths_are_isolated: true,
        min_finding_confidence: 0,

        promotion: PromotionConfig::default(),
    })
    .await?;
    let canonical = rustyfuzz_artifacts::RunLayout::new(
        std::path::Path::new(".rustyfuzz"),
        &benchmark_campaign_id(run_id, idx),
    );
    copy_directory_contents(&canonical.inputs_dir(), &corpus_dir)?;
    copy_directory_contents(&canonical.reports_dir(), &report_dir)?;
    Ok(())
}

fn copy_directory_contents(source: &Path, destination: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink() && metadata.is_file(),
            "benchmark canonical output contains an unsupported entry"
        );
        fs::copy(entry.path(), destination.join(entry.file_name()))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildCompletion {
    timed_out: bool,
}

fn child_completion_outcome(success: bool, timed_out: bool) -> anyhow::Result<ChildCompletion> {
    anyhow::ensure!(
        success,
        "benchmark child exited unsuccessfully (status success={success}, timed_out={timed_out})"
    );
    Ok(ChildCompletion { timed_out })
}

fn run_contract_child(args: &Args, run_id: &str, idx: usize) -> anyhow::Result<bool> {
    let mut child = Command::new(std::env::current_exe()?)
        .current_dir(verified_benchmark_root()?)
        .arg(&args.artifacts_dir)
        .arg("--max-execs")
        .arg(args.max_execs.to_string())
        .arg("--output-dir")
        .arg(&args.output_dir)
        .arg("--timeout-secs")
        .arg(args.timeout_secs.to_string())
        .arg("--child-index")
        .arg(idx.to_string())
        .arg("--work-run-id")
        .arg(run_id)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| anyhow::anyhow!("failed to spawn benchmark child {idx}: {err:#}"))?;

    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return child_completion_outcome(status.success(), false)
                .map(|completion| completion.timed_out)
                .with_context(|| format!("benchmark child {idx} exited unsuccessfully"));
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

fn benchmark_campaign_id(run_id: &str, idx: usize) -> String {
    format!("benchmark-{run_id}-{idx:06}")
}

fn benchmark_run_id(existing: Option<&str>) -> anyhow::Result<String> {
    if let Some(run_id) = existing {
        anyhow::ensure!(
            (16..=64).contains(&run_id.len())
                && run_id.chars().all(|ch| ch.is_ascii_alphanumeric()),
            "invalid benchmark work run id"
        );
        return Ok(run_id.to_string());
    }
    Ok(uuid::Uuid::new_v4().simple().to_string())
}

fn verified_benchmark_root() -> anyhow::Result<PathBuf> {
    let root = std::env::temp_dir().join("rustyfuzz-daedaluzz");
    fs::create_dir_all(&root)
        .with_context(|| format!("create benchmark work root {}", root.display()))?;
    let metadata = fs::symlink_metadata(&root)
        .with_context(|| format!("inspect benchmark work root {}", root.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "benchmark work root must be a non-symlink directory: {}",
        root.display()
    );
    let canonical = fs::canonicalize(&root)
        .with_context(|| format!("canonicalize benchmark work root {}", root.display()))?;
    anyhow::ensure!(
        canonical.starts_with(
            std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|_| std::env::temp_dir())
        ),
        "benchmark work root escapes the system temporary directory"
    );
    Ok(canonical)
}

fn benchmark_paths(
    run_id: &str,
    artifact: &ContractArtifact,
    idx: usize,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let run_id = benchmark_run_id(Some(run_id))?;
    let root = verified_benchmark_root()?;
    let run_dir = root.join(run_id);
    let run_metadata = fs::symlink_metadata(&run_dir)
        .with_context(|| format!("inspect benchmark run directory {}", run_dir.display()))?;
    anyhow::ensure!(
        run_metadata.is_dir() && !run_metadata.file_type().is_symlink(),
        "benchmark run directory must be a non-symlink directory: {}",
        run_dir.display()
    );
    let work_dir = run_dir.join(format!("{idx:06}-{}", sanitize_name(&artifact.name)));
    let metadata = fs::symlink_metadata(&work_dir)
        .with_context(|| format!("inspect benchmark work directory {}", work_dir.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "benchmark work directory must be a non-symlink directory: {}",
        work_dir.display()
    );
    let corpus_dir = work_dir.join("corpus");
    let report_dir = work_dir.join("reports");
    for path in [&corpus_dir, &report_dir] {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect benchmark output directory {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "benchmark output directory must be a non-symlink directory: {}",
            path.display()
        );
    }
    Ok((work_dir, corpus_dir, report_dir))
}

fn create_benchmark_work_paths(
    run_id: &str,
    artifact_name: &str,
    idx: usize,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let run_id = benchmark_run_id(Some(run_id))?;
    let root = verified_benchmark_root()?;
    let run_dir = root.join(run_id);
    fs::create_dir(&run_dir).with_context(|| {
        format!(
            "benchmark run directory already exists or cannot be created: {}",
            run_dir.display()
        )
    })?;
    let run_dir = fs::canonicalize(&run_dir)
        .with_context(|| format!("canonicalize benchmark run directory {}", run_dir.display()))?;
    anyhow::ensure!(
        run_dir.starts_with(&root),
        "benchmark run directory escaped the benchmark work root"
    );
    let safe_name = sanitize_name(artifact_name);
    let safe_name = if safe_name.is_empty() {
        "contract"
    } else {
        &safe_name
    };
    let work_dir = run_dir.join(format!("{idx:06}-{safe_name}"));
    fs::create_dir(&work_dir).with_context(|| {
        format!(
            "benchmark work directory already exists or cannot be created: {}",
            work_dir.display()
        )
    })?;
    let work_dir = fs::canonicalize(&work_dir).with_context(|| {
        format!(
            "canonicalize benchmark work directory {}",
            work_dir.display()
        )
    })?;
    let corpus_dir = work_dir.join("corpus");
    let report_dir = work_dir.join("reports");
    fs::create_dir(&corpus_dir)?;
    fs::create_dir(&report_dir)?;
    for path in [&work_dir, &corpus_dir, &report_dir] {
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "benchmark work path is not a verified directory: {}",
            path.display()
        );
    }
    Ok((work_dir, corpus_dir, report_dir))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn benchmark_config_digest(args: &Args) -> String {
    let payload = serde_json::json!({
        "artifacts_dir": fs::canonicalize(&args.artifacts_dir)
            .unwrap_or_else(|_| args.artifacts_dir.clone()),
        "max_execs": args.max_execs,
        "output_dir": args.output_dir,
        "timeout_secs": args.timeout_secs,
    });
    sha256_digest(&serde_json::to_vec(&payload).unwrap_or_default())
}

fn benchmark_manifest_digest(artifacts: &[ContractArtifact]) -> String {
    let mut payload = Vec::new();
    for artifact in artifacts {
        payload.extend_from_slice(artifact.name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(artifact.input_digest.as_bytes());
        payload.push(0);
    }
    sha256_digest(&payload)
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
    collect_artifact_paths_with_limits(
        dir,
        MAX_ARTIFACT_FILES,
        MAX_ARTIFACT_FILE_BYTES,
        MAX_ARTIFACT_TOTAL_BYTES,
        MAX_ARTIFACT_DEPTH,
    )
}

fn collect_artifact_paths_with_limits(
    dir: &Path,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_depth: usize,
) -> anyhow::Result<Vec<PathBuf>> {
    anyhow::ensure!(
        max_files > 0,
        "benchmark artifact file count limit must be positive"
    );
    anyhow::ensure!(
        max_file_bytes > 0,
        "benchmark artifact file size limit must be positive"
    );
    anyhow::ensure!(
        max_total_bytes > 0,
        "benchmark artifact total byte limit must be positive"
    );
    let input_metadata = fs::symlink_metadata(dir)
        .with_context(|| format!("inspect benchmark artifact directory {}", dir.display()))?;
    anyhow::ensure!(
        input_metadata.is_dir() && !input_metadata.file_type().is_symlink(),
        "benchmark artifact directory must be a non-symlink directory: {}",
        dir.display()
    );
    let root = dir.canonicalize().with_context(|| {
        format!(
            "canonicalize benchmark artifact directory {}",
            dir.display()
        )
    })?;
    let root_metadata = fs::symlink_metadata(&root)?;
    anyhow::ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "benchmark artifact directory must be a non-symlink directory: {}",
        root.display()
    );
    let mut stack = vec![(root.clone(), 0usize)];
    let mut paths = Vec::new();
    let mut total_bytes = 0u64;
    while let Some((dir, depth)) = stack.pop() {
        for entry in fs::read_dir(&dir)
            .with_context(|| format!("read benchmark artifact directory {}", dir.display()))?
        {
            let path = entry
                .with_context(|| format!("read benchmark artifact entry in {}", dir.display()))?
                .path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect benchmark artifact {}", path.display()))?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "benchmark artifacts must not contain symlinks: {}",
                path.display()
            );
            if metadata.is_dir() {
                anyhow::ensure!(
                    depth < max_depth,
                    "benchmark artifact directory exceeds maximum depth of {max_depth}: {}",
                    path.display()
                );
                let canonical = fs::canonicalize(&path)?;
                anyhow::ensure!(
                    canonical.starts_with(&root),
                    "benchmark artifact directory escapes input root: {}",
                    path.display()
                );
                stack.push((canonical, depth.saturating_add(1)));
            } else if metadata.is_file() {
                anyhow::ensure!(
                    paths.len() < max_files,
                    "benchmark artifact file count exceeds limit of {max_files}"
                );
                anyhow::ensure!(
                    metadata.len() <= max_file_bytes,
                    "benchmark artifact file size exceeds limit of {max_file_bytes} bytes: {}",
                    path.display()
                );
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("benchmark artifact total byte count overflow")?;
                anyhow::ensure!(
                    total_bytes <= max_total_bytes,
                    "benchmark artifact total byte count exceeds limit of {max_total_bytes} bytes"
                );
                let canonical = fs::canonicalize(&path)?;
                anyhow::ensure!(
                    canonical.starts_with(&root),
                    "benchmark artifact file escapes input root: {}",
                    path.display()
                );
                paths.push(canonical);
            } else {
                anyhow::bail!(
                    "benchmark artifact is not a regular file or directory: {}",
                    path.display()
                );
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_bounded_artifact(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect benchmark artifact {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "benchmark artifact must be a regular non-symlink file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_ARTIFACT_FILE_BYTES,
        "benchmark artifact {} is {} bytes and exceeds limit of {} bytes",
        path.display(),
        metadata.len(),
        MAX_ARTIFACT_FILE_BYTES
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("open benchmark artifact {}", path.display()))?
        .take(MAX_ARTIFACT_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read benchmark artifact {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_ARTIFACT_FILE_BYTES,
        "benchmark artifact {} exceeds limit of {} bytes",
        path.display(),
        MAX_ARTIFACT_FILE_BYTES
    );
    Ok(bytes)
}

fn load_json_artifact(path: &Path) -> anyhow::Result<Option<ContractArtifact>> {
    let raw = read_bounded_artifact(path)?;
    let value: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parse benchmark artifact {}", path.display()))?;
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
    let digest = sha256_digest(&raw);
    Ok(Some(ContractArtifact {
        name,
        runtime_bytecode,
        abi: value.get("abi").cloned(),
        input_digest: digest.clone(),
        fixture_digest: digest,
    }))
}

fn compile_solidity_artifacts(path: &Path) -> anyhow::Result<Vec<ContractArtifact>> {
    let source = read_bounded_artifact(path)?;
    let fixture_digest = sha256_digest(&source);
    let mut command = Command::new("solc");
    command
        .arg("--optimize")
        .arg("--combined-json")
        .arg("abi,bin-runtime")
        .arg(path);
    let output = run_bounded_command_with_output_limit(
        &mut command,
        MAX_EXTERNAL_COMMAND_TIMEOUT,
        MAX_EXTERNAL_ARTIFACT_BYTES,
    )
    .map_err(|err| anyhow::anyhow!("failed to run solc for {}: {err:#}", path.display()))?;
    anyhow::ensure!(
        !output.timed_out,
        "solc timed out after {}s for {}",
        MAX_EXTERNAL_COMMAND_TIMEOUT.as_secs(),
        path.display()
    );
    anyhow::ensure!(
        !output.stdout_truncated,
        "solc stdout exceeded the {MAX_EXTERNAL_ARTIFACT_BYTES} byte limit for {}",
        path.display()
    );
    anyhow::ensure!(
        output.status.success(),
        "solc failed for {}: {}",
        path.display(),
        redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES)
    );
    let value: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse solc output for {}", path.display()))?;
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
                    input_digest: fixture_digest.clone(),
                    fixture_digest: fixture_digest.clone(),
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

fn collect_campaign_metrics(
    corpus_dir: &Path,
    report_dir: &Path,
) -> anyhow::Result<CampaignMetrics> {
    let mut metrics = CampaignMetrics::default();
    let summary_path = report_dir.join("campaign_summary.json");
    if summary_path.exists() {
        let summary: PromotionCampaignSummary = serde_json::from_slice(&fs::read(&summary_path)?)?;
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
    println!(
        "| contract name | bugs found | confirmed | PoCs | coverage edges | executions | exec/sec | crashes | timed out | first signal <= | replay FP rate | time |"
    );
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

fn write_reports(
    args: &Args,
    run_id: &str,
    config_digest: &str,
    manifest_digest: &str,
    rows: &[BenchmarkRow],
) -> anyhow::Result<()> {
    fs::create_dir_all(&args.output_dir)?;
    let report = BenchmarkReport {
        artifacts_dir: args.artifacts_dir.clone(),
        config_digest: config_digest.to_string(),
        manifest_digest: manifest_digest.to_string(),
        max_execs: args.max_execs,
        total_bugs_found: rows.iter().map(|row| row.bugs_found).sum(),
        total_crashes: rows.iter().map(|row| row.crashes).sum(),
        rows: rows.to_vec(),
    };

    let json_path = args.output_dir.join(format!("daedaluzz-{run_id}.json"));
    write_atomic(&json_path, serde_json::to_vec_pretty(&report)?)?;

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
    markdown.push_str("\n## Provenance digests\n\n");
    markdown.push_str("| contract | input | config | manifest | fixture |\n");
    markdown.push_str("|---|---|---|---|---|\n");
    for row in rows {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row.contract,
            row.digests.input_digest,
            row.digests.config_digest,
            row.digests.manifest_digest,
            row.digests.fixture_digest
        ));
    }
    write_atomic(&markdown_path, markdown.as_bytes())?;

    println!(
        "Benchmark reports written: {}, {}",
        markdown_path.display(),
        json_path.display()
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rusty_fuzz_bin_benchmark_{label}_{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn artifact_ingestion_is_bounded_by_count_size_and_total_bytes() {
        let base = unique_test_dir("limits");
        fs::create_dir_all(base.join("nested")).expect("create artifact tree");
        fs::write(base.join("one.json"), b"1234").expect("write first artifact");
        fs::write(base.join("nested/two.json"), b"5678").expect("write second artifact");

        let paths = collect_artifact_paths_with_limits(&base, 2, 4, 8, 2)
            .expect("bounded ingestion accepts exact limits");
        assert_eq!(paths.len(), 2);

        let error = collect_artifact_paths_with_limits(&base, 1, 4, 8, 2)
            .expect_err("artifact count is bounded");
        assert!(error.to_string().contains("file count"));

        let error = collect_artifact_paths_with_limits(&base, 2, 3, 8, 2)
            .expect_err("artifact file size is bounded");
        assert!(error.to_string().contains("file size"));

        let error = collect_artifact_paths_with_limits(&base, 2, 4, 7, 2)
            .expect_err("artifact total size is bounded");
        assert!(error.to_string().contains("total byte"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn benchmark_child_campaign_ids_are_deterministic_and_distinct_per_artifact() {
        let run_id = "0123456789abcdef";
        assert_eq!(
            benchmark_campaign_id(run_id, 0),
            "benchmark-0123456789abcdef-000000"
        );
        assert_eq!(
            benchmark_campaign_id(run_id, 1),
            "benchmark-0123456789abcdef-000001"
        );
        assert_eq!(
            benchmark_campaign_id(run_id, 0),
            benchmark_campaign_id(run_id, 0)
        );
    }

    #[test]
    fn benchmark_child_non_success_is_an_explicit_failure_not_a_timeout() {
        let error = child_completion_outcome(false, false)
            .expect_err("a child exit failure must propagate to the parent");
        assert!(error.to_string().contains("exited unsuccessfully"));
        assert!(
            child_completion_outcome(true, true)
                .expect("a deadline kill remains a timeout")
                .timed_out
        );
        assert!(
            !child_completion_outcome(true, false)
                .expect("a successful child is not a timeout")
                .timed_out
        );
    }

    #[test]
    fn benchmark_work_directories_are_unique_verified_and_non_reused() {
        let first_run = format!("{}", uuid::Uuid::new_v4().simple());
        let second_run = format!("{}", uuid::Uuid::new_v4().simple());
        let first = create_benchmark_work_paths(&first_run, "Token/../Vault", 0)
            .expect("create first work directory");
        let second = create_benchmark_work_paths(&second_run, "Token/../Vault", 0)
            .expect("create second work directory");
        assert_ne!(first.0, second.0);
        assert!(first
            .0
            .canonicalize()
            .expect("canonical first work dir")
            .starts_with(
                std::env::temp_dir()
                    .join("rustyfuzz-daedaluzz")
                    .canonicalize()
                    .expect("canonical benchmark root")
            ));
        assert!(first.0.is_dir());
        assert!(first.1.is_dir());
        assert!(first.2.is_dir());

        let error = create_benchmark_work_paths(&first_run, "Token", 0)
            .expect_err("an existing run work directory is not reused");
        assert!(error.to_string().contains("already exists"));

        let _ = fs::remove_dir_all(first.0);
        let _ = fs::remove_dir_all(second.0);
        let _ = fs::remove_dir_all(
            std::env::temp_dir()
                .join("rustyfuzz-daedaluzz")
                .join(&first_run),
        );
        let _ = fs::remove_dir_all(
            std::env::temp_dir()
                .join("rustyfuzz-daedaluzz")
                .join(&second_run),
        );
    }
}
