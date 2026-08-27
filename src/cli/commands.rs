use clap::Parser;
use rusty_fuzz::satori::cli::SatoriCommand;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Fuzz {
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        contract: Option<String>,
        #[arg(long, default_value_t = false)]
        hardened_defi: bool,
        #[arg(long, num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
        single_process: bool,
        #[arg(long)]
        cores: Option<String>,
        #[arg(long, default_value_t = false)]
        deterministic: bool,
        #[arg(long)]
        rng_seed: Option<u64>,
        #[arg(long, default_value_t = false)]
        bounded_search: bool,
        #[arg(long)]
        seed_file: Option<String>,
        #[arg(long, default_value_t = false)]
        require_seed_bundle: bool,
        #[arg(long, default_value_t = false)]
        require_rpc_fork: bool,
        #[arg(long, default_value_t = false)]
        allow_synthetic_fallback: bool,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long)]
        max_execs: Option<u64>,
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Hard wall-clock timeout for the fuzz process. Defaults to an auto bound for bounded runs.
        #[arg(long)]
        wall_timeout_secs: Option<u64>,
        #[arg(long, default_value_t = false)]
        unbounded: bool,
        #[arg(long)]
        artifact_limit: Option<u64>,
        #[arg(long)]
        campaign_id: Option<String>,
        #[arg(long, default_value_t = false)]
        no_synthetic_fallback: bool,
        #[arg(long, default_value_t = 0)]
        min_finding_confidence: u64,
        #[arg(long, default_value_t = false)]
        promote_findings: bool,
        #[arg(long, default_value_t = false)]
        no_promote_findings: bool,
        #[arg(long, default_value_t = true)]
        require_replay_for_report: bool,
        #[arg(long, default_value_t = true)]
        require_poc_for_confirmed: bool,
        #[arg(long, default_value_t = false)]
        strict_proof: bool,
        #[arg(long, default_value_t = false)]
        no_synthetic_proof: bool,
        #[arg(long, default_value_t = false)]
        require_foundry_poc: bool,
        #[arg(long, default_value_t = false)]
        require_minimized: bool,
        #[arg(long, default_value_t = false)]
        reject_heuristics: bool,
        #[arg(long)]
        max_finding_noise: Option<u64>,
        #[arg(long)]
        poc_out: Option<String>,
        #[arg(long)]
        promotion_limit: Option<u64>,
    },
    AbiIngest {
        #[arg(long)]
        file: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        output: Option<String>,
    },
    BytecodeAnalyze {
        #[arg(long)]
        file: String,
        #[arg(long)]
        output: Option<String>,
    },
    Seed {
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long, default_value = "evm")]
        chain: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value_t = 32)]
        max_seeds: usize,
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long, default_value_t = 10_000)]
        search_depth: u64,
        #[arg(long, default_value_t = false)]
        include_address_hints: bool,
        #[arg(long, default_value_t = 0.0, alias = "rate-limit-rps")]
        seed_max_blocks_per_second: f64,
        #[arg(long, default_value_t = 3)]
        seed_rpc_retry_count: usize,
        #[arg(long, default_value_t = 250)]
        seed_rpc_backoff_ms: u64,
        #[arg(long, default_value_t = false)]
        resume: bool,
        #[arg(long)]
        seed_resume_cursor: Option<String>,
        #[arg(long)]
        seed_output_manifest: Option<String>,
        #[arg(long, default_value = "block-scan")]
        seed_mode: String,
    },
    SeedIngest {
        #[arg(long)]
        file: String,
        #[arg(long, default_value = "historical-json")]
        bundle_id: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        chain_id: Option<u64>,
        #[arg(long)]
        fork_block: Option<u64>,
    },
    Setup {
        #[arg(long, default_value = "default")]
        bundle_id: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        abi: Option<String>,
    },
    Invariants {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        abi_report: Option<String>,
        #[arg(long)]
        setup_report: Option<String>,
        #[arg(long)]
        bytecode_report: Option<String>,
        #[arg(long)]
        satori_job: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    Replay {
        #[arg(long, alias = "input_id")]
        input: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long, default_value_t = false)]
        live: bool,
    },
    Minimize {
        #[arg(long)]
        input_id: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long, default_value = "cli-minimize")]
        reason: String,
    },
    Report {
        #[arg(long)]
        input_id: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    Promote {
        #[arg(long)]
        input_id: String,
        #[arg(long)]
        fork_cache_id: Option<String>,
        #[arg(long)]
        campaign_id: Option<String>,
        #[arg(long, default_value_t = false)]
        strict_proof: bool,
        #[arg(long, default_value_t = false)]
        no_synthetic_proof: bool,
        #[arg(long, default_value_t = false)]
        require_foundry_poc: bool,
        #[arg(long, default_value_t = false)]
        require_minimized: bool,
        #[arg(long, default_value_t = false)]
        reject_heuristics: bool,
        #[arg(long)]
        max_finding_noise: Option<u64>,
        #[arg(long)]
        poc_out: Option<String>,
    },
    ProveLive {
        #[arg(long, alias = "contract")]
        target: String,
        #[arg(long, default_value = "evm")]
        chain: String,
        #[arg(long)]
        block: Option<u64>,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long, alias = "etherscan-api-key")]
        abi_key: Option<String>,
        #[arg(long)]
        explorer_url: Option<String>,
        #[arg(long)]
        campaign_id: Option<String>,
        #[arg(long, default_value_t = 300)]
        duration_secs: u64,
        #[arg(long)]
        max_execs: Option<u64>,
        #[arg(long)]
        wall_timeout_secs: Option<u64>,
        #[arg(long, default_value_t = 32)]
        max_seeds: usize,
        #[arg(long, default_value_t = 10_000)]
        search_depth: u64,
        #[arg(long, default_value = "block-scan")]
        seed_mode: String,
        #[arg(long, default_value_t = false)]
        include_address_hints: bool,
        #[arg(long, default_value_t = 0.0, alias = "rate-limit-rps")]
        seed_max_blocks_per_second: f64,
        #[arg(long, default_value_t = false)]
        skip_seed_discovery: bool,
        #[arg(long, default_value_t = 8)]
        artifact_limit: u64,
        #[arg(long, default_value_t = 4)]
        promotion_limit: u64,
        #[arg(long, default_value_t = 0)]
        min_finding_confidence: u64,
        #[arg(long, default_value_t = true)]
        strict_proof: bool,
        #[arg(long, default_value_t = true)]
        no_synthetic_proof: bool,
        #[arg(long, default_value_t = true)]
        require_foundry_poc: bool,
        #[arg(long, default_value_t = true)]
        require_minimized: bool,
        #[arg(long, default_value_t = true)]
        reject_heuristics: bool,
        #[arg(long)]
        max_finding_noise: Option<u64>,
        #[arg(long)]
        poc_out: Option<String>,
        #[arg(long, default_value_t = false)]
        deterministic: bool,
        #[arg(long)]
        rng_seed: Option<u64>,
    },
    Validate {
        #[arg(long)]
        benchmarks: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = true)]
        broker_free: bool,
    },
    Satori {
        #[command(subcommand)]
        command: SatoriCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum JobCommand {
    Run {
        file: String,
        #[arg(long)]
        abi: Option<String>,
        #[arg(long)]
        seed_bundle: Option<String>,
        #[arg(long, default_value_t = false)]
        require_seed_bundle: bool,
    },
}
