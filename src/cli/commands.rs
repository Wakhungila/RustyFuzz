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
    /// Zero-config campaign: an address, a chain and a block, nothing else.
    ///
    /// Deliberately a thin alias over `fuzz` rather than a second code path. Its job is
    /// to remove the three things that stopped a fresh user: writing a harness, editing
    /// `config.toml`, and knowing which flags the real entry point needs. Everything it
    /// does is the same work `fuzz` does, with sensible defaults filled in.
    Target {
        /// Address to fuzz.
        address: String,
        /// RPC endpoint to fork from. Required: there is no default worth guessing.
        #[arg(long)]
        rpc_url: String,
        /// Block to pin the fork at. Defaults to the endpoint's latest block.
        #[arg(long)]
        fork_block: Option<u64>,
        /// Wall-clock budget in seconds.
        #[arg(long, default_value_t = 300)]
        duration_secs: u64,
        /// Execution budget, if a caller prefers a count to a duration.
        #[arg(long)]
        max_execs: Option<u64>,
        /// Deterministic RNG seed, for a reproducible first run.
        #[arg(long, default_value_t = 1)]
        rng_seed: u64,
        /// JSON file of invariants to check after every transaction.
        #[arg(long)]
        invariants: Option<String>,
    },
    Fuzz {
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        contract: Option<String>,
        /// RPC endpoint to fork from, overriding `config.toml`.
        ///
        /// Exists because pointing at any chain other than the one in the shared config
        /// previously required editing `config.toml`, which is a usability cliff: the
        /// file is not meant to be rewritten per test run, and it is shared.
        #[arg(long)]
        rpc_url: Option<String>,
        /// Block number to pin the fork at, overriding `config.toml`.
        ///
        /// Must be paired with `--rpc-url` in practice; an unreachable pin makes every
        /// benchmark skip, which is what happened when the shared config's block was not
        /// available on the endpoint.
        #[arg(long)]
        fork_block: Option<u64>,
        /// JSON file of invariants to check after every transaction.
        ///
        /// Kept as a flag rather than a `config.toml` table so a campaign's invariants
        /// travel with the invocation, not with a file shared between runs -- the same
        /// reasoning as `--rpc-url`. See `src/engine/invariant_file.rs` for the format.
        ///
        /// Validation happens before the campaign starts: every invalid invariant is
        /// reported at once, and a file declaring none is refused rather than silently
        /// checking nothing. Its declared target must match `--contract` or the
        /// configured `target_contract`; an invariant file without an effective target
        /// is rejected.
        #[arg(long)]
        invariants: Option<String>,
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
    /// Capture a real fork snapshot for offline historical replay.
    ///
    /// The offline replay path accepts only a `ForkDbCacheSnapshot` with a matching digest
    /// and pinned provenance, and nothing else in the tool could produce one. This is that
    /// producer.
    ///
    /// Only the slots you name are captured. Every other slot is ABSENT from the snapshot,
    /// so a replay that reads one reports Unknown rather than a fabricated zero — which is
    /// the only honest option, since a mapping cannot be enumerated over JSON-RPC.
    Capture {
        /// RPC endpoint to capture from. Must be an archive node for a historical block.
        #[arg(long)]
        rpc_url: String,
        /// State block to capture. For historical replay, use the pre-transaction
        /// block (normally the exploit transaction's block number minus one).
        #[arg(long)]
        block: u64,
        /// Historical fixture whose target and transaction parties are captured.
        #[arg(long)]
        fixture: String,
        /// Invariants file whose plain storage bindings are also captured.
        ///
        /// Mappings and return values are skipped: a mapping needs a key we do not have,
        /// and a return value is not storage.
        #[arg(long)]
        invariants: Option<String>,
        /// Extra slot to capture, as `0xaddress:0xslot`. Repeatable.
        #[arg(long = "slot", num_args = 1)]
        slots: Vec<String>,
        /// Address-mapping storage entry, as `0xcontract:0xbase-slot:0xkey-address`.
        ///
        /// Use only when the contract's storage layout establishes the base slot.
        /// Repeatable.
        #[arg(long = "mapping-slot", num_args = 1)]
        mapping_slots: Vec<String>,
        /// Where to write the snapshot.
        #[arg(long)]
        output: String,
        /// Where to write the capture report. Defaults to `<output>.report.json`.
        #[arg(long)]
        report: Option<String>,
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
        /// RPC endpoint for mainnet_fork cases, overriding `config.toml`.
        #[arg(long)]
        rpc_url: Option<String>,
        /// Fork block for every mainnet_fork case, overriding both `config.toml` and each
        /// manifest.
        ///
        /// Without an override each manifest uses its own `fork_block`, which is what a
        /// historical corpus needs: the cases pin different blocks, and one global value
        /// would silently validate the wrong state for all but one of them.
        #[arg(long)]
        fork_block: Option<u64>,
    },
    Satori {
        #[command(subcommand)]
        command: SatoriCommand,
    },
    #[command(name = "ops")]
    Ops {
        #[command(subcommand)]
        command: OpsCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum OpsCommand {
    Status {
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Campaigns {
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Metrics,
    Events {
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    Alerts {
        #[arg(long, default_value_t = false)]
        active: bool,
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        backup: Option<std::path::PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Backup {
        #[command(subcommand)]
        command: OpsBackupCommand,
    },
    Drill {
        #[command(subcommand)]
        command: OpsDrillCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum OpsBackupCommand {
    Create {
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    List,
    Verify {
        path: std::path::PathBuf,
    },
    Restore {
        path: std::path::PathBuf,
        #[arg(long)]
        target: std::path::PathBuf,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum OpsDrillCommand {
    Restore {
        path: std::path::PathBuf,
        #[arg(long)]
        target: std::path::PathBuf,
        #[arg(long, default_value_t = false)]
        keep_payload: bool,
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
