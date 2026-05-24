# RustyFuzz

RustyFuzz is a stateful EVM fuzzing foundation for protocol-security research. It is built around deterministic transaction-sequence execution, fork-aware state replay, real coverage feedback, protocol oracle evidence, and reproducible crash reporting.

The current priority is not breadth of speculative features. The core path is:

```text
EvmInput
  -> ABI/sequence mutator
  -> deterministic revm executor
  -> canonical SequenceExecutionResult
  -> coverage + state novelty + protocol oracles + concolic hints
  -> campaign scorer
  -> custom LibAFL scheduler
  -> persistent corpus / replay / minimization / Foundry PoC
```

## Current Capabilities

### EVM Execution

- Uses one coherent `revm` stack.
- Executes real EVM transactions against mutable `CacheDB` state.
- Supports multi-transaction sequences.
- Tracks gas, status, output, coverage, storage reads/writes, storage diffs, and nested call/create traces.
- Separates runtime state from serialized corpus metadata.

### Canonical Execution Artifact

Execution produces `SequenceExecutionResult`, which is the shared artifact between executor, feedback, corpus, minimizer, oracles, reporting, and PoC generation.

It contains:

- per-transaction execution results,
- total gas and coverage hash,
- storage read/write sets,
- storage diffs,
- nested call/create trace,
- oracle observations,
- waypoint evidence for concolic and dataflow use.

### Fork State and Replay

RustyFuzz has a fork database layer with lazy RPC-backed account, code, balance, nonce, storage, and block-hash loading. Loaded fork state can be cached and persisted so replay can use deterministic cached state rather than live RPC.

Persistent corpus support includes:

- replayable input JSON,
- deterministic input IDs,
- crash metadata,
- fork cache manifests,
- reproduction reports,
- replay verifier integration.

### Coverage and Feedback

The EVM feedback path is no longer fake-positive.

Current feedback signals include:

- AFL-style edge coverage with hitcount bucketing,
- stable path hashing,
- state novelty over storage transitions, slots, reads, call edges, and contracts,
- protocol-oracle findings,
- expression-backed branch frontier pressure,
- economic and invariant pressure.

### Campaign Scheduling

RustyFuzz uses a custom LibAFL scheduler instead of relying only on bitmap-side reward projection.

Corpus entries are prioritized by `CampaignScore`, including:

- economic pressure,
- invariant pressure,
- oracle severity,
- state novelty,
- exploration depth,
- branch-frontier pressure,
- scheduling decay after repeated selection.

The bitmap bridge still exists as a secondary signal, but campaign economics now live in the scheduler where they belong.

### ABI-Aware Mutation

The mutator supports:

- ABI-valid sequence insertion,
- ABI argument mutation through `alloy-dyn-abi`,
- target discovery mutation,
- caller mutation,
- semantic sequence chaining,
- value-boundary mutation,
- flashloan-style wrapping,
- MEV sandwich pressure,
- oracle-pressure calls,
- mutation provenance tracking.

Concolic hints are applied as ABI words when possible and can extend short calldata instead of dropping solvable sequence constraints.

### Concolic and Expression Solving

RustyFuzz now has deterministic taint-guided expression solving without requiring the core build to depend on Z3.

The engine tracks symbolic expressions through:

- calldata,
- memory,
- arithmetic,
- bitwise operations,
- storage writes,
- storage reads across transaction sequences,
- SHA3/mapping derivations.

Supported expression inversion currently covers practical single-source forms:

- `arg + c`,
- `arg - c`,
- `arg * c` when divisible,
- `arg / c`,
- `arg % c` when satisfiable,
- `arg ^ c`,
- direct calldata/storage comparisons,
- branch-path inversion.

This is not full symbolic execution. It is a bounded, deterministic concolic assist designed to feed the mutator with high-value calldata words.

### Foundry Harness and PoC Support

RustyFuzz can ingest Foundry invariant harness metadata and use it to populate selectors and campaign context.

Crash minimization can emit Foundry PoC scaffolds that:

- replay exact transaction sequences,
- select the requested fork block,
- embed calldata and callers,
- assert replay status,
- assert protocol evidence where available,
- assert storage diffs from oracle evidence,
- expose an `assertRustyFuzzInvariant` extension point.

### Protocol Oracle Packs

Protocol oracle packs currently cover evidence patterns for:

- ERC20 accounting and allowance behavior,
- ERC4626 inflation and rounding behavior,
- AMM reserve/asymmetry behavior,
- lending accounting desynchronization and liquidation paths,
- governance/timelock takeover patterns.

These are evidence-driven oracle packs, not replacements for protocol-specific human invariants. They are intended to focus campaigns and generate reproducible triage artifacts.

## Experimental or Limited Areas

These areas compile or have scaffolding, but should not be treated as equivalent to the EVM core:

- SVM support is separate and not part of the hardened EVM campaign path.
- SGX support is feature-gated and experimental.
- LLM guidance is intentionally inert unless a real integration is added.
- Z3 remains optional; the current core concolic path is deterministic and internal.
- Full symbolic execution, dynamic-array constraint solving, keccak preimage solving, and protocol-specific exploit synthesis remain future work.

## Build

Default EVM build:

```bash
cargo build
```

Run the full validation set:

```bash
cargo fmt
cargo check
cargo build
cargo test
cargo clippy -- -D warnings
```

Optional Z3 feature check:

```bash
cargo check --features z3
```

SVM is intentionally separate:

```bash
cargo build --features svm --no-default-features
```

## Configuration

The binary expects `config.toml` in the project root.

Minimal EVM configuration:

```toml
rpc_url = "http://localhost:8545"
fork_block = 19000000
chain = "evm"
target_contract = "0x0000000000000000000000000000000000000000"
timeout_secs = 3600
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
foundry_project = "."
mainnet_seed_bundle = "target-mainnet"
```

Run a fuzz campaign:

```bash
cargo run -- fuzz --chain evm --contract 0xTarget
```

Single-process mode avoids the LibAFL broker/TCP launcher and keeps the campaign inside one process:

```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --single-process \
  --bounded-search
```

`--bounded-search` enables the exhaustive bounded search layer over the configured transaction-depth and actor-role bounds. Within those bounds, RustyFuzz records whether a candidate is:

- `heuristic_only`
- `abstractly_proven`
- `concretely_replayed`

Seed a campaign from mainnet fork history:

```bash
cargo run -- seed --target 0xTarget --max-seeds 64 --bundle-id target-mainnet --search-depth 50000 --include-address-hints
```

Set `mainnet_seed_bundle` to the same bundle id before running `fuzz` to
load those historical calldata sequences into the initial campaign corpus.
Use `--start-block <block>` to scan backward from a known active range. The
`--include-address-hints` mode also accepts transactions whose calldata
contains the target address, which helps seed router/proxy-mediated protocols.

Replay a persisted input against cached fork state:

```bash
cargo run -- replay --input-id <input-id> --fork-cache-id <cache-id>
```

Compare cached replay against live RPC-backed fork reads:

```bash
cargo run -- replay --input-id <input-id> --fork-cache-id <cache-id> --live
```

Minimize a persisted crashing/finding input and emit a Foundry PoC:

```bash
cargo run -- minimize --input-id <input-id> --fork-cache-id <cache-id> --reason protocol-finding
```

Write a reproduction report for a persisted input:

```bash
cargo run -- report --input-id <input-id> --fork-cache-id <cache-id>
```

Scan mempool:

```bash
cargo run -- scan-mempool
```

## Repository Map

```text
src/common/types.rs              canonical input, execution, trace, symbolic, and oracle types
src/common/oracle/               legacy and protocol oracle logic
src/common/oracle/packs.rs       ERC20/ERC4626/AMM/lending/governance oracle packs
src/common/verifier.rs           deterministic replay verification
src/engine/fuzz_engine.rs        main LibAFL campaign orchestration
src/engine/scheduler.rs          campaign-aware LibAFL scheduler
src/engine/scoring.rs            economic/invariant/state/frontier campaign scoring
src/engine/concolic.rs           deterministic expression hint solver
src/engine/minimizer.rs          sequence minimization and crash artifact generation
src/engine/exploit_synthesizer.rs Foundry PoC generation
src/engine/foundry_ingest.rs     Foundry invariant harness ingestion
src/evm/executor.rs              deterministic revm execution
src/evm/inspector.rs             unified coverage/dataflow/trace/concolic instrumentation
src/evm/feedback.rs              coverage and state novelty feedback
src/evm/fork_db.rs               lazy RPC fork database and cache persistence
src/evm/corpus.rs                persistent corpus, crash metadata, replay artifacts
src/evm/fuzz.rs                  structured EVM input and mutation engine
src/evm/seed_ingester.rs         mainnet seed normalization and discovery
src/svm/                         separated SVM surface
tests/benchmarks.rs              regression and integration coverage
```

## What To Do Next

The next highest-impact engineering work is:

1. Promote CLI campaign commands into a polished operator workflow.
   - Add structured output, dry-run modes, explicit fork-cache IDs, and CI-friendly exit codes.

2. Deepen solver-backed sequence synthesis.
   - Move beyond cloning patched transactions and synthesize setup/action/assertion sequences from branch-frontier evidence.

3. Expand ABI-aware dynamic type placement.
   - Fully repair offset tables for dynamic arrays, bytes, strings, and nested tuples when applying concolic hints.

4. Generate stronger protocol-specific invariants.
   - Convert ERC4626, AMM, lending, and governance oracle evidence into replay assertions that verify semantic deltas, not only storage reproduction.

5. Use persisted frontier metadata in scheduling and minimization.
   - Corpus entries now store branch-distance, expression, mapping, and oracle-frontier summaries; the next step is to consume them for energy assignment and crash shrinking.

6. Harden cached-vs-live differential replay.
   - Add richer diff reports for gas, output, storage diffs, call traces, and fork-cache misses.

7. Keep SVM separate.
   - Stabilize it as its own execution target after the EVM campaign loop is complete.

## Engineering Position

RustyFuzz is now a coherent EVM fuzzing foundation with real execution, coverage, state novelty, fork caching, protocol evidence, concolic assists, custom scheduling, replay, minimization, and Foundry PoC generation.

It is not honest to claim a fixed success rate against hardened protocols. Finding high-impact bugs in mature systems still depends on target modeling, harness quality, seed quality, invariants, fork state, oracle precision, and researcher judgment.

The goal of this codebase is to make those inputs compound instead of fighting a broken runtime.

## License

MIT.

## Validation Mode

RustyFuzz can load benchmark manifests and emit an honest validation report for known vulnerability-class targets. Validation now executes local synthetic fixtures for supported benchmark modes and reports explicit statuses when a benchmark cannot run.

Run manifest validation:

```bash
cargo run --release -- validate --benchmarks benchmarks/ --output reports/validation_report.json
```

Live-fork validation benchmarks are supported as a separate opt-in path. They consume historical/trace seed JSON fixtures and replay them against the fork settings from `config.toml`:

```bash
cargo run --release -- validate --benchmarks benchmarks/live --output reports/live_validation_report.json
```

If the validation context does not include an RPC URL, fork block, or block environment, live-fork benchmarks are reported as `skipped_by_config` rather than being misclassified as failures. If RPC-backed replay fails, the benchmark is reported as `failed_execution` with the underlying replay/RPC cause. Live-fork benchmarks do not silently fall back to synthetic bytecode. To prove a fork benchmark offline, the fixture must explicitly include a serialized `fork_cache` captured from fork state.

Current live-fork manifests require replay proof and PoC output before they can be counted as `found`:

```toml
success_criteria = [
  "expected_finding",
  "invariant_violation",
  "replayable_artifact",
  "foundry_poc_generated",
]
```

PoC generation is gated behind proof confirmation. Heuristic-only evidence can be reported for triage, but it is not enough to mark a forked rediscovery benchmark as found.

A benchmark manifest may be TOML or JSON. Minimal TOML example:

```toml
id = "erc4626-share-inflation-basic"
class = "share_inflation"
mode = "local_fixture"
target = "0x1111111111111111111111111111111111111111"
fixture = "benchmarks/fixtures/erc4626-share-inflation-basic.json"
expected_invariant = "attacker_profit_or_share_price_manipulation"
expected_selectors = ["deposit", "withdraw", "redeem"]
success_criteria = ["expected_finding", "invariant_violation", "share_price_manipulation"]
max_duration_secs = 600
seed_hints = ["deposit", "redeem"]
```

Report fields include:

- `status`, `reason`, `executed`, `found`, `observed_finding`, and `confidence`
- `expected_invariant`, `exploit_path_length`, `minimized`, `replayable`, and `foundry_poc_generated`
- `executions_to_signal`, `time_to_signal_secs`, `artifact_path`
- `matched_criteria`, `missing_criteria`, and `false_positive_notes`

Validation statuses are explicit and stable:

- `found`
- `not_found`
- `not_run_missing_fixture`
- `not_run_missing_target`
- `not_run_missing_success_criteria`
- `not_run_unsupported_mode`
- `failed_execution`
- `skipped_by_config`

Proof-status reporting is carried through validation results and exploit candidates:

- `heuristic_only`
- `abstractly_proven`
- `concretely_replayed`

Example manifests live under `benchmarks/`, including ERC4626 share inflation, stale accounting, access-control bypass, AMM reserve manipulation, and stale oracle price cases. A sample report format lives at `docs/sample_validation_report.json`. These are synthetic validation fixtures/manifests, not claims that RustyFuzz has reproduced historical exploits.

Live-fork example manifests live under `benchmarks/live/` and demonstrate real fork-backed replay of historical seed JSON. They are intended for honest measurement against a configured RPC/fork block, not for claiming a bug was reproduced unless the report says `found`.

Cached-fork rediscovery manifests live under `benchmarks/forked/`. These are deterministic vulnerable benchmark deployments encoded as explicit cached fork fixtures, not historical exploit claims. They are useful for measuring the full confirmation pipeline:

```bash
cargo run --release -- validate --benchmarks benchmarks/forked --output reports/forked_validation_report.json
```

The cached-fork pack currently covers ERC4626 inflation, Uniswap-style reserve/oracle manipulation, lending bad-debt accounting, proxy initializer/upgrade takeover, permit/allowance replay, and stale/sudden oracle price movement. A benchmark only passes when it has a replay-confirmed proof, a minimized sequence, and a generated Foundry PoC artifact.

## Hardened DeFi Mode

Hardened DeFi Mode is an optional target-adaptive layer for mature DeFi targets. It does not claim reliable exploitation by itself; it adds machinery to profile a target, seed realistic flows, model actors, score economic state deltas, and measure progress through validation benchmarks.

Enable through config:

```toml
[hardened_defi]
enabled = true
historical_seed_file = "seeds/example_historical_seed.json"
max_template_sequences = 128
enable_actor_model = true
enable_economic_delta = true
enable_protocol_invariants = true
enable_exploit_templates = true
min_persist_confidence = 0.70
```

Or for a single fuzz run:

```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --hardened-defi \
  --seed-file seeds/example_historical_seed.json
```

Historical seed JSON can be persisted into the existing seed-bundle store:

```bash
cargo run --release -- seed-ingest \
  --file seeds/example_historical_seed.json \
  --bundle-id target-historical
```

Current Hardened DeFi components:

- Target profiling from ABI selectors, Foundry hints, and seed metadata.
- Role-specific actor generation for attacker, victim, whale, depositor, borrower, liquidator, trader, governance actors, keeper, privileged candidate, and random users.
- Historical transaction JSON ingestion into `SeedCandidate` and `EvmInput` seeds.
- Profile-gated dependency/exploit template startup seeds.
- Heuristic economic delta scoring from observed token-balance inputs or execution storage deltas.

Limitations: protocol-specific invariants are still heuristic packs, historical seeds require useful calldata, economic deltas are strongest when token/share balances are observable, and benchmark success should be treated as the source of truth for exploit-class capability.
