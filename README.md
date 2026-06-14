# RustyFuzz

A stateful EVM fuzzer for smart contract security research. RustyFuzz executes transaction sequences deterministically against forked EVM state, with coverage feedback, protocol oracle detection, and reproducible crash reporting.

## What Is RustyFuzz?

RustyFuzz is a fuzzing engine designed for finding state-machine bugs in smart contracts. Unlike property-based testing frameworks, RustyFuzz:

- **Executes transaction sequences deterministically** against a mutable EVM state, capturing coverage, storage deltas, and call traces.
- **Caches fork state** (accounts, code, storage, balances) from an RPC endpoint and replays inputs against cached state for reproducibility.
- **Feeds multiple feedback signals** into a custom LibAFL scheduler: AFL-style coverage, storage novelty, state reachability, protocol oracle findings, and economic pressure.
- **Minimizes crashes** to the shortest sequence that reproduces the issue.
- **Generates Foundry PoC scaffolds** with transaction sequences, fork block, callers, and assertions.
- **Supports protocol-specific oracles** for ERC20, ERC4626, AMM, lending, and governance patterns.
- **Applies concolic hints** to guide the mutator toward satisfying branch constraints without requiring a full symbolic solver.

**Scope**: Designed for multi-transaction invariant violations and economic attacks where state carries meaning across transactions. Not a general-purpose fuzzer.

## Core Architecture

```
EvmInput (sequence of transactions)
  ↓
[ABI-aware mutation + concolic hints]
  ↓
[Deterministic revm executor against CacheDB state]
  ↓
SequenceExecutionResult (canonical artifact)
  ├─ per-tx gas, status, output
  ├─ cumulative coverage hash
  ├─ storage reads/writes/diffs
  ├─ call/create trace
  ├─ oracle findings
  └─ branch/value frontier evidence
  ↓
[Coverage + State novelty + Oracle pressure + Concolic hints]
  ↓
[Campaign scoring and LibAFL scheduler]
  ↓
[Persistent corpus + replay + minimization + PoC generation]
```

## Key Features

### Deterministic Execution

- Executes transaction sequences against `revm` with a `CacheDB` wrapper for determinism.
- Supports gas tracking, nested call/create tracing, and storage-diff capture.
- Results are deterministic: same input, fork state, and block context always produce the same output.
- Can replay cached fork state offline or compare against live RPC-backed fork reads for verification.

### Fork State Management

- **Lazy RPC loading**: Accounts, code, balances, nonces, and storage are fetched on-demand from an RPC endpoint.
- **Persistent caching**: Fork state is snapshotted and stored locally; campaigns can run fully offline once cached.
- **Fork database**: `ForkDb` implements `revm`'s `DatabaseRef` trait, enabling drop-in use with any `revm` executor.
- **Differential verification**: Compare cached replay against live RPC to detect cache misses or RPC divergence.

### Coverage and State Novelty

- **AFL-style edge coverage** with hitcount bucketing.
- **Stable path hashing** for coverage comparison.
- **State novelty** feedback on:
  - Storage slot transitions
  - Read/write set patterns
  - Call-graph edges
  - Contract invocation sequences
- **Expression-backed frontier pressure** to explore unvisited branch constraints.

### Campaign Scoring and Scheduling

Custom LibAFL scheduler (`CampaignScore`) prioritizes corpus entries by:
- Economic pressure (balance deltas, share inflation/deflation)
- Invariant pressure (oracle violations, access-control breaks)
- Oracle severity
- State novelty
- Exploration depth
- Branch-frontier distance
- Scheduling decay (prevent stale selection)

### ABI-Aware Mutation

- Valid ABI sequence insertion (callers, functions, arguments).
- Dynamic type mutation through `alloy-dyn-abi`.
- Target discovery and caller role mutation.
- Semantic sequence chaining (data flow across transactions).
- Value-boundary mutation (min/max, powers of 2, zero).
- Flashloan-style wrapping and MEV sandwich pressure.
- Mutation provenance tracking for triage.

### Concolic Solving

Deterministic taint-guided expression solver—**no Z3 dependency required by default**. Tracks symbolic expressions through:
- Calldata and memory
- Arithmetic and bitwise operations
- Storage reads/writes across transactions
- Keccak/mapping derivations

Inversion handles:
- `arg + c`, `arg - c`, `arg * c`, `arg / c`, `arg % c`, `arg ^ c`
- Direct storage/calldata comparisons
- Branch-path constraints

Concolic hints are applied as ABI words and can extend calldata instead of dropping solvable constraints.

### Protocol Oracle Packs

Evidence-driven oracle packs detect patterns in:
- **ERC20**: Token balance accounting, allowance behavior
- **ERC4626**: Share inflation, rounding, redemption desynchronization
- **AMM**: Reserve asymmetry, oracle price staleness
- **Lending**: Bad-debt accumulation, liquidation paths, interest-rate desynchronization
- **Governance**: Timelock bypass, vote manipulation, proxy upgrade takeover

Oracles generate reproducible evidence artifacts, not just binary pass/fail verdicts.

### Crash Minimization and PoC Generation

- Minimize transaction sequences to the shortest reproduction.
- Generate Foundry invariant harness PoC scaffolds that:
  - Replay exact sequences
  - Set the fork block and environment
  - Assert replay status
  - Include protocol oracle evidence
  - Assert storage diffs
  - Expose an `assertRustyFuzzInvariant()` extension point

### Validation Benchmarks

Built-in benchmark framework for honest measurement:
- **Local fixtures**: Synthetic EVM bytecode deployments.
- **Live-fork benchmarks**: Replay historical seed JSON against a configured RPC endpoint.
- **Cached-fork rediscovery**: Deterministic vulnerable deployments encoded as fork snapshots.
- **Historical fork-state benchmarks**: Replay public historical exploit transactions at pre-exploit fork blocks. These can use local `revm` archive-state replay when the RPC endpoint can serve all touched storage, or explicit provider-side `eth_call` replay when the fixture sets `provider_replay_only = true`.
- **Blind rediscovery benchmarks**: Benign historical selector/state hints plus fork state, with bounded search synthesizing the candidate exploit path instead of replaying exploit calldata directly.

Benchmarks report explicit statuses: `found`, `not_found`, `not_run_*`, `failed_execution`, `skipped_by_config`.

Proof statuses are tracked: `heuristic_only`, `abstractly_proven`, `concretely_replayed`.

Historical validation example:

```bash
export ETH_RPC_URL="https://your-archive-rpc"
cargo run --release -- validate \
  --benchmarks benchmarks/historical \
  --output reports/historical_validation_report.json
```

Current historical examples include Euler Finance's 2023 donate/liquidation exploit replay and Audius' 2022 governance reinitialization exploit replay. Provider-side replay findings are labeled in the report and PoC evidence as real fork-state `eth_call` replay with local storage diffs unavailable; they are stronger than synthetic cached runtimes, but weaker than full local `revm` archive-state replay with storage-diff proof.

Blind rediscovery example:

```bash
cargo run --release -- validate \
  --benchmarks benchmarks/blind \
  --output reports/blind_validation_report.json
```

Blind reports include:
- `found`, `not_found`, `failed_execution`, and `not_run_*` statuses
- `equivalence_class`
- `synthesized_sequence`
- `search_driver`
- replay/minimize/PoC status fields

### Hardened DeFi Mode

Target-adaptive machinery for mature DeFi protocols:
- **Target profiling** from ABI, Foundry harness hints, seed metadata.
- **Actor-role generation**: attacker, victim, whale, depositor, borrower, liquidator, trader, keeper, governance, privileged.
- **Historical seed ingestion**: Load real transaction JSON into the corpus.
- **Economic delta scoring**: Observe balance changes and storage deltas.
- **Template-based exploit generation**: Build action/assertion sequences from frontier evidence.
- **Confidence filtering**: Only persist findings above a configurable threshold.

**Limitations**: Protocol invariants are heuristic packs, not protocol-specific. Historical seeds require useful calldata. Economic deltas are strongest when token balances are observable. Benchmark validation is the source of truth.

### Real-Fork Target Workflow

Use fail-closed fork mode for real target campaigns so an RPC or bytecode failure cannot silently become synthetic-state fuzzing:

```bash
# Set rpc_url in your local config.toml to a BSC archive RPC first.
export TARGET="0x85f86ef7E72e86BdEAb5F65e2B76A2c551f22109"

RUST_LOG=info \
LIBAFL_CORES=0-1 \
RUSTYFUZZ_EXEC_TIMEOUT_SECS=60 \
RUSTYFUZZ_REQUIRE_RPC_FORK=1 \
timeout -k 60s 10m cargo run --release -- fuzz \
  --chain evm \
  --contract "$TARGET" \
  --require-rpc-fork
```

`--allow-synthetic-fallback` is intentionally separate and should be reserved for local smoke tests and benchmarks. RPC errors are reported with the RPC host only; credentials, paths, and query strings are not logged.

Seed bundle handling is explicit. If a configured bundle is missing or empty, default behavior is to continue as `synthetic-seed-start`; add `--require-seed-bundle` to abort instead:

```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract "$TARGET" \
  --require-rpc-fork \
  --require-seed-bundle
```

### Rate-Aware Seed Discovery

Discover bounded historical seeds without hammering public RPC endpoints:

```bash
cargo run --release -- seed \
  --target "$TARGET" \
  --bundle-id dexe-poolfactory-bsc \
  --max-seeds 128 \
  --search-depth 5000 \
  --include-address-hints \
  --rate-limit-rps 2 \
  --seed-rpc-retry-count 5 \
  --seed-rpc-backoff-ms 500 \
  --resume \
  --seed-output-manifest reports/seeds/dexe-poolfactory-bsc.scan.json
```

The seed manifest records the target, fork block, seed count, discovered accounts, selectors, scan range, and scan settings. Resume cursors are written under `corpus/seed_cursors/` by default when `--resume` is used.

### Historical Seed Ingestion

RustyFuzz can ingest existing RustyFuzz historical JSON, BscScan-style `result` exports, or a generic transaction array. Minimal generic format:

```json
[
  {
    "hash": "0x...",
    "from": "0x1313131313131313131313131313131313131313",
    "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "value": "0",
    "input": "0x095ea7b3...",
    "blockNumber": "100600727",
    "isError": "0"
  }
]
```

Ingest it into a reusable bundle:

```bash
cargo run --release -- seed-ingest \
  --file seeds/dexe-poolfactory-bsc.json \
  --bundle-id dexe-poolfactory-bsc \
  --target "$TARGET" \
  --chain-id 56 \
  --fork-block 100600727
```

Historical direct calls are high-confidence seeds; routed target references are medium/high; adjacent synthetic variants keep provenance and lower confidence. Reportable findings still require replay/proof evidence. Heuristic signals are not confirmed bugs.

### Bytecode-Only Profiling

When ABI/source metadata is unavailable, RustyFuzz statically analyzes runtime bytecode. It decodes opcodes without treating `PUSHn` immediates as opcodes, extracts `PUSH4` constants, identifies dispatcher selectors, matches known protocol signatures, detects EIP-1167/EIP-1967/proxy/delegatecall patterns, records risky opcodes, and feeds the result into target profiling, seed intelligence, mutation dictionaries, and scoring. This improves profiles beyond `Unknown` when selector or proxy evidence is meaningful. `Unknown` remains valid when bytecode evidence is weak.

Standalone bytecode report:

```bash
cargo run --release -- bytecode-analyze \
  --file runtime-bytecode.hex \
  --output reports/bytecode/${TARGET}.json
```

### ABI Ingestion and Target-Aware Setup

ABI metadata is the fastest way to move a real target from `Unknown` to actionable. Ingest an ABI into the local cache:

```bash
cargo run --release -- abi-ingest \
  --file abi/PoolFactory.json \
  --target "$TARGET" \
  --bundle-id dexe-poolfactory-bsc
```

Or pass it directly to fuzzing:

```bash
RUST_LOG=info \
LIBAFL_CORES=0-1 \
RUSTYFUZZ_EXEC_TIMEOUT_SECS=60 \
RUSTYFUZZ_REQUIRE_RPC_FORK=1 \
timeout -k 60s 10m cargo run --release -- fuzz \
  --chain evm \
  --contract "$TARGET" \
  --abi abi/PoolFactory.json \
  --require-rpc-fork
```

Startup logs include loaded function count, event count, and classified selectors. Classifications feed target profiling, seed intelligence, mutation dictionaries, scoring, and invariant selection.

Build a bounded setup report from seeds plus ABI:

```bash
cargo run --release -- setup \
  --bundle-id dexe-poolfactory-bsc \
  --abi abi/PoolFactory.json \
  --output reports/fork_setup/${TARGET}.json
```

Setup discovery is bounded and read-only by default. It records proxy/admin slots to probe, ABI-derived read-only probe plans, candidate tokens, pools, registries, oracle feeds, holders, whales, and confidence/evidence. It does not broadcast transactions or mutate live-chain state.

Generate target-specific invariants:

```bash
cargo run --release -- invariants \
  --target "$TARGET" \
  --abi-report corpus/abi/dexe-poolfactory-bsc/report.json \
  --setup-report reports/fork_setup/${TARGET}.json \
  --output reports/invariants/${TARGET}.toml
```

Generated invariant manifests are goal guidance. A finding remains heuristic until replay, minimization, proof, or PoC evidence promotes it.

Example invariant manifest shape:

```toml
target = "0x85f86ef7E72e86BdEAb5F65e2B76A2c551f22109"

[[invariants]]
id = "attacker-profit-bound"
kind = "require_attacker_profit_below"
max_bps = 500
min_profit = 1
severity = "high"
```

### RustyFuzz Job Execution

Satori can emit RustyFuzz job JSON. Run a job directly:

```bash
cargo run --release -- job run satori/runs/<run_id>/jobs/<job>.rustyfuzz.json \
  --abi abi/PoolFactory.json
```

Job execution is fork-required and fail-closed. The adapter loads ABI, seed bundle configuration, generated hypotheses, and invariants, then starts a bounded campaign under `reports/jobs/<job_id>/`. Satori hypotheses are preserved as references; RustyFuzz proves, rejects, or leaves them heuristic based on local replay evidence.

Minimal job shape:

```json
{
  "job_id": "dexe-poolfactory-001",
  "hypothesis_id": "hyp-001",
  "job_type": "fork_campaign",
  "target_contract": "0x85f86ef7E72e86BdEAb5F65e2B76A2c551f22109",
  "bug_class": "factory_registry",
  "actors": ["attacker", "governance", "keeper"],
  "preconditions": ["BSC archive RPC is configured"],
  "sequence_template": [],
  "mutation_focus": ["register", "create", "setPool"],
  "invariants": [
    {
      "id": "inv-001",
      "description": "unauthorized pool registration should not succeed",
      "check": "registry ownership and pool pointer remain authorized",
      "expected_signal": "accounting or registry mutation without authorized caller"
    }
  ],
  "objective": "prove or reject unauthorized pool registration hypothesis",
  "success_condition": "replayed/minimized/proof-carrying evidence only",
  "max_depth": 3,
  "fork_block": 100600727,
  "fork_rpc_url": "https://bsc-rpc.example",
  "abi_hints": ["PoolFactory.json"]
}
```

### Satori AI Audit Harness

Satori is RustyFuzz's AI-guided repo audit control plane. It ingests a Solidity/Vyper repository, builds deterministic protocol context, selects critical functions, creates compact packets, uses OpenAI `o3` behind `--features llm` for hypothesis generation, emits RustyFuzz job JSON, generates Foundry PoC scaffolds, stores memory, and writes reports that separate unvalidated hypotheses from locally validated findings.

No LLM:
```bash
cargo run -- satori ingest ./protocol
cargo run -- satori graph ./protocol
cargo run -- satori packets ./protocol
```

With `o3`:
```bash
export OPENAI_API_KEY="..."
cargo run --features llm -- satori audit ./protocol \
  --model o3 \
  --max-critical-functions 8 \
  --max-hypotheses-per-function 2 \
  --min-confidence 0.40 \
  --validate true \
  --generate-jobs true
```

Satori does not broadcast transactions, use private keys, or label model output as confirmed findings without deterministic local evidence. See [docs/SATORI.md](docs/SATORI.md).

## Installation

### Requirements

- Rust 1.70+
- Cargo
- libz3-dev (optional, for Z3 concolic solver integration)

### Build

**Default (EVM only)**:
```bash
cargo build --release
```

**With Z3 concolic solver**:
```bash
# Linux
sudo apt install libz3-dev
cargo build --release --features z3

# macOS
brew install z3
cargo build --release --features z3
```

**SVM (Solana)** - separate build:
```bash
cargo build --release --features svm --no-default-features
```

**Verification**:
```bash
cargo fmt
cargo check
cargo clippy -- -D warnings
cargo test --lib
```

## Configuration

RustyFuzz expects `config.toml` in the project root. Example:

```toml
chain = "evm"
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY"
fork_block = 22000000
target_contract = "0x1234567890123456789012345678901234567890"
fuzzer_address = "0x1234567890123456789012345678901234567890"
timeout_secs = 3600
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
foundry_project = "."
mainnet_seed_bundle = "target-mainnet"
target_abi = "abi/Target.json"
abi_cache_dir = "corpus/abi"

[hardened_defi]
enabled = false
historical_seed_file = "seeds/example_historical_seed.json"
max_template_sequences = 128
enable_actor_model = true
enable_economic_delta = true
enable_protocol_invariants = true
enable_exploit_templates = true
min_persist_confidence = 0.70
```

See `config.toml.example` for full reference.

## CLI Usage

### Live Target Runbook

This is the shortest complete path for running RustyFuzz against a live EVM target with fail-closed fork behavior. Use an archive-capable RPC endpoint; public free endpoints often fail on historical storage reads.

**1. Set target variables**

```bash
export TARGET="0xYourTargetContract"
export RPC_URL="https://your-archive-rpc"
export FORK_BLOCK="22000000"
export CAMPAIGN_ID="live-target-001"
```

For BSC, keep `--chain bsc` in the commands below and use a BSC archive RPC. For Ethereum mainnet, use `--chain evm`.

**2. Build the release binaries**

```bash
cargo build --release --bin rusty-fuzz --bin benchmark
```

Optional Z3 build:

```bash
cargo build --release --features z3 --bin rusty-fuzz
```

**3. Create or update `config.toml`**

```toml
chain = "evm"
rpc_url = "https://your-archive-rpc"
fork_block = 22000000
target_contract = "0xYourTargetContract"
corpus_dir = "corpus"
report_dir = "reports"
foundry_project = "."
mainnet_seed_bundle = "live-target-001"
target_abi = "abi/Target.json"
abi_cache_dir = "corpus/abi"

[hardened_defi]
enabled = true
enable_actor_model = true
enable_economic_delta = true
enable_protocol_invariants = true
enable_exploit_templates = true
```

`config.toml` is read by replay, promotion, setup, validation, and fuzz commands. Keep RPC credentials out of committed files.

**4. Optional but recommended: add ABI knowledge**

```bash
target/release/rusty-fuzz abi-ingest \
  --file abi/Target.json \
  --target "$TARGET" \
  --bundle-id "$CAMPAIGN_ID"
```

Or pass the ABI directly during fuzzing with `--abi abi/Target.json`.
If you do not have an ABI, remove every `--abi abi/Target.json` flag below; RustyFuzz will fall back to bytecode selector discovery.

**5. Optional but recommended: ingest recent mainnet seeds**

```bash
target/release/rusty-fuzz seed \
  --contract "$TARGET" \
  --rpc-url "$RPC_URL" \
  --chain evm \
  --output "corpus/mainnet_seeds/$CAMPAIGN_ID" \
  --limit 100 \
  --search-depth 10000 \
  --include-address-hints \
  --seed-mode block-scan \
  --rate-limit-rps 2 \
  --resume
```

With an ABI:

```bash
target/release/rusty-fuzz seed \
  --contract "$TARGET" \
  --rpc-url "$RPC_URL" \
  --chain evm \
  --output "corpus/mainnet_seeds/$CAMPAIGN_ID" \
  --limit 100 \
  --abi abi/Target.json \
  --seed-mode block-scan \
  --rate-limit-rps 2 \
  --resume
```

This writes `corpus/mainnet_seeds/$CAMPAIGN_ID/manifest.json`. The bundle is loaded when `mainnet_seed_bundle = "$CAMPAIGN_ID"` in `config.toml`.

Equivalent config-driven seed ingestion, which persists directly under `corpus/mainnet_seeds/<bundle-id>/`:

```bash
target/release/rusty-fuzz seed \
  --target "$TARGET" \
  --bundle-id "$CAMPAIGN_ID" \
  --max-seeds 100 \
  --search-depth 10000 \
  --include-address-hints \
  --seed-mode block-scan \
  --rate-limit-rps 2 \
  --resume
```

**6. Optional: discover setup context and invariants**

```bash
target/release/rusty-fuzz setup \
  --bundle-id "$CAMPAIGN_ID" \
  --target "$TARGET" \
  --abi abi/Target.json \
  --output "reports/$CAMPAIGN_ID/fork_setup.json"

target/release/rusty-fuzz invariants \
  --target "$TARGET" \
  --abi-report "corpus/abi/$CAMPAIGN_ID/report.json" \
  --setup-report "reports/$CAMPAIGN_ID/fork_setup.json" \
  --output "reports/$CAMPAIGN_ID/invariants.json"
```

If you do not have ABI/setup reports yet, skip this step. Findings still require replay and PoC evidence.

**7. Run a one-execution smoke proof**

```bash
RUST_LOG=info \
RUSTYFUZZ_REQUIRE_RPC_FORK=1 \
target/release/rusty-fuzz fuzz \
  --chain evm \
  --contract "$TARGET" \
  --campaign-id "$CAMPAIGN_ID-smoke" \
  --max-execs 1 \
  --wall-timeout-secs 120 \
  --artifact-limit 4 \
  --require-rpc-fork \
  --no-synthetic-fallback \
  --abi abi/Target.json
```

Expected result: startup logs show bytecode analysis, seed startup mode, shared coverage size, and a campaign summary under `reports/$CAMPAIGN_ID-smoke/`. If RPC bytecode or storage fetch fails, the command should fail instead of silently fuzzing synthetic state.

**8. Run the live campaign**

Single-process, easiest to debug:

```bash
RUST_LOG=info \
RUSTYFUZZ_REQUIRE_RPC_FORK=1 \
target/release/rusty-fuzz fuzz \
  --chain evm \
  --contract "$TARGET" \
  --campaign-id "$CAMPAIGN_ID" \
  --max-execs 50000 \
  --wall-timeout-secs 3600 \
  --artifact-limit 100 \
  --single-process \
  --hardened-defi \
  --bounded-search \
  --require-rpc-fork \
  --no-synthetic-fallback \
  --promote-findings \
  --min-finding-confidence 70 \
  --abi abi/Target.json
```

Brokered multi-core run:

```bash
RUST_LOG=info \
RUSTYFUZZ_REQUIRE_RPC_FORK=1 \
target/release/rusty-fuzz fuzz \
  --chain evm \
  --contract "$TARGET" \
  --campaign-id "$CAMPAIGN_ID-mc" \
  --max-execs 200000 \
  --wall-timeout-secs 7200 \
  --artifact-limit 200 \
  --cores 0-3 \
  --single-process false \
  --hardened-defi \
  --bounded-search \
  --require-rpc-fork \
  --no-synthetic-fallback \
  --promote-findings \
  --min-finding-confidence 70 \
  --abi abi/Target.json
```

Use `--allow-synthetic-fallback` only for smoke tests against dummy targets. Do not use it for vulnerability claims.

**9. Inspect the outputs**

Campaign summaries:

```bash
cat "reports/$CAMPAIGN_ID/campaign_summary.json"
cat "reports/$CAMPAIGN_ID/campaign_summary.md"
```

Candidate artifacts:

```bash
find "corpus/$CAMPAIGN_ID/campaign_artifacts" -maxdepth 1 -type f -name '*.json'
find "reports/$CAMPAIGN_ID/findings" -type f
```

Proof-quality indicators:
- `confirmed_findings > 0`
- `poc_count > 0`
- `replay_failure_count = 0`
- finding report includes oracle evidence, replay result, call trace, storage diffs, and PoC path
- generated PoC exists under `reports/$CAMPAIGN_ID/findings/.../*.t.sol`

Score-only artifacts are triage leads, not confirmed vulnerabilities.

**10. Replay, minimize, or promote a candidate manually**

For a campaign artifact `<input_id>.json`:

```bash
target/release/rusty-fuzz replay \
  --input <input_id> \
  --fork-cache-id <fork_cache_id>

target/release/rusty-fuzz replay \
  --input <input_id> \
  --fork-cache-id <fork_cache_id> \
  --live

target/release/rusty-fuzz minimize \
  --input-id <input_id> \
  --fork-cache-id <fork_cache_id> \
  --reason "oracle-preserving-minimization"

target/release/rusty-fuzz promote \
  --input-id <input_id> \
  --fork-cache-id <fork_cache_id> \
  --campaign-id "$CAMPAIGN_ID"
```

**11. Confirm the toolchain before a serious run**

```bash
cargo check
cargo check --features z3
cargo test benchmark --lib
target/release/rusty-fuzz validate \
  --benchmarks benchmarks/realistic \
  --output reports/known_vulnerable_validation_report.json
cat reports/scoring_calibration.json
```

For the current validation pack, the expected calibration is `pass_rate = 1.0`, `replay_success_rate = 1.0`, `minimized_success_rate = 1.0`, and `poc_generation_rate = 1.0`.

### Fuzz Campaign

Start a campaign against a target contract:

```bash
cargo run --release -- fuzz --chain evm --contract 0xTarget
```

**Single-process mode** (no LibAFL broker, keeps campaign in one process):
```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --single-process \
  --bounded-search
```

`--bounded-search` enables exhaustive search within configured transaction-depth and actor-role bounds. Reports whether each candidate is `heuristic_only`, `abstractly_proven`, or `concretely_replayed`.

**Hardened DeFi mode**:
```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --hardened-defi
```

**With a seed file**:
```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --seed-file seeds/example_historical_seed.json
```

**Deterministic with fixed RNG seed**:
```bash
cargo run --release -- fuzz \
  --chain evm \
  --contract 0xTarget \
  --deterministic \
  --rng-seed 42
```

### Seed Generation and Ingestion

**Discover seeds from mainnet fork history**:
```bash
cargo run --release -- seed \
  --target 0xTarget \
  --max-seeds 64 \
  --bundle-id target-mainnet \
  --search-depth 50000 \
  --include-address-hints
```

Options:
- `--target`: Contract to seed.
- `--max-seeds`: Maximum seeds to extract.
- `--bundle-id`: Save bundle under this name (loaded by `mainnet_seed_bundle` in config).
- `--start-block`: Scan backward from this block (instead of fork block).
- `--search-depth`: How far back to scan (default: 10,000).
- `--include-address-hints`: Also include transactions whose calldata contains the target address (helps with routers/proxies).

**Ingest historical seed JSON**:
```bash
cargo run --release -- seed-ingest \
  --file seeds/example_historical_seed.json \
  --bundle-id target-historical
```

Converts transaction JSON into the seed bundle store. Useful for reproducing historical exploits.

**Infer fork-state setup from a seed bundle**:
```bash
cargo run --release -- setup \
  --bundle-id target-mainnet \
  --output reports/fork_setup.json
```

The setup report summarizes observed and inferred target context for forked Immunefi-style testing:
tokens, funded holders/whales, AMM pools, oracle feeds, collateral candidates, governance/timelock
targets, EIP-1967 proxy/admin slots to probe, and recent valid transaction-flow windows. Findings are
labeled by source, such as historical seed, discovered account, execution trace, selector heuristic,
or known slot. This is setup automation, not proof of vulnerability.

### Replay and Verification

**Replay a persisted input**:
```bash
cargo run --release -- replay --input <input-id> --fork-cache-id <cache-id>
```

**Compare cached vs. live RPC**:
```bash
cargo run --release -- replay \
  --input <input-id> \
  --fork-cache-id <cache-id> \
  --live
```

Differential replay detects cache misses, RPC divergence, or stale state.

### Minimization and PoC Generation

**Minimize a crash and generate Foundry PoC**:
```bash
cargo run --release -- minimize \
  --input-id <input-id> \
  --fork-cache-id <cache-id> \
  --reason protocol-finding
```

Outputs:
- Minimized transaction sequence
- Reproduction report
- `foundry_poc.sol` harness (ready to run in Foundry)

### Reproduction Reports

**Generate a reproduction report**:
```bash
cargo run --release -- report \
  --input-id <input-id> \
  --fork-cache-id <cache-id>
```

Outputs markdown report with transaction details, gas, storage diffs, and oracle findings.

### Validation and Benchmarking

**Run local fixture benchmarks**:
```bash
cargo run --release -- validate --benchmarks benchmarks/ --output reports/validation_report.json
```

**Run live-fork benchmarks** (requires RPC and fork_block in config):
```bash
cargo run --release -- validate --benchmarks benchmarks/live --output reports/live_validation_report.json
```

**Run cached-fork rediscovery benchmarks**:
```bash
cargo run --release -- validate --benchmarks benchmarks/forked --output reports/forked_validation_report.json
```

**Run the strict known-vulnerable validation gate**:
```bash
cargo run --release --bin rusty-fuzz -- validate \
  --benchmarks benchmarks/historical/known_vulnerable \
  --output reports/known_vulnerable_validation_report.json
```

This pack requires every case to produce a finding, replay confirmation, minimized path, and Foundry PoC. A case without a generated PoC is reported as not found.

**Run blind rediscovery benchmarks**:
```bash
cargo run --release -- validate --benchmarks benchmarks/blind --output reports/blind_validation_report.json
```

Reports include:
- `status` (found, not_found, not_run_*, failed_execution, skipped_by_config)
- `proof_status` (heuristic_only, abstractly_proven, concretely_replayed)
- Execution stats: `executions_to_signal`, `time_to_signal_secs`
- Artifact paths, evidence, match criteria, `equivalence_class`, and `synthesized_sequence`

### Mempool Scanning

**Scan mempool for pending transactions**:
```bash
cargo run --release -- scan-mempool
```

Useful for monitoring real-time activity and discovering attack patterns.

## Project Structure

```
src/
├── main.rs                      CLI entry point and command dispatch
├── config.rs                    Configuration loading (TOML)
├── common/
│   ├── types.rs                 Canonical input, execution, trace, oracle types
│   ├── oracle/                  Legacy and protocol oracle logic
│   │   ├── mod.rs
│   │   └── packs.rs             ERC20, ERC4626, AMM, lending, governance oracles
│   └── verifier.rs              Deterministic replay verification
├── chain/
│   ├── mod.rs
│   ├── interface.rs             Chain abstraction
│   └── mempool.rs               Mempool scanning
├── engine/
│   ├── fuzz_engine.rs           Main LibAFL campaign orchestration
│   ├── scheduler.rs             Custom LibAFL scheduler (CampaignScore)
│   ├── scoring.rs               Economic, invariant, state, frontier scoring
│   ├── concolic.rs              Deterministic taint-guided expression solver
│   ├── minimizer.rs             Sequence minimization and artifact generation
│   ├── exploit_synthesizer.rs   Foundry PoC generation
│   ├── foundry_ingest.rs        Foundry invariant harness ingestion
│   ├── seed_intelligence.rs     Semantic seed analysis
│   ├── benchmark.rs             Validation benchmark framework
│   └── mod.rs
├── evm/
│   ├── executor.rs              Deterministic revm execution
│   ├── inspector.rs             Coverage, dataflow, trace, concolic instrumentation
│   ├── feedback.rs              Coverage and state novelty feedback signals
│   ├── fork.rs                  Fork block environment setup
│   ├── fork_db.rs               Lazy RPC fork database and persistence
│   ├── corpus.rs                Persistent corpus, crash metadata, replay artifacts
│   ├── fuzz.rs                  EvmInput structure and ABI-aware mutation
│   ├── seed_ingester.rs         Mainnet seed discovery and normalization
│   ├── abi_mutator.rs           ABI-driven mutation engine
│   ├── registry.rs              Contract registry
│   ├── economic.rs              Economic state analysis
│   ├── dataflow.rs              Dataflow tracking
│   ├── trace.rs                 Call/create trace collection
│   ├── snapshot.rs              State snapshots
│   ├── erc20_discovery.rs       ERC20 token detection
│   ├── sgx_executor.rs          SGX-based execution (experimental)
│   └── mod.rs
├── svm/                         Separated Solana VM surface (experimental)
└── lib.rs                       Public API

benchmarks/
├── fixtures/                    EVM bytecode fixtures for synthetic benchmarks
├── forked/                      Cached-fork rediscovery manifests
└── live/                        Live-fork benchmark manifests

corpus/
├── inputs/                      Persisted EvmInput JSON
├── executions/                  Execution artifacts
├── crashes/                     Crash metadata
├── fork_caches/                 Persistent fork snapshots
└── seed_bundles/                Mainnet seed bundles

reports/
├── validation_report.json       Benchmark validation results
├── scoring_calibration.json     Score calibration metadata
└── artifacts/                   Generated PoC files, reports

docs/
├── sample_validation_report.json Example validation output
└── README files for subdomains
```

## Experimental and Limited Areas

- **SVM**: Separated and intentionally not part of hardened EVM campaign path.
- **SGX**: Feature-gated and experimental.
- **LLM guidance**: Scaffolding present but inert unless explicitly integrated.
- **Z3 integration**: Optional; core concolic path is deterministic and internal.
- **Symbolic execution**: Not full symbolic execution; bounded, deterministic concolic assistance.
- **Keccak preimage solving**: Not implemented.
- **Dynamic array constraint solving**: Partial; offset tables are repaired for simple cases.
- **Protocol-specific exploit synthesis**: Future work; oracles are evidence-driven, not protocol replacements.

## Hardened DeFi Mode

Optional, target-adaptive machinery for DeFi campaigns. Enable in config:

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

Or via CLI:
```bash
cargo run --release -- fuzz --chain evm --contract 0xTarget --hardened-defi
```

**Components**:
- Target profiling from ABI selectors and Foundry harness metadata.
- Actor-role generation (attacker, victim, whale, depositor, etc.).
- Historical transaction JSON ingestion.
- Economic delta scoring from balance and storage changes.
- Template-based exploit sequences.
- Confidence-based corpus filtering.

**Limitations**: Heuristic protocol invariants, not formal properties. Requires good historical seeds and observable token balances. Validation benchmarks are the source of truth.

## Development

### Running Tests

```bash
cargo test
```

### Linting and Formatting

```bash
cargo fmt
cargo clippy -- -D warnings
```

### Adding a New Oracle Pack

1. Add oracle logic to `src/common/oracle/packs.rs`.
2. Implement `evaluate()` to return findings given `SequenceExecutionResult`.
3. Register in `ProtocolOraclePack::default()`.
4. Add test fixtures to `tests/benchmarks.rs`.

### Extending Feedback Signals

1. Implement feedback module in `src/evm/feedback.rs`.
2. Register with the scheduler in `src/engine/scheduler.rs`.
3. Update `CampaignScore` to incorporate the signal.

### Adding a New Mutator Strategy

1. Extend `EvmMutator` in `src/evm/fuzz.rs`.
2. Add mutation provenance tracking.
3. Register with LibAFL's `Mutator` trait.

## Development Roadmap

Priority engineering tasks:

1. Operator workflow: CI-friendly operation with structured output and dry-run modes
2. Solver-backed synthesis: Synthesize setup/action/assertion sequences from branch frontiers
3. Dynamic type repair: Full offset table repair for dynamic arrays, bytes, strings, nested tuples
4. Semantic invariants: Convert oracle evidence into replay assertions for semantic deltas
5. Frontier-driven scheduling: Use branch-distance and expression metadata for energy assignment
6. Differential replay hardening: Rich diff reports for gas, output, storage, call traces
7. SVM stabilization: Complete as standalone execution target

## Technical Limitations

- **SVM**: Separated and not part of hardened EVM campaign path
- **SGX**: Feature-gated and experimental
- **LLM guidance**: Scaffolding present but inert unless explicitly integrated
- **Z3 integration**: Optional; core concolic path is deterministic and internal
- **Symbolic execution**: Bounded, deterministic concolic assistance only
- **Keccak preimage solving**: Not implemented
- **Dynamic array constraint solving**: Partial; offset tables repaired for simple cases
- **Protocol-specific exploit synthesis**: Oracles are evidence-driven, not protocol replacements

## Contributing

Contributions are welcome. Please:

1. Run `cargo fmt` and `cargo clippy -- -D warnings` before submitting.
2. Add tests for new features.
3. Update documentation if APIs change.
4. Reference issues in commit messages.

## License

MIT.

## Citation

If RustyFuzz is useful in your research, please cite:

```bibtex
@software{rustyfuzz,
  title={RustyFuzz: Stateful EVM Fuzzing for Protocol Security Research},
  author={Wakhungila},
  year={2025},
  url={https://github.com/Wakhungila/RustyFuzz}
}
```

## Acknowledgments

RustyFuzz is built on:
- [LibAFL](https://github.com/AFLplusplus/LibAFL) for fuzzing orchestration
- [revm](https://github.com/bluealloy/revm) for deterministic EVM execution
- [Alloy](https://github.com/alloy-rs/alloy) for Ethereum primitives and RPC
- [Foundry](https://github.com/foundry-rs/foundry) for test harness integration


For issues, feature requests, or discussion, please open a GitHub issue or pull request.

---

**Last Updated**: May 2025  
