# RustyFuzz

A stateful EVM fuzzer for protocol-security research. RustyFuzz combines deterministic transaction-sequence execution, fork-aware state replay, real coverage feedback, protocol oracle evidence, and reproducible crash reporting into a coherent fuzzing foundation.

**Status**: Production-ready EVM core with hardened execution, fork caching, and deterministic replay. Protocol oracle packs, concolic solving, and PoC generation are integrated. SVM support is separate and experimental.

## What Is RustyFuzz?

RustyFuzz is a fuzzing engine designed for finding state-machine bugs in smart contracts. Unlike property-based testing frameworks, RustyFuzz:

- **Executes transaction sequences deterministically** against a mutable EVM state, capturing coverage, storage deltas, and call traces.
- **Caches fork state** (accounts, code, storage, balances) from an RPC endpoint and replays inputs against cached state for reproducibility.
- **Feeds multiple feedback signals** into a custom LibAFL scheduler: AFL-style coverage, storage novelty, state reachability, protocol oracle findings, and economic pressure.
- **Minimizes crashes** to the shortest sequence that reproduces the issue.
- **Generates Foundry PoC scaffolds** with transaction sequences, fork block, callers, and assertions.
- **Supports protocol-specific oracles** for ERC20, ERC4626, AMM, lending, and governance patterns.
- **Applies concolic hints** to guide the mutator toward satisfying branch constraints without requiring a full symbolic solver.

It is **not** a general-purpose fuzzer. It is built for multi-transaction invariant violations and economic attacks, where state carries meaning across transactions.

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

## Installation

### Prerequisites

- **Rust 1.70+** ([install](https://rustup.rs/))
- **Cargo**
- **libz3-dev** (if using `--features z3` for optional Z3 solver integration)

### Building

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

**SVM (Solana)** — separate, non-default build:
```bash
cargo build --release --features svm --no-default-features
```

**Validation**:
```bash
cargo fmt
cargo check
cargo clippy -- -D warnings
cargo test
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

## What's Next

The highest-impact engineering priorities:

1. **Operator workflow**: Promote CLI commands to polished, CI-friendly operation with structured output and dry-run modes.
2. **Solver-backed synthesis**: Move beyond cloning patched transactions; synthesize setup/action/assertion sequences from branch frontiers.
3. **Dynamic type repair**: Fully repair offset tables for dynamic arrays, bytes, strings, nested tuples when applying concolic hints.
4. **Semantic invariants**: Convert oracle evidence into replay assertions that verify semantic deltas, not only storage reproduction.
5. **Frontier-driven scheduling**: Use persisted branch-distance and expression metadata for energy assignment and crash shrinking.
6. **Differential replay hardening**: Rich diff reports for gas, output, storage, call traces, fork-cache misses.
7. **SVM stabilization**: Complete and harden as a standalone execution target after EVM core is complete.

## Engineering Position

RustyFuzz is a coherent EVM fuzzing foundation with deterministic execution, real coverage, state novelty, fork caching, protocol evidence, concolic assists, custom scheduling, replay, minimization, and PoC generation.

It is **not** a magic bullet. Finding high-impact bugs in mature protocols depends on:
- Target modeling (what invariants matter?)
- Harness quality (how do we encode those invariants?)
- Seed quality (are we starting with realistic states?)
- Fork state (is the RPC endpoint honest?)
- Oracle precision (are detections accurate or noisy?)
- Researcher judgment (does the evidence make sense?)

The goal of this codebase is to make these inputs compound instead of fighting a broken runtime.

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

## Contact

For issues, feature requests, or discussion, please open a GitHub issue or pull request.

---

**Last Updated**: May 2025  
**Maintainers**: @Wakhungila and @nutcas3
