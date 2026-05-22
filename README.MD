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
```

Run a fuzz campaign:

```bash
cargo run -- fuzz --chain evm --contract 0xTarget
```

Seed a campaign from mainnet fork history:

```bash
cargo run -- seed --target 0xTarget --max-seeds 32 --bundle-id target-mainnet
```

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
