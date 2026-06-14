# RustyFuzz Engineering Status

Last updated: 2026-06-12.

This document records the repository state observed from source, tests, workflows,
fixtures, and configuration. It intentionally does not rely on README claims.

## Workspace

- Package: `rusty-fuzz`, Rust 2021 edition.
- Main binary: `src/main.rs`, package binary name `rusty-fuzz`.
- Additional binary: `benchmark` at `src/bin/benchmark.rs`.
- Default feature set: `evm`.
- Optional features: `z3`, `llm`, `notifier`, `sgx`, `svm`.

## Source Map

- `src/evm`: EVM execution, fork database, fuzz input/mutator, corpus, seed ingestion,
  feedback, traces, ABI fetching, snapshots, and economic views.
- `src/engine`: campaign orchestration, scoring, concolic hints, benchmark validation,
  seed intelligence, protocol modeling, promotion, proof records, minimization,
  invariant manifests, bytecode analysis, actor modeling, and exploit synthesis.
- `src/common`: shared types, replay verifier, reporting, notification, and oracle APIs.
- `src/common/oracle`: protocol oracle packs for DeFi, security, governance, MEV,
  SVM-labeled findings, and protocol invariants.
- `src/satori`: source ingestion, static analysis packets, reasoning client/prompt
  plumbing, memory, reporting, validation, and job pipeline.
- `src/hybrid`: taint, concolic, and differential stubs/experiments.
- `src/chain`: chain interface abstractions.
- `src/svm`: quarantined Solana/SVM prototype code. It is not built by the supported
  feature policy.
- `src/sgx`: explicit unsupported SGX status shim.

## Tests And Fixtures

- Library unit tests live throughout `src/**`.
- Integration and benchmark-style tests:
  - `tests/benchmarks.rs`
  - `tests/end_to_end_smoke.rs`
- Satori Solidity fixtures:
  - `tests/fixtures/satori/*.sol`
  - `tests/fixtures/smoke_vault.abi.json`
- Benchmark manifests and JSON fixtures:
  - `benchmarks/live`
  - `benchmarks/blind`
  - `benchmarks/historical`
  - `benchmarks/historical/known_vulnerable`
  - `benchmarks/realistic`
  - `benchmarks/forked`

## Workflows

- `.github/workflows/ci.yml` runs formatting, clippy, check, unit tests,
  integration tests, sanitizer tests, release benchmark tests, and build jobs.
  It checks supported optional features and asserts that `svm` fails with the
  explicit unsupported-feature policy.
- `.github/workflows/rust.yml` runs a simple build and full test job.

## Current Support Status

- EVM: supported default engine. `cargo check`, `cargo test --lib`, and
  full `cargo test` pass.
- Z3: optional solver feature. `cargo check --features z3` passes.
- SGX: not implemented. `cargo check --features sgx` compiles a small module
  that reports unsupported status and fails closed at runtime.
- SVM: unsupported and quarantined. `cargo check --features svm` intentionally
  fails with a single compile-time message instead of compiling stale prototype
  code. The code under `src/svm` is retained for future reconstruction but is
  not part of the working support surface.

## Verified Commands

These commands passed after the Phase 1 repair:

- `cargo fmt --all -- --check`
- `cargo check`
- `cargo test --lib`
- `cargo test`
- `cargo check --features z3`
- `cargo check --features sgx`

This command intentionally fails by policy:

- `cargo check --features svm`

## Working Components

- EVM fork database with offline cache snapshots and bounded RPC budget.
- EVM execution through revm with coverage, dataflow, storage, and call-trace capture.
- Persistent corpus for inputs, fork cache, mainnet seed bundles, and campaign artifacts.
- ABI ingestion, bytecode analysis, seed intelligence, benchmark validation, and Satori
  static-analysis packet generation.
- Protocol oracle packs and benchmark fixtures with unit/integration coverage.
- Replay, minimization, promotion, proof records, and PoC scaffold generation exist.

## Implemented Audit Repairs

- Exploration execution and proof execution are now separate modes. Exploration may use
  synthetic funding and bounded value. Proof execution does not fund callers, does not cap
  value, replays deterministically, and returns explicit rejection reasons.
- `SnapshotCorpus` can insert meaningful post-transaction snapshots as first-class fuzz
  states, score them, and prune them to a bounded size. Unit coverage proves runtime corpus
  growth beyond the initial snapshot.
- Live seed discovery captures top-level target transactions, logs, calldata address hints,
  and mocked/tested `debug_traceBlockByNumber` callTracer internal calls. Provider-specific
  trace shapes beyond callTracer need more fixtures.
- Finding lifecycle status is now `Lead | Replayed | Minimized | Proved | Rejected`.
- CI is aligned with the real feature policy and no longer runs unsupported `--all-features`
  builds.

## Remaining Technical Gaps

- Proof mode is wired into promotion, but existing oracle packs still need systematic
  precondition and false-positive-rule hardening.
- PoC/report generation exists as scaffolded output, but it is not yet a complete Foundry
  exploit test generator for every proved finding class.
- Snapshot scoring uses available coverage/state/delta signals; broader branch-distance and
  oracle-proximity metrics still need deeper executor/oracle integration.
- Seed ingestion handles callTracer-style debug traces; more provider-specific trace
  fixtures are needed before claiming broad live-RPC compatibility.
