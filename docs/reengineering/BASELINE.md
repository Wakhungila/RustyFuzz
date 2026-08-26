# RustyFuzz Stage 0 Baseline

Date: 2026-08-26
Repository path: `/home/pin0ccs/Desktop/RustyFuzz`
Commit inspected: `9caf67d528ce3e824c29dae6050726150d2c6a2f`

Stage 0 scope only. No workspace refactor or production Rust behavior change was made. The original Stage 0 baseline is preserved below, with Stage 0.5 stabilization updates recorded explicitly.

## Toolchain

Local active toolchain:

```text
rustc 1.97.1 (8bab26f4f 2026-07-14)
host: x86_64-unknown-linux-gnu
LLVM version: 22.1.6

cargo 1.97.1 (c980f4866 2026-06-30)
os: Ubuntu 26.4.0 (resolute) [64-bit]

rustup active toolchain:
stable-x86_64-unknown-linux-gnu (default)
```

Stage 0 observation: no `rust-toolchain.toml` or `rust-toolchain` file was checked in. Installed local toolchains observed then: stable, 1.79.0, 1.89.0, 1.89.0-sbpf-solana-v1.54, 1.93.0.

Stage 0.5 update:

```text
rust-toolchain.toml added:
  channel = "1.97.1"
  profile = "minimal"
  components = ["rustfmt", "clippy"]

rustup active toolchain:
1.97.1-x86_64-unknown-linux-gnu (overridden by rust-toolchain.toml)
```

Pinned sanitizer toolchain:

```text
nightly-2026-08-01-x86_64-unknown-linux-gnu
rustc 1.99.0-nightly (ad3d0bc14 2026-07-31)
```

## Stage 0.5 Stabilization Results

Date: 2026-08-26

| Command | Result | Notes |
| --- | --- | --- |
| `cargo fmt --all -- --check` | pass | Pinned Rust 1.97.1. |
| `cargo check --workspace` | pass | Finished in about 6s. |
| `cargo test --workspace` | pass | 181 lib tests, 4 binary tests, 38/39 benchmark integration tests with 1 ignored, 1 smoke test, 1 doctest. |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass | Clippy warning-denied gate is now green. |
| `cargo build --workspace --release` | pass | Finished in about 52s. |
| `cargo doc --workspace --no-deps` | pass | Generated local docs under `target/doc`. |
| `cargo test --test benchmarks --release` | pass | 38 passed, 1 ignored. |
| `cargo check --features z3` | pass | Supported optional proof feature. |
| `cargo check --features llm` | pass | Optional Satori/LLM path compiles. |
| `cargo check --features notifier` | pass | Optional notifier path compiles. |
| `cargo check --features sgx` | pass | Unsupported SGX shim still compiles. |
| `cargo check --features svm` | intentional fail | Crate-root compile guard preserves unsupported status. Stage 0 observed that enabling the feature can still resolve/build optional Solana dependencies before the guard in a cold build. |
| `cargo check --no-default-features` | expected fail | Current monolith has EVM/Alloy/REVM references outside coherent feature isolation. Deferred to Stage 2 core/workspace extraction. |
| `python3 -c 'import pathlib, yaml; ...'` | pass | PyYAML 6.0.3 parsed `.github/workflows/ci.yml` and `.github/workflows/rust.yml`. |
| `env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std` | pass | 181 library tests passed under the pinned nightly sanitizer configuration. |

## Cargo Feature Matrix

| Feature / Command | Result | Notes |
| --- | --- | --- |
| `default = ["evm"]` | pass | Default supported build target is EVM. |
| `cargo check --workspace` | pass after dependency resolution | First sandboxed run failed because `index.crates.io` DNS was blocked; re-run with approved Cargo network access passed. Fresh offline CI is not guaranteed unless dependencies are cached/vendor-managed. |
| `cargo build --workspace` | pass | Debug build passed. |
| `cargo build --workspace --release` | pass | Release build passed in about 2m31s locally. |
| `cargo test --workspace` | pass | 181 lib tests, 4 main tests, 38/39 `tests/benchmarks.rs` tests with 1 ignored, 1 smoke test, 1 doctest. |
| `cargo test --test benchmarks --release` | pass | 38 passed, 1 ignored. |
| `cargo doc --workspace --no-deps` | pass | Generated local docs under `target/doc`. |
| `cargo check --features z3` | pass | Downloaded `z3`/`z3-sys`; local environment could build it. |
| `cargo check --features sgx` | pass | Only compiles the unsupported SGX status shim. |
| `cargo check --features llm` | pass | Compiles optional reqwest-backed Satori path. |
| `cargo check --features notifier` | pass | Compiles optional Discord notifier path. |
| `cargo check --features svm` | intentional fail | After downloading/building a large Solana dependency graph, fails with the crate-root compile error saying SVM is intentionally unsupported. |
| `cargo check --no-default-features` | fail | About 130 unresolved REVM/Alloy/EVM imports; non-EVM build is not coherent. |
| `--all-features` | not run | Expected to fail because it includes intentionally unsupported `svm`. |

Repeated future-incompatibility warning observed on passing cargo commands:

```text
the following packages contain code that will be rejected by a future version of Rust:
proc-macro-error2 v2.0.1
```

## Stage 0 Command Results (Historical)

```text
cargo fmt --all -- --check
result: pass

cargo check --workspace
result: pass after approved network dependency resolution

cargo build --workspace
result: pass

cargo build --workspace --release
result: pass

cargo test --workspace
result: pass
details:
  lib: 181 passed
  main binary tests: 4 passed
  tests/benchmarks.rs: 38 passed, 1 ignored
  tests/end_to_end_smoke.rs: 1 passed
  doctests: 1 passed

cargo test --test benchmarks --release
result: pass
details: 38 passed, 1 ignored

cargo doc --workspace --no-deps
result: pass

cargo clippy --workspace --all-targets -- -D warnings
result: fail
```

## Stage 0 Clippy Failures (Resolved In Stage 0.5)

At Stage 0, `cargo clippy --workspace --all-targets -- -D warnings` failed. The first run reported 32 library errors and the lib-test target reported 36 after duplicate target checking. These were mostly mechanical lints.

Failing files/classes:

- `src/engine/abi_ingest.rs`: `unnecessary_sort_by`.
- `src/engine/bounded_search.rs`: `unnecessary_sort_by`.
- `src/engine/bytecode_analysis.rs`: `redundant_closure`, `manual_range_patterns`.
- `src/engine/control_flow.rs`: `if_same_then_else`.
- `src/common/verifier.rs`: `items_after_test_module`.
- `src/engine/exploit_synthesizer.rs`: `collapsible_match`.
- `src/engine/fork_setup.rs`: `unnecessary_sort_by`.
- `src/engine/fuzz_engine.rs`: `too_many_arguments`, `question_mark`, `redundant_closure`, test-only `field_reassign_with_default`.
- `src/engine/ordering_mutations.rs`: `unnecessary_cast`.
- `src/engine/permission_model.rs`: `unwrap_or_default`, `collapsible_if`.
- `src/engine/protocol_model.rs`: `unnecessary_sort_by`.
- `src/engine/scoring.rs`: `collapsible_match`.
- `src/engine/exploit_path.rs`: `items_after_test_module`.
- `src/engine/seed_intelligence.rs`: `unnecessary_sort_by`.
- `src/engine/state_machine_inference.rs`: `clone_on_copy`.
- `src/engine/state_transition_checker.rs`: `unnecessary_map_or`.
- `src/engine/temporal_constraints.rs`: `unused_enumerate_index`, `unnecessary_cast`, `collapsible_if`.
- `src/evm/economic.rs`: `unwrap_or_default`, `new_without_default`.
- `src/evm/fuzz.rs`: `collapsible_match`.
- `src/hybrid/taint.rs`: `collapsible_match`.
- `src/satori/ingest/project.rs`: `ptr_arg`.

No production Rust lint fixes were made in Stage 0. Stage 0.5 fixed these lints mechanically without workspace refactoring or intended fuzzing-semantic changes; the warning-denied Clippy gate now passes.

## CI Review

Workflows present:

- `.github/workflows/ci.yml`
- `.github/workflows/rust.yml`
- `tests/ci.yml` exists but is not an active GitHub workflow.

Stage 0 CI repair applied, superseded by the Stage 0.5 pinned-nightly update:

- The sanitizer job in `.github/workflows/ci.yml` previously installed stable Rust and ran `RUSTFLAGS=-Zsanitizer=address`.
- It was changed to install nightly and run:

```text
cargo +nightly test --lib --target x86_64-unknown-linux-gnu -Zbuild-std
RUSTFLAGS=-Zsanitizer=address
```

Current CI status after Stage 0.5:

1. Mandatory stable local gates are green under pinned Rust 1.97.1.
2. `.github/workflows/ci.yml` now runs `cargo clippy --workspace --all-targets -- -D warnings`.
3. Normal CI jobs are pinned to Rust 1.97.1.
4. The sanitizer job is pinned to `nightly-2026-08-01` and the equivalent local ASan library test passed.
5. `.github/workflows/rust.yml` still duplicates part of `ci.yml`; proposed consolidation is deferred to Stage 1.
6. Default fresh builds require crates.io access unless dependencies are already cached/vendor-managed.
7. `cargo check --features svm` intentionally fails; cold builds may still resolve/download optional Solana dependencies before reaching the compile guard.
8. `cargo check --no-default-features` fails because common/engine/EVM modules are not correctly feature-isolated. This is an expected current monolith limitation.
9. YAML syntax was validated locally with Python/PyYAML 6.0.3.

Do not claim CI is healthy until the mandatory jobs pass under the intended toolchains.

## Current Module Sizes

Total Rust source measured: 47,786 lines.

Area totals by inspection:

| Area | Approx. Lines | Notes |
| --- | ---: | --- |
| `src/engine/**` | ~26,178 | Largest and most coupled area; campaign, benchmark, scoring, proof, seed, model, and analysis code are mixed. |
| `src/evm/**` | ~10,260 | EVM executor, fork DB, corpus, mutator, feedback, seed ingestion, traces. |
| `src/satori/**` | ~2,633 | AI/static analysis/reporting pipeline. |
| `src/common/**` | ~4,220 | Shared types, verifier, reports, oracle packs. |
| `src/main.rs` | 1,993 | CLI command implementations are too large for a thin binary. |
| `src/bin/benchmark.rs` | 543 | Benchmark orchestration and child process runner. |
| `src/hybrid/**` | 1,228 | Experimental taint/differential/concolic. |
| `src/svm/**` | 586 | Unsupported SVM prototype. |
| `src/sgx/mod.rs` | 25 | Unsupported shim. |

Largest files:

| File | Lines |
| --- | ---: |
| `src/engine/benchmark.rs` | 4,263 |
| `src/engine/fuzz_engine.rs` | 3,044 |
| `src/evm/corpus.rs` | 2,199 |
| `src/main.rs` | 1,993 |
| `src/engine/bytecode_analysis.rs` | 1,487 |
| `src/engine/economic_delta.rs` | 1,451 |
| `src/engine/promotion.rs` | 1,402 |
| `src/evm/fuzz.rs` | 1,324 |
| `src/engine/seed_intelligence.rs` | 1,295 |
| `src/evm/seed_ingester.rs` | 1,234 |
| `src/common/oracle/packs.rs` | 1,153 |
| `src/engine/scoring.rs` | 1,060 |
| `src/engine/fork_setup.rs` | 1,044 |
| `src/engine/protocol_model.rs` | 1,029 |
| `src/evm/inspector.rs` | 937 |
| `src/engine/bounded_search.rs` | 828 |
| `src/common/oracle/protocol_invariants.rs` | 805 |
| `src/engine/target_profile.rs` | 815 |
| `src/engine/invariant_manifest.rs` | 712 |
| `src/engine/dependency.rs` | 692 |

## Runtime And Artifact Layout

Current configured/default runtime paths:

```text
config.toml.example:
  corpus_dir = "corpus"
  report_dir = "reports"
  abi_cache_dir = "corpus/abi"

satori/config.example.toml:
  cache_dir = "satori/cache"
  memory_path = "satori/memory/events.jsonl"
```

`PersistentCorpus::new(root)` currently creates:

```text
<root>/
  inputs/
  crashes/
  fork_cache/
  mainnet_seeds/
  campaign_artifacts/
    index/
    summaries/
```

Other current artifact paths:

```text
<root>/snapshots/*.manifest.json
reports/
reports/benchmarks/
satori/runs/<run-id>/
satori/cache/
satori/memory/events.jsonl
satori/reports/
saved-runs/*.tar.gz
/tmp/rustyfuzz-daedaluzz/<artifact>-<idx>/{corpus,reports}
```

There is no single `RunLayout` owner. Paths are reconstructed in `src/main.rs`, `src/evm/corpus.rs`, `src/engine/promotion.rs`, `src/engine/benchmark.rs`, `src/bin/benchmark.rs`, and Satori filesystem utilities.

## Generated / Historical Data Inventory

Observed directory sizes:

```text
audits/      4.6M
saved-runs/ 284K
satori/      60K
benchmarks/ 144K
tests/      108K
docs/       108K
src/        2.1M
target/     7.4G local build output
```

Tracked non-source runtime/historical content includes:

- `audits/coinbase-cantina/**`: audit scope, target metadata, foundry fixtures, seed corpus, bytecode/ABI, logs including explorer HTML.
- `saved-runs/*.tar.gz`: previous campaign archives.
- `satori/{runs,reports,cache,packets,jobs,memory}` with `.gitkeep` placeholders plus Satori config/README.
- `benchmarks/{historical,live,blind,daedaluzz}` manifests and small fixtures.

Migration plan:

- Keep deterministic fixtures required by tests.
- Move historical audit material and saved campaign archives outside the product source tree or behind an explicit dataset/artifact import process.
- Route future runtime output into one versioned `.rustyfuzz/runs/<run-id>/` layout.
- Keep live-RPC benchmark fixtures optional and outside default CI.

## Known Functional / Architecture Failures

1. `EvmInput` already has `base_snapshot_id`, but still embeds `waypoints` and `mutation_provenance`. Current input hashes are derived from full serialized input in `PersistentCorpus`, so semantic identity can change when feedback/metadata changes.
2. `common::types` is not core-clean: it depends on `evm::fork_db`, REVM types, and reexports `EvmInput`.
3. There are duplicate finding lifecycle models:
   - `common::oracle::FindingStatus::{Lead,Replayed,Minimized,Proved,Rejected}`
   - `engine::promotion::FindingLifecycleStage::{Candidate,Replayed,Minimized,PocGenerated,Confirmed,Rejected}`
   - `docs/IMPLEMENTATION_STATUS.md` still describes `Signal/Candidate/Confirmed/Rejected`.
4. Oracle output is often heuristic `VulnType` or `ProtocolFinding`, not a typed evidence signal with strict proof policy.
5. `engine::fuzz_engine` and `src/main.rs` are monolithic and mix CLI, filesystem, ABI discovery, RPC setup, fuzz worker, scoring, artifact persistence, oracle evaluation, and promotion.
6. Artifact layout is manually reconstructed in multiple modules and lacks versioned schema ownership.
7. Satori has useful architecture but is hardcoded around an `O3Client`, `OPENAI_API_KEY`, and after-the-fact token counting. No provider boundary or enforceable pre-request budget exists.
8. SVM and SGX are not production backends. SVM is intentionally compile-blocked; SGX compiles only an unsupported shim.
9. No-default-feature builds fail; feature isolation is incomplete.
10. Stage 0 Clippy failures were resolved in Stage 0.5; `cargo clippy --workspace --all-targets -- -D warnings` now passes.

## Benchmark Commands

Observed or current benchmark-related commands:

```bash
cargo test --test benchmarks
cargo test --test benchmarks --release
cargo run --bin benchmark -- <artifacts-dir> --max-execs 50000 --timeout-secs 300
cargo run -- validate --benchmarks <manifest-or-dir> --output <report.json>
```

Current release benchmark smoke result:

```text
cargo test --test benchmarks --release
38 passed, 1 ignored
```

No performance improvement claims were made. No executions/sec or time-to-bug baseline was generated beyond existing benchmark tests.

## Stage 0 Working Set

Files changed in Stage 0:

- `.github/workflows/ci.yml`
- `docs/reengineering/CODEBASE_INVENTORY.md`
- `docs/reengineering/BASELINE.md`

Architectural change:

- None to production Rust architecture.
- CI sanitizer job now uses nightly for nightly-only sanitizer flags.

Behavioral change:

- No runtime behavior change to RustyFuzz.

Remaining risks:

- CI still not green because clippy is red under the required command.
- Sanitizer workflow patch was not executed locally because nightly is not installed.
- YAML parsing validation was not run because no local YAML parser tool was available.
- Fresh offline builds are not reproducible without cached/vendor dependencies.

## Stage 0.5 Working Set

Files changed in Stage 0.5:

- `rust-toolchain.toml`
- `.github/workflows/ci.yml`
- `.github/workflows/rust.yml`
- mechanical Clippy fixes in production, binary, and test Rust files
- `docs/reengineering/BASELINE.md`
- `docs/reengineering/STAGE_0_5_STABILIZATION.md`

Behavioral-risk assessment:

- Clippy changes were local/mechanical: sorting helper replacements, redundant closure removal, range pattern simplification, default initialization cleanup, test-module ordering, `Option` `?`, `or_default`, `is_none_or`, copy-value dereference, print literal formatting, and a private telemetry record struct replacing a long private function argument list.
- No workspace refactor, module migration, input-model redesign, SVM resurrection, or `no-default-features` repair was performed.

Readiness decision:

- Stage 0.5 mandatory stable gates are green.
- Proceed to Stage 1 only after review.

Next stage after review:

- Stage 1 should fix repository hygiene and documentation contradictions only after reviewing this baseline and inventory.
- Stage 2 should then extract core semantic types and fix `EvmInput` identity semantics.
