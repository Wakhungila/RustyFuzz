# Stage 5: Engineering Hardening

Status: COMPLETE for review. Honest scope inside; measured numbers in
`docs/reengineering/V0_2_BENCHMARK_REPORT.md`.

## 5.1 Performance Benchmarks

Benchmark *infrastructure* is the existing `tests/benchmarks.rs` suite
(38 tests / release) covering corpus, replay, snapshot, mutator, and
end-to-end smoke workloads on synthetic deterministic state. Engineering
measurements recorded in the benchmark report; no performance claims are made
without a run logged with hardware/OS/commit.

## 5.2 Time-to-Bug Regression Fixtures

Covered by `tests/benchmarks.rs` blind-rediscovery paths over local
deterministic vulnerable fixtures (ERC20 mint inflation, ERC4626 share
inflation, AMM invariant, oracle manipulation classes) plus CI calibration
outputs. No live/network targets.

## 5.3 Fuzzer Reproducibility (documented contract)

- Deterministic mode: `--deterministic --rng-seed <seed>` seeds worker RNGs
  (`config.rng_seed + core_id`, see `campaign_rng_seed`). Manifest records
  the seed and `assumptions: ["deterministic=true"]`.
- Individual-input replay: `rusty-fuzz replay <id|file>` re-executes a
  persisted semantic input against its base snapshot / fork cache; verified
  by `verify_deterministic` (double replay equality).
- Campaign-level exact determinism under multi-core concurrency is NOT
  guaranteed (interleaved scheduling); stated honestly here and in README.

## 5.4 Corpus Management

Separated stores already: active LibAFL in-memory corpus, persistent input
corpus (`PersistentCorpus`, semantic ids), snapshot corpus with pruning,
crash/finding artifacts, fork cache. Historical datasets are read-only;
nothing rewrites tracked fixtures.

## 5.5 Crash Safety

Artifact writes go through temp+fsync+rename (`rustyfuzz-artifacts::fsutil`)
with tests proving no partial/temp residue and safe overwrite. Interrupted
runs leave either the previous manifest or none — never a corrupt one marked
complete.

## 5.6 CI

Legacy duplicate workflow `.github/workflows/rust.yml` REMOVED (it lacked
clippy gates, pins nothing, and duplicated ci.yml jobs). `ci.yml` now covers:
fmt/clippy -D warnings/check/tests, feature checks (z3/sgx; svm asserted to
fail intentionally), integration tests on PRs, per-crate sanitizer matrix
(root-lib/bins/benchmarks/core/engine/evm/artifacts), benchmark regression,
build matrix.

## 5.7 Feature Matrix

| Feature | Status |
| --- | --- |
| evm (default) | supported |
| z3 | optional, checked in CI |
| sgx | compile-only shim |
| llm | optional, gates Satori provider calls only |
| notifier | optional |
| svm | explicitly unsupported (compile error asserted in CI) |

## 5.8 no-default-features

DECISION: not supported at v0.2 — the root fuzzer/CLI fundamentally requires
the EVM backend (executor/fork handling are the product). Neutral crates DO
build independently: `cargo check -p rustyfuzz-core` and
`-p rustyfuzz-artifacts` (verified) carry no revm/libafl trees. This is
documented rather than forced for aesthetics.

## 5.9 Dependency Audit

- Per-crate `cargo tree` audited: core = serde+thiserror only; artifacts =
  serde/serde_json/log; engine = libafl/core/evm utilities; evm = revm stack.
- reqwest reaches rustyfuzz-evm via ForkDb remote fetching — improvement
  path noted in ADR debt (inject provider), not churned now.
- Future-incompat warnings: single transitive offender
  `proc-macro-error2 v2.0.1` (via thiserror-adjacent macro deps);
  upstream-owned, documented here.

## 5.10 Documentation

Docs updated through stages 0–5; architecture/trust/persistence claims now
match source. Remaining: README refresh at RC phase below.
