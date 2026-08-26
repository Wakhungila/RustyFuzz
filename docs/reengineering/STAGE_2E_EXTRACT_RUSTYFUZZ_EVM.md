# Stage 2E: Extract rustyfuzz-evm

Status: COMPLETE for review.

## What Moved

New production crate `crates/rustyfuzz-evm` (dependency direction enforced by
cargo: `rustyfuzz-core <- rustyfuzz-evm <- root fuzzer`):

| Module | Origin | Contents |
| --- | --- | --- |
| `transaction.rs` | `src/common/types.rs` | `SingletonTx` + `to_revm_tx_env` |
| `execution.rs` | `src/common/types.rs` | `ChainState`, `TxExecutionResult`, `SequenceExecutionResult`, `StorageAccess/Diff`, `CallObservation/Kind/Phase`, `OracleObservation`, `Waypoint` (+`TaintSource`, `SymbolicExpression`, `ComparisonOperand`), waypoint-limit consts |
| `fork_db.rs` | moved verbatim | `ForkDb`, `EvmCacheDb`, fork cache snapshots |
| `inspector.rs` | moved verbatim | `CoverageInspector`, `MAP_SIZE` |
| `dataflow.rs` | moved verbatim | `DataflowRegistry` |
| `executor.rs` | moved verbatim | `EvmExecutor`, `ExecutionMode` |
| `coverage.rs` | split from monolith feedback | `stable_path_hash` (+bucket helper), byte-identical hashing |

The two unit tests that lived inside the moved files continue to run under
`rustyfuzz-evm` (2 passed).

## Compatibility Strategy

- Root `src/evm/{executor,fork_db,inspector,dataflow}.rs` are now one-line
  re-export shims (`pub use rustyfuzz_evm::<module>::*;`) so all
  `crate::evm::…` call sites compile unchanged (`TODO(stage-4)` removal).
- `src/common/types.rs` re-exports the moved domain types so
  `crate::common::types::SingletonTx/Waypoint/...` keep compiling
  (`TODO(stage-2f/4)` removal).
- Monolith's `EvmCoverageFeedback::stable_path_hash` delegates to
  `rustyfuzz_evm::coverage::stable_path_hash`; persisted hashes unchanged.

## Semantics Preserved

Executor/fork/inspector code moved without modification except import paths.
Exploration caller funding, proof-mode strictness, value bounding, gas policy,
TxEnv construction: untouched. `ExecutionRequest/Context/Observation` API
reshaping deliberately deferred; no behavior churn.

## Dependency Audit

```text
cargo tree -p rustyfuzz-evm --depth 1
├── anyhow, bitvec, hex, parking_lot, reqwest, revm v38.0.0, serde, serde_json
└── rustyfuzz-core

cargo tree -i rustyfuzz-core -> rustyfuzz-evm -> rusty-fuzz (acyclic)
```

`rustyfuzz-core` remains dependency-neutral (serde, thiserror only).

## Gates

Stable gate PASS (fmt/check/test/clippy -D warnings/build release/doc/release
benchmarks). lib 201 · bins 4 · benchmarks 38+1 ign · smoke 1 · core 17 ·
evm 2. `git diff --check` clean.

## Known Risks / Debt

- `reqwest` lives in `rustyfuzz-evm` because `ForkDb` fetches remote state;
  a later stage should make RPC/fork configuration an injected provider so
  offline builds can drop it cleanly.
- Compat shims remain until consumers migrate; tracked as TODO(stage-2f/4).
