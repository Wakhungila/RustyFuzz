# Stage 2F: Compatibility Cleanup

Status: COMPLETE for review.

## Shim Inventory And Disposition

| Shim | Location | Remaining consumers | Disposition this stage |
| --- | --- | --- | --- |
| `crate::evm::{executor,fork_db,inspector,dataflow}` module shims | were `src/evm/*.rs` | 36 call sites | **REMOVED**: all monolith/test consumers migrated to `rustyfuzz_evm::…` directly; shim files deleted |
| `rusty_fuzz::evm::X` external paths in `src/main.rs`, `tests/benchmarks.rs` | — | — | migrated to `rustyfuzz_evm::X` |
| `crate::common::types::*` domain re-exports (SingletonTx, Waypoint, execution results, ChainState, limits) | `src/common/types.rs` | broad (dozens of files) | **KEPT** with `TODO(stage-2e/4)`; removal requires domain-type path migration across all engine/oracle modules — scheduled for Stage 4 crate split where the churn is unavoidable anyway |
| core ID/ExecutionStatus re-exports in `common/types.rs` | `src/common/types.rs` | several | **KEPT**, `TODO(stage-2b)` noted for numeric/string identifier replacement (Stage 3 metadata work) |
| `EvmTestcaseMetadataStore` sidecar + `load_input` legacy wrapper | `src/evm/fuzz.rs`, `src/evm/corpus.rs` | harness/mutator | **KEPT**, `TODO(stage-4)`: requires LibAFL testcase-metadata integration and worker boundary split |
| `FindingStatus` / `FindingLifecycleStage` `canonical()` adapters | `oracle/mod.rs`, `promotion.rs` | pipeline | **KEPT**, `TODO(stage-4)`: consumers migrate when finding model extraction happens |

## Timeline

- v0.3 (Stage 4): remove `common/types.rs` domain re-export layer and
  lifecycle `canonical()` adapters as part of the crate extraction that makes
  their migration mandatory.
- v0.3+ (Stage 4): retire `EvmTestcaseMetadataStore` sidecar.

Legacy persisted-file readers are NOT shims and are retained indefinitely
while historical artifacts are supported (Stage 2B decision).

## Gates

Stable gate PASS after removal: fmt/check/test/clippy `-D warnings`;
lib 201 · bins 4 · benchmarks 38+1 ign · smoke 1 · core 17 · evm 2.
