# Stage 2B Input Usage Map

Status: COMPLETE pre-edit map. Created before modifying `EvmInput`.

## Current EvmInput Fields

| Field | Execution-defining | Feedback | Mutation input | Scheduling | Replay | Persistence | Artifact identity | Migration destination |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `txs` | yes | no | yes | indirectly through scoring | yes | yes | yes | remain in semantic `EvmInput` |
| `base_snapshot_id` | yes | no | yes | snapshot selection | yes | yes | yes | remain in semantic `EvmInput`; keep field name for schema stability |
| `waypoints` | no | yes | yes, concolic mutators read it | no direct scheduler policy | no, replay uses execution-produced waypoints | yes today via full input JSON | yes today by accident | `EvmTestcaseMetadata` / metadata store / sidecar persistence |
| `mutation_provenance` | no | provenance metadata | yes, economic objective mutator reads goal tags | telemetry only | no | yes today via full input JSON | yes today by accident | `EvmTestcaseMetadata` / metadata store / sidecar persistence |

## Usage Records

| File | Function/type | Access | Purpose | Execution-defining | Feedback | Mutation | Scheduling | Replay | Persistence | Artifact identity | Migration destination |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `src/evm/fuzz.rs` | `EvmInput` struct | READ/WRITE/DERIVE | LibAFL input currently mixes transactions, snapshot id, waypoints, provenance, `Hash`, `Eq`, serde | partial | yes | yes | indirect | yes | yes | yes | semantic `EvmInput`; metadata moves to `EvmTestcaseMetadata` |
| `src/evm/fuzz.rs` | `Input::generate_name`, `HasLen`, `validate` | READ | Names and limits from snapshot id and tx bytes | yes | no | no | no | no | no | no | remain on semantic `EvmInput` |
| `src/evm/fuzz.rs` | `apply_waypoint_backpressure` | WRITE | Truncates feedback to memory limits | no | yes | yes | no | no | no | no | move to `EvmTestcaseMetadata::apply_waypoint_backpressure` |
| `src/evm/fuzz.rs` | `concolic_mutation` | READ `waypoints` / WRITE provenance | Uses comparison/dataflow waypoints to repair calldata/caller/value | no | yes | yes | no | no | no | no | read/write metadata from `EvmTestcaseMetadataStore` |
| `src/evm/fuzz.rs` | `concolic_sequence_synthesis` | READ `waypoints` / WRITE provenance | Inserts solver-backed transaction after hinted tx | no | yes | yes | no | no | no | no | read/write metadata from `EvmTestcaseMetadataStore` |
| `src/evm/fuzz.rs` | `economic_objective_mutation` | READ `mutation_provenance` | Reads `goal_*` objective tags to bias calldata/value/caller | no | no | yes | no | no | no | no | read objective tags from metadata |
| `src/evm/fuzz.rs` | other mutation strategies / `record_mutation` | WRITE `mutation_provenance` | Records selected strategy and details | no | provenance | yes | telemetry | no | no | no | write to metadata store after mutation |
| `src/engine/flashloan.rs` | `FlashLoanTemplate::wrap_sequence` | WRITE provenance | Adds flashloan template provenance while replacing sequence | no | provenance | yes | no | no | no | no | return semantic input only; mutator records provenance in metadata |
| `src/engine/fuzz_engine.rs` | LibAFL state aliases and corpus setup | READ/WRITE `EvmInput` | `InMemoryCorpus<EvmInput>` and `Testcase::new` for seeds | `txs`, `base_snapshot_id` | no | yes | scheduler owns corpus entries | yes | no | no | keep LibAFL input type semantic; add shared metadata store for mutation/harness telemetry |
| `src/engine/fuzz_engine.rs` | harness closures | READ `base_snapshot_id`, `txs` | Select snapshot and execute tx sequence | yes | execution emits separate waypoints | no | no | yes | no | no | semantic input remains; execution waypoints written to metadata store after execution |
| `src/engine/fuzz_engine.rs` | `mutation_strategies` | READ provenance | Telemetry strategy mix | no | provenance | no | telemetry | no | no | no | read from metadata store; default remains `seed_or_imported` |
| `src/engine/fuzz_engine.rs` | snapshot insertion | READ input clone | Stores producing input in snapshot | yes | should not include feedback | no | snapshot corpus | replay lineage | no | no | store semantic `EvmInput` only |
| `src/evm/corpus.rs` | `persist_input` | READ full serialized input | Generates input hash/id and writes input JSON | should be semantic only | currently yes by accident | no | no | replay load | yes | yes | use `EvmInput::semantic_input_id`; write semantic input + metadata sidecar |
| `src/evm/corpus.rs` | `persist_execution_input` | READ full serialized input and execution | Generates input hash/id, frontier metadata | should be semantic only | execution feedback separate | no | no | replay load | yes | yes | canonical semantic ID; persist execution waypoints in testcase metadata sidecar |
| `src/evm/corpus.rs` | `load_input` | READ persisted input JSON | Replay/promotion compatibility | yes | legacy files may contain feedback | no | no | yes | yes | no | legacy loader converts to semantic input; `load_testcase_metadata` preserves old fields |
| `src/evm/corpus.rs` | `write_reproduction_report` | READ full serialized input | Report id and displayed hash | yes | currently yes by accident | no | no | yes | report | report id | use canonical semantic input ID |
| `src/evm/corpus.rs` | `artifact_equivalence_components` | READ full serialized input | Campaign artifact dedup key | yes | currently yes by accident | no | no | no | yes | yes | use canonical semantic sequence hash |
| `src/evm/corpus.rs` | `SnapshotCorpus::maybe_add_post_execution_snapshot` | READ input clone | Stores producing input and execution waypoints | input clone yes | execution waypoints yes | no | snapshot scoring | lineage | no | no | producing input becomes semantic; snapshot waypoint field remains execution feedback |
| `src/evm/corpus.rs` | `update_snapshot_metadata_from_execution` | READ producing input txs | Selector novelty from snapshot ancestry | yes | no | no | snapshot scoring | no | no | no | unchanged; producing input semantic is sufficient |
| `src/evm/seed_ingester.rs` | `MainnetSeed` and `stable_seed_id` | READ persisted seed input | Seed bundle input and seed id | yes | currently empty feedback | no | startup corpus | replay seed | yes | seed identity | use canonical semantic input bytes/hash plus seed metadata |
| `src/engine/seed_intelligence.rs` | `SeedCandidate::into_evm_input` / historical windows | WRITE provenance | Seed source and historical-sequence provenance | input yes | provenance | mutation/telemetry | no | replay seed | no | no | add parts-returning helper with semantic input + metadata |
| `src/engine/dependency.rs` | `dependency_sequence_score` | READ provenance | Rewards dependency-template provenance | no | provenance | scoring helper | score component | no | no | no | accept metadata-aware variant; keep semantic flow scoring |
| `src/engine/dependency.rs` | flow template builders/tests | WRITE/READ provenance | Marks known ordered flows | no | provenance | seed/template quality | score component | no | no | no | return/register metadata beside semantic inputs |
| `src/engine/bounded_search.rs` | `annotate_objectives` | WRITE provenance | Adds `goal_*` objective tags used later by economic mutator | no | provenance | yes | objective score | no | no | no | write to metadata attached to generated candidates |
| `src/engine/minimizer.rs` | `minimize_crash_to_foundry_poc` | READ input txs / persist minimized | Replay and persistence | yes | no | no | no | yes | yes | input id | persist semantic ID; no feedback needed |
| `src/engine/promotion.rs` | `promote_finding_artifact` | READ `load_input` result | Replay/minimize/proof workflow | yes | no | no | no | yes | yes | no | legacy loader returns semantic input |
| `src/engine/exploit_synthesizer.rs` | PoC file hash | READ full serialized input | Foundry test file name | yes | currently yes by accident | no | no | PoC replay | report | name hash | use canonical semantic input hash |
| `src/engine/benchmark.rs` | benchmark synthetic inputs | WRITE empty metadata fields | Fixtures and known-bug inputs | mostly yes | no | no | no | replay | no | no | update constructors; preserve explicit metadata where assertions require it |
| `tests/benchmarks.rs` | corpus/replay/snapshot tests | READ/WRITE old fields | Regression fixtures and artifact assertions | mixed | yes in specific tests | yes in mutator/corpus tests | yes in scoring tests | yes | yes | yes | update to semantic input plus metadata/legacy fixtures |
| `src/common/verifier.rs`, `src/engine/proof.rs`, `src/engine/economic_delta.rs`, `src/engine/protocol_model.rs`, `src/engine/scoring.rs`, `src/engine/scheduler.rs`, `src/engine/fork_setup.rs`, `src/evm/economic_views.rs` | test/input construction | WRITE mostly empty fields | Local unit fixtures | yes | no | no | no | yes in verifier/proof | no | no | remove feedback fields from semantic input literals |

## Migration Choice

Stage 2B will keep LibAFL's input type as `EvmInput` to avoid a broad engine
type rewrite. `EvmInput` will become semantic-only. EVM-specific feedback and
provenance will move to `EvmTestcaseMetadata` and, where LibAFL does not expose
testcase metadata directly to the current mutator/harness paths, a temporary
`EvmTestcaseMetadataStore` keyed by canonical semantic `InputId`.

This is a compatibility bridge, not the final engine design.

```text
TODO(stage-4): move EVM testcase metadata into LibAFL testcase/state metadata
or explicit mutation context when campaign/worker boundaries are split.
```

## Required Preservation Points

- Concolic mutation must still receive waypoint guidance.
- Economic objective mutation must still receive `goal_*` provenance tags.
- Mutation strategy telemetry must still report provenance when available.
- Legacy serialized inputs must split old feedback fields into metadata.
- New input identity must hash only `base_snapshot_id` and `txs`.
- Snapshot `producing_input` must store semantic executable input only.

## Stage 2B.1 Addendum — SingletonTx Field Classification

Audit of `src/common/types.rs` (`SingletonTx`) and `src/evm/executor.rs`
(`EvmExecutor::execute_with_result` -> REVM `TxEnv` construction):

| Field | Class | Evidence |
| --- | --- | --- |
| `input` (calldata) | A. EVM EXECUTION DEFINING | passed to `TxEnv.data` |
| `caller` | A. EVM EXECUTION DEFINING | passed to `TxEnv.caller`; also funds/nonce read |
| `to` | A. EVM EXECUTION DEFINING | selects `TxKind::Call(to)` vs `TxKind::Create` when zero |
| `value` | A. EVM EXECUTION DEFINING | passed to `TxEnv.value` (mode-bounded in exploration) |
| `is_victim` | B. FUZZING/ANALYSIS METADATA | never referenced by executor/TxEnv; consumed by MEV oracle (`common/oracle/mev.rs`), economic-delta attacker/victim split (`engine/economic_delta.rs`), actor role assignment (`engine/actors.rs`) |

Decision: `is_victim` stays in `SingletonTx` as a compatibility bridge
(Stage 2C+ owns transaction-role metadata extraction) but is **excluded from
semantic InputId v1** and from any claim of semantic identity. Derived
`Hash/Eq` on `EvmInput` remains *structural* equality; canonical persisted /
corpus identity is exclusively `EvmInput::semantic_input_id()`. Both facts are
enforced by tests:

- `evm::fuzz::tests::is_victim_role_marker_does_not_change_semantic_input_id`
- `common::verifier::tests::is_victim_role_marker_does_not_change_evm_execution`
  (same state, only the marker differs -> identical gas / coverage hash /
  storage diffs / call trace).
