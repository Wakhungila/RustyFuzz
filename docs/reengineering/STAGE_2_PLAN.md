# Stage 2 Migration Plan

Status: TARGET plan with Stage 2A progress recorded.

Stage 2 is the first production architecture migration. It must proceed in
small, compilable steps and preserve the Stage 0.5 regression gate.

## Non-Goals

Stage 2 must not extract every target crate at once. It must not change EVM
execution behavior, scheduler policy, mutator behavior, oracle semantics, or AI
integration in the same patch as type extraction.

## Stage 2A - Extract `rustyfuzz-core`

Goal: create a stable, REVM-free domain crate.

Implementation progress:

- Stage 2A introduced `crates/rustyfuzz-core` as the only new production crate.
- The root `rusty-fuzz` package remains in place and now participates in the
  workspace.
- Strong IDs, typed core errors, neutral snapshot/testcase metadata skeletons,
  evidence references, and `ExecutionStatus` are present in `rustyfuzz-core`.
- `ExecutionStatus` is temporarily re-exported through `src/common/types.rs` so
  existing callers keep their public path.
- Semantic transaction/input reshaping was deliberately deferred to Stage 2B.
- Snapshot corpus, EVM executor, scheduler, mutators, oracles, Satori, and
  artifact layout were not changed.

Initial type families:

- strong IDs: `InputId`, `SnapshotId`, `CampaignId`, `OracleId`;
- semantic transaction/input shapes; deferred to Stage 2B except for ID
  destination types;
- execution status/result summaries that do not require REVM internals;
- snapshot metadata;
- finding/evidence skeletons;
- testcase metadata skeletons;
- typed public errors.

Rules:

- no REVM dependency;
- no LibAFL implementation dependency;
- no RPC/HTTP dependency;
- no AI provider dependency;
- no CLI framework dependency.

Compatibility bridge:

- keep existing monolith exports compiling while core types are introduced;
- move one type family at a time;
- run the full gate after each substantial move.

## Stage 2B - Separate Semantic Input From Metadata

Most important invariant:

```text
semantic input != execution feedback
```

Target semantic input:

```text
EvmInput
  base_snapshot_id
  transactions
```

Target metadata:

```text
TestcaseMetadata
  coverage
  waypoints
  comparison feedback
  mutation provenance
  state novelty
  scheduling score
  parent relationships
```

Target `InputId` rule:

```text
InputId = H(base_snapshot_id || canonical_transaction_sequence)
```

`InputId` must not change when coverage, waypoints, mutation provenance,
oracle signals, scores, or execution statistics change.

Required tests:

- same semantic input produces same `InputId`;
- mutating metadata does not change `InputId`;
- executing a testcase does not silently change its identity;
- existing serialized inputs have an explicit migration/compatibility path.

### Stage 2B Implementation Status (CURRENT)

Stage 2B is implemented; see
`docs/reengineering/STAGE_2B_INPUT_METADATA_SEPARATION.md`. Summary of deltas
from the plan above:

- Semantic input field names were kept as-is (`txs`, `base_snapshot_id`) for
  persisted-schema stability.
- Only EVM-relevant metadata was moved: `EvmTestcaseMetadata { waypoints,
  mutation_provenance }`. Coverage, comparison feedback, state novelty, and
  scheduler data keep their existing owners; no single giant metadata object
  was created.
- Concrete identity contract: `rustyfuzz-input-id-v1`, Keccak-256 over
  length-prefixed schema version, base snapshot id, and transaction sequence
  (documented in ADR 0003). Golden regression test pins an exact digest.
- Legacy compatibility: `LegacyEvmInputV1` + `EvmInput::split_legacy_json`;
  `PersistentCorpus::load_input_with_metadata` reads pre-separation files
  without discarding feedback. Historical corpus entries are not rewritten.
- Metadata ownership during campaigns is a temporary sidecar
  (`EvmTestcaseMetadataStore`) shared by harnesses and `EvmMutator`,
  marked `TODO(stage-4)`; scoring/mutator signatures take provenance
  explicitly to avoid feedback re-entering semantic identity through wrappers.

## Stage 2C - Snapshot Semantic Model

Goal: define snapshot identity, ancestry, and restoration contracts before
changing scheduler behavior.

Target snapshot fields:

- `snapshot_id`;
- state hash;
- parent snapshot id;
- producing input id;
- block/fork identity;
- execution assumptions;
- summary feedback dimensions.

Required tests:

- exact snapshot restoration;
- parent/producing-input ancestry can reconstruct sequences;
- snapshot hash is deterministic for the same state and environment.

## Stage 2D - Finding/Evidence Lifecycle Model

Goal: introduce one canonical lifecycle and typed evidence model.

Target lifecycle:

```text
Signal -> Candidate -> Replayed -> Minimized -> Proved
```

`Rejected` may occur from intermediate states.

Required tests:

- oracle signals cannot become proved findings directly;
- replay evidence survives serialization;
- minimization preserves the required finding predicate;
- proof mode rejects exploration-only assumptions.

## Stage 2E - Extract `rustyfuzz-evm`

Goal: move REVM-specific implementation behind explicit EVM request/context and
output types after core semantics are stable.

Candidate boundaries:

- executor;
- fork database;
- block environment;
- ABI handling;
- bytecode analysis;
- inspector/instrumentation;
- traces;
- EVM state representation.

Rules:

- preserve existing `EvmExecutor` behavior;
- keep exploration/proof distinction explicit;
- do not add a generic VM abstraction.

## Stage 2F - Compile/Test Compatibility Bridge

Goal: keep users working while the workspace emerges.

Bridge tactics:

- temporary reexports only where they avoid breaking existing CLI/tests;
- deprecation notices for moved APIs;
- no circular crate dependencies;
- no hidden behavior changes in compatibility shims.

## Validation After Each Substage

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

For larger moves also run:

```bash
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo test --test benchmarks --release
```

Unsupported configurations remain documented until the architecture can support
them honestly:

- `cargo check --features svm`: intentional failure;
- `cargo check --no-default-features`: unsupported until core extraction.

## Risks To Resolve Before Code Moves

- existing serialized corpus inputs include metadata fields;
- old finding lifecycle names must map to the new canonical lifecycle;
- artifacts do not have a single layout owner yet;
- benchmark fixtures may depend on legacy paths;
- Satori should not become coupled to the new core before the EVM kernel is stable.
