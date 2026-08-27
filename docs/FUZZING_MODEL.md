# Fuzzing Model

Status: CURRENT plus TARGET notes.

## Current v0.1 Model

RustyFuzz currently executes EVM transaction sequences through REVM, records
coverage/storage/call/oracle observations, and feeds campaign scoring into a
LibAFL-backed scheduler.

Current important implementation details:

- `EvmInput` is sequence-oriented and already carries a base snapshot id.
- Stage 2B (CURRENT): `EvmInput` carries only execution-defining data; waypoints
  and mutation provenance were moved to `EvmTestcaseMetadata`. During campaigns,
  guidance flows through `EvmTestcaseMetadataStore` keyed by semantic `InputId`
  (`rustyfuzz-input-id-v1`); persisted inputs no longer contain feedback fields.
- Stage 3 (CURRENT): campaign budget/telemetry/scheduler and the semantic
  input model live in `rustyfuzz-engine`; cold-path outputs flow through a
  bounded non-blocking event sink.
- `SnapshotCorpus` exists in the current EVM corpus implementation. Stage 2C
  (CURRENT) gives it explicit identity semantics: monotonic assigned
  SnapshotIds are separate from `StateFingerprint` state digests, lineage is
  parent+semantic-input based with cycle rejection, and manifests are schema-
  versioned.
- Sequence mutation and snapshot scoring are implemented inside the monolith.
- Exploration may use explicit synthetic fallback paths for smoke/benchmark modes.
- Proof/replay paths are stricter but still live inside coupled modules.

## Target v0.2 Model

The target model separates semantic testcase identity from execution feedback.

Target semantic input:

```text
EvmInput
  base_snapshot_id
  transactions
```

Target metadata outside semantic input:

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

Target state exploration:

```text
SnapshotCorpus
  -> select interesting snapshot
  -> generate or mutate transaction
  -> execute
  -> ObservationBundle
  -> coverage/state/comparison/oracle feedback
  -> retain or discard resulting state
  -> new Snapshot
```

Stage 2A implemented `rustyfuzz-core`; Stage 2B implemented the semantic-input
boundary for `EvmInput` plus canonical `InputId`. Full `ObservationBundle`
metadata and snapshot redesign remain future stages.
