# Fuzzing Model

Status: CURRENT plus TARGET notes.

## Current v0.1 Model

RustyFuzz currently executes EVM transaction sequences through REVM, records
coverage/storage/call/oracle observations, and feeds campaign scoring into a
LibAFL-backed scheduler.

Current important implementation details:

- `EvmInput` is sequence-oriented and already carries a base snapshot id.
- `EvmInput` still also carries feedback/provenance fields such as waypoints and mutation provenance.
- `SnapshotCorpus` exists in the current EVM corpus implementation.
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

Stage 1 does not implement this target. Stage 2 starts with `rustyfuzz-core`
and the semantic-input boundary.
