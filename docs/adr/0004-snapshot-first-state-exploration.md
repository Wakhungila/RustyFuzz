# ADR 0004: Snapshot-First State Exploration

## Status

Accepted as target direction.

CURRENT (Stage 2C): snapshot identity made explicit in the monolith —
`SnapshotId` documented as an assigned logical reference, distinct from the
new dependency-neutral `rustyfuzz_core::StateFingerprint` (deterministic state
content digest, stored per snapshot in corpus metadata). Ancestry is
parent-reference + semantic producing input, with cycle rejection on snapshot
insertion and deterministic lineage reconstruction (`SnapshotCorpus::
lineage_inputs`). Snapshot manifests carry `schema_version`. Restoration is
defined and tested as: cloned cached chain state + identical block env ->
equivalent execution; determinism only under identical environment
provenance. Scheduler policy unchanged. Full ObservationBundle consolidation
and corpus/scheduler separation remain future work.

## Context

RustyFuzz already has snapshot corpus concepts, but sequence-oriented fuzzing
and snapshot/state exploration are still coupled inside the monolith.

## Decision

State exploration should become first-class:

```text
SnapshotCorpus
  -> select interesting snapshot
  -> generate or mutate transaction
  -> execute
  -> ObservationBundle
  -> feedback
  -> retain or discard resulting state
  -> new Snapshot
```

Snapshots must retain predecessor metadata sufficient to reconstruct complete
transaction histories.

## Alternatives Considered

- Keep only full-sequence testcase mutation.
- Store complete exploit histories in every testcase.
- Copy ItyFuzz internals.

## Consequences

- More explicit state-centric scheduling and telemetry.
- Requires exact snapshot restoration tests.
- Requires careful memory/disk policy for state retention.

## Migration Notes

Stage 2 should define core snapshot types before changing scheduler or corpus
behavior. Existing sequence mutation should remain available for comparison.
