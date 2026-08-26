# ADR 0003: Semantic Input vs Testcase Metadata

## Status

Accepted as the Stage 2 target. Not implemented in Stage 1.

## Context

Current `EvmInput` carries execution-defining data and feedback/provenance data.
That makes semantic testcase identity sensitive to instrumentation and mutation
metadata.

## Decision

`EvmInput` semantic identity should ultimately contain only execution-defining
input such as:

```text
base_snapshot_id
transactions
```

Execution feedback belongs in testcase or execution metadata, not semantic
input identity:

```text
waypoints
coverage
comparison information
mutation provenance
state novelty
scheduler score
parent relationships
```

`InputId` should be derived only from canonical execution-defining semantic
input.

## Alternatives Considered

- Keep feedback fields inside `EvmInput`.
- Add a second hash while preserving current serialized identity.
- Delay identity cleanup until after all crate extraction.

## Consequences

- Replay and artifact identity become deterministic under instrumentation changes.
- Migration requires compatibility handling for existing serialized inputs.
- Scheduler and artifact code must learn to read metadata from a separate owner.

## Migration Notes

Do not modify `EvmInput` during Stage 1. Stage 2A extracts core IDs/types, and
Stage 2B separates `EvmInput` from `TestcaseMetadata`.
