# ADR 0003: Semantic Input vs Testcase Metadata

## Status

Accepted as the Stage 2 target.

CURRENT (Stage 2B): implemented for `EvmInput`. Semantic input contains only
`txs` and `base_snapshot_id`; waypoints and mutation provenance moved to
`EvmTestcaseMetadata`; canonical versioned `InputId` (`rustyfuzz-input-id-v1`)
is derived from execution-defining content only. Legacy pre-separation JSON
remains readable through `LegacyEvmInputV1` splitting.

TARGET (later stages): feedback/provenance should move from the temporary
`EvmTestcaseMetadataStore` sidecar into native LibAFL testcase/state metadata
when campaign worker boundaries are split (tracked with `TODO(stage-4)`).

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

## Stage 2B Implementation Record

- Semantic `EvmInput`: `pub txs: Vec<SingletonTx>`, `pub base_snapshot_id: u64`
  (field names kept for schema stability; renaming is deferred).
- `EvmTestcaseMetadata { waypoints, mutation_provenance }` owns feedback.
- `EvmTestcaseMetadataStore`: Arc/parking_lot sidecar keyed by semantic
  `InputId`; held on `EvmMutator`, shared with the harnesses for seed
  provenance and execution-time reads.
- `EvmMutator` strategy buckets, probabilities, and RNG use are unchanged;
  strategies now receive `&mut EvmTestcaseMetadata` instead of reading
  provenance from the input itself.
- Guidance read paths preserved: concolic mutation (waypoints), economic
  objective mutation (`goal_*` tags), dependency/exploit/scoring pressure
  functions take explicit provenance slices.
- Scoring/telemetry signatures updated: `CampaignScorer::score`,
  `dependency_sequence_score`, `exploit_path_score`, and
  `mutation_strategies` now receive provenance explicitly instead of
  deriving it from the input.
- Bounded-search objective annotations land in `BoundedSearchOutcome.metadata`
  and are registered in the store when candidates become corpus seeds.

### InputId contract (`rustyfuzz-input-id-v1`)

```text
identity_bytes =
    len_prefixed("rustyfuzz-input-id-v1")
    || base_snapshot_id        as u64 big-endian
    || u64 big-endian(txs.len())
    || per transaction in sequence order:
          len_prefixed(calldata)
          || caller  (20 bytes)
          || to      (20 bytes)
          || value   (32-byte big-endian U256)

len_prefixed(b) = u64 big-endian(len(b)) || b

InputId = "0x" || hex(keccak256(identity_bytes))
```

- Hash algorithm: Keccak-256 via REVM's `revm::primitives::keccak256` in the
  monolith (the core crate stays dependency-free).
- Hashed content includes ONLY: schema version, base snapshot id, calldata,
  caller, to, value, and transaction order. The analysis-only `is_victim`
  role marker is deliberately excluded (Stage 2B.1): `EvmExecutor` builds
  REVM `TxEnv` from caller/value/data/to and never reads the flag.
- Never hashed: waypoints, provenance, coverage, comparison feedback, oracle
  findings, scheduler scores, state novelty, counters, timestamps.
- No filesystem/network access; no pretty JSON; no map iteration; fixed field
  order and lengths make concatenation unambiguous.
