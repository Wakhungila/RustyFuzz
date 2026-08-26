# ADR 0005: Finding Lifecycle

## Status

Accepted as target direction. Not implemented in Stage 1.

## Context

Current source and docs use multiple lifecycle vocabularies. That makes it easy
to confuse heuristic evidence with proved findings.

## Decision

Use one canonical lifecycle in the target architecture:

```text
Signal -> Candidate -> Replayed -> Minimized -> Proved
```

`Rejected` is available from intermediate states.

Proof requires deterministic machine-verifiable evidence under the selected
proof policy. Raw oracle output is evidence, not proof.

## Alternatives Considered

- Keep `Lead` as the primary lifecycle term.
- Keep `Confirmed` separate from `Proved`.
- Treat oracle findings as proved vulnerabilities.

## Consequences

- Reports become easier to interpret.
- Old artifacts need compatibility mapping.
- Promotion, replay, minimization, proof, PoC validation, and reporting can be
  tested independently.

## Migration Notes

Stage 1 documents the target only. Stage 2D should introduce the canonical enum
and transition rules after core/evidence types exist.
