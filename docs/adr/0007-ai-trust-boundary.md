# ADR 0007: AI Trust Boundary

## Status

Accepted as target direction. Not implemented in Stage 1.

## Context

Satori provides useful experimental AI/static-analysis flow, but the fuzzing
kernel must not depend on model availability or trust model output as proof.

## Decision

AI is an optional proposal subsystem:

```text
AI proposes.
RustyFuzz validates.
```

AI must never directly prove findings, mutate persistent chain state, bypass
replay/minimization policy, alter proof evidence silently, or modify corpus
state without deterministic validation.

## Alternatives Considered

- Remove Satori.
- Hardcode one model/provider.
- Allow AI triage to mark findings as confirmed.

## Consequences

- The engine remains functional when AI is disabled.
- Provider boundaries, budgets, caching, proposal provenance, and validation
  status are mandatory for production AI integration.
- Satori can be refactored rather than discarded.

## Migration Notes

Stage 1 only documents the boundary. AI extraction waits until the EVM/core
kernel is stable.
