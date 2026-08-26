# ADR 0001: EVM-First Architecture

## Status

Accepted for the v0.2 target. Not fully implemented in Stage 1.

## Context

RustyFuzz currently has useful EVM implementation depth and unsupported SVM/SGX
source. The production backend with real execution value is EVM through REVM.

## Decision

RustyFuzz v0.2 will be EVM-first. EVM is the only supported production backend.
SVM and SGX will not participate in the supported dependency graph until they
are rebuilt and tested as real production backends.

## Alternatives Considered

- Keep a generic VM abstraction now.
- Make SVM compile during the EVM rearchitecture.
- Delete unsupported source immediately.

## Consequences

- The supported architecture can be simpler and more honest.
- Future non-EVM support requires a new production-readiness decision.
- Existing SVM/SGX source remains useful historical/experimental material but
  must not shape the EVM kernel.

## Migration Notes

Stage 1 documents this decision only. Quarantine happens in a later migration
stage after the EVM/core boundary is established.
