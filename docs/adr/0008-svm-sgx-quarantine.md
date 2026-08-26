# ADR 0008: SVM/SGX Quarantine

## Status

Accepted as target direction. Not implemented in Stage 1.

## Context

The current `svm` feature intentionally fails compilation, and `sgx` only
builds an unsupported shim. Keeping them in the supported architecture creates
misleading backend expectations.

## Decision

Unsupported SVM and SGX code should be quarantined outside the supported EVM
dependency graph, for example under `experimental/svm/` and `experimental/sgx/`
or a similarly explicit location.

## Alternatives Considered

- Make SVM compile as part of Stage 1.
- Delete all unsupported source immediately.
- Keep a generic VM enum with only EVM production-ready.

## Consequences

- Supported CI and architecture stay honest.
- Experimental code remains available for future reuse.
- Re-enabling SVM/SGX requires explicit production-readiness work.

## Migration Notes

Stage 1 documents the quarantine decision only. The actual move happens after
the core/EVM dependency graph can be enforced.
