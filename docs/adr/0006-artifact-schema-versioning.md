# ADR 0006: Artifact Schema Versioning

## Status

Accepted as target direction. Not implemented in Stage 1.

## Context

Runtime paths are currently assembled in several modules. Serialized artifacts
do not have one layout owner.

## Decision

Introduce a dedicated artifact layer with a `RunLayout` owner and versioned
schemas. Future artifacts must include `schema_version` and deterministic
reproduction provenance.

## Alternatives Considered

- Keep path construction inside campaign, corpus, promotion, and CLI modules.
- Version only reports, not inputs/snapshots/finding records.
- Use ad hoc directory creation during campaign startup.

## Consequences

- Artifacts become easier to replay and migrate.
- Hot-path persistence can move behind a bounded queue.
- Existing artifact readers need compatibility handling.

## Migration Notes

Stage 1 defines `.rustyfuzz/` and policy only. `RunLayout` implementation is a
later artifact subsystem stage.
