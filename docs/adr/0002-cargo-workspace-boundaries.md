# ADR 0002: Cargo Workspace Boundaries

## Status

Accepted as target boundaries. Not implemented in Stage 1.

## Context

RustyFuzz is currently a single crate with CLI, engine, EVM backend, oracles,
artifacts, benchmarks, and Satori logic coupled together.

## Decision

The target workspace is:

- `rustyfuzz-core`
- `rustyfuzz-evm`
- `rustyfuzz-engine`
- `rustyfuzz-oracles`
- `rustyfuzz-artifacts`
- `rustyfuzz-ai`
- `rustyfuzz-cli`
- `rustyfuzz-testkit`

Dependency direction must point toward stable lower layers and avoid cycles.

## Alternatives Considered

- Keep the monolith and only split files.
- Extract all crates in one patch.
- Add a generic VM framework before a second production backend exists.

## Consequences

- Stage 2 can extract stable domain types first.
- The CLI can become thin after engine/artifact boundaries exist.
- Cross-crate moves require compatibility shims and repeated regression gates.

## Migration Notes

Do not create all crates at once. Stage 2 starts with `rustyfuzz-core`, then
extracts EVM and engine boundaries only after semantic types stabilize.
