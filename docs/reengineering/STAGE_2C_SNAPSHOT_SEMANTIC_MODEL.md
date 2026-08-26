# Stage 2C: Snapshot Semantic Model

Status: COMPLETE for review.

## Starting Checkpoint

- Stage 2B commit/tag: `41c3aaa` / `reengineering-stage-2b`, clean worktree.

## Scope

Snapshot identity/ancestry/restoration correctness inside the monolith.
No scheduler change, no engine-crate extraction, no `SnapshotCorpus`
restructuring beyond explicit identity metadata.

## What Changed

1. **`rustyfuzz_core::StateFingerprint`** (new, dependency-neutral newtype in
   `crates/rustyfuzz-core/src/snapshot.rs`). Deliberately distinct from
   `SnapshotId`: ids are *assigned monotonic logical references*; fingerprints
   are *deterministic digests of cached EVM state content* (keccak over sorted
   accounts/storage via the backend's `hash_snapshot_state`). Equal
   fingerprints ⇔ equivalent state material; equal ids are only corpus refs.
2. **`SnapshotCorpus::add_snapshot`** now records
   `SnapshotMetadata.state_fingerprint` for every registered snapshot and
   refuses link insertion that would close a lineage cycle (defensive; the
   normal max+1 id assignment makes cycles structurally impossible).
3. **`SnapshotCorpus::lineage_inputs(id)`**: deterministic root-first input
   sequence reconstruction from parent references + semantic producing inputs;
   returns `None` on missing/cyclic lineage.
4. **Versioned persistence**: `SnapshotManifest.schema_version` (`1`,
   serde-defaulted) — historical manifests load unchanged; global invariant #7
   begins here.
5. Core also gained `SnapshotMetadata::ancestry(parent_of)` with cycle
   rejection and self-parent root semantics matching the monolith.

## Restoration Contract (tested)

Restore = clone cached chain state out of the snapshot + identical block env
=> equivalent execution (gas / coverage hash / storage diffs). Determinism is
claimed ONLY under identical environment provenance; never across different
fork/RPC state.

## Tests Added

Core:

- `state_fingerprint_round_trips_and_rejects_empty`
- `ancestry_walks_to_root_and_rejects_cycles`

Monolith (`src/evm/corpus.rs`):

- `stage_2c_ancestry_reconstruction_is_deterministic`
  (root has no parent; depth = parent+1; deterministic reconstruction)
- `stage_2c_assigned_ids_and_state_fingerprints_are_distinct_concepts`
- `stage_2c_cyclic_lineage_insertion_is_refused`
- `stage_2c_snapshot_manifest_schema_version_survives_round_trip`
- `stage_2c_restored_snapshot_state_executes_equivalently`

## Commands / Results

```text
cargo fmt --all -- --check                             PASS
cargo check --workspace                                PASS
cargo test --workspace                                 PASS
                                                        lib 201 passed (+5)
                                                        bins 4 passed
                                                        benchmarks 38 passed / 1 ignored
                                                        smoke 1 passed
                                                        core 13 passed (+2)
cargo clippy --workspace --all-targets -- -D warnings  PASS
git diff --check                                       PASS
```

(Related sanitizer scopes re-run at next checkpoint.)

## Behavioral Changes

- Persisted snapshot manifests gain `"schema_version": 1`.
- Snapshot insertions compute one extra state hash per snapshot (cold path).

## Known Risks / Debt

- Fingerprint computed at insertion from the passed-in pre-execution child
  state; matches manifest-time hashing approach but both remain "cached-state
  content" digests, not full-network-equivalence claims.
- `SnapshotCorpus` still owns storage + scoring together; split is later work.
- ObservationBundle consolidation documented as direction only (ADR 0004).

## Readiness Decision

READY FOR STAGE 2D after review/gates.
