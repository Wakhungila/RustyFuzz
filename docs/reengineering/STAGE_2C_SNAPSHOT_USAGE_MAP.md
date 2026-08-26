# Stage 2C Snapshot Usage Map

Status: COMPLETE pre-edit audit. Created before modifying the snapshot model.

## Current Inventory

| Concept | Current owner | Notes |
| --- | --- | --- |
| `Snapshot` struct | `src/common/types.rs` | `id: u64`, `state: Arc<RwLock<ChainState>>`, `coverage: BitVec`, `producing_input: Option<EvmInput>`, `waypoints: Vec<Waypoint>`, `depth: u32`, `gas_used: u64` |
| REVM state ownership | `Snapshot.state` via `ChainState::Evm(EvmCacheDb)` | backend-coupled; must never move into core |
| `SnapshotCorpus` | `src/evm/corpus.rs` | `snapshots: HashMap<u64, Arc<RwLock<Snapshot>>>`, `parent_map`, `children_map`, `metadata: HashMap<u64, SnapshotMetadata>`, global read hotspots, priority gap map |
| Snapshot IDs | assigned, monotonic (`max+1`) inside `maybe_add_post_execution_snapshot` | NOT content-derived |
| State digest | `hash_snapshot_state(snapshot)` -> keccak over sorted accounts/storage (`0x…`) | computed per manifest persist only; not stored on metadata |
| Parent/predecessor | `parent_map: HashMap<u64, u64>`; root uses `id == parent_id`; children list exists | depth comes from metadata (`parent.depth + 1`) |
| Producing input | full `EvmInput` clone stored inside `Snapshot.producing_input` | semantic-only post Stage 2B |
| Coverage ownership | per-snapshot `BitVec<u8, Lsb0>` (MAP_SIZE) | copied from execution coverage map |
| Waypoint ownership | flattened execution waypoints on `Snapshot.waypoints` (backpressure-limited) | feedback, not identity |
| Scoring/selection | `SnapshotScore` + `SnapshotScoreWeights` inside `corpus.rs` metadata | selection policy currently embedded in corpus |
| Persistence | `PersistentCorpus::persist_snapshot_manifest` -> `snapshots/<id>.manifest.json` (`SnapshotManifest`: id, state_hash, coverage_hash, edges, producing_input_id, depth, gas_used) | schema has NO version field yet |
| Restore | harnesses read `snapshot_corpus.get_snapshot(input.base_snapshot_id)` and clone chain state | exercised by replay/fork-cache paths |

## Usage Records (significant)

| File | Function/type | Access | Purpose | Notes |
| --- | --- | --- | --- | --- |
| `src/evm/corpus.rs` | `SnapshotCorpus::add_snapshot` | WRITE | register snapshot + parent/children/metadata | no cycle validation today |
| `src/evm/corpus.rs` | `maybe_add_post_execution_snapshot` | WRITE/CONSTRUCT | creates child snapshots after meaningful executions | assigns monotonic id; sets depth |
| `src/evm/corpus.rs` | `update_snapshot_metadata_from_execution` | WRITE | read/write sets, scores, hotspots | selection-side feedback |
| `src/evm/corpus.rs` | `prune_to_limit` | WRITE | bounded snapshot retention | memory policy |
| `src/evm/corpus.rs` | `hash_snapshot_state` | HASH | deterministic state digest | becomes basis of `StateFingerprint` |
| `src/evm/corpus.rs` | `persist_snapshot_manifest` | SERIALIZE | durable manifest | needs schema_version |
| `src/engine/fuzz_engine.rs` | both harness closures | READ | select base snapshot via `input.base_snapshot_id`, clone state | restore path |
| `src/common/verifier.rs` | replay/minimization drivers | READ | restore + execute | determinism tests rely on this |
| `src/engine/scheduler.rs` | pending campaign score | READ | scheduling pressure | unchanged this stage |

## Decisions Recorded

1. **SnapshotId vs StateFingerprint are distinct concepts.**
   - `SnapshotId` remains an *assigned*, monotonic logical reference (u64).
     It is not content identity and must not be presented as such.
   - `StateFingerprint` is introduced (core, dependency-neutral newtype) as a
     deterministic digest of relevant EVM state (sorted accounts/storage,
     keccak hex). Two snapshots with equal fingerprints hold equivalent
     cached-state content even when their ids differ.
2. **Ancestry** stays `parent references + producing semantic input`
   (`parent_map` + `Snapshot.producing_input`). No redundant full histories.
   Cycle rejection is added explicitly even though monotonic ids make cycles
   structurally impossible today.
3. **Restoration contract**: restore = clone cached chain state from the
   snapshot, execute identical semantic input under identical block env ->
   equivalent execution/state. Determinism is claimed ONLY under identical
   environment provenance (same fork cache/block env), never across different
   RPC state.
4. **ObservationBundle** direction recorded (ADR 0004): coverage, comparisons,
   storage accesses, call observations, state fingerprint, oracle observations
   will consolidate behind one boundary in later stages. Not forced in this
   patch.
5. **Persistence**: manifests gain a `schema_version` (default 1) so schemas
   become explicitly versioned; historical files load unchanged.

## Preservation Points

- Scheduler/scoring weights untouched.
- `SnapshotCorpus` keeps its current struct shape (splitting storage vs
  selection is later-stage work).
- No REVM types enter `rustyfuzz-core`.
- Runtime layout unchanged.
