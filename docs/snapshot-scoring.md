# Snapshot Scoring

Runtime snapshots are scored with explicit components instead of a single opaque
coverage number. The score is stored on `SnapshotMetadata` as `SnapshotScore`.

Components:

- `new_coverage`: coverage edges reached by the producing transaction sequence.
- `branch_distance`: near branch misses with distance <= 256.
- `comparison_distance`: comparison waypoints with distance <= 4096.
- `oracle_proximity`: oracle observations emitted by the execution.
- `asset_delta_proximity`: large storage/value-like deltas.
- `storage_slot_sensitivity`: newly touched storage slots.
- `call_depth_novelty`: deepest observed internal call depth.
- `selector_novelty`: selectors not already represented by existing snapshots.
- `revert_reason_novelty`: reverting/halting outputs with nonempty reason data.
- `event_novelty`: event-labeled oracle observations.
- `state_transition_rarity`: storage transitions not already represented.

`SnapshotScoreWeights::default()` defines deterministic weights. Scheduling adds
the weighted score to coverage and gap-map energy. Pruning removes the lowest
weighted score first, while preserving the root snapshot.

Known-bug and benchmark-driven campaigns can derive class-aware weights with
`SnapshotScoreWeights::for_known_bug_class(...)` or
`benchmark::snapshot_weights_for_manifest(...)`. These profiles preserve the
same components but shift energy toward the state features that matter for a
bug family:

- access-control/proxy/upgrade: branch distance, comparisons, selectors, and
  sensitive storage slots.
- share/accounting/donation: asset deltas, oracle proximity, sensitive storage,
  and rare transitions.
- oracle/price: oracle proximity, event novelty, call depth, and comparisons.
- bridge/replay/finalization: selectors, call depth, rare transitions, and
  events.
- permission/approval/allowance: selectors, sensitive storage, branch frontier,
  and oracle proximity.

`SnapshotCorpus::select_snapshot_with_weights` applies these profiles without
changing the default scheduler path. This lets known-bug benchmarks tune state
selection while keeping strict replay and proof requirements outside the
exploration scheduler.
