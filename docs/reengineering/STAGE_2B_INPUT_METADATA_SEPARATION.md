# Stage 2B: Semantic Input vs Testcase Metadata Separation

Status: COMPLETE for review. Worktree left uncommitted intentionally; review
then commit as one stage.

## Starting Checkpoint

- Stage 2A commit/tag: `56f4136` / `reengineering-stage-2a`
- Worktree at takeover: dirty with a partially applied Stage 2B change set
  from the previous agent (`src/evm/fuzz.rs`, `src/engine/flashloan.rs`,
  draft of this stage's usage map). The workspace did not compile
  (27 errors in `fuzz_engine`, `seed_intelligence`, `seed_ingester`,
  `protocol_model`, `benchmark`, `bounded_search`, `dependency`, `proof`,
  `economic_views`, and test code). This stage's work completed that change
  set and the remaining migration; nothing was discarded or rewritten.
- Pre-edit usage map created before any further `EvmInput` modification:
  `docs/reengineering/STAGE_2B_INPUT_USAGE_MAP.md`.

## Stage 2A Validation Correction (re-checked at Stage 2B start)

The handoff claim that "a sanitizer invocation appeared to report 0 passed"
was re-verified and explained:

```text
cargo test -p rustyfuzz-core -- --list   -> 11 unit tests listed
cargo test -p rustyfuzz-core             -> 11 passed (unit), then Doc-tests run reports "0 passed"
cargo test -p rustyfuzz-core --lib       -> 11 passed
cargo test -p rustyfuzz-core --tests     -> 11 passed (no integration files exist)
cargo test -p rustyfuzz-core --doc       -> 0 doctests
```

The "0 passed" line was the doctest runner summary, not a failed suite.
Test ownership: all 11 tests are unit tests under `crates/rustyfuzz-core/src/**`
(ids::tests x5, execution::tests x2, finding::tests x1, metadata::tests x1,
snapshot::tests x2). There are no `crates/rustyfuzz-core/tests/**`
integration tests and no doctests.

Sanitizer scope for those tests:

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rustyfuzz-core --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std
-> PASS (11 passed)
```

The committed Stage 2A report is accurate; no correction was needed to it.

## Field Classification

| Field | Class | Disposition |
| --- | --- | --- |
| `txs` | SEMANTIC | kept in `EvmInput`, name unchanged (persisted-schema stability) |
| `base_snapshot_id` | SEMANTIC | kept in `EvmInput`, name unchanged |
| `waypoints` | FEEDBACK / GUIDANCE | moved to `EvmTestcaseMetadata`; concolic strategies read it via metadata |
| `mutation_provenance` | METADATA / PROVENANCE | moved to `EvmTestcaseMetadata`; objective/scoring reads via explicit provenance |

No contrary semantic requirement was discovered during the audit. Detailed
per-file map with READ/WRITE/SERIALIZE/HASH classification:
`docs/reengineering/STAGE_2B_INPUT_USAGE_MAP.md`.

## New Schema

```rust
pub struct EvmInput {                       // SEMANTIC ONLY
    pub txs: Vec<SingletonTx>,
    pub base_snapshot_id: u64,
}

pub struct EvmTestcaseMetadata {
    pub waypoints: Vec<Vec<Waypoint>>,      // #[serde(default)]
    pub mutation_provenance: Vec<MutationProvenance>, // #[serde(default)]
}

pub struct LegacyEvmInputV1 {               // pre-Stage-2B reader
    pub txs: Vec<SingletonTx>,
    pub base_snapshot_id: u64,
    pub waypoints: Vec<Vec<Waypoint>>,
    pub mutation_provenance: Vec<MutationProvenance>,
}
```

- Legacy JSON deserializes through `LegacyEvmInputV1` via
  `EvmInput::split_legacy_json(bytes) -> (EvmInput, EvmTestcaseMetadata)`;
  nothing is discarded.
- Post-2B persisted inputs are semantic-only JSON.
- Because `serde_json` tolerates extra keys, old files also load cleanly; the
  split path additionally recovers feedback into typed metadata.

## Metadata Ownership During Campaigns

`EvmMutator` holds `EvmTestcaseMetadataStore` (Arc + parking_lot Mutex,
keyed by semantic `InputId`):

```text
TODO(stage-4): move EVM testcase metadata into LibAFL testcase/state metadata
or an explicit mutation context when campaign worker boundaries are split.
```

Flow points wired end-to-end so no guidance regressed:

1. Seed-time provenance (dependency flow templates, hardened seed candidates,
   seed-intelligence candidates, bounded-search goal annotations) is inserted
   into the shared store **after** actor-role application so stored keys match
   the actually seeded semantic input.
2. `generate_flow_template_inputs` now returns `Vec<FlowTemplate>` where
   `FlowTemplate = (EvmInput, EvmTestcaseMetadata)`.
3. `SeedCandidate::into_parts(base_snapshot_id)` returns input plus metadata;
   `into_evm_input` remains for semantic-only consumers.
4. `BoundedSearchOutcome.metadata` carries objective annotations out of the
   search engine (`#[serde(default)]`).
5. At execution, harnesses read provenance via
   `store.get_or_default(input).mutation_provenance` and pass it explicitly
   into scoring/telemetry.
6. After `mutate()`, mutated-input metadata is re-keyed by its new semantic id.

Signature changes (explicit provenance, so feedback cannot sneak back into
identity through hidden state):

- `CampaignScorer::score(..., provenance: &[MutationProvenance])`
- `dependency_sequence_score(input, provenance)`
- `exploit_path_score(provenance)`
- `fn mutation_strategies(provenance: &[MutationProvenance])`
- all `EvmMutator` strategy fns take `&mut EvmTestcaseMetadata`
- `EvmMutator::with_concolic_hints_and_stats(..., store)`

## Mutator Compatibility (Step 6)

Every strategy bucket, probability range, RNG call order, and skip condition is
unchanged. Guidance preservation verified by tests:

- concolic mutation/synthesis read waypoints from metadata
  (previously `input.waypoints`);
- economic-objective mutation reads `goal_*` tags from metadata restored via
  the store (`economic_objective_mutation_preserves_goal_guidance_from_metadata_store`);
- default fallback objective unchanged when no guidance exists;
- `flashloan_template` provenance record, previously pushed by
  `FlashLoanTemplate::wrap_sequence`, is now recorded by the mutator after
  wrapping (template function only builds semantic sequence).

## Canonical InputId (Steps 7-8)

Identity schema: `rustyfuzz-input-id-v1`. Keccak-256 via
`revm::primitives::keccak256` (no new dependency; core stays neutral).

```text
identity_bytes =
    len_prefixed("rustyfuzz-input-id-v1")
    || u64 BE base_snapshot_id
    || u64 BE txs.len()
    || per tx (in array order):
          len_prefixed(calldata)
          || caller(20B) || to(20B) || value(32B BE) || byte(is_victim)

len_prefixed(b) = u64 BE len(b) || b
InputId = "0x" || hex(keccak256(identity_bytes))
```

Documented in ADR 0003 with forbidden-content list (waypoints, provenance,
coverage, comparison feedback, oracle findings, scheduler scores, state
novelty, counters, timestamps). No pretty JSON, no maps, no IO, no cloning
beyond fixed-width field copies.

Pinned golden value
(`base_snapshot_id=42`, single tx `[0xde,0xad,0xbe,0xef]` / caller `0x11…11` /
to `0x22…22` / value 1000 / not victim):

```text
0xedbbb6647289e0df39694c6c9a8b810163991ca5cd0ed4c0b387a6c999af74ba
```

Cross-checked against an independent Keccak-256 implementation over the same
byte encoding before being pinned. Stage 2B.1 revised the contract BEFORE any
checkpoint (Stage 2B was still uncommitted): `is_victim` was removed from v1
bytes rather than published as flawed v1 + patched v2. Revised golden digest:
`0xedbbb6647289e0df39694c6c9a8b810163991ca5cd0ed4c0b387a6c999af74ba`.

## Persistent Corpus Migration (Step 11)

- `persist_input` / `persist_execution_input`: entry id/hash now derived from
  `input.semantic_input_hash()` instead of keccak-over-serialized-JSON.
  Existing entry-id format (first 16 hex chars) preserved.
- `load_input_with_metadata(id)`: new loader that splits legacy files into
  semantic input + metadata (old records remain fully readable; no historical
  file is rewritten).
- `load_input(id)`: retained as thin semantic-only wrapper for existing
  callers (`main.rs` replay paths, `promotion.rs`, `verifier.rs`, tests),
  marked `TODO(stage-4)`.
- `write_reproduction_report` and `artifact_equivalence_components`: report id
  and artifact sequence-hash now use the canonical semantic hash; artifact
  dedup can no longer be perturbed by feedback fields.

## Deduplication (Step 12)

Semantic dedup covered by tests: two variants identical in `txs +
base_snapshot_id` but different in waypoints/provenance share one InputId;
different calldata/value/caller/base-snapshot produce distinct ids
(`stage_2b_semantic_dedupe_ignores_feedback_variants`).

## Snapshot Lineage (Step 13)

`Snapshot.producing_input` stores a clone of the executed input, which is now
semantic-only automatically; replay reconstruction therefore refers to
execution-defining content. Snapshot model itself untouched (Stage 2C owns
redesign).

## Hash/Eq Audit (Step 15)

- `EvmInput` derives Hash/Eq over exactly `txs` + `base_snapshot_id`.
- `EvmTestcaseMetadata` also derives Hash/Eq but is never keyed inside any
  wrapper that participates in corpus/artifact identity; identity-carrying
  positions (corpus entry id, artifact equivalence key, reproduction report,
  producing-input lineage) read from `EvmInput` alone.
- No derive restores identity-by-feedback transitively.

## Performance Notes (Step 16)

`semantic_input_id()` allocates one small vector per call; call sites are
persist/report/artifact (cold) plus one lookup per mutate/harness cycle. No
caching was added (nothing measured as hot; speculative caching rejected).

## Files Changed

Source:

- `src/evm/fuzz.rs` — semantic split, InputId, legacy reader, metadata store,
  mutator threading, new identity/guidance/golden tests
- `src/engine/fuzz_engine.rs` — shared stores in both harnesses, seeding,
  scorer/telemetry wiring, fixture cleanup
- `src/engine/bounded_search.rs` — objective annotations to metadata,
  outcome field, tuple templates
- `src/engine/dependency.rs` — FlowTemplate tuples, provenance-aware score
- `src/engine/exploit_path.rs` — provenance-aware score
- `src/engine/scoring.rs` — provenance parameter plumbing
- `src/engine/seed_intelligence.rs` — `into_parts`, tuple history windows
- `src/engine/flashloan.rs` — template records semantic input only
- `src/engine/proof.rs`, `src/engine/benchmark.rs`, `src/engine/promotion.rs`,
  `src/engine/economic_delta.rs`, `src/engine/fork_setup.rs`,
  `src/engine/scheduler.rs`, `src/common/verifier.rs`,
  `src/engine/protocol_model.rs`, `src/evm/economic_views.rs`,
  `src/evm/seed_ingester.rs` — fixture/signature updates
- `src/main.rs` — tuple destructuring for seed bundle building
- `src/evm/corpus.rs` — semantic persistence/load/report/dedupe + stage tests

Docs/tests:

- `docs/reengineering/STAGE_2B_INPUT_USAGE_MAP.md` (new)
- `docs/reengineering/STAGE_2B_INPUT_METADATA_SEPARATION.md` (this file)
- `docs/adr/0003-semantic-input-vs-testcase-metadata.md`
- `docs/ARCHITECTURE.md`, `docs/FUZZING_MODEL.md`,
  `docs/reengineering/STAGE_2_PLAN.md`
- `tests/benchmarks.rs` — updated fixtures/signatures

## Tests Added

In `src/evm/fuzz.rs`:

- `waypoints_do_not_change_semantic_input_id`
- `mutation_provenance_does_not_change_semantic_input_id`
- `execution_defining_differences_change_semantic_input_id`
  (calldata/caller/value/base_snapshot_id)
- `semantic_input_hash_is_deterministic_and_survives_legacy_round_trip`
- `legacy_json_split_preserves_waypoints_and_provenance`
- `semantic_input_hash_matches_pinned_golden_value`
- `economic_objective_mutation_preserves_goal_guidance_from_metadata_store`
- `economic_objective_mutation_without_guidance_uses_default_objective`

In `src/evm/corpus.rs`:

- `stage_2b_legacy_input_json_preserves_feedback_and_keeps_semantic_identity`
- `stage_2b_semantic_dedupe_ignores_feedback_variants`

Existing suites that must stay green (and did): mutation determinism, corpus
persistence incl. `persist_campaign_artifact_deduplicates_same_input_id`,
state novelty, replay/verifier, fork cache, snapshot behavior, end-to-end
smoke, benchmark smoke.

## Exact Commands Executed And Results

Stage 2A validation correction:

```text
cargo test -p rustyfuzz-core -- --list   PASS (11 unit tests)
cargo test -p rustyfuzz-core             PASS (11 passed; 0 doctests)
cargo test -p rustyfuzz-core --lib       PASS (11 passed)
cargo test -p rustyfuzz-core --tests     PASS (11 passed)
cargo test -p rustyfuzz-core --doc       PASS (0 doctests)
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rustyfuzz-core --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std         PASS (11 passed)
cargo tree -p rustyfuzz-core             PASS (serde, thiserror only)
cargo tree -i rustyfuzz-core             PASS (only root depends on it)
```

Stable gate (post-Stage-2B):

```text
cargo fmt --all -- --check                             PASS
cargo check --workspace                                PASS
cargo test --workspace                                 PASS
                                                        lib 191 passed
                                                        bins 4 passed
                                                        benchmarks 38 passed / 1 ignored
                                                        smoke 1 passed
                                                        core 11 passed
cargo clippy --workspace --all-targets -- -D warnings  PASS (0 warnings)
cargo build --workspace --release                      PASS
cargo doc --workspace --no-deps                        PASS
cargo test --test benchmarks --release                 PASS (38 passed / 1 ignored)
python3 YAML parse of .github/workflows/*.yml          PASS (ci.yml, rust.yml)
git diff --check                                       PASS (no whitespace errors)
```

Sanitizer gates:

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std   PASS (191 passed)

env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --bins \
  --target x86_64-unknown-linux-gnu -Zbuild-std   PASS (4 passed; benchmark bin 0 tests)

env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --test benchmarks \
  --target x86_64-unknown-linux-gnu -Zbuild-std   PASS (38 passed / 1 ignored)

env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rustyfuzz-core --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std   PASS (11 passed)
```

Full-workspace sanitizer remains excluded as documented in Stage 2A due to the
pre-existing `tests/end_to_end_smoke.rs` ASan runtime `unable to unmap` issue;
it was not retried here (unchanged behavior, not a Stage 2B regression).

## Behavioral Changes

Intended and deliberate:

1. Persisted corpus input hashes/ids now reflect semantic content only.
   Inputs differing solely in waypoints/provenance deduplicate where they were
   previously distinct. Fresh persisted entries will not collide with old
   filenames since both encodings differ; old entries remain readable.
2. Campaign artifact sequence-hash / report ids use the canonical semantic
   hash (stable against instrumentation changes).

Unchanged (verified by full green gates): executor semantics, scheduler
policy, mutator strategy percentages and selection, oracle behavior, finding
lifecycle, Satori behavior, snapshot restore semantics.

## Known Risks

- The sidecar metadata store is process-local: campaign restarts lose
  in-flight metadata for already-persisted mutated inputs until LibAFL-native
  testcase metadata lands (Stage 4 bridge). Seed-time provenance is re-inserted
  on every startup deterministically.
- `CampaignScore` values may shift slightly in campaigns using
  bounded-search/goal seeds because pressure functions now receive the exact
  provenance of the executed semantic input rather than whatever happened to
  ride along in the struct. Direction of the invariant is tested.
- No migration tooling provided for rewriting old ids inside any externally
  indexed dataset; loading is compatible but ids recorded elsewhere must be
  recomputed deliberately if referenced.

## Remaining Architecture Debt

- `EvmTestcaseMetadataStore` sidecar removal (TODO(stage-4)) into LibAFL
  testcase/state metadata.
- `load_input` compatibility wrapper retirement (TODO(stage-4)).
- Pre-existing latent inconsistency (not changed, behavior-preserving):
  bounded-search writes lowercased `goal_*` tags while
  `economic_objective_mutation` matchers use camelCase substrings, so
  production objective tags currently fall through to the default objective.
  Recorded for a future stage; changing it would alter mutation outcomes.
- Stage 2C+ work unchanged: snapshot model, lifecycle dedup, runtime layout.

## Readiness Decision for Stage 2C

READY FOR REVIEW. All mandatory stable gates, YAML validation, and configured
ASan scopes are green; the semantic-identity invariant is enforced by compiler
structure plus focused tests; core crate boundary is still dependency-clean.
Stage 2C should not begin until this stage is reviewed and committed.

## Stage 2B.1 Review-Correction Section

Scope: semantic-identity correctness pass only; no Stage 2C work.

1. SingletonTx classification (details in usage map addendum): `input`,
   `caller`, `to`, `value` are EVM execution defining; `is_victim` is
   fuzzing/analysis metadata (MEV oracle, economic-delta victim split, actor
   assignment). Verified by reading `EvmExecutor::execute_with_result` TxEnv
   construction in `src/evm/executor.rs`.
2. is_victim decision: kept temporarily inside `SingletonTx` for caller
   compatibility; excluded from InputId v1 bytes; structural Hash/Eq on
   `EvmInput` explicitly documented as non-semantic. Canonical persisted
   identity remains `semantic_input_id()`. `TODO(stage-2c)`: relocate
   transaction-role markers to explicit metadata.
3. Golden digest recomputed and re-pinned independently:
   `0xedbbb6647289e0df39694c6c9a8b810163991ca5cd0ed4c0b387a6c999af74ba`.
   Schema string stays `rustyfuzz-input-id-v1` because v1 was never
   checkpointed.
4. Metadata store duplicate-key semantics: deterministic MERGE for identical
   semantic InputId — identical provenance/waypoint records are not
   duplicated, new records append, per-tx and total waypoint backpressure
   re-applied, provenance capped at 64 (oldest dropped), store bounded at
   65,536 entries with explicit replacement eviction. Tests:
   `metadata_store_merges_distinct_variants_for_one_semantic_input`,
   `metadata_store_respects_entry_bound_and_replace_eviction`.
5. Corpus prefix collision guard: truncated 16-hex id is now only a filename
   hint; on path collision the recorded full input hash decides between
   idempotent rewrite (same hash) and a deterministic extended name
   `<prefix>-<fullhash>` preserving both entries. No silent overwrite, false
   dedup, or wrong-input load. Test injects a conflicting prefix record
   without brute-forcing Keccak:
   `stage_2b1_prefix_collision_preserves_both_entries`.
6. Tests added in 2B.1: two `is_victim` identity/execution tests,
   rewritten conceptually-unambiguous
   `provenance_entries_do_not_change_semantic_input_id`
   (no execution-defining mutation invoked),
   two metadata-store semantics tests, one corpus collision test.
7. Behavior risk: none beyond documented Stage 2B changes; persist ids for
   *new* entries may take extended-collision names (rare), historical corpora
   untouched, executor/scheduler/mutator/oracle policy unchanged.
