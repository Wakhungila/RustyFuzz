# Stage 3: Engine Extraction — Budget, Telemetry, Scheduler, Events, Input Model

Status: COMPLETE for review. Honest scope statement inside.

## Starting Checkpoint

- Stage 2F commit/tag: `f78963f` / `reengineering-stage-2f`, clean worktree.

## Delivered

New production crate `crates/rustyfuzz-engine`
(`core <- evm <- engine <- root`, compiler-enforced):

| Module | Origin | Contents |
| --- | --- | --- |
| `input.rs` | moved from monolith `src/evm/fuzz.rs` | semantic input model: `EvmInput`, `EvmTestcaseMetadata` (+merge/backpressure), `MutationProvenance`, `LegacyEvmInputV1`, `EvmTestcaseMetadataStore` (bounded merge semantics), `MAX_SEQUENCE_LENGTH`, canonical `rustyfuzz-input-id-v1` hashing (keccak via `rustyfuzz_evm::keccak256` re-export), LibAFL `Input`/`HasLen` impls; store bounds test travels with it |
| `scoring/` | split from monolith `engine/scoring.rs` | `CampaignScore` (single source; monolith re-exports the path) |
| `scheduler/` | moved verbatim from monolith | `RustyFuzzScheduler` + campaign metadata + its `TestState` tests; weight policy now documented + pinned by a deterministic formula test |
| `campaign/budget.rs` | moved from `fuzz_engine.rs` | `CampaignBudget` (+ grace-window helper) + 3 unit tests |
| `campaign/telemetry.rs` | moved from `fuzz_engine.rs` | `CampaignTelemetry`, `ExecutionTelemetryRecord` (`concolic_hint_stats`/`artifacts` fields made pub for the root harness) |
| `concolic_stats.rs` | moved from `engine/concolic.rs` | `ConcolicHintStats{,+Snapshot}` + test |
| `events.rs` | NEW | bounded `EventSink` (`sync_channel`, non-blocking `try_send`, drop accounting), `CampaignEvent::{NewSnapshot, CandidateFinding, CampaignCheckpoint}`, capacity const, 2 tests |

Legacy paths preserved via shims:

- `src/evm/fuzz.rs` re-exports the input model (all `crate::evm::fuzz::*`
  consumers unchanged); retains `AbiRegistry` and `EvmMutator`.
- `src/engine/scheduler.rs`: shim to engine scheduler.
- `src/engine/scoring.rs`: re-exports `CampaignScore`.
- `src/engine/concolic.rs`: re-exports stats types.

## New Capabilities

1. **Bounded event channel (invariant #8)**: both harnesses construct an
   `Arc<EventSink>` (capacity 4096) and emit
   `NewSnapshot{id,parent}` at both snapshot-retention sites and
   `CandidateFinding{input_id}` at both artifact-persistence success sites.
   Emission is a single non-blocking try-send on the hot path; nothing else.
   The receiver handle is retained in-scope for the upcoming cold-path
   consumer/report command (Stage 4).
2. **Named mutation strategies + counters (3.6, additive only)**:
   `MutationStrategyKind` enum fixes strategy labels; dispatch records one
   `attempted` per bucket selection and provenance recording bumps `mutated`.
   Verified behavior-neutral: RNG draws/order untouched (attempt counting is
   outside the RNG sequence), probabilities/skip conditions untouched;
   regression test pins seeded value-boundary outcome plus counters.

## Explicit Non-Goals This Pass (Debt, with owners)

- The two ~1500-line harness closures remain in the root fuzzer. Splitting
  them into `campaign/{runtime,worker}` requires the LibAFL worker/shmem
  boundary redesign flagged since Stage 0 — recorded as TODO(stage-4)
  rather than force-moved intact (mandated by "do not move 3000 lines").
- Seeds unification under typed `SeedSource`s (3.10): deferred, TODO(stage-4).
- Concolic internal splitting (solver/constraint/mutation interfaces) (3.9):
  crate boundary fixed, internals deferred.
- `CampaignBuilder`: not fabricated ahead of runtime extraction; budget/
  telemetry/events are already usable typed building blocks.
- Feedback implementations stay in root until Stage 4 feedback module work.

## Gates

Stable gate PASS: fmt/check/test/clippy `-D warnings`/release build/doc/
release benchmarks. Totals: lib 199 · bins 4 · benchmarks 38+1 ign · smoke 1
· core 17 · engine 9 · evm 2. YAML OK, `git diff --check` clean,
`cargo tree -i rustyfuzz-core` acyclic (core stays serde+thiserror only).

## Sanitizers

All explicit scopes PASS on nightly-2026-08-01 ASan/LSan: lib 199, bins 4,
benchmarks 38+1, core 17, evm 2, **engine 9 (new scope)**.

## Behavioral Changes

- Additive telemetry counters/event emissions only. One log-line wording is
  unchanged; no persisted-format change; artifact ids/hashes unchanged.
