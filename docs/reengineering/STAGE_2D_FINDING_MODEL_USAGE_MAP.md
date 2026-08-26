# Stage 2D Finding Model Usage Map

Status: COMPLETE. Canonical lifecycle introduced; legacy models wrapped.

## Inventory

| Concept | Location | Values | Disposition |
| --- | --- | --- | --- |
| `FindingStatus` | `src/common/oracle/mod.rs` | Lead, Replayed, Minimized, Proved, Rejected | legacy; `canonical()` adapter added (TODO(stage-4)) |
| `FindingLifecycleStage` | `src/engine/promotion.rs` | Candidate, Replayed, Minimized, PocGenerated, Confirmed, Rejected | legacy pipeline stage; `canonical()` adapter added (TODO(stage-4)) |
| `EvidenceGrade` | `src/common/oracle/mod.rs` | Heuristic, DeterministicReplay, RealisticForkProof, RegressionTested | retained; grades strength of evidence, not proof status |
| `RejectionReason` | `src/common/oracle/mod.rs` | 9 typed reasons | retained as typed rejection payload |
| `VulnerabilityOracle` trait | `src/common/oracle/mod.rs` | snapshot-diff oracles returning `VulnType` findings | oracle output = signal/evidence; never Proved |
| Promotion pipeline | `src/engine/promotion.rs` | Candidate → Replayed → Minimized → PocGenerated → Confirmed / Rejected | responsibilities conceptually split in docs; Confirmed is policy-gated (`require_poc_for_confirmed`, `strict_proof`, etc.) |
| Proof | `src/engine/proof.rs`, verifier replay/realism checks | deterministic replay + realism gates | proof requires deterministic validation — preserved |
| Finding dedup today | promotion records keyed by `finding_id` string + artifact keys in corpus | no canonical component identity | replaced at domain level by core `FindingIdentity` |

## Canonical Lifecycle (Stage 2D)

```text
Signal -> Candidate -> Replayed -> Minimized -> Proved
                   \____________ Rejected from any intermediate stage
```

- `rustyfuzz_core::FindingLifecycle` + `transition()` validator
  (illegal transitions are typed errors).
- Rejection terminal; backward transitions illegal.
- Idempotent same-stage transitions allowed.

Mapping notes: `Lead -> Signal`; `PocGenerated -> Minimized` (PoC generation
gathers evidence and must not advance proof); `Confirmed -> Proved`
(policy-gated by promotion config).

## Finding Identity

`rustyfuzz_core::FindingIdentity::v1`: versioned normalized components
(rule id, target, semantic input id, evidence fingerprint). Dedup must use
these, not messages/paths/timestamps.

## Invariants Enforced By Tests

- `signal_cannot_become_proved_without_policy_stages` (core)
- `canonical_lifecycle_allows_forward_and_rejects_backward` (core)
- `rejection_is_terminal_and_available_from_intermediates` (core)
- `stage_2d_promotion_pipeline_transitions_are_canonical_legal` (monolith)
- `stage_2d_oracle_signal_maps_to_signal_not_proved` (monolith)

Behavior-preserving: no pipeline transition values changed this stage.
