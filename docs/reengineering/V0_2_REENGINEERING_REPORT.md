# RustyFuzz v0.2 Re-engineering Report

Status: RELEASE CANDIDATE REVIEW. Covers the full Stage 0 → 5 migration.

## Initial Architecture (v0.1 baseline, tag `99ac76e`)

Single-crate monolith (~46k LOC at final): CLI + engine + EVM backend +
oracles + persistence + Satori AI pipeline all in `rusty-fuzz`; mixed
identity/feedback in `EvmInput`; no schema versioning; duplicate finding
lifecycles; ad-hoc artifact paths; SVM half-present; SGX vestigial.

## Final Architecture

```text
rustyfuzz-core        ids · input? no — core stays neutral
   ↑
rustyfuzz-evm         executor · fork_db · inspector · dataflow · coverage hash
                      SingletonTx · execution result domain types
   ↑
rustyfuzz-engine      EvmInput model + InputId v1 · scheduler · budget ·
                      telemetry · event sink · concolic stats · CampaignScore
   ↑
root binary           cli/{commands,handlers,helpers} (thin dispatch)
                      harness runtimes · corpus persistence · promotion/proof

rustyfuzz-artifacts   RunLayout · versioned RunManifest · atomic writes
rustyfuzz-testkit     deterministic fixtures (dev-facing only)

core ← artifacts/engine/evm ← root; no cycles (cargo-tree verified)
```

## Stage Ledger

| Tag | Commit | Content |
| --- | --- | --- |
| reengineering-stage-0.5 | 99ac76e | warning-denied clippy, toolchain pins |
| reengineering-stage-1 | d876daa | docs/ADRs/policy |
| reengineering-stage-2a | 56f4136 | workspace + rustyfuzz-core |
| reengineering-stage-2b | 41c3aaa | semantic input/metadata split (+2B.1 correctness) |
| reengineering-stage-2c | 1235ab2 | snapshot identity/fingerprints/ancestry/versioned manifests |
| reengineering-stage-2d | e342583 | canonical FindingLifecycle + FindingIdentity |
| reengineering-stage-2e | e3d2904 | rustyfuzz-evm extraction |
| reengineering-stage-2f | f78963f | shim cleanup, direct crate imports |
| reengineering-stage-3 | 90e994b | rustyfuzz-engine campaign infra + EventSink |
| reengineering-stage-4a | ac41276 | artifacts run layout/manifests |
| reengineering-stage-4d | 501efdb | thin CLI split |
| reengineering-stage-4 | b0da1e9 | OracleSignal + AI proposal seam + testkit |
| reengineering-stage-5 | bbe7014 | CI consolidation, crash-safety, hardening |

## Compatibility Decisions

Legacy pre-2B input JSON remains loadable (`LegacyEvmInputV1` splitting,
`load_input_with_metadata`) and victim-role info survives round trips.
Remaining shims (11 total, each tagged):

- `common/types.rs` re-export layer (TODO stage-2b/2e) — removed with the
  Stage 4 module migration that makes path changes unavoidable;
- scheduler/scoring shims, lifecycle `canonical()` adapters,
  metadata sidecar, legacy `load_input`, oracle pack adapter — all
  TODO(stage-4/v0.3) with owners recorded;
- historical corpora are never rewritten in place.

## Proof Trust Model (FINAL verification)

Only transition to `Proved` is gated by
`status_for_lifecycle`: requires `replayed && minimized && poc_validated`
under promotion policy flags (`strict_proof`, `no_synthetic_proof`,
realism checks via `RealismVerifier`). Oracles emit heuristic signals;
AI proposals are unvalidated-by-construction. No signal→proved shortcut
exists; tests pin this on both sides of the boundary.

## Test / Sanitizer Summary (final run)

Test totals across crates: **248** (lib 202, bins 4, benchmarks-integration
38+1 ign, smoke 1, core 19, engine 9, evm 2, artifacts 7). Sanitizer ASan+LSan
scopes green for every production crate on nightly-2026-08-01; documented
full-workspace ASan exclusion (`end_to_end_smoke.rs` runtime check) persists.

## Known Debt / Unsupported

SVM/SGX unsupported by design. Harness closures remain monolithic pending
worker-boundary redesign. Satori single-provider. `nix v0.30.1`
future-incompat warning is upstream-owned and UNFIXABLE locally:
libafl/libafl_bolts pin nix exactly at 0.30.1, so cargo rejects any
version-changing patch (the previous proc-macro-error2 offender was
cleared by a lockfile refresh alongside alloy 2.4.1). Time-to-signal measurement needs
per-target forks (documented honestly).

## Verdict

All mandatory gates pass; architecture invariants hold with test evidence.
**READY for `reengineering-v0.2-rc1`.**
