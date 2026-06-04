# RustyFuzz Implementation Status

Last audited: 2026-06-04

Current cleanup state:

- Phase 1 active dead-code cleanup: complete for stale LibAFL integration,
  mitigation bot, dummy mempool CLI/module, inline LLM guidance stub, visible
  SGX executor module, visible SVM/SGX feature claims, and legacy top-of-file
  executor/fork comments.
- Phase 2 bounded single-process mutational loop: complete. Bounded
  single-process runs `fuzzer.fuzz_one(...)` under budget and reports
  `mutated_inputs` vs `seed_replays`.
- Phase 3 finding lifecycle: in progress. Promotion and campaign artifact
  summaries now persist `Signal`, `Candidate`, `Confirmed`, and `Rejected`
  status; promotion only marks `Confirmed` after replay, minimization, and
  validated PoC.
- Phase 4 and later: partially advanced. High-noise oracle rewrites and
  live-RPC replay equivalence remain open; promoted findings now carry replay
  evidence hashes, richer audit-grade markdown sections, and more
  vulnerability-class-specific Foundry assertion helpers.

This document is a source-code status audit. It is intentionally stricter than
README-level claims. The project goal is an EVM-first vulnerability fuzzer that
can complete this loop:

```text
target + fork block + RPC + ABI/bytecode/seeds
  -> fuzz
  -> candidate finding
  -> deterministic replay
  -> minimization
  -> Foundry PoC generation
  -> forge validation
  -> audit-grade report
```

A finding is not confirmed until replay, minimization, and PoC validation
preserve the vulnerability evidence.

## Status Labels

- Working: Active, compiled, tested, and part of the current EVM path.
- Working but heuristic: Active and useful, but evidence can false positive
  without replay/protocol-specific validation.
- Partially wired: Some real implementation exists, but it is incomplete,
  inconsistently connected, or missing strict lifecycle semantics.
- Stub: Placeholder behavior that should not be advertised as capability.
- Broken: Expected to fail compilation or runtime if made active.
- Dead/orphaned: Not exported or not used by the current runtime path.
- Experimental unsupported: Keep out of the default scope until fixed.

## Module Audit

| Module | Status | Evidence | Required Action |
| --- | --- | --- | --- |
| `src/evm/executor.rs` | Working | Active revm sequence execution path; collects tx status, gas, output, storage reads/writes/diffs, call trace, coverage hash, and waypoints. Legacy top-of-file implementation block removed. | Preserve. Make caller funding, value clamping, gas, gas price, and block env assumptions explicit/configurable. |
| `src/evm/fork.rs` | Working | Active fork DB and block-env creation using Alloy provider and revm `CacheDB`. Legacy top-of-file implementation block removed. | Preserve. Keep fail-closed behavior for real campaigns. |
| `src/evm/fork_db.rs` | Working | Lazy RPC-backed account/code/storage/block-hash cache with snapshots, RPC budget, and sanitized RPC errors. | Preserve. Improve diagnostics for budget exhaustion, archive RPC validation, cache consistency checks, and per-campaign RPC budget config. |
| `src/evm/inspector.rs` | Working but heuristic | Valuable coverage, storage, call, taint, branch, and waypoint instrumentation exists. | Harden opcode taint semantics, cross-tx storage taint, memory regions, keccak mapping propagation, boolean negation, shifts, sign extension, expression simplification, and depth management. |
| `src/evm/fuzz.rs` | Working but heuristic | Multi-transaction `EvmInput`, ABI registry, selector-aware mutation, concolic hints, semantic chaining, caller/value mutation, provenance, and DeFi mutations exist. | Add mutation effectiveness telemetry, seed-to-finding attribution, invalid-ABI spam controls, sequence explosion caps, and realistic/disabled flashloan mode distinction. |
| `src/engine/fuzz_engine.rs` | Working, still needs proof hardening | Main LibAFL campaign path is active. Brokered and single-process bounded modes now call `fuzzer.fuzz_one`; telemetry records executions, mutated inputs, seed replays, coverage edges, state novelty, oracle findings, and artifacts. | Add explicit `--replay-seeds-only` only if direct replay is needed. Continue wiring candidate/confirmed finding counters into all surfaces and add regression coverage that bounded campaigns mutate through LibAFL stages. |
| `src/engine/libafl_integration.rs` | Removed | Deleted from active source because it was stale and referenced obsolete symbols. | Keep deleted unless a future rewrite is compiled, tested, and wired through the active engine. |
| `src/engine/mitigation.rs` | Removed | Deleted from active source because mitigation/backrunning is not part of the vulnerability discovery core. | Do not implement mitigation/backrunning before fuzz/prove/report loop is reliable. |
| `src/common/oracle/*` | Working but heuristic | Protocol packs, security, governance, DeFi, MEV, bridge/SVM oracles exist and feed current finding signals. Many emit broad `VulnType` signals. | Reclassify all oracle output as Signal/Candidate until replay-confirmed. Rewrite high-noise reentrancy, ERC4626, access control, price/oracle, governance, and bridge oracles around structured evidence. |
| `src/engine/invariant_manifest.rs` | Partially wired, improving | Runtime invariant manifests are loaded/generated and evaluated from `EconomicDeltaReport`. Explicit math invariant kinds now exist for ERC4626 share price, AMM product, lending health, fee credit conservation, and interest index bounds. | Continue moving math-heavy claims from heuristic storage signals to concrete before/after view probes. |
| `src/engine/economic_delta.rs` | Working but heuristic | Tracks attacker/victim deltas, semantic storage deltas, reserve deltas, flashloan signals, price impact, debt/collateral pressure, share-price pressure, and normalized profit. | Prefer concrete view snapshots over storage classification for confirmed findings. Add clearer provenance for heuristic vs view-derived evidence. |
| `src/engine/promotion.rs` | Working, still needs proof hardening | Promotion lifecycle replays, minimizes, generates/validates Foundry PoCs, persists `FindingStatus`, stores replay evidence hashes, gates `Confirmed` on replay + minimization + validated PoC, and labels unconfirmed severity as a hint. Campaign summaries expose mutated inputs, seed replays, candidates, confirmed findings, rejected candidates, and PoC/replay/minimization counts. Finding markdown now includes affected contracts/functions, root-cause hypothesis, impact, storage/call evidence, false-positive checks, limitations, and recommended fix sections. | Add live-RPC replay equivalence and evidence-hash comparison after minimization/live replay. |
| `src/engine/minimizer.rs` | Partially wired | Minimizes crash/finding paths and generates Foundry PoC artifacts. | Ensure every shrink is replay-validated and preserves evidence hash/profit/invariant/privileged-state change. |
| `src/evm/corpus.rs` | Working | Persistent corpus, seed bundles, fork cache, campaign artifacts, reports, triage markdown, and triage `FindingStatus` exist. | Reorganize campaign output into `candidates/`, `confirmed/`, `rejected/`, `fork-cache/`, `minimized/`, `foundry-poc/`, `reports/`. |
| `src/engine/abi_ingest.rs` | Working | ABI ingestion, selector extraction/classification, ABI cache, and report generation exist. `prove-live` now falls back from an empty proxy ABI to the EIP-1967 implementation ABI when explorer and fork storage data are available. | Add selector confidence levels, proxy ABI fallback metadata in reports, chain-specific explorer metadata, and robust unverified-contract handling. |
| `src/engine/bytecode_analysis.rs` | Working but heuristic | PUSH4/dispatcher selector extraction, proxy/risk flag detection, target profile hints, and function summaries exist. | Preserve. Improve selector confidence, proxy implementation discovery, and decompiler-free fallback paths. |
| `src/evm/etherscan_abi_fetcher.rs` | Partially wired | Fetches verified ABIs and now handles base URLs with existing query parameters; `prove-live` defaults to Etherscan v2 and can fetch implementation ABIs after EIP-1967 proxy discovery. | Add chain-aware explorer abstraction, response classification, cache metadata, rate-limit handling, and tests for v1/v2 URL construction. |
| `src/satori/*` | Partially wired | Satori has static analysis, packet generation, memory, jobs, validation, and reporting paths. Some pieces are real; LLM reasoning depends on external OpenAI API and strict prompts. | Keep Satori separate from inline fuzzing. Do not let Satori findings become confirmed without RustyFuzz replay/minimize/PoC validation. |
| `src/svm/*` | Experimental unsupported | Files remain for future reconstruction, but crate root emits a controlled compile error when `svm` is enabled. | Keep out of EVM default scope. Rebuild only after EVM proof loop is reliable. |
| `src/evm/sgx_executor.rs` | Removed / unsupported | Deleted from active source; crate root emits a controlled compile error when `sgx` is enabled. | Do not spend time on SGX before EVM proof loop works. |
| `src/chain/mempool.rs` | Removed | Dummy mempool scanner and CLI path removed from active source. | Do not advertise mempool scanning until there is a real implementation and tests. |
| `src/hybrid/llm_guidance.rs` | Removed | Empty inline LLM hint stub removed from active source. | Keep LLM guidance in Satori/job generation only. |

## Bounded Single-Process Mode

Bounded brokered and single-process campaigns now call the LibAFL mutation loop:

```text
fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)
```

This replaced the old direct seed/template replay loop:

```text
while !budget.exhausted() {
    let input = direct_seed_inputs[next_seed % direct_seed_inputs.len()].clone();
    let exit = harness(&input);
}
```

Common practical invocations such as `--single-process --max-execs` or
`--single-process --duration-secs` should therefore execute LibAFL mutations
instead of merely replaying seed templates.

Implemented:

- Telemetry includes `executions`, `mutated_inputs`, `seed_replays`,
  coverage edges, state novelty, oracle findings, persisted artifacts,
  candidate findings, and confirmed findings.
- Regression coverage verifies telemetry distinguishes imported seed replays
  from mutated inputs.
- Campaign summaries persist `mutated_inputs`, `seed_replays`,
  `candidate_findings`, `confirmed_findings`, and `rejected_candidates`.

Still open:

- Add an explicit `--replay-seeds-only` mode if direct replay is useful.
- Add an integration test that runs a bounded single-process campaign and
  observes mutated provenance through persisted artifacts.

## Finding Lifecycle Gap

Current code now has promotion stages, confidence caps, and an explicit
lifecycle status:

```rust
enum FindingStatus {
    Signal,
    Candidate,
    Confirmed,
    Rejected,
}
```

Rules:

- Raw oracle output is Signal or Candidate only.
- Replay success upgrades evidence, but does not by itself prove impact.
- Confirmed requires deterministic replay, minimization, and a validated Foundry
  PoC with meaningful assertions.
- Divergent replay or failed PoC marks the artifact Rejected or unstable
  Candidate.
- Severity labels such as High/Critical must be attached only to Confirmed
  reports, or clearly labeled as `severity_hint`.

Implemented surfaces:

- `FindingPromotionRecord.status`
- `CampaignArtifactTriageSummary.status`
- finding markdown status and severity-hint labeling
- campaign summary candidate/confirmed/rejected counters

## Proof Pipeline Requirements

The strict EVM path should become:

```text
fuzz execution
  -> signal/candidate
  -> replay on same fork cache
  -> replay on live RPC at same block
  -> minimize sequence
  -> regenerate exploit path
  -> generate Foundry PoC
  -> run forge test
  -> Confirmed only if all required checks pass
```

Replay artifacts must record:

- chain ID and fork block
- sanitized RPC host
- target address
- bytecode hash
- ABI hash if used
- seed bundle ID
- input ID and fork cache ID
- transaction sequence with callers, values, calldata
- storage diffs, call trace, return data, gas used, tx status
- oracle evidence and economic deltas

## CI / Feature Matrix Truth

Required EVM checks:

```bash
cargo fmt --check
cargo clippy --all-targets --features evm -- -D warnings
cargo test --features evm
cargo check --no-default-features --features evm
```

Optional checks should only be advertised when made real:

```bash
cargo check --no-default-features --features z3
cargo check --no-default-features --features llm
cargo check --no-default-features --features svm
cargo check --features sgx
```

Current audit expectation:

- `svm`: unsupported until crate-root/module/typing issues are fixed.
- `sgx`: unsupported until missing dependencies and outdated revm APIs are fixed.
- `mempool`: not an active product feature.
- inline `llm_guidance`: not an active product feature.

## Phase Status

Phase 1: remove or quarantine active dead code.

- Complete: stale `src/engine/libafl_integration.rs` deleted.
- Complete: `src/engine/mitigation.rs` deleted.
- Complete: dummy `scan-mempool` CLI path and `src/chain/mempool.rs` removed.
- Complete: `sgx` feature emits a controlled unsupported compile error and
  `src/evm/sgx_executor.rs` is deleted.
- Complete: `svm` feature emits a controlled unsupported compile error.
- Complete: old commented-out blocks removed from `src/evm/executor.rs` and
  `src/evm/fork.rs`.
- Complete: empty inline `src/hybrid/llm_guidance.rs` removed.

Phase 2: fix bounded single-process fuzzing.

- Complete for the active bounded loop and telemetry.
- Open: add a persisted-artifact integration test for mutation provenance.
- Open: add explicit `--replay-seeds-only` only if seed replay is still needed.

Phase 3: implement explicit finding lifecycle.

- Complete for promotion records, triage summaries, finding markdown, and
  campaign summaries.
- Open: extend status propagation into any remaining benchmark/reporting paths
  that still expose raw heuristic findings as final results.

Phase 4: rewrite high-noise oracles around structured evidence.

- Open: reentrancy, ERC4626, access control, price/oracle, governance, and
  bridge oracles need true-positive, benign-flow, and known-false-positive
  tests.
- Open: math-heavy detectors should use concrete before/after view probes where
  possible, not hardcoded storage-slot assumptions.

Phase 5: tighten replay/minimization.

- Open: replay same fork cache and live RPC at same block.
- In progress: promoted findings persist replay evidence hashes.
- Open: evidence hash comparison after minimization and live-RPC replay.
- Open: deterministic rejection/unstable-candidate handling when replay
  diverges.

Phase 6: Foundry PoC validation.

- In progress: promotion requires validated PoC before `Confirmed`.
- In progress: generated PoCs include class-specific helper assertions for
  vault/accounting, market/oracle, governance, access-control/proxy,
  reentrancy, bridge, flashloan, and lending evidence.
- Open: make every helper assert class-specific economic/privileged-state
  impact, not only replay status and bounded return-shape sanity.

Phase 7: report quality.

- In progress: promoted finding markdown includes root cause, affected
  contracts/functions, impact, storage/call evidence, reproduction,
  false-positive checks, limitations, and recommended fix sections.
- Open: enrich these sections with detector-owned structured fields instead of
  class-level templates.
