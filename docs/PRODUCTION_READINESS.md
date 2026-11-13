# PRODUCTION_READINESS.md — checklist for launch

Status as of 2026-11-12, branch `prod-hardening`, 12 commits on top of
upstream `main` (`a9e2589`). Every claim below is verified by a command you
can run; nothing is aspirational unless it says **ROADMAP**.

---

## 1. Verification discipline (the core product)

| # | Item | Status | Proof |
|---|------|--------|-------|
| 1.1 | Promotion routes `Confirmed` through `FindingConfirmationGate` — one confirmation authority for corpus triage and report artifacts | DONE (`1b29ed8`) | `cargo test -p rusty-fuzz --lib promotion` — 5 gate-routing tests; gate verdict persisted in `finding.json` (`confirmation` field) |
| 1.2 | Campaign↔promotion replay environment parity: promotion replays with the campaign's `TimeWarp`, not a silent default | DONE (`db7f1db`) | `PromotionRequest.time_warp` plumbed at both construction sites (`fuzz_engine.rs`, `cli/handlers.rs`) |
| 1.3 | Fail-closed evidence: economic-view failure is recorded as a caveat, never silently-empty `replay.json` | DONE (`db7f1db`) | promotion.rs `replay_with_economic_views` match + caveat |
| 1.4 | Offline fork cache fails loudly on missing code (`code_by_hash_ref`) instead of executing empty bytecode | DONE (`db7f1db`) | fork_db.rs Decode error; `cargo test -p rustyfuzz-evm --lib` 58/58 |
| 1.5 | Realism preflight distinguishes absent account from unreadable state (RPC outage ≠ `MissingBalance`) | DONE (`db7f1db`) | verifier.rs preflight match |
| 1.6 | Satori bounded-command temp files are `0600` (pre-redaction output exposure) | DONE (`db7f1db`) | fsutil.rs OpenOptionsExt |
| 1.7 | Gate-confirmed tier can never be downgraded by evidence attachment (`with_foundry_poc_path` / `with_economic_delta`) | DONE (`6fe97c2`) | proof.rs upgrade-only recomputation |
| 1.8 | Tri-state predicate discipline (Unknown never promotes) | PRE-EXISTING, verified | audit pass: `eval.rs`/`resolve.rs`/`signal.rs` airtight; every consumer gates on `Outcome::False` only |
| 1.9 | Digest-bound artifact verification (SHA-256, tamper-detection) | PRE-EXISTING, verified | `verify_record_evidence` tests in `rustyfuzz_runner.rs` |

## 2. Rediscovery baseline (the honest headline)

| # | Item | Status | Proof |
|---|------|--------|-------|
| 2.1 | Five `known_vulnerable` cases converted to `executable_evm` fixtures with authored invariant files (`7699d19`…`6b1fe31`) | DONE — **5/5 replay-verified** | `python3 scripts/validate_rediscovery_gate.py` → `rediscovered: 5`, each `found` + `confirmed` + typed predicate + offline Foundry PoC. **Note**: this is replay verification of human-authored exploit calldata, NOT autonomous discovery by the fuzzer. |
| 2.2 | Reentrancy-shaped bugs reachable: replay-mode **Security pack** derives a reentrancy witness from the call trace (re-entry into an open frame from a different account) | DONE (`6fe97c2`) | `known-read-only-reentrancy` produces `VulnType::Reentrancy`; negative controls stay silent |
| 2.3 | Offline Foundry PoC generation for `poc_generation = "required"` cases (no RPC needed) | DONE (`6fe97c2`) | `synthesize_local_validation_poc` wired into the executable path |
| 2.4 | CI replay regression gate pins 5/5 replay-verified + 0 false positives + gate2 parity; ratchet can only tighten | DONE (`cd685b9`) | `.github/workflows/ci.yml` (Replay Regression Gate job); script exits non-zero on any regression |
| 2.5 | Historical `mainnet_fork` cases (Audius 2022, Euler 2023) | **BLOCKED — needs one-time RPC capture** | Audius capture lacks token/WETH balance-mapping slots; Euler has no capture at block 16817995. Re-capture with extended slot manifest, then add typed predicates; the gate already fails any discovery claim without one. ROADMAP until captures exist |
| 2.6 | Baseline report updated honestly | DONE | `docs/backtest/BASELINE_REPORT.md` header |
| 2.7 | **Autonomous rediscovery** (fuzz engine finds bugs WITHOUT authored calldata) — the ItyFuzz-class capability | **PARTIAL — smoke gate landed; historical rate still 0** | The `--attacker-harness` flag (GAP-2) + SMT `smt` feature (GAP-3) are landed. An autonomous-discovery SMOKE gate (`scripts/validate_autonomous_discovery.py` + CI job `autonomous-smoke`) runs `rusty-fuzz fuzz --attacker-harness --allow-synthetic-fallback` with a tight budget and confirms the campaign engine boots, runs, and produces a report. The synthetic target is benign (0 findings expected). A non-zero autonomous rediscovery rate against the `known_vulnerable` fixtures requires a `--fixture` flag (loading fixture pre-deployed state into the fuzz campaign's CacheDB) — the integration point is the existing `in_memory_bytecode` branch at `fuzz_engine.rs:1110`; ROADMAP. |

## 3. Dead code and provenance hygiene

| # | Item | Status | Proof |
|---|------|--------|-------|
| 3.1 | Dead-code purge: ~8,100 LOC across 4 verified groups (orphan files, islands, dead subsystems, crate leaf fns) | DONE (`adfdbab`, `0b5c36f`, `352c1d4`, `842c224`) | `git diff --stat a9e2589..HEAD` ≈ −8.4k; clippy 0 warnings; every group committed after `check`+`clippy`+`fmt` |
| 3.2 | Dormant `z3` feature removed (d364bf5) then re-added as real `smt` feature with working solver (GAP-3) | DONE | `rg z3 Cargo.toml` shows `smt = ["dep:z3"]` (real solver) + legacy `z3 = ["dep:z3"]` (dormant alias). `cargo check --features smt` gates in CI. The old dormant stub is gone; the solver is real. |
| 3.3 | Live items deliberately kept were re-verified before keeping | DONE | purge agent skip-list (telemetry `first_finding`, `DataflowScoreReport`, `EvidenceGrade`, `compare_cached_vs_live`, manifest load/generate/evaluate) |

## 4. Attacker-contract harness

| # | Item | Status | Proof |
|---|------|--------|-------|
| 4.1 | Compiled attacker contract with receive/callback executed mid-sequence inside REVM (validation/benchmark path) | DONE (`6417d3d` + `6fe97c2`) | `ReentrantAttacker`/`HookToken`/`ReentrantVault` fixtures: withdraw → token transfer → attacker `onReceive` → vault re-entry; oracle sees the nested write |
| 4.2 | Campaign-time attacker-contract deployment + `ReentrancyProbe` mutator (flag-guarded `--attacker-harness`, default OFF) | DONE (GAP-2) | `src/engine/attacker_harness.rs`; deploys a reentrancy-attacker template at `ATTACKER_ADDRESS` into the campaign CacheDB at setup; `ReentrancyProbe` mutator inserts probe sequences. 486 lib tests pass with flag OFF (zero regressions). |
| 4.3 | Parameterized attacker with `setTarget(address)` + `setReentrySelector(bytes4)` (re-enter ANY fuzz target, not just pre-baked fixtures) | DONE (GAP-2) | `param_attacker_runtime.bin` (solc-js 0.8.38 compiled); revm unit test `test_param_attacker_reentrancy_callback` proves the deployed attacker re-enters a configured target with the configured selector. |
| 4.4 | Campaign-time attacker-bytecode mutation (evolve attacker behavior alongside calldata) | **ROADMAP** | `ReentrancyProbe` inserts fixed probe sequences; evolving attacker bytecode in parallel with calldata is future work |

## 5. Tooling, crates, throughput

| # | Item | Status | Proof |
|---|------|-------|-------|
| 5.1 | `rustyfuzz-testkit` has real consumers (deterministic fixture builders in integration tests) | DONE (`d364bf5`) | `tests/violation_predicate.rs`, `tests/snapshot_exploration.rs` |
| 5.2 | Release throughput profile (LTO, codegen-units, panic strategy) | PRE-EXISTING | `Cargo.toml` build profiles; `RUSTFLAGS="-C target-cpu=native"` documented for local campaigns |
| 5.3 | Targeted exec/s measurement (350 dev vs 30k tuned claim) | **PARTIAL — per-tx clone eliminated; per-input clone remains** | The executor hot path already eliminated the per-transaction `CacheDB::clone` (executor.rs:149-155, measured 86x win at 50k slots). The remaining per-INPUT clone (`snapshot_base_db.clone()` at fuzz_engine.rs:1886) still dominates on warm forks (~567 exec/s at 50k cached slots vs ~30k on a bare synthetic cache). The flagged structural fix is `Arc<CacheDB>` + per-input overlay journal (share the base fork state, revert touched accounts after each input instead of deep-cloning). This is a deeper refactor with state-isolation correctness risk; ROADMAP. The `exec_throughput.rs` benchmark tracks both shapes. |
| 5.4 | SMT-backed concolic | DONE (GAP-3) behind `smt` feature | `z3` crate links system `libz3.so.4`; `solve_path_constraint_smt` in `src/engine/concolic.rs` discharges linear-arithmetic + bitwise + comparison path constraints over 256-bit symbolic calldata/caller/callvalue/storage. Keccak/mappings return `None` (honest ceiling — z3 has no keccak theory). `cargo check --features smt` gates compilation in CI; 5 SMT unit tests pass. Legacy `z3` feature retained as dormant alias for backward compat. |

## 6. Launch gates (run these before announcing)

```bash
# 1. Clean gates
cargo fmt --all --check
cargo clippy --workspace --all-targets          # 0 warnings
cargo test --workspace --lib                     # ~790 tests, 0 failures
cargo test --test benchmarks                     # 52 tests
cargo test --test end_to_end_smoke               # 2 tests (1 live-gated, ignored)

# 2. Detection gates (after cargo build --release --bin rusty-fuzz)
python3 scripts/validate-oracle-controls.py      # negatives silent, gate2 matches
python3 scripts/validate_rediscovery_gate.py     # 5/5 rediscovered, gate exits 0

# 3. Release build
cargo build --release --locked --bin rusty-fuzz --bin benchmark
scripts/verify-release-artifacts.sh              # if cutting a tagged release
```

## 7. What must happen outside this sandbox (durability)

1. **Push the branch**: `git push origin prod-hardening` — this environment has
   no GitHub credentials; the 12 commits exist only locally until pushed.
   Open the PR against `main` and let CI (including `rediscovery-gate`) run.
2. **Historical captures** (when RPC access exists):
   `rusty-fuzz capture` at Euler block 16817995 and an Audius re-capture with
   token/WETH mapping slots, then author their `InvariantViolated` predicates
   and flip the gate to include them.
3. **Release tag**: cut `v0.2.0` after CI green; `build-release.sh` +
   `verify-release-artifacts.sh` handle provenance.

## 8. Honest capability statement (for the launch post)

- **Strong**: replay, verification, minimization, PoC generation of a
  suspected bug on forked mainnet state; typed three-state invariant
  language where `Unknown` can never promote; digest-bound, gate-confirmed
  evidence artifacts; reentrancy detectable in replay AND reachable in
  campaign mode via the `--attacker-harness` flag (parameterized attacker);
  SMT-backed concolic path solving behind the `smt` feature (linear-arith +
  bitwise + comparison over 256-bit symbolic calldata); 5/5 replay-verified
  regression gate in CI.
- **Not claimed**: autonomous cold-start rediscovery of historical bugs at
  ityfuzz strength (the replay gate verifies authored exploits, not autonomous
  discovery — that gate is ROADMAP); keccak/mapping constraint solving (z3 has
  no keccak theory); exec/s parity with tuned builds (per-input CacheDB clone
  still dominates on warm forks). These are named integration points, not
  silent gaps.
