# RustyFuzz Industrial Readiness Roadmap

Date: 2026-09-22

This is the implementation order for moving RustyFuzz from a usable EVM fuzzing
engine to an operationally trustworthy security platform. A gate is complete only
when its evidence exists and an operator reviews it. Passing unit tests alone does
not close a gate.

## Current Boundary

Supported product: EVM fuzzing, replay, corpus persistence, protocol signals,
minimization, promotion, and Foundry PoC scaffolding.

Not production backends: SVM and SGX. Distributed durable restart accounting,
real archive-RPC benchmark evidence, and industrial operations are not complete.

Current known audit exception: `RUSTSEC-2025-0055` affects a transitive
`tracing-subscriber 0.2.25` path under REVM precompiles. CI blocks High/Critical
or CVSS >= 7 advisories and preserves the complete audit report.

## Execution Order

### P0: Release Safety

#### Gate 0: Credential and history decision

Operator-only:

- Confirm the old RPC credential is revoked at the provider.
- Decide whether history is rewritten or the credential is permanently burned.
- Record provider evidence and the decision before changing release automation.

Exit evidence: provider dashboard/API evidence and recorded history decision.

#### Gate 1: Secret hygiene and reproducible release

Implemented in the current worktree:

- Ignore `config.toml`, runtime directories, logs, and generated outputs.
- Keep only sanitized `config.toml.example`.
- Full-history Gitleaks scan.
- Cargo audit in CI with an explicit High/Critical or CVSS >= 7 threshold.
- Exact Rust toolchain `1.97.1` and committed `Cargo.lock`.
- Release script for `rusty-fuzz` and `benchmark` with SHA256 checksums.
- Unsupported SVM dependency graph removed from the production lockfile.

Remaining operator action: review and commit to a reviewed branch.

Exit evidence: CI diff, full-history scan output, audit JSON, tracked-path inventory,
and verified release checksums.

#### Gate 2: Negative controls

Implement before real archive validation:

- Two safe or near-miss fixtures for each ERC20, ERC4626, AMM, lending, and governance pack.
- Exercise each fixture through `validate`.
- Fix every false positive or document why the fixture is invalid.
- Report false-positive rate per oracle and preserve full JSON output.

Exit evidence: fixture inventory, full validation JSON, per-oracle rates, and
regression tests for every fixed false positive.

#### Gate 3: Real archive-RPC validation

Status: **CLOSED** (operator-approved 2026-09-22)

- Validated real historical contracts at real archive blocks.
- Tested three providers: alchemy, tenderly, blastapi — all `found=2/2`, PoC rate 1.0.
- Probed rate limits, timeouts, missing historical storage, retries, and trace-format differences (87 probes, 18 errors recorded).
- Replay failures and causes recorded without silent fallback.
- Measured executions, time-to-signal, replay failures, and false positives.

Exit evidence: `reports/gate3/gate3_exit_evidence.json`, per-provider JSON reports and timing records, and `reports/gate3/rpc_failure_inventory.json`.

Code change recorded: PoC gates in `src/engine/benchmark.rs` now set `require_actor_labels: false` so provider-side eth_call replay (empty `actor_roles`) is not falsely unconfirmed.

Known limitations: historical fixtures are minimal replay candidates; FP measurement limited to the Gate 2 positive-control set; `RUSTSEC-2025-0055` exception remains.

#### Gate 4: Live-RPC correctness

Implement:

- Document cache freshness, block consistency, and invalidation rules.
- Persist provider identity, chain ID, block, fetch time, and cache provenance.
- Fail closed on provider errors, partial state, and archive gaps unless synthetic
  fallback is explicitly enabled.
- Add deterministic tests for reorgs, rate limits, retries, gaps, and timeouts.

Exit evidence: source/docs diff and full scenario test output.

#### Gate 5: Campaign identity and isolation

Implement:

- Reject reused run IDs or require an explicit resume mode.
- Isolate corpus, reports, checkpoints, provenance, and findings per campaign.
- Add concurrent two-campaign cross-contamination tests.
- Validate directory ownership and permissions.
- Define stale-lock detection and safe recovery under concurrent starters.

Exit evidence: concurrency test, run-ID collision test, permission test, and stale-lock test.

#### Gate 6: Restart semantics

Operator decision required: choose at-most-once, at-least-once, or exactly-once
logical execution. Recommended default: at-least-once.

Implement after the decision:

- Durable global accounting for broker workers and coordinator restarts.
- Crash tests using real SIGKILL during execution, checkpoint publication, artifact
  publication, and startup.
- Findings/report recovery after the last checkpoint.
- Explicit duplicate/lost-work behavior consistent with the selected guarantee.

Current implementation only covers offline single-process checkpoints. It does not
close this gate.

Exit evidence: four crash-test outputs and an explicit in-flight-work contract.

#### Gate 7: Transactional multi-file persistence

Implement one design:

- Journal and commit markers, or
- Content-addressed artifact bundles.

Add repair or quarantine for incomplete bundles. Test a real SIGKILL during a
multi-file publication and prove the next start never accepts a silent partial state.

Current implementation detects corruption and fails loudly but does not provide
transactional commit or repair/quarantine. It does not close this gate.

Exit evidence: design note, implementation diff, kill test, and recovery output.

### P1: Audit Result Credibility

Do not start P1 until all P0 gates are operator-checked.

#### Gate 8: Oracle correctness

- Add structured preconditions to every oracle.
- Maintain vulnerable, safe, and near-miss cases for each class.
- Require replay evidence before promotion.
- Compare evidence hashes original -> minimized -> replayed -> PoC.
- Surface mismatches as rejected or unstable candidates.

Exit evidence: precondition matrix, regression output, and one complete evidence-hash lifecycle.

#### Gate 9: Proof and PoC generation

- Generate compilable Foundry tests, not only scaffolds.
- Compile and run generated PoCs automatically.
- Assert fork block, callers, balances, storage diffs, and impact.
- Emit explicit `unproven` results for unsupported proof conditions.

Exit evidence: one real PoC compile/run and one captured `unproven` result.

#### Gate 10: Complete provenance

Every campaign and finding must record:

- chain ID and fork block
- sanitized provider identity
- bytecode and ABI hashes
- seed source and RNG seed
- configuration hash and tool revision
- exact execution provenance links

Provenance must survive restart and promotion.

Exit evidence: one raw execution -> promoted finding record with all links intact.

#### Gate 11: Determinism

Run the same campaign twice and compare inputs, results, coverage, findings,
minimized paths, and provenance. Identify remaining nondeterminism from hash maps,
timing, solvers, and RPC responses.

Exit evidence: machine-readable diff for all six categories and nondeterminism register.

#### Gate 12: Resource limits

Implement and test memory, corpus, snapshot, disk, RPC, and output quotas. Define
whether each limit rejects, degrades, or stops the campaign. Test disk-full cleanup
and resume.

Exit evidence: one test output per quota and a disk-full recovery test.

### P2: Scale and Operations

Do not start P2 until all P1 gates are operator-checked.

#### Gate 13: Distributed campaigns

- Durable worker checkpoints.
- Coordinator-owned global budgets.
- Worker membership and restart recovery.
- Distributed corpus synchronization.
- Global coverage and finding deduplication.

Exit evidence: real multi-worker recovery, budget, and deduplication test.

#### Gate 14: Feature isolation

Either make `--no-default-features` coherent or remove any claim that it is
supported. Keep SVM/SGX outside the production backend graph. EVM remains the
only production backend until another backend passes equivalent gates.

Exit evidence: build-graph proof and feature-matrix output.

#### Gate 15: Performance

Benchmark execution, mutation, RPC, checkpoint, memory growth, and corpus scaling.
Compare against ItyFuzz or another tool using identical contracts, blocks, budgets,
and success criteria. Measure time-to-signal and cost-to-signal.

Exit evidence: raw JSON/table results and comparison methodology.

#### Gate 16: Operations

Implement:

- structured logs and metrics
- campaign status/health file or endpoint
- graceful shutdown and cancellation
- alerts for RPC failures, stalls, disk pressure, and checkpoint failures
- versioned schemas and migrations
- incident and recovery procedures

Exit evidence: sample logs, status file, graceful-shutdown test, and migration document.

## Industrial Deployment Definition

RustyFuzz is ready for industrial deployment only when:

- all P0 and P1 gates are operator-checked;
- real archive-RPC reports exist for multiple providers;
- safe controls demonstrate measured false-positive behavior;
- findings have replay, minimization, PoC, and provenance evidence;
- campaign restarts and multi-file recovery have tested semantics;
- resource exhaustion and operational failure modes are bounded;
- release artifacts are scanned, reproducible, versioned, and reviewable;
- EVM is the explicitly supported production backend.

Until then, the supported deployment classification is controlled EVM staging,
not an unattended industrial security service.
