# RustyFuzz Production Readiness — Tracked Checklist

**Purpose of this file:** this is the working contract between the operator and Codex for
moving RustyFuzz from "working EVM fuzzing engine" to "operationally trustworthy security
platform." It replaces open-ended prompts like "make it production ready."

**Rules for every gate below:**

1. One gate is worked at a time, in order, unless explicitly reordered by the operator.
2. A gate is only checked off when its **Evidence required** artifact exists and has been
   shown — not described. Command output, diffs, and file paths, not summaries.
3. If a gate cannot be finished, Codex states exactly what is blocking it and why, instead of
   writing a completion-shaped summary around the gap.
4. Codex does not mark a checkbox. The operator does, after reviewing the evidence.
5. No gate in P1 starts until every P0 gate is checked. No gate in P2 starts until every P1
   gate is checked. Sub-items within a gate may be parallelized by Codex only if the operator
   says so.

Standing instruction to paste at the top of every Codex session working this file:

> Work only on the gate I name below. Do not touch other gates. Do not summarize completion —
> show me the diff and the actual command output for every item in "Evidence required." If
> something is blocked, say what's blocking it and stop; do not write around the gap.

---

## Status snapshot (fill in / update as gates close)

**Current gate boundary: Gate 2 closed (with follow-ups A–D tracked) and Gate 3 closed
(operator-approved 2026-09-22) → working on Gate 4.**
**Overall classification: controlled EVM staging with operator review of every finding.
Not ready for unattended bounty hunting, CI-as-security-gate, or customer-facing scanning.**

| Area | Status |
|---|---|
| Internal EVM fuzzing | usable |
| Offline deterministic campaigns | usable |
| Controlled staging | possible with safeguards, operator reviews every finding |
| Live archive-RPC production service | multi-provider archive validation done (Gate 3); live-RPC correctness hardening is Gate 4 |
| Distributed production fuzzing | not implemented |
| SVM/SGX production support | not implemented |
| ItyFuzz-level maturity | not yet |

---

## P0 — Required before production deployment

### Gate 0 — Rotate secrets (operator-only, not Codex)

This gate is **not delegated to Codex.** Rewriting git history or `.gitignore` does not
neutralize an exposed credential; only rotating it at the provider does.

- [ ] RPC credential rotated at the provider dashboard (Alchemy/Infura/etc.), old key revoked.
- [ ] Decision made and recorded: is git history being scrubbed (BFG / `git filter-repo`), or
      is the key being treated as permanently burned and left in history?
- [ ] If scrubbing: confirm every clone/fork that matters is aware, since rewritten history
      breaks existing checkouts.

**Evidence required:** confirmation from the provider dashboard that the old key is revoked
(screenshot or provider API response), and the recorded decision above. Do this before Gate 1.

---

### Gate 1 — Secret hygiene and release boundary

**Prompt to send Codex:**
> I've already rotated the RPC credential at the provider — do not touch that. Your job:
> 1. Remove `config.toml` from git tracking, add it to `.gitignore`, confirm
>    `config.toml.example` has no real values.
> 2. Add a CI job running gitleaks (or trufflehog) against the full history and fail the build
>    on any hit.
> 3. Add `cargo audit` or `cargo deny` to CI; fail on any advisory at or above [severity — set
>    this before sending].
> 4. List every generated/runtime path currently tracked in git that shouldn't be (`corpus/`,
>    `reports/`, `.rustyfuzz/`, `target/`, etc.) and remove them from tracking.
> 5. Produce a reproducible build: confirm `rust-toolchain.toml` pins an exact patch version
>    (not a channel), confirm `Cargo.lock` is committed, and add a build script that emits
>    SHA256 checksums for the release binaries.
>
> Show me the CI YAML diff, the gitleaks scan output run locally against current HEAD, and the
> checksum output from one real build.

- [ ] `config.toml` untracked, `.gitignore` updated, `config.toml.example` confirmed clean.
- [ ] CI secret scan added and passing against current HEAD (paste output).
- [ ] `cargo audit`/`cargo deny` added to CI, severity threshold set and enforced.
- [ ] Generated/runtime paths removed from tracking (list them).
- [ ] Reproducible release: pinned toolchain, committed lockfile, checksummed binaries from a
      real build.
- [ ] Changes committed to a reviewed branch (not pushed straight to main).

**Evidence required:** CI YAML diff, local gitleaks run output, one real checksum output.

---

### Gate 2 — Negative-control benchmarks

Do this before Gate 3. Every known-vulnerable fixture today is a positive case — a detector
that has never been run against known-safe contracts can't be distinguished from one that
flags everything. This changes what "validation passed" means for every later gate.

**Prompt to send Codex:**
> For every oracle pack (ERC20, ERC4626, AMM, lending, governance), add at least 2
> negative-control fixtures — contracts deliberately *not* vulnerable to that oracle's
> pattern, including near-miss cases that share surface features with vulnerable ones but
> aren't exploitable. Run `validate` against them. Report false-positive rate per oracle. If a
> negative control fires, that is a bug in the oracle — fix it or explain in writing why the
> fixture is wrong. Paste the actual validation JSON output, not a summary.

- [x] ≥2 negative-control fixtures per oracle pack (ERC20, ERC4626, AMM, lending, governance).
      *Reported: 10 fixtures, 2/class, all executable.*
- [x] Near-miss cases included (share surface features, not actually exploitable).
- [x] `validate` run against all negative controls; JSON output pasted in full.
- [x] False-positive rate reported per oracle. *Reported: 0% FP on 10 fixtures; positive
      counterparts trigger all 5 classes.*
- [x] Any firing negative control resolved. *None fired — no resolution needed for this
      fixture set.*

**Evidence required:** fixture list, full validation JSON, per-oracle false-positive rate. —
**received and reviewed.**

**Gate 2 status: closed for this fixture set, with three follow-ups carried forward before
the 0% FP claim is leaned on anywhere downstream (Gate 3 sequencing, reports, marketing
copy, etc.). Do not treat "0% FP" as a production statistic yet — see below.**

- [ ] **Follow-up A — sample size.** 2 fixtures/class catches regressions but isn't enough to
      claim a production false-positive rate. Ask Codex, per oracle class: what is the
      smallest additional fixture count that would make the FP claim statistically
      meaningful, and what would those fixtures need to vary (parameter values, contract
      structure, not just copies with renamed variables)?
- [ ] **Follow-up B — coverage-dependent oracle soundness.** The new mint rule ("no observed
      mint rejection ⇒ inflation") is unsound against fuzzer coverage gaps, not just against
      contract behavior: if the fuzzer never generates an input that exercises the
      unauthorized-mint path, the oracle cannot distinguish "contract has no protection" from
      "fuzzer didn't try hard enough." This is not fixed by adding more fixtures — it's fixed
      by measuring whether the campaign actually exercised the negative path before a finding
      from this oracle is trusted. Ask Codex to report, per finding from this oracle class,
      whether the unauthorized path was observed-and-rejected (strong evidence) or
      never-attempted (weak evidence, currently indistinguishable from a real bug in the
      report). Track this as its own line item, since it recurs for any oracle built the same
      way — carried forward into Gate 8.
- [ ] **Follow-up C — unmatched cross-pack signals.** 4 unmatched signals (e.g. bridge-on-mint)
      are currently classified as "heuristic noise, not class FPs." That classification is
      only trustworthy if each of the 4 has actually been triaged by hand. Ask Codex for the
      per-signal triage: what fired, why it's judged noise and not a real gap, and whether
      it's expected to recur. Undocumented "noise" and an unexamined bug look identical from
      outside — this closes that gap.
- [ ] **Follow-up D — RUSTSEC-2025-0055 exception.** Reported as a "documented exception."
      Confirm this by asking Codex to show the actual `cargo audit`/`cargo deny` config line
      registering the exception and the written justification — not just the word
      "documented" in a summary.

---

### Gate 3 — Real archive-RPC validation

**Prompt to send Codex:**
> Run `validate` against real historical contracts and real archive blocks — not cached/local
> fixtures. Test against multiple RPC providers, and exercise: rate limiting, timeouts,
> missing storage, provider-specific trace-format differences. Record the JSON reports,
> false positives, replay failures, and timing for each. Paste the actual reports.

- [x] `validate` run against ≥2 real archive-RPC providers on real historical contracts.
      *3 providers: alchemy, tenderly, blastapi — all `found=2/2`, PoC rate 1.0, exit 0.*
- [x] Rate-limit behavior tested and documented. *Tenderly `-32005`, Alchemy free-tier
      trace rejects, BlastAPI burst drops recorded in failure inventory.*
- [x] Timeout behavior tested and documented. *BlastAPI 1s timeout and eth_call 2328ms
      failure recorded.*
- [x] Missing-storage (archive gap) behavior tested and documented.
- [x] Provider-specific trace-format differences identified and handled or documented as gaps.
      *Alchemy rejects `debug_traceTransaction`/`trace_transaction` (-32600); BlastAPI
      "Only core evm requests are allowed."*
- [x] Replay failures logged with cause, not silently retried/ignored. *87 probes, 18
      errors — no silent fallback.*

**Evidence required:** JSON validation reports per provider, timing data, explicit list of
replay failures and their causes. — **received, reviewed, and operator-approved 2026-09-22.**

**Gate 3 status: CLOSED (operator-approved 2026-09-22).**

Evidence paths:

- `reports/gate3/gate3_exit_evidence.json` (status `ready_for_operator_review`, all exit
  criteria true)
- Per provider: `reports/gate3/{alchemy,tenderly,blastapi}/{validation_report,scoring_calibration,timing_record}.json`
  and Foundry `.t.sol` artifacts under `validation/<benchmark>/`
- `reports/gate3/rpc_failure_inventory.json` (87 probes, 69 ok, 18 errors)

Wall clock: alchemy 2.446s, tenderly 2.138s, blastapi 2.376s. TTS avg ~0.41–0.61s.

Code change recorded: PoC gates in `src/engine/benchmark.rs` now set
`require_actor_labels: false` so provider-side eth_call replay (empty `actor_roles`) is not
falsely unconfirmed.

Known limitations carried: historical fixtures are minimal replay candidates; FP measurement
limited to the Gate 2 positive-control set; `RUSTSEC-2025-0055` exception remains (see
Follow-up D); Gate 2 follow-ups A–D still open.

---

### Gate 4 — Harden live-RPC behavior

**Prompt to send Codex:**
> 1. Define cache invalidation and RPC consistency rules explicitly (when is cached fork
>    state considered stale, and what happens then).
> 2. Persist RPC/fork provenance (which provider, which block, when fetched) alongside cached
>    state.
> 3. Handle provider errors and partial historical state explicitly — no silent fallback to
>    synthetic state unless `--allow-synthetic-fallback` is passed.
> 4. Write tests for: chain reorgs, rate limiting, retries, archive gaps, timeouts.
> Show me the test file and the actual test run output.

- [ ] Cache invalidation / consistency rules documented in code and docs.
- [ ] RPC/fork provenance persisted with cached state.
- [ ] Provider errors and partial state fail closed by default (confirmed by test, not code
      reading).
- [ ] Reorg test written and passing.
- [ ] Rate-limit test written and passing.
- [ ] Retry-behavior test written and passing.
- [ ] Archive-gap test written and passing.
- [ ] Timeout test written and passing.

**Evidence required:** test file diff, full test run output (not just "passed" — the actual
assertions and scenario names).

---

### Gate 5 — Campaign identity and isolation

**Prompt to send Codex:**
> 1. Prevent accidental reuse of run IDs (collision detection or enforced uniqueness).
> 2. Ensure corpus, reports, checkpoints, provenance, and findings cannot overlap between
>    campaigns — write a test that runs two campaigns with different IDs concurrently and
>    asserts zero cross-contamination of any of those five artifact types.
> 3. Add ownership/permission checks for campaign directories.
> 4. Make stale-lock recovery explicit: define what "stale" means (age threshold? PID check?),
>    and what happens on recovery (wait, force-break with warning, refuse to start).
> Show me the concurrency test and its output.

- [ ] Run-ID collision prevented (test: attempt reuse, confirm rejection or safe handling).
- [ ] Concurrent-campaign isolation test written, covering all five artifact types (corpus,
      reports, checkpoints, provenance, findings), passing.
- [ ] Ownership/permission checks added for campaign directories.
- [ ] Stale-lock definition documented (age threshold and/or liveness check).
- [ ] Stale-lock recovery behavior implemented and tested (what happens, is it safe under
      concurrent recovery attempts).

**Evidence required:** concurrency test file and output, stale-lock test output.

---

### Gate 6 — Restart semantics

**Operator decision required before Codex starts implementation:** does RustyFuzz guarantee
at-most-once, at-least-once, or exactly-once logical execution across a restart? For a
security-finding tool, at-least-once (never silently lose a finding; tolerate rare duplicate
work) is usually the safer default — exactly-once is expensive and often illusory across
distributed workers. Record the decision here before sending the prompt below.

**Decision:** _______________ (fill in before starting this gate)

**Prompt to send Codex:**
> The product guarantees [at-most-once / at-least-once / exactly-once] logical execution
> across restarts — implement to that guarantee, don't pick your own.
> 1. Implement durable campaign-wide accounting for broker/worker processes, not just
>    single-process offline campaigns (current checkpoints only cover that case).
> 2. Add crash tests at each of: mid-execution, mid-checkpoint-publication,
>    mid-artifact-publication, and process startup. Each test kills the process (SIGKILL) at
>    that exact point and asserts recovery matches the stated guarantee.
> 3. Define and implement recovery of findings/reports created after the last checkpoint —
>    are they replayed, lost, or double-counted, and does that match the stated guarantee?
> Paste the actual test output for all four crash points.

- [ ] Execution guarantee decided and recorded above.
- [ ] Durable multi-worker/broker checkpoint accounting implemented (not just single-process).
- [ ] Crash test: mid-execution kill — recovery matches guarantee.
- [ ] Crash test: mid-checkpoint-publication kill — recovery matches guarantee.
- [ ] Crash test: mid-artifact-publication kill — recovery matches guarantee.
- [ ] Crash test: process-startup kill — recovery matches guarantee.
- [ ] Post-last-checkpoint findings/reports recovery behavior defined and tested.

**Evidence required:** four crash-test outputs (real SIGKILL, not simulated), explicit
statement of what happens to in-flight work at each kill point.

---

### Gate 7 — Transactional multi-file persistence

**Prompt to send Codex:**
> Current recovery detects corruption and fails loudly — that's necessary but not sufficient.
> Implement one of:
> (a) a journal/transaction manifest with commit markers, or
> (b) a content-addressed artifact bundle.
> Add repair-or-quarantine behavior for incomplete bundles (define which one, and why).
> Write a test that kills the process mid-write across a multi-file artifact set and asserts
> the result is either a clean commit or a cleanly quarantined incomplete write — never a
> silently-accepted partial state. Paste the test output.

- [ ] Approach chosen (journal+commit-markers vs. content-addressed bundle) and documented.
- [ ] Implementation complete.
- [ ] Repair-or-quarantine behavior implemented for incomplete bundles.
- [ ] Mid-write kill test written and passing — confirms no silent partial-state acceptance.

**Evidence required:** design note on approach chosen, test file, test output from a real
kill mid-write.

---

## P1 — Required for credible audit results

*(Do not start until every P0 box above is checked.)*

### Gate 8 — Oracle correctness hardening

- [ ] Precondition checks added to every oracle.
- [ ] False-positive regression cases added (builds on Gate 2's negative controls).
- [ ] Replay evidence required before any finding is promoted (not just scored).
- [ ] Evidence hashes compared across original → minimized → replayed → PoC executions;
      mismatches surfaced, not swallowed.
- [ ] Each finding class tested against both a vulnerable and a safe contract.
- [ ] **Coverage-dependent soundness (carried forward from Gate 2 Follow-up B).** For every
      oracle whose logic includes an "absence of X ⇒ vulnerable" rule (e.g. the mint-rejection
      rule: "no observed mint rejection ⇒ inflation"), the oracle's output is only as trustworthy
      as the fuzzer's coverage of the negative path. Add a coverage flag to every finding from
      this class of oracle: was the unauthorized/negative path actually observed-and-rejected
      (strong evidence), or never attempted (weak evidence — currently reported identically to
      a real bug)? Audit every oracle in the current pack for this pattern, not just the mint
      rule — it's a design smell, not a one-off bug.
- [ ] Reports and promoted findings do not overstate certainty: since current oracles are
      heuristic (selector + storage-diff + text match) rather than formal-invariant checks,
      confirm nothing downstream of the oracle (report text, promotion status, CLI output)
      implies more certainty than "heuristic match, unproven" until Gate 9's PoC validation
      has run on that specific finding.

**Evidence required:** per-oracle precondition list, regression test output, evidence-hash
comparison output for at least one full finding lifecycle, and the coverage-flag audit above.

---

### Gate 9 — Proof and PoC generation

- [ ] Scaffold-only PoCs replaced with compilable Foundry tests.
- [ ] Generated PoCs validated automatically (compiled and run, not just emitted).
- [ ] Fork block, caller roles, balances, storage diffs, and expected impact verified in the
      PoC, not assumed.
- [ ] Unsupported proof conditions produce an explicit `unproven` result (never silently
      dropped or misreported as proven).

**Evidence required:** one real PoC compiled and run end-to-end with output pasted; one
example of an `unproven` result and the condition that triggered it.

---

### Gate 10 — Provenance completeness

- [ ] Every campaign records: chain ID, fork block, RPC provider identity, bytecode hash, ABI
      hash, seed source, RNG seed, configuration hash, tool revision.
- [ ] Each finding links to the exact execution provenance record(s) that produced it.
- [ ] Provenance survives restart (ties to Gate 6) and survives promotion.

**Evidence required:** one full provenance record from a real campaign, shown end-to-end from
raw execution through a promoted finding.

---

### Gate 11 — Determinism testing

- [ ] Identical campaign run twice; inputs compared and matched.
- [ ] Execution results compared and matched.
- [ ] Coverage compared and matched.
- [ ] Findings compared and matched.
- [ ] Minimized paths compared and matched.
- [ ] Provenance compared and matched.
- [ ] Any remaining nondeterminism (hash-map ordering, timing, solver internals, RPC response
      variance) identified and documented, even if not yet fixed.

**Evidence required:** diff output from the two runs across all six categories above; a
written list of known remaining nondeterminism sources.

---

### Gate 12 — Bounded resource usage

- [ ] Memory limit implemented and tested.
- [ ] Corpus size limit implemented and tested.
- [ ] Snapshot limit implemented and tested.
- [ ] Disk quota implemented and tested.
- [ ] RPC budget implemented and tested.
- [ ] Output quota implemented and tested.
- [ ] Behavior at each limit tested (what happens when hit — reject, degrade, stop cleanly?).
- [ ] Cleanup and resumability after a disk-full condition tested explicitly.

**Evidence required:** test output for each limit being hit, and one disk-full
recovery test output.

---

## P2 — Capability expansion

*(Do not start until every P1 box above is checked.)*

### Gate 13 — Brokered and distributed campaigns

- [ ] Durable worker checkpoints across the broker architecture.
- [ ] Coordinator-owned global budgets (not per-worker only).
- [ ] Worker membership tracking and restart recovery.
- [ ] Distributed corpus synchronization.
- [ ] Consistent global coverage and finding deduplication across workers.

**Evidence required:** multi-worker test showing checkpoint recovery, budget enforcement, and
deduplication in a real run.

---

### Gate 14 — Feature isolation

- [ ] `cargo check --no-default-features` made coherent, OR the "supports
      `--no-default-features`" claim removed from docs — pick one and make the repo consistent.
- [ ] SVM and SGX prototypes moved out of the supported build graph (feature-gated and
      clearly marked experimental, or removed from default build entirely).
- [ ] EVM confirmed as the only production backend until another backend passes equivalent
      validation gates (P0–P1) on its own.

**Evidence required:** `cargo check --no-default-features` output (or doc diff removing the
claim), build graph showing SVM/SGX isolation.

---

### Gate 15 — Performance engineering

- [ ] Execution throughput benchmarked.
- [ ] Mutation throughput benchmarked.
- [ ] RPC overhead benchmarked.
- [ ] Checkpoint overhead benchmarked.
- [ ] Memory growth over a long campaign benchmarked.
- [ ] Corpus scaling behavior benchmarked.
- [ ] Comparison run against ItyFuzz (or another tool) using the same contracts, blocks,
      budgets, and success criteria.
- [ ] Time-to-signal and cost-to-signal measured, not just bug count.

**Evidence required:** benchmark output tables/JSON, the comparison methodology and raw
results against the comparator tool.

---

### Gate 16 — Operational platform work

- [ ] Structured logs and metrics emitted.
- [ ] Campaign health endpoint or status file implemented.
- [ ] Graceful shutdown and cancellation implemented and tested.
- [ ] Alerting for RPC failures, stalled campaigns, disk pressure, checkpoint failures.
- [ ] Artifact schemas versioned, with a migration path for old versions.
- [ ] Incident/recovery procedures documented.

**Evidence required:** sample structured log output, sample status file, one tested graceful
shutdown, the schema migration doc.

---

## How to use this file with Codex

1. Copy the **Prompt to send Codex** block for the current gate (or write one following the
   same pattern for P1/P2 gates, which are left as checklists for the operator to prompt from
   since they're narrower).
2. Send it in its own session/message — do not batch gates.
3. Require the evidence listed before checking the box yourself.
4. If Codex reports a blocker, record it inline under the gate (add a `**Blocked:**` note)
   rather than letting the checkbox sit ambiguous.
5. Re-run Gate 2's negative controls and Gate 11's determinism test periodically as regression
   checks even after they're checked off — these are the two gates most likely to silently
   regress as other gates change execution paths.
