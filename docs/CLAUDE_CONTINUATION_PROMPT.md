# Claude continuation prompt — RustyFuzz

You are taking over active implementation of my RustyFuzz project. Continue
building from the existing working tree. This is an implementation handoff,
not a request for another broad review or a proposal that waits for approval.

## My request and working preferences

I own this tool and have authorized its development and local testing. My
latest implementation request was: proceed with the remaining environment,
snapshot, scheduler, and proof improvements tracked in
`docs/IMPLEMENTATION_PLAN.md`. My longer-term objective is a reliable,
competitive EVM fuzzing tool with reproducible discovery and trustworthy
evidence. I repeatedly authorized continuing the build.

Start doing useful implementation work after inspecting the current state.
Do not ask whether to proceed with changes already covered by this request.
Ask only for information or permissions actually required by your environment.
Preserve unrelated work and existing tests. Do not reset the repository,
overwrite my changes, or commit/push without a request. Give short progress
updates and explain material changes, tests, and remaining limits honestly.
Do not claim market leadership or production readiness from feature counts,
synthetic demonstrations, supplied exploit replay, or passing unit tests.

## Workspace and exact stopping point

- Repository: `/home/pin0ccs/Desktop/RustyFuzz`.
- Shell: Bash. Handoff date: 2026-10-20, Africa/Nairobi.
- HEAD at handoff: `b3bafb4`.
- All implementation changes described below are **uncommitted**. Several
  important new source/test/doc files are still untracked. Read both tracked
  diffs and untracked files; `git diff` alone is insufficient.
- The previous session was limited to writes in this repository and `/tmp`;
  `.git` was read-only. Honor the permissions of your own environment.
- No build/test process was intentionally left running at handoff.
- `docs/IMPLEMENTATION_PLAN.md` exists but still mostly describes the first
  correctness patch. Its current unchecked boxes and v4 narrative have NOT
  been reconciled with the subsequent implementation. Update it after checking
  the code; do not assume its stale statuses mean the newer work is absent.
- Earlier assessment: `/tmp/rustyfuzz-review.md`, if still available.
- Earlier completed-patch test log:
  `/tmp/rustyfuzz-implementation-final-tests.log`, if still available.
- Latest workspace test output captured at handoff:
  `/tmp/rustyfuzz-continuation-final-tests.log`. This is captured tool output,
  not a separately instrumented benchmark or a proof of performance.

The latest `cargo test --workspace --locked` completed successfully with exit
code 0 after the environment, scheduler, snapshot, typed-predicate, benchmark,
fallback, and pin-reconciliation edits. Root library tests: 392 passed. The
snapshot integration suite has 3 passing tests; the predicate suite has 6.
The backend environment suite has 8 passing tests and 1 intentionally ignored
Anvil-dependent test. Other workspace suites and doctests passed too.

Latest `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo fmt --all -- --check`, and `git diff --check` also passed.
These checks do not establish that all roadmap gates are complete.

**First concrete unfinished item:** snapshot pin reconciliation was added
after `fuzz_one` in the bounded single-process loop and the unbounded
checkpoint-enabled loop, but the unbounded single-process loop **without**
checkpointing still lacks that call. Inspect the final `else` loop in
`run_single_process_campaign`, around lines 3227–3234 at handoff. Add equivalent
reconciliation there and a regression that covers all single-process loop
variants. This was noticed while writing the handoff and is not yet fixed.

## Read these first

1. Any applicable `AGENTS.md`, local instructions, and skills in your session.
2. `git status --short`, `git diff --stat`, and the implementation diff.
3. `docs/IMPLEMENTATION_PLAN.md` and
   `docs/adr/0009-committed-storage-observations.md`.
4. The new environment module and backend execution tests.
5. Snapshot mutation/persistence/checkpoint integration.
6. The verifier, predicate, minimizer, promotion, proof, and confirmation paths.
7. The new campaign and proof integration tests.

Use the repository and executable observations as authority. This handoff
describes intent and the last inspected state; verify it before relying on it.
Keep a written stage plan with testable completion gates. Parallel workers
may help if available and allowed, but they must own distinct files/tasks and
must not change each other's work. Do not depend on prior-session agents.

## Implemented foundation: transaction correctness

Main files:

- `crates/rustyfuzz-evm/src/executor.rs`
- `crates/rustyfuzz-evm/src/inspector.rs`
- `crates/rustyfuzz-evm/src/execution.rs`
- `src/evm/fork.rs`
- `src/engine/fuzz_engine.rs`
- `crates/rustyfuzz-evm/tests/execution_state.rs`
- `crates/rustyfuzz-evm/tests/storage_context.rs`
- `tests/proof_state_boundary.rs`

The executor now executes against a transaction-local database clone, loads the
actual caller nonce/account information, and restores ownership correctly on
validation/execution errors. Exploration funding preserves existing account
attributes. Nonexistent funded callers are inserted as existing accounts so
REVM does not silently ignore the synthetic balance. Caller code is preserved
instead of being erased to bypass transaction validation.

Canonical `storage_diffs` come from finalized, committed REVM state:
authoritative original values, final values after repeated writes, rollback
handling, deterministic ordering, and no delta when the final value equals
the original. Attempted SSTORE observations and waypoints remain telemetry;
they must never be treated as committed effects.

Storage observations use the storage-context address for DELEGATECALL,
including nested delegation and transient storage. The fork target preload
preserves balance, nonce, and code rather than replacing the account with a
default account. Root campaign snapshots no longer contain startup fuzzer or
actor funding. Exploration may fund its own transaction-local state, but
original-state proof replay must not inherit that funding.

Existing regressions cover cold storage, repeated writes, top-level revert or
halt, caught child reverts, telemetry exhaustion, call/delegatecall context,
uncached caller attributes, validation failure/retry, original root funding,
and persisted proof-baseline account preservation.

Known scope boundary: these changes canonicalize storage deltas; they do not
yet provide a complete account-effect model for balances, code, creation, and
selfdestruct. Do not describe them as complete EVM state-delta evidence.

## Implemented environment policy

New module: `crates/rustyfuzz-evm/src/environment.rs`, exported from `lib.rs`.
Main integration: executor, `src/evm/fork.rs`, campaign startup, provenance.
Tests: `crates/rustyfuzz-evm/tests/environment.rs`.

`EnvironmentPolicy` is versioned and serializable. It records source, chain,
hardfork, transaction gas limit/price, fee strategy, and blob fee update
fraction. Only fixtures without chain identity/provider provenance receive
explicitly named synthetic Osaka semantics. Identified historical forks
currently support Ethereum mainnet only; unsupported chain IDs are rejected.

The policy validates pinned block number/hash and required post-Merge and
post-Cancun header fields. It resolves mainnet historical forks from block and
timestamp activation schedules. BPO blob pricing changes are handled
separately from instruction-set forks. Transaction gas is capped by both the
configured 10M ceiling and actual block gas limit. Legacy gas price is
`max(1 gwei, header base fee)`. Blob pricing uses actual excess blob gas.

`create_fork_block_env_for_provenance` validates provider chain, block number,
and block hash against the database provenance. Header loading requires real
base fee and excess blob gas when the fork requires them.

A read-only integration review caught a mixed fallback: a successful live DB
could previously be paired with a failed header request's synthetic header.
The latest code makes the DB mutable during startup and replaces BOTH DB and
header with synthetic fixtures when synthetic fallback is explicitly allowed.
If fallback is disabled, startup fails. Verify this with a targeted regression;
the existing workspace pass alone does not isolate that branch.

The schedule was checked against go-ethereum's mainnet chain specification:
`https://github.com/ethereum/go-ethereum/blob/master/params/chainspecs/mainnet.json`.
Pin the reference/version when making reproducibility claims or future updates.

An ignored test compares PUSH0 before/after Shanghai, CHAINID, and high base
fee behavior against a local Anvil process. A previous worker actually ran it
successfully using `/home/pin0ccs/.foundry/bin/anvil`, version 1.7.1, reported
SHA `4072e487`. It was not rerun in the final workspace command because it is
ignored by default. **Anvil uses REVM too:** this is an external client-boundary
check, not independent EVM-engine validation. The independent-engine gate is
still pending. Do not relabel this as Geth/Nethermind differential coverage.

## Implemented scheduler work

File: `crates/rustyfuzz-engine/src/scheduler/mod.rs`.

- Selection alternates pressure ranking and stable-ID round-robin fairness.
- For a stable corpus of N entries, fairness selections reach every entry
  within 2N total selections, including entries with no campaign metadata.
- Weight/count arithmetic saturates instead of overflowing.
- LibAFL calls `on_evaluation` before `on_add`. The scheduler stages the score
  with the semantic input identity, then attaches it only to a matching
  retained child. It does not overwrite the current parent's score.
- Discarded pending scores are cleared on the next evaluation, scheduling
  selection, and restore.
- The checkpoint tuple API remains `(u64, u64)`, but now means fair-turn flag
  and next fair ID, not the old queue-cycle interpretation.
- Seven scheduler regressions include actual StdFuzzer/NopExecutor lifecycle,
  discarded-child ownership, corpus serialization/restore, and add/remove
  fairness.

Do not weaken the pressure-score ownership tests to restore the old behavior.

## Implemented snapshot exploration and portability

Files: `src/evm/corpus.rs`, `src/evm/fuzz.rs`, `src/engine/fuzz_engine.rs`,
`src/engine/checkpoint.rs`, `src/engine/provenance.rs`, and
`tests/snapshot_exploration.rs`.

`SnapshotCorpus::lineage_inputs` is strict: missing snapshots/parents, cycles,
nonzero self-parented roots, missing producing inputs, mismatched producing
input base IDs, and invalid inputs cannot masquerade as valid ancestry.
`root_replay_input` concatenates producing prefixes and the current suffix
into a base-0 input and enforces the full 100-transaction limit.

Post-execution snapshot insertion checks that parent ID equals input base ID,
requires reconstructible lineage, and returns an ID only if it survived
pruning. Pins protect selected/retained bases and their ancestry from pruning.
Pins are serialized with checkpoints. `retain` respects protected ancestry.

The single-process `EvmMutator` accepts a snapshot catalog through
`with_snapshot_corpus`. One mutation branch selects a weighted saved state,
rebases a single transaction on it, validates the complete replay length,
pins it, clears stale waypoint/provenance metadata, and records
`snapshot_rebase`. Sequence growth checks the complete root path length.

Brokered workers deliberately do not use this worker-local rebasing feature.
Their harness rejects nonzero base snapshot IDs because local numeric handles
are not portable across processes. Do not enable brokered snapshot mutation
without implementing portable identities/state transfer.

`persist_root_replayed_artifact` reconstructs nonroot inputs, executes the full
sequence twice from the original DB/environment, checks determinism, reruns
the protocol oracle pack, and persists the full root input, original cache,
full execution, and full replay coverage. It refuses a suffix finding that
does not survive full replay with matching pack/class/target. It drops
suffix-only exploit hypotheses rather than relabeling them as full proof.
That pack/class/target check is a conservative portability gate, not a
replacement for the later typed security predicate.

`ReplayVerifier::replay_with_coverage` was added so persisted full-path coverage
cannot accidentally remain the suffix-only map.

Pin lifecycle was reviewed: pinning every attempted mutation forever would
eventually freeze useful catalog replacement. Latest code adds
`SnapshotCorpus::reconcile_pins` and a campaign helper that derives live base
references from the retained LibAFL corpus after each stage. It is wired into
the bounded loop and checkpoint-enabled loop. **Finish the missing
unbounded/no-checkpoint loop connection first.** Add tests that discard
temporary bases, release their pins, retain live ancestry, and keep the catalog
bounded while allowing new useful states. Ordinary insertion already prunes
unprotected new states; an earlier reviewer corrected an initial claim of
unbounded growth. The established issue was stale pins freezing replacement.

Dataflow state is reset at the beginning of each campaign input so unrelated
inputs do not reuse stale symbolic storage expressions. Transactions within
the same input still share the registry. Snapshot prefixes do not yet carry a
fully reconstructed symbolic/dataflow history; treat this as guidance scope,
not evidence that snapshot continuation has complete prefix taint semantics.

The campaign regression uses a child process, seed 42, 128 executions, and a
minimal storage-counter runtime. It finds a nonroot execution, loads its
recorded full root input, and independently replays it from newly constructed
original state, checking the final storage value. It passed in about 30s.
**This is a multi-step state-continuation test, not the roadmap's withheld
multi-step security-violation discovery gate. That stronger gate remains to
be implemented.**

Campaign startup canonicalizes paths under `.rustyfuzz/runs/<campaign_id>/`.
The test reads `inputs/execution_provenance` there; the initially supplied
`corpus_dir` is not the final canonical path. Tests must isolate CWD in a child
process, since in-process campaigns involve LibAFL signals/shared state.

The counter campaign exposed an existing ABI cache lock problem in
`EvmMutator::abi_mutation`: a temporary read guard survived into an `or_else`
closure that requested the same lock for writing. Latest code first stores
`cached_type` in a separate scoped statement, dropping the read guard before
filling a miss. Keep this fix. The campaign passed after it was applied.

## Implemented proof and predicate work

Files: `src/common/verifier.rs`, `src/engine/promotion.rs`,
`src/engine/proof.rs`, `src/engine/confirmation.rs`,
`src/engine/exploit_synthesizer.rs`, `src/engine/benchmark.rs`,
and `tests/violation_predicate.rs`.

`RealismVerifier::prove` now means deterministic, feasible proof-mode replay.
It returns status `Replayed` and grade `DeterministicReplay`, not `Proved`.
Only `prove_violation` can upgrade to `Proved`/`RealisticForkProof`, after
checking a typed predicate. Predicate mismatch returns `Rejected` with
`OracleWeakness`. Nonroot suffix inputs and invalid inputs are rejected.

Preflight checks only the first transaction's value against initial balance.
It no longer subtracts every later transaction's value from initial balances,
which incorrectly rejected callers legitimately funded earlier in the same
sequence. REVM validates sequential balances and gas during actual replay.

The first supported `ViolationPredicate` is deliberately narrow:
`DeniedMint { target, caller, recipient, mint_calldata, policy_calldata }`.
It requires four adjacent successful top-level calls on the same target and
caller: balanceOf(recipient), an explicit canMint/isMinter denial for that
caller, the exact mint(recipient, amount), and a later balanceOf showing an
increase. ABI address padding and positive amount are checked. Probe calls
must not have committed storage mutations. It is bound to the original rule,
target, caller, recipient, and calldata. Unsupported oracle heuristics have
no predicate and must remain unproved.

Promotion derives the original predicate, uses a **proof-mode** executor for
minimization, and minimizes only while that exact predicate holds. Removed
policy probes, changed actors/targets/recipients, or same-class unrelated
signals do not satisfy it. The selected finding's transaction index is rebound
for the minimized sequence before PoC generation. Promotion separately calls
`RealismVerifier::prove_violation` against its original fork cache.

Generated Foundry code for the supported predicate asserts successful calls,
32-byte outputs, the denied policy, and the recipient balance increase.
Unsupported predicates produce an explicitly failing scaffold instead of
empty helpers that could pass as proof. Pre-state storage assertions use the
first old value for each slot; final assertions use the last new value, avoiding
contradictory intermediate-value assertions when a slot changes repeatedly.

`ProofCarryingFinding` now stores an optional typed predicate and a
serde-default `original_state_violation_verified` flag. `from_candidate`
initializes the flag false. Confidence and confirmation are capped until real
original-state predicate verification succeeds. A generated path, score,
invariant label, or repeatable heuristic execution is insufficient.

`verify_original_state(base, environment, map_size)` executes that check and
updates the flag/replay result/confidence. A read-only reviewer initially
found no callers; the final edits wired it into both live and blind benchmark
paths, preserving the original proof DB before exploration. Synthetic
observation-only fixture paths intentionally cannot manufacture that flag.
Those final integrations compiled and passed the latest full suite, but
deserve a targeted positive integration regression.

The tests execute a minimal token runtime with a denied policy and either a
working unauthorized mint or a rejecting safe version. They check predicate
binding, safe-counterpart rejection, missing policy rejection, nonroot replay
rejection, sequentially funded callers, and proof-mode minimization from a
redundant 5-call sequence to the required 4 calls.

Four old benchmark tests failed because they treated heuristic vault or
initializer signals as confirmed proofs. Their expectations now explicitly
reject unsupported predicates, while aggregation behavior is tested
separately. Do not revert this semantic correction just to restore previous
headline "found" counts. All 36 benchmark unit tests passed afterwards, and
the final full workspace suite passed too.

## Evidence, schemas, and boundaries to preserve

- Checkpoint schema: **5**. Its tuple/pin interpretation changed. Older
  checkpoints are rejected; do not silently reinterpret them.
- Execution provenance schema: **5**. New records include
  `root_replay_input` and `environment_policy`; legacy optional fields deserialize
  without pretending legacy evidence has new semantics.
- ADR 0009 still describes the earlier v4 transition and needs a v5 follow-up.
- Source identity, canonical config, run ownership, atomic artifacts, digest
  validation, and path containment already exist. Preserve them.
- Exploration is allowed to synthesize balances. Proof must use original
  pinned state and recorded assumptions. Do not use `deal`, role writes, or
  allowance injection to make an otherwise invalid proof pass.
- Do not equate successful transaction replay with a security violation.
- Do not equate raw storage magnitude with token profit. Keep heuristic
  economic pressure distinct from measured per-token/native asset deltas.
- Default SVM support is intentionally incomplete/unsupported. Do not run an
  indiscriminate all-features build and then "fix" SVM by adding a placeholder.

## What to build next, in order

### Stage A — close and document the current integration

1. Fix the missing pin-reconciliation call in the unbounded/no-checkpoint loop.
   Test stale temporary pin release, retained ancestry, restore, and catalog
   replacement. Verify pin capture is consistent with the retained corpus.
2. Add a targeted startup regression for real DB success followed by header
   failure. Verify fallback replaces both DB and environment, provenance says
   synthetic consistently, and fallback-disabled startup rejects the case.
3. Add a positive end-to-end proof-object/confirmation integration regression:
   a supported predicate starts unverified, succeeds only after original-state
   proof replay, and loses confirmation when original state or the predicate's
   bound observations change. Cover the newly connected benchmark paths.
4. Exercise nonroot artifact persistence directly: full root input, full replay
   coverage/hash, original baseline cache, correct finding indices, rejection
   when a suffix-only signal disappears, and no synthetic funding laundering.
5. Review remaining duplicate lifecycle/proof statuses across candidate,
   confirmation, promotion, artifacts, and CLI. Fix concrete inconsistencies;
   keep unsupported predicates unconfirmed while adding support deliberately.
6. Update `docs/IMPLEMENTATION_PLAN.md` with checked subitems and separate
   incomplete gates; update/add the appropriate ADR for environment, lineage,
   scheduler cursor, schema v5, and typed proof semantics.

### Stage B — finish the actual environment and search gates

1. Add independent-engine comparison against a pinned Geth, Nethermind, or
   equivalent execution implementation. Anvil alone does not fulfill this.
   Compare fork activation, CHAINID, BASEFEE/GASPRICE, blobs where supported,
   transaction status/output/gas, and committed state on representative cases.
   If unavailable, report the exact unverified gate and keep other work moving.
2. Add a withheld multi-step property fixture. The campaign must discover it
   through a nonroot snapshot rather than receive an exploit sequence, then
   reconstruct and reproduce the same property from original state in a fresh
   process. Include the safe counterpart. Separate this from supplied replay.
3. Bind ABI types, selector entries, argument dictionaries, and actor values to
   the concrete target. Inspect `AbiRegistry`, `GlobalAccountRegistry`, ABI
   ingestion, mutation, and generation. Address selector collisions across
   contracts with differing signatures/types. Add executable multi-target
   regressions, not just map-shape assertions.
4. Decide how to reconstruct/persist prefix dataflow for snapshot continuation.
   Current per-input reset prevents stale cross-input expressions but does not
   restore full symbolic prefix history. Keep guidance separate from proof.

### Stage C — expand real evidence and executable harness support

1. Extend typed predicates one protocol/rule at a time. Each needs explicit
   target/actor/asset binding, before/after observations, permission and setup
   assumptions, a vulnerable executable fixture, a safe fixture, negative
   binding tests, minimization preservation, and actual exported assertions.
2. Prioritize concrete accounting/economic predicates supported by real token
   views. Measure per-token/native asset movement, debt, repayment, fees, and
   actor attribution. Do not sum unrelated token units into invented profit.
3. Review generated Foundry replay semantics, especially caller versus origin,
   value source, transaction versus nested-call behavior, setup, gas, and
   environment. Verify equivalence instead of assuming `vm.prank` plus a test
   contract's low-level call is a faithful transaction adapter.
4. Implement executable callback/reentrancy and flashloan attacker harnesses
   with validated deployments, entry points, callbacks, repayment, and property
   checks. Template names or encoded hypothetical calls are not execution.
5. Build the Foundry campaign adapter so setup, handlers, target selectors,
   senders, and invariant semantics survive ingestion and replay. Current
   metadata ingestion is not evidence of complete semantic support.
6. Validate exported PoCs in an actual supported Foundry setup and a fresh
   process, using the original fork and explicit assumptions. Preserve the
   existing opt-in and external-command controls of the host environment.

### Stage D — measured performance and usability

After correctness gates, profile representative campaigns before optimizing.
Track executions/sec, useful discoveries, memory, disk, RPC calls, tracing and
persistence costs. Then implement bounded asynchronous consumers where
appropriate, reduce unnecessary DB/state copying, reuse RPC connections, and
separate stable coverage from guidance channels. Preserve boundedness,
cancellation, crash durability, original-state proof, and deterministic resume.

Add explicit trusted-local-node support through a documented narrow policy,
with tests. Do not globally relax RPC URL/SSRF validation just to reach Anvil.
Add compiler AST/build-info ingestion for Satori where it improves concrete
target understanding. Keep implementation details out of user-facing flows
unless they affect a meaningful user decision.

### Stage E — competitive evidence

Maintain separate results for oracle controls, supplied exploit replay,
guided discovery, and held-out blind discovery. Compare pinned competitors
under matched time/CPU/memory/fork budgets with repeated seeds and ablations.
Count all unmatched signals on safe targets; do not hide them because they
do not match the requested class. Publish limitations alongside results.

## Validation commands and practical notes

Begin with focused tests for your change; run the required workspace checks
once the relevant integration is ready:

```bash
cargo test -p rustyfuzz-evm --locked
cargo test -p rustyfuzz-engine --locked
cargo test --test snapshot_exploration --locked
cargo test --test violation_predicate --locked
cargo test --test proof_state_boundary --locked
cargo test --test checkpoint_restart --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
cargo build --workspace --locked
```

The final explicit `cargo build --workspace --locked` was not run after the
latest edits; test compilation and Clippy passed. Build it before claiming
updated runnable CLI binaries. An earlier oracle-controls run passed 5
matching vulnerable controls and 10 safe controls with no class-matching
signals, plus one existing unmatched accounting signal. That run predates the
latest environment/proof integration; rerun it with newly built binaries:

```bash
python3 scripts/validate-oracle-controls.py \
  --binary target/debug/rusty-fuzz \
  --output /tmp/rustyfuzz-continuation-oracle-controls
```

Optional explicit external-client test:

```bash
cargo test -p rustyfuzz-evm --test environment anvil_client \
  --locked -- --ignored --nocapture
```

Local mock-RPC tests need loopback sockets. In the previous environment, a
sandboxed full suite could fail on socket permissions; the successful final
suite ran through the authorized elevated `cargo test` prefix. Distinguish
an environment-denied test from a code failure, use the actual approval flow
if required, and never silently skip required checks.

The snapshot campaign uses test-only source-identity environment values and
an isolated temporary CWD. Do not copy those synthetic identities into real
campaign configuration. The tests also set
`RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS=0`; retain normal production shutdown
semantics outside a controlled test.

## Definition of done for your next delivery

Finish Stage A and make concrete progress through the original environment,
snapshot, scheduler, and proof gates. Continue further stages as authorized
time and environment permit; do not stop at another architecture essay.
Report precisely what is implemented, what was exercised, which commands
passed, and which gates remain. Review final changes independently when
possible and fix verified findings. Do not mark an entire stage complete
because one narrow example passes.

Your first update should state the current code state and the exact next
implementation step. Then work. My existing authorization to build and test
persists; another generic confirmation request is unnecessary.
