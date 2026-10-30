# Codex handoff — RustyFuzz, from `057d884` forward

You are taking over active implementation of RustyFuzz, an EVM smart-contract fuzzer.
This is an implementation handoff. Start building after reading the state below; do not
respond with a review, a plan for approval, or a request to confirm scope already given
here.

Written 2026-10-23. Repository: `/home/pin0ccs/Desktop/RustyFuzz`, branch `backtest/v1`,
HEAD `057d884`, working tree clean.

---

## 0. Read this first: the one defect you must fix before anything else

**`ViolationPredicate::holds` is vacuously true for the new `InvariantViolated` variant,
which makes `RealismVerifier::prove_violation` a rubber stamp for every invariant
finding.**

Evidence:

- `src/common/verifier.rs:382-393` — `holds` returns
  `!predicate.trim().is_empty() && !terms.is_empty()`.
- `src/common/verifier.rs:564-589` — `prove_violation` sets `status = Proved` and
  `evidence_grade = RealisticForkProof` when `predicate.holds(execution)` is true.
- `ViolationPredicate::from_invariant_violation` (`src/common/verifier.rs`) **refuses to
  construct** a predicate unless the text is non-empty and `terms` is non-empty
  (tested: `a_violation_without_terms_is_not_a_predicate`).

The two together mean `holds` can never return false for a predicate that exists. So any
invariant finding that reaches `verify_original_state` is stamped `Proved` with
`RealisticForkProof` **without re-evaluating anything on the replayed state**.

Why this matters more than a normal bug: `original_state_violation_verified` is one of the
two conjuncts in the confirmation gate (`src/engine/confirmation.rs:68-70`), and
`evidence_grade` flows into reports. This is the exact failure mode the project's own
rules forbid — a green confirmation path that is green because it stopped checking.

**Required fix, with the reasoning already decided:**

`holds` must **re-evaluate the predicate against the replayed execution**, not trust the
recorded terms. The recorded `terms` are evidence for a human; they are not a proof the
same verdict holds on a fresh replay. Concretely:

1. Give `ViolationPredicate::InvariantViolated` enough to re-run: the predicate text (it
   has it) and the binding manifest (it does **not** have it — add it).
2. Implement `holds` for this variant by building a `rustyfuzz_predicate::PredicateOracle`
   from `(predicate text, manifest)` and evaluating it over the *replayed*
   `SequenceExecutionResult` at `tx_index`.
3. Return true only on `Outcome::False`. `Unknown` and `SatisfiedButDiv0` must return
   **false** here: a re-read that cannot decide is not proof.
4. Add a test that a **stale** predicate — one whose recorded terms say "violated" but
   whose replayed state satisfies it — makes `holds` return false and
   `prove_violation` return `Rejected`. That test is the point of the fix; without it the
   bug can come back silently.

Note the dependency direction: `src/common/verifier.rs` is in the main crate, and
`rustyfuzz-predicate` is already a dependency of it (`Cargo.toml:91`). No new dependency
is needed for this fix.

**Do not** instead delete the `InvariantViolated` variant or revert its use. The variant is
load-bearing: it is the only way a non-`DeniedMint` finding can ever satisfy
`violation_predicate.is_some()`, which is the other conjunct of the gate. Reverting it
restores the deadlock described in §3.

---

## 1. Current state, verified

Measured in this session, not recalled:

```
cargo test --workspace --locked     44 suites, 855 passed, 0 failed, 2 ignored
cargo clippy --workspace --all-targets --locked -- -D warnings    clean
cargo fmt --all                                                   clean
```

Per-suite highlights:

| suite | tests |
|---|---|
| `rustyfuzz-predicate` unit | 108 |
| `approx_eq_matches_foundry` | 9 |
| `real_solidity_basin` | 9 |
| `real_solidity_merkle` | 9 |
| `arithmetic_matches_evm` | 2 |
| `mapping_slots_match_reference` | 1 |
| `end_to_end` (predicate) | 9 |
| main crate unit | 419 |
| `rustyfuzz-evm` unit | 53 |
| `end_to_end_smoke` | 2 pass, 1 ignored (child worker) |

Crates: `rustyfuzz-core`, `rustyfuzz-evm`, `rustyfuzz-engine`, `rustyfuzz-artifacts`,
`rustyfuzz-operations`, `rustyfuzz-testkit`, `rustyfuzz-backtest`, `rustyfuzz-predicate`.

Commits on this branch, newest first, all mine and all passing:

```
057d884  --invariants <path>, wired through to the campaign loop
8f141ef  per-transaction invariant checking (IncrementalChecker)
faaf84a  ViolationPredicate::InvariantViolated
8967b15  zero-config `target` subcommand
cad861c  --rpc-url/--fork-block + ChainProfile (replaces chain_id == 1)
7c76a30  approx_eq matching assertApproxEqRelN
1d123e8  multi-word + cross-contract returns (Basin validation)
d840ded  return-value bindings (Merkle validation)
c6bc1ac  end-to-end acceptance fixture
a1c292e  Signal/InvariantOracle/Evidence
b511b84  tri-state evaluator
c0fdd38  four-step resolution + on-demand re-read
6b41e3a  binding (mandatory bit ranges, packed slots, mapping Keccak)
a89bd4d  type checker + 256-bit wrapping arithmetic
9563204  parser + typed AST
```

---

## 2. Build environment — non-negotiable

These are the owner's explicit instructions. Violating them has already caused wasted
runs and disk pressure.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
```

- `.cargo/config.toml` holds them, but **that path is gitignored**, so it is
  machine-local. Re-export in every new shell, or re-create the file.
- **Never run two build/test commands at once.** They contend and produce misleading
  timings and OOM kills.
- `--offline` works and is preferred for repeat runs.
- Release profile is `lto = "fat"`, `codegen-units = 1`, so a release build is slow. Use
  `cargo build` (dev) for iteration and only build release to measure.

---

## 3. What the deadlock was, and what broke it

This history matters because the next blocker is downstream of it.

**Symptom:** 5 of 7 baseline cases reported "missed (false positives)" with
`rediscovery_rate 0.000`.

**Misdiagnosis (recorded, corrected):** `docs/backtest/PHASE0_POC_GATE.md` and the
correction note in `docs/backtest/BASELINE_REPORT.md` (dated 2026-10-25) record that the
diagnosis "the PoC gate blocks rediscovery" was **wrong**. Re-running with
`RUSTYFUZZ_RUN_FORGE_TESTS=1` produced byte-identical results.

**Real cause — a circular dependency:**

```
PoC generation      requires  confidence_is_confirmed()        (src/engine/benchmark.rs)
confidence_is_confirmed  requires  violation_predicate.is_some()
                                        AND tier == Confirmed  (src/engine/proof.rs:278-280)
Confirmed tier      requires  original_state_violation_verified (src/engine/confirmation.rs:68-70)
original_state_violation_verified requires proof.violation_predicate to exist
                                        (src/engine/proof.rs:166-177)
```

And `ViolationPredicate` had exactly **one** variant, `DeniedMint`
(`src/common/verifier.rs`), constructed only from a mint-authorization finding
(`ViolationPredicate::from_finding`). No other finding could ever supply a predicate. No
entry point into the loop.

**What broke it, in this order:**

1. `faaf84a` added `ViolationPredicate::InvariantViolated { predicate, tx_index, terms }`.
2. `8f141ef` added `IncrementalChecker`/`check_sequence` that evaluate registered
   invariants after every transaction.
3. `057d884` added the `--invariants <path>` file and wired both harness loops to push a
   violation into the same `findings` vector as oracle hits, as
   `VulnType::InvariantViolation`.

**What is NOT yet proven:** that the 5 baseline cases now confirm. The mechanism is
proven end to end (see §5), the baseline has **not** been re-run. Treat "the 5 cases now
confirm" as unknown until you run it.

---

## 4. The predicate layer — what exists, precisely

`crates/rustyfuzz-predicate`. Modules and their real contents:

| file | lines | key items |
|---|---|---|
| `expr.rs` | 169 | `Expr` (incl. `ApproxEq`, `RequiresNoOverflow`), `BinOp`, `BlockField`, `Symbol`, `U256Lit` |
| `lib.rs` | 829 | lexer, `parse`, `compile` → `CheckedPredicate` |
| `types.rs` | 731 | `Sort`, `check`, `Int256`, `ArithmeticCounters`, `Widened` |
| `binding.rs` | 801 | `Binding`, `BindingKind`, `BindingManifest`, `RawBinding`, `mapping_slot`, `extract_bits` |
| `resolve.rs` | 868 | `WriteRecord`, `ReadRecord`, `Provenance`, `Unresolved`, `KeyCoverage`, `StateReader`, `ReReadBudget` |
| `eval.rs` | 1013 | `evaluate`, `Outcome`, `Reason`, `BlockContext`, `verdict_text` |
| `signal.rs` | 171 | `Signal::{Finding, Held, NoSignal}` |
| `oracle.rs` | 706 | `PredicateOracle`, `InvariantRegistry`, `Evidence`, `TermEvidence`, `SequenceView` |
| `chain_profile.rs` (in `rustyfuzz-evm`) | — | `ChainProfile`, `ForkSchedule`, `BlobPricing`, `HeaderRequirements` |

**Operators available today:** `+ - * / %`, `== != < <= > >=`, `&& || !`, `-` (unary),
`approx_eq(a, b, tolerance_bps, precision)`, `requires_no_overflow(expr)`, symbols,
integer literals, `block.timestamp`, `block.number`.

**Binding kinds:** `slot`, `mapping`, `return_value` (with `call_target`, `word_index`).

**Design rulings that are load-bearing — do not reverse them without the owner:**

1. **Bit range is mandatory**, refused at manifest load with the exact text
   `binding X: offset_bits/width_bits required (no default)`. Rationale: a predicate that
   only breaks mid-campaign wastes the run, and silence about packing is how access-control
   predicates break.
2. **Arithmetic is 256-bit wrapping**, EVM-faithful. Checked arithmetic → `Unknown` was
   rejected as trading correctness for safety in the wrong direction.
3. **`div0` returns `0` (EVM-faithful) but a non-zero counter degrades a pass to
   `SatisfiedButDiv0`**, never a clean pass.
4. **Stale reads are `Unknown` for both satisfaction and violation.** The owner rejected
   "stale may prove satisfaction": a stale `True` is as dangerous as a stale `False`
   because it makes the search stop looking.
5. **`Unknown` is "no signal"** — never a finding, never a pass, never raises scheduler
   priority, never penalises. `NoSignal.pressure_delta() == 0`.
6. **`sum` over unobserved keys → `Unknown`**, reporting both `observed_keys` and
   `unobserved_keys`. A harness is not required to read every key; mappings cannot be
   enumerated.
7. **`block.timestamp` is readable, never settable.** `block.number` likewise.
8. **`approx_eq` reproduces `assertApproxEqRelN` exactly**: `b == 0 → a == 0`, else
   `(|a-b| * 10^precision) / b <= tolerance_bps`, integer division **after** scaling.
   Overflow of the scaling multiply yields `false`, never a wrap — a wrapped delta makes
   an enormous discrepancy look tiny.

---

## 5. Verification discipline — the standard this repo is held to

Every claim in a report or commit message needs a path and a line, and every "it works"
needs pasted output. Rules learned the hard way in this session:

1. **A campaign run in-process completes with ZERO executions.** Every test in this repo
   that asserts real execution spawns a child via `std::env::current_exe()`. Running
   `run_fuzz_campaign` in-process reported `total_executions: 0` while "passing". If you
   write an execution test, assert `total_executions > 0` **first**, or a vacuous pass is
   indistinguishable from success.
2. **Synthetic forks deliberately emit no artifacts.** `campaign_artifact_reason`
   (`src/engine/fuzz_engine.rs:3703`) returns `None` when `synthetic_fork_mode`, because
   there is no real chain state to attest a finding against. Do not assert artifacts in a
   synthetic test; assert that the verdict reached the execution provenance.
3. **`sequence_result_from_tx_results` flattens per-transaction diffs.** A fixture that
   puts all diffs only at sequence level models nothing real, and will pass tests that the
   engine cannot.
4. **Grep output is redacted for credential-shaped text** (`Authorization=[redacted]`), so
   matching on it fails. Use hex dumps to read true content.
5. **`parse_word` left-pads short hex**, so a 4-byte selector written `0xdeadbeef` lands
   in bytes 28..32, not 0..4.
6. **Never fabricate** corpus data, fork blocks, addresses, case IDs or ground-truth
   invariants. `docs/backtest/INCOMPLETE.md` is the mechanism: unknown fields are `null`
   with a reason, never a plausible value.
7. **Never edit a report to improve a number.** If a number is bad, report it.

**Write-guard false positives (recurring):** the workspace write guard blocks whole-file
writes when content contains a credential-shaped literal. Historical hits:
`src/common/oracle/packs.rs` (`enum MintAuthorization`), `src/engine/promotion.rs`
(redaction fixture), `src/engine/fuzz_engine.rs` (RPC-URL sanitiser fixture). **All were
fixed at source** by assembling the input from fragments. When it fires, fix the source
the same way; do not reach for a bypass. `apply_patch`/`edit` now work on all three.

---

## 6. Phase status

### Complete

**Phase 0 — trustworthy measurement.** TTFF recording (`f89bd49`), surfaced in campaign
summary with `none` never rendered as `0` (`51842bf`), CI on `backtest/**` (`c099167`),
corrected PoC-gate diagnosis (`6f75eb2`). Baseline re-published unchanged.

**Phase 1 — predicate IR.** All eight components, 108 unit + 22 integration tests across
5 targets. Validated against real Solidity (see §7).

**Phase 3 (partial) — environment ergonomics.** `--rpc-url`/`--fork-block`, `ChainProfile`,
zero-config `target`.

**Phase 2.1, 2.2 — invariant execution, partially.** Registry, per-transaction checking,
finding promotion, `--invariants` file. All wired and proven end to end.

### Incomplete — ordered by what unblocks the most

**A. Fix `holds` for `InvariantViolated` (§0).** Blocks trustworthy confirmation of
every invariant finding. Do this first.

**B. Re-run the baseline and find out whether the 5 cases confirm.** This is the only
question that matters about the work to date. Command (from
`docs/backtest/BASELINE_REPORT.md:128-140`):

```bash
RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS=https://eth-mainnet.g.alchemy.com \
  rusty-fuzz validate \
    --benchmarks /path/to/RustyFuzz/benchmarks/historical \
    --output /tmp/rf-bt/validate.json

GIT_COMMIT_HASH=$(git rev-parse HEAD) cargo run -p rustyfuzz-backtest \
  --bin baseline_report -- \
  /tmp/rf-bt/validate.json /tmp/rf-bt/validate_kv.json \
  docs/backtest/BASELINE_REPORT.json
```

Requires a working RPC endpoint and `benchmarks/historical` present. If either is missing,
**stop and ask the owner** — do not substitute a synthetic fixture and present it as the
baseline. Known environment trap, already documented: `RUSTYFUZZ_RPC_API_KEY` breaks
endpoints that need no auth (Alchemy returns `Must be authenticated!`); unset it.

Then, for each of the 5 cases, record **which** conjunct of the gate failed, if any. Do not
report "5/5 confirmed" — report per case.

**C. Phase 2.3 — structure-aware action grammar.** Measured: **nothing exists.**
`grep -rn "action_grammar\|ActionGrammar" src/engine/*.rs` returns zero matches. This is a
build-from-nothing item, not a refactor. Scope: restrict the mutator to call sequences the
target's ABI and state model actually permit (deposit before withdraw, approve before
transferFrom, no mint after pause) so the fuzzer stops wasting executions on sequences a
contract can never see. Estimate: new module plus mutator integration plus tests; several
days. Do not start it before B answers the baseline question.

**D. Phase 4.1 — SMT solver.** `z3` is a **declared dependency with zero Rust
references** (`Cargo.toml:75,242-244`; `grep -rn z3 --include=*.rs src crates` returns
nothing). It is behind feature `z3`, not built by default. **Enabling it needs owner
approval** — it adds a native library dependency (`libz3-dev` / `brew install z3`) to the
build, which changes what "it builds" means for every contributor. Do not enable it
unilaterally.

**E. Phase 4.2 — attacker contract synthesis.** Measured: **not built.**
`grep -rn "deploy.*attacker\|attacker.*deploy" src` returns nothing. What exists is
`ExploitPathBuilder::from_execution` and `FormalProtocolModel::synthesize`, which reason
about an observed sequence; neither deploys a contract. Building this means: generate a
Solidity contract that performs the attack, deploy it in the fork, and prove the violation
from the attacker contract's call rather than from the tool's own transactions.

**F. Phase 4.3 — PoC against the target suite.** `synthesize_foundry_poc_with_findings`
(`src/engine/exploit_synthesizer.rs:17`) exists and emits `forge-std/Test.sol`-based tests.
`validate_foundry_poc` only runs when `external_foundry_opt_in` is true
(`src/engine/promotion.rs:677`). The gap: a synthesised PoC is validated against
**RustyFuzz's own recorded findings**, not compiled and run against the target's own test
suite as Foundry would. That is what "PoC that compiles against the target suite" means and
it is not there.

**G. Phase 5.1 — corpus expansion.** 7 Tier-1 cases against a 150 target. **143 short.**
Blocked on the owner supplying real data (file paths or URLs) for Tier 2. Do not invent
cases. `docs/backtest/INCOMPLETE.md` documents the shortfall and the rule.

**H. Phase 5.2 — head-to-head benchmark vs Echidna and ItyFuzz.** Nothing exists.
Needs external tool installs and a shared corpus, and must report numbers as measured, not
as desired.

**I. Phase 5.3/5.4 — installer, public report.** `scripts/` has release tooling
(`build-release.sh`, `verify-release-artifacts.sh`, `verify-release-signature.sh`) but no
end-user installer. The public report must carry the caveats in §8.

### Known IR gaps, pinned as tests (not prose)

`crates/rustyfuzz-predicate/tests/real_solidity_basin.rs:329+`, section
"Declared gaps: tests that fail to compile or run when the gap closes":

- `a_call_with_computed_array_arguments_is_not_expressible` — `calcReserve(reserves, 0,
  supply, data)` needs function-call syntax with computed arguments.
  **Still a real gap.** Blocks `invariant_reservesMatchFunctionCalcReserve`.
- `a_multi_word_return_requires_an_explicit_word_index` — supported, but must be named.
- `relative_tolerance_comparison_is_not_expressible` — **this test's premise is now stale.**
  `approx_eq` exists (`7c76a30`) and works through the file format
  (`approx_eq_works_through_the_file_format`). **Rewrite this test**: it should now assert
  that the tolerance form compiles and reproduces `assertApproxEqRelN`, and a new gap test
  should cover whatever genuinely remains. Leaving a stale "declared gap" is worse than no
  test, because it tells the next reader a capability is missing when it is not.

Basin result: **3 of 6** real invariants expressible. Remaining two need computed-argument
calls and nested conditionals.

---

## 7. External validation targets — reproducible, not vendored

Third-party code is **never vendored**. Each is recorded as a manifest with URL + commit.

| target | commit | location | verified |
|---|---|---|---|
| polytope-labs/solidity-merkle-trees | `6bbc83d5ac33f85761725cf2eba4f8700164e8ba` | `/tmp/smt-probe` | 22 tests, confirmed two ways (forge output + static grep 12+4+6) |
| Code4rena 2024-07 Basin | `bbe3cafed46822b0d0b1e0b80f9dee623012bd92` | `~/Desktop/2024-07-basin` | 7 invariants passing, 23.44s, `runs=50 depth=500 fail_on_revert=true`, 14 handler selectors |

Manifests: `docs/backtest/cases/polytope-solidity-merkle-trees.json`,
`docs/backtest/cases/code4rena-2024-07-basin.json`.

Useful detail: Basin's reserves slot is
`0x4bba01c388049b5ebd30398b65e8ad45b632802c5faf4964e58085ea8ab03715`
= `keccak256("reserves.storage.slot") - 1`, independently verified. reserve0 = bits 0..128,
reserve1 = bits 128..256.

**Scope honesty about this validation:** validating the predicate layer on polytope-labs
proved the layer works on real code; it was **not** expected to and did not find a bug,
because Foundry's fuzzer already covers that stateless library faster. Do not re-describe
it as a discovery.

---

## 8. Claims you may not make

The owner has stated these rules repeatedly. Breaking them is the fastest way to be
replaced.

- **Do not claim market leadership, production readiness, or parity with ItyFuzz/Echidna**
  from feature counts, synthetic demos, supplied exploit replay, or passing unit tests.
- **Do not present the baseline as good.** It is: 7 cases, 0 rediscovered, 5 missed,
  2 inconclusive, `rediscovery_rate 0.000`, `false_positive_rate 0.714`,
  `novel_findings 0`. Those are the real numbers
  (`docs/backtest/BASELINE_REPORT.json`, `report` object).
- **Do not describe the predicate layer as finding bugs.** It has never found one. It has
  been validated for correctness on real code, and shown to fire end to end on a
  deliberately impossible invariant.
- **Do not add a dependency without stated justification and owner approval.** In
  particular `z3`.
- **Do not loosen `confidence_is_confirmed`**, flip the Forge gate default, or make
  `holds` permissive to get baseline cases to pass. That generates PoCs against unproven
  findings, which is the exact thing the gate exists to prevent.
- **Do not edit report files to improve numbers.** Regenerate them; never hand-edit.

---

## 9. Where things live

```
src/engine/fuzz_engine.rs        campaign loops; both harness closures (~1819, ~2926)
                                 predicate_registry built ~1312 and in run_single_process_campaign
src/engine/invariant_runtime.rs  IncrementalChecker, check_sequence, ChainStateReader,
                                 build_registry, INVARIANT_REREAD_BUDGET = 16
src/engine/invariant_file.rs     InvariantFile format, InvariantEntry, build_registry
src/engine/proof.rs              ProofCarryingFinding, confidence_is_confirmed (:278),
                                 verify_original_state (:160)
src/engine/confirmation.rs       the gate; two conjuncts (:68-70)
src/engine/promotion.rs          PoC promotion; forge opt-in (:677)
src/engine/exploit_synthesizer.rs  synthesize_foundry_poc_with_findings (:17)
src/common/verifier.rs           ViolationPredicate (holds :382, prove_violation :564)
src/common/types.rs              PredicateTerm
src/evm/fork.rs                  chain gate via ChainProfile
crates/rustyfuzz-evm/src/chain_profile.rs   ChainProfile, ForkSchedule, BlobPricing
crates/rustyfuzz-predicate/      the IR (see §4)
docs/backtest/BASELINE_REPORT.{json,md}     generated, not hand-edited
docs/backtest/PHASE0_POC_GATE.md            the corrected diagnosis
docs/backtest/INCOMPLETE.md                 declared gaps, null-with-reason rule
docs/CLAUDE_CONTINUATION_PROMPT.md          prior handoff; its "uncommitted work" notes
                                            are historical and no longer apply
```

CLI surfaces: `fuzz`, `target`, `validate`, `abi-ingest`, `bytecode-analyze`, `seed`,
`seed-ingest`, `prove`. `--invariants <path>` on both `fuzz` and `target`.
`--rpc-url`, `--fork-block` on `fuzz`; `--rpc-url` required on `target`.

**The `--invariants` file format** (one shared symbol table, then predicates):

```json
{
  "target": "0x...",
  "symbols": {
    "totalSupply": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 },
    "sumBalances": { "kind": "slot", "slot": "0x3", "offset_bits": 0, "width_bits": 256 }
  },
  "invariants": [
    { "name": "supplyMatchesBalances", "predicate": "totalSupply == sumBalances" },
    { "name": "withinRounding", "predicate": "approx_eq(totalSupply, sumBalances, 100, 6)" }
  ]
}
```

Refused at load, each with a test: no invariants, no symbols, duplicate names, empty
name/predicate, invalid symbol table (one file-level error, not per-invariant), and every
broken predicate reported at once.

---

## 10. Order of work

1. **§0 fix** — `holds` must re-evaluate. Ship with the stale-predicate test.
2. **Rewrite the stale gap test** in `real_solidity_basin.rs` (`approx_eq` now exists).
3. **§6B** — re-run the baseline, report per case which conjunct failed.
4. **Then, and only then**, choose between 2.3 (action grammar) and 4.3 (PoC against the
   target suite) based on what the baseline says. If cases still fail on
   `original_state_violation_verified`, the problem is in the proof path, not the grammar.
5. Phase 4.1 needs owner approval before any `z3` work.

Commit messages in this repo state what was verified and how. Keep doing that; a commit
that says "wired in" without naming the check that proved it is a claim, not evidence.
