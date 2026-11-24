# Head-to-head vs ItyFuzz on Daedaluzz (item 4)

Measured 2026-11-20 in the sandbox. Harness: `scripts/bench/daedaluzz.py`.

**Setup.** Daedaluzz mazes 0-4 (210 assertion bugs total), each rewritten by
`scripts/bench/instrument_maze.py` so `emit AssertionFailed("N"); assert(false);` becomes a
non-reverting `bug(N)` that sets a state flag (read by RustyFuzz `--invariants`) and emits ItyFuzz's
typed-bug event. Same contract bytes for both tools, one core, tools run one at a time,
120 s wall clock per tool per maze, one seed (RustyFuzz `--rng-seed 1`).
A bug counts as found when the tool itself reports that bug id.

| Maze | Bugs | ItyFuzz | RustyFuzz | RustyFuzz execs |
|---|---|---|---|---|
| 0 | 43 | 18 | 0 | 2,121 |
| 1 | 40 | 16 | 0 | 2,265 |
| 2 | 45 | 16 | 1 | 8,314 |
| 3 | 41 | 13 | 2 | 11,672 |
| 4 | 41 | 16 | 2 | 8,971 |
| **Total** | **210** | **79 (38%)** | **5 (2%)** | |

Every bug RustyFuzz found was also found by ItyFuzz. ItyFuzz executes roughly 13k execs/s on these
mazes; RustyFuzz 20-100/s (the invariant check per transaction adds cost).

## Reading the result
- RustyFuzz is far behind on deep-state exploration. The autonomous gate's 5/5 comes from shallow,
  single-property fixtures; mazes need long, precise argument sequences at 10^5+ executions.
- Throughput is the dominant factor (see the profiling notes in the commit history); a second factor
  is that RustyFuzz replays full sequences while ItyFuzz keeps a state-snapshot corpus.

## Limits of this measurement
- One seed, 120 s, one machine; ItyFuzz was built on stable with patched dependencies
  (see below) and may differ from a release build.
- RustyFuzz was given the ABI and an invariant file, ItyFuzz only bytecode + ABI.
- **Medusa not run:** needs Go 1.26 and `golang.org/x/*`, unreachable from the sandbox.
- **DeFiHackLabs not run:** fork replays need an archive RPC, blocked in the sandbox.

## Reproduce
```
npm i solc@0.8.28 --prefix <dir>
python3 scripts/bench/daedaluzz.py --daedaluzz <clone of fuzzland/daedaluzz> \
  --ityfuzz <ityfuzz binary> --work <scratch> --solcjs-dir <dir> --secs 120
```
ItyFuzz on stable: `RUSTC_BOOTSTRAP=1`, edition 2024, bump `time` to 0.3.36, patch `metatype` and
`serde_traitobject` (add `arbitrary_self_types_pointers`, `transmute` for the Send/Sync casts), replace
`downcast_ref_unchecked` with `downcast_ref().unwrap()`, wrap `env::set_var` in `unsafe`,
`#![allow(static_mut_refs)]`.

## Re-run after throughput work (lean execution, predicate hot path, lineage length)

RustyFuzz only, 120 s per maze, seeds 1-3, mazes 0-4 (same instrumented mazes as above).
Bugs counted from `sum(bN) <= 0` invariant violations in campaign artifacts (oracle-based, not the replay judge).

| maze | seed 1 | seed 2 | seed 3 | union |
|---|---|---|---|---|
| 0 | 2 | 0 | 2 | 2 |
| 1 | 3 | 3 | 2 | 5 |
| 2 | 2 | 5 | 3 | 5 |
| 3 | 2 | 2 | 2 | 2 |
| 4 | 3 | 2 | 3 | 3 |

Mean 12.0 / 210 per seed (5.7%), union 17 / 210 (8.1%). Previous single run: 5 / 210; ItyFuzz: 79 / 210.
Executions per 120 s rose from 2-12k to 33-67k. The dominant win was the predicate oracle
(eager hex formatting and whole-manifest evidence on every check), not the EVM.

### With input-to-state (comparison-operand log + `i2s` mutator)

Same setup (120 s, seeds 1-3, mazes 0-4):

| maze | seed 1 | seed 2 | seed 3 | union |
|---|---|---|---|---|
| 0 | 3 | 3 | 2 | 4 |
| 1 | 3 | 2 | 2 | 4 |
| 2 | 4 | 1 | 3 | 5 |
| 3 | 3 | 2 | 2 | 3 |
| 4 | 2 | 5 | 3 | 6 |

Mean 13.3 / 210 per seed (6.3%), union 22 / 210 (10.5%), up from 12.0 / 17. Executions per 120 s: 44-96k.
The gain is small and within seed noise per maze; the union gain (17 -> 22) is the clearer signal.
The same shallow bugs are found every run, so the remaining gap is not guard-value solving.

### With hint share 40% (was 15%) and hot-path fixes (memoised mapping slots, coverage-observe skip)

Same setup (120 s, seeds 1-3, mazes 0-4): per seed 13.7 / 210 (6.5%), union 26 / 210 (12.4%).
Per maze (seed1/2/3, union): m0 2/3/4 u7, m1 6/3/2 u7, m2 1/6/3 u7, m3 2/2/1 u2, m4 3/1/2 u3.
Concolic hints on maze-2 (30k execs): 120k generated, 58k deduplicated, 3.6k applied, 531 successful (15% of applied).
Per-seed variance (+/-3 per maze) is as large as the per-change gains, so the per-seed mean is not distinguishable from 13.3;
the union (17 -> 22 -> 26) is the steadier signal. ItyFuzz: 79 / 210.

### Rarity-weighted snapshot selection + `uint_havoc` (item 9)

A/B at 60 s, seeds 1-3, mazes 0-4 (`RUSTYFUZZ_RARITY=0|1`; `uint_havoc` is on in both, so it is not isolated):

| | bugs / 15 runs | per seed | union | mean execs / 60 s |
|---|---|---|---|---|
| rarity off | 33 | 11.0 | 17 | 53,392 |
| rarity on | 36 | 12.0 | 20 | 44,899 |

Direction is positive but inside seed noise; rarity costs ~16% of execs. Kept on by default.

## Replay-judge result (item 16) — oracle-based scores were inflated

`replay-judge` (src/bin/replay-judge.rs) replays every persisted input on pristine fixture state
(attacker harness + flash-loan setup mirrored) and reads `__bugs[id]` directly from storage.
It consults no RustyFuzz oracle. Mazes 0–4, 60 s, seed 1, single-process:

| maze | oracle-claimed bugs | judge-confirmed |
|------|---------------------|-----------------|
| 0    | 1 ([5])             | 0 |
| 1    | 1 ([16])            | 0 |
| 2    | 3 ([2,26,38])       | 0 |
| 3    | 2 ([3,8])           | 1 ([8]) |
| 4    | 4 ([5,10,11,17])    | 0 |

Every unconfirmed artifact reverts on replay with no storage writes; the campaign logs
"snapshot signal did not survive complete replay from original state" for them and
persists them with `replay_success: false`. The earlier 13.7 (union 26) numbers counted these
heuristic artifacts and must not be quoted as Daedaluzz scores. Judge-verified is ~1/5 mazes.
Open bug: findings raised on snapshot-derived executions are not reproducible from root.

### Root cause and fix (compaction leak)
With `--compact-fork-state`, compacting a non-root snapshot absorbed its warm storage into the
`Arc`-shared `ForkDb` backend, so bugs set in one lineage appeared pre-set for every other snapshot and the
root (state leak; oracle then "found" them on reverting txs). Fix: `ForkDb::detached_clone()` before
compaction of non-root snapshots, plus `findings_reproduce` in artifact persistence: every finding
(pack and predicate) must re-establish on a stateful replay from pristine state or no artifact is written.
Autonomous gate after the fix: 5/5 with verified artifacts.

### Judge-verified A/B (mazes 0-4, 45 s, seeds 1-2, single-process; confirmed bugs, all stored inputs)
| config | seed 1 | seed 2 | mean | union |
|---|---|---|---|---|
| baseline | 6 | 12 | 9.0 | 14 |
| rarity off | 9 | 12 | 10.5 | 17 |
| i2s off | 7 | 10 | 8.5 | 12 |
| hint 0% | 14 | 8 | 11.0 | 18 |
| uint-havoc off | 10 | 13 | 11.5 | 17 |

Differences are within seed noise (±3-4); no knob is shown to help. i2s is the only one whose removal
lowers both mean and union, and only slightly. The previously reported gains were not demonstrated by
verified counts. Judge-verified baseline ≈ 9/5 mazes per 45 s run vs ItyFuzz 79/210 over the full suite
(not directly comparable: different suite coverage and time).

### Judge-verified long run after oracle fixes (mazes 0-4, 120 s, seeds 1-3, single-process)
Confirmed bugs per seed: 13 / 10 / 15 (mean 12.7), union across seeds 21. Counting is `replay-judge` only
(`scripts/bench/daedaluzz.py` now does the same). Versus the 45 s runs (mean ~9, union 14) more time still
buys more bugs, so the search is not saturated; the shallow bugs (5, 16, 17, 10, 8) are found by every seed.
Oracle fixes: Reentrancy requires the target to have called out (harness dispatch/self-recursion no longer
qualifies); GenericAccounting is informational. Maze artifacts dropped from ~47 to 2 per run; autonomous
gate 5/5, replay gate 5/5 with 0 false positives on 10 negative controls.

## Methodology and caveats (read before quoting any number)
- Headline = judge-verified rows only (120 s table above). Every oracle-counted row earlier in this file is
  **not comparable / not judge-verified** and is kept only as history.
- Setup: mazes 0-4 of Daedaluzz (210 bugs total), RustyFuzz single-process, 2-core cloud sandbox, seeds 1-3,
  120 s each, build = commit $(git rev-parse --short HEAD at time of run: see git log for "docs: judge-verified 120s").
  Raw per-run output: benchmarks/results/daedaluzz/judge_120s_seeds123.log (45 s A/B logs alongside).
- Seed variance is 3-5 bugs per seed (13/10/15); deltas smaller than that are noise.
- Not apples-to-apples: ItyFuzz's 79/210 comes from its typed-bug event, RustyFuzz's from the replay judge
  reading `__bugs[N]` after replaying *all* stored corpus inputs (not only reported artifacts). ItyFuzz was run
  with the budget/hardware of the earlier session, not re-run alongside the 120 s runs above. Treat the gap as an
  estimate (~6x) until both run back-to-back with the same time budget.
- "No real-target finding" means: none produced by RustyFuzz in this project's own runs; no
  independently verified novel finding on a live contract is documented.

## Back-to-back head-to-head (same session, same 2-core sandbox, mazes 0-4, 120 s per tool per maze)
Run with `scripts/bench/daedaluzz.py --secs 120 --seeds 1,2,3`; raw output
`benchmarks/results/daedaluzz/h2h_120s_seeds123.log`. ItyFuzz ran once per maze (typed-bug event, one core);
RustyFuzz ran three seeds per maze (replay-judge confirmed).

| maze | bugs | ItyFuzz (1 run) | RustyFuzz per seed (1/2/3) | RustyFuzz union |
|---|---|---|---|---|
| 0 | 43 | 15 | 3 / 2 / 3 | 3 |
| 1 | 40 | 17 | 3 / 1 / 5 | 6 |
| 2 | 45 | 17 | 1 / 2 / 4 | 5 |
| 3 | 41 | 15 | 4 / 2 / 1 | 4 |
| 4 | 41 | 14 | 2 / 3 / 2 | 3 |
| **total** | 210 | **78 (37.1%)** | **13 / 10 / 15 (mean 12.7, 6.0%)** | **21 (10.0%)** |

Result: ItyFuzz finds ~6x more per equal wall-clock; every bug RustyFuzz confirmed was also found by ItyFuzz
(`only_rustyfuzz` empty on all mazes). RustyFuzz's per-seed totals reproduce the earlier 13/10/15 exactly
(deterministic). Zero oracle claims failed judge replay. ItyFuzz variance was not measured (single run).

CI: `scripts/validate_daedaluzz_subset.py` (mazes 0 and 3, seeds 1-2, 60 s) fails on any oracle claim the judge
cannot reproduce or if the judge-confirmed union < 3 (measured 6); wired into the `autonomous-smoke` job.

## Search experiment: origin-bound ("targeted") concolic hints — no gain, left off by default
Diagnosis: the global hint queue applies hints to arbitrary corpus inputs (hint = "tx k, calldata word w"
only makes sense on the path that produced it); only ~8-10% of applied hints yield new coverage.
Change: `TargetedHints` pairs each hint with its origin input; the mutator clones the origin, applies the
hint and executes (`RUSTYFUZZ_TARGETED_HINT_PCT`, single-process path only).
Result (judge-verified, mazes 0-4, 120 s, seeds 1-3, 30% of mutations): per-seed 9 / 18 / 9, mean 12.0,
union 24, versus baseline 13 / 10 / 15, mean 12.7, union 21: within seed noise. Hint success rate on maze 2
(40 s): 8.0% targeted vs 8.6% untargeted. Conclusion: hint/origin mismatch is not the bottleneck; the
default is now 0 (off). Next candidates: per-guard constraint solving across the whole nested guard
(not one comparison flip at a time), and corpus scheduling toward the deepest-guard entries.

## Whole-guard solver experiment (z3) — solver is right, integration did not help
**Ceiling test.** `scripts/bench/solver_ceiling/{solve_guards,gen_inputs}.py` parse each maze's nested guard
conjunction (uint64 wrap semantics), solve it with z3, build wall-avoiding move paths, and replay through
`replay-judge`. Result: every satisfiable guard was solved (<20 s each) and judge-confirmed on the real EVM:
33/43, 26/40, 30/45, 27/41, 31/41 = **147 of 210 bugs are reachable; 63 are provably unsat** (e.g. `p2 != p2`).
So the real ceiling is 147, ItyFuzz's 78 is 53% of it, RustyFuzz's 12.7 is 8.6%, and the 49% target (103) is
70% of the reachable set. (Unsat verdicts come from my parser; sat verdicts are execution-verified.)

**Integration.** `--features smt` + `prefix_flip_groups`: for the deepest symbolic comparisons of an execution
solve "all earlier comparisons keep their outcome AND this one flips" over the observed `SymbolicExpression`s,
queue the full calldata-word set as a group bound to the origin input, apply 30% of mutations.
Findings along the way (fixed): the existing per-waypoint SMT path was unbounded and hung the campaign
(stack-sampled: `Z3_solver_check` under `solve_hint`) and cost ~100 ms/call (10 execs/s); it is now bounded
(timeout+rlimit) and opt-in (`RUSTYFUZZ_SMT_SINGLE`). Result (judge-verified, 120 s, seeds 1-3): per seed 10 / 4 / 8,
mean 7.3, union 13 vs baseline 12.7 / 21: **worse**. Only 2.8% of prefix solves were SAT (687 of 24.5k on maze 2);
the observed symbolic expressions do not capture the 64-bit wrap/mask semantics or storage-derived operands
well enough, and solver children displace productive mutations. Left opt-in
(`RUSTYFUZZ_PREFIX_SOLVE=1`, `RUSTYFUZZ_TARGETED_HINT_PCT`), default off.
**Conclusion:** the solver works when the constraints are exact. The gap is constraint extraction at fuzz time:
the next step is symbolic execution of the target function from bytecode (exact path conditions), not more
tuning of runtime hints.
