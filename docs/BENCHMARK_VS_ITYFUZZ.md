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
