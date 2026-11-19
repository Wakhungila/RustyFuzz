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
