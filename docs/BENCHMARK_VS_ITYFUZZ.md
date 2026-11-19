# Head-to-head vs ItyFuzz (item 4) — status and first real numbers

Measured 2026-11-19 in the sandbox, one core each, Daedaluzz `maze-0` (7x7, 43 assertions), 60 s.

| | ItyFuzz (`80e3b44`) | RustyFuzz (`--single-process`) |
|---|---|---|
| Executions in 60 s | 770,976 (~13k/s) | 1,350 (~22/s) |
| Coverage reported | 68.75% instr / 68.43% branch | 2,428 edges (different unit) |
| Assertion bugs reported | 0 (see below) | 15 `UnintendedPanic` (no bug id) |

**Throughput is the headline gap: ~570x.** Autonomous-gate wins at 2000 execs do not scale to
mazes that need 10^5+ executions.

## Why bug counts are not comparable yet
- ItyFuzz only treats an event with the magic `"fuzzland"` topic (or Scribble's) as a bug.
  Daedaluzz's `AssertionFailed(string)` + `assert(false)` is invisible to it.
- RustyFuzz reports `Panic(0x1)` but not *which* assertion, so distinct-bug counting is impossible.
- A fair metric needs either (a) instrumented mazes that emit the ItyFuzz bug event and a per-bug
  flag RustyFuzz can read via `--invariants`, or (b) a replay judge over both tools' reproducers.

## Not run
- **Medusa:** needs Go 1.26 and `golang.org/x/*`, unreachable here.
- **DeFiHackLabs:** fork replays need an archive RPC, blocked here.

## Reproduce
ItyFuzz on stable: `RUSTC_BOOTSTRAP=1`, edition 2024, bump `time` to 0.3.36, patch `metatype` and
`serde_traitobject` (add `arbitrary_self_types_pointers`, `transmute` for the Send/Sync casts), replace
`downcast_ref_unchecked` with `downcast_ref().unwrap()`, wrap `env::set_var` in `unsafe`, `#![allow(static_mut_refs)]`.
Maze fixtures: `node scripts/bench/maze_fixture.js Maze.sol out.json` (needs `npm i solc@0.8.28`).
