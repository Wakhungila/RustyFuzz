# Execution and discovery improvement plan

Started 2026-10-20 after the repository assessment at `b3bafb4`.
Complete each correctness gate before relying on downstream measurements.

Status note (2026-10-23): sections 1 and 2 are implemented. Section 4
(performance) now has measured results in `docs/perf/results.md`. Section 3 and 5
remain open, and the reasons are stated rather than implied.

## 1. Execution correctness — done

- [x] Derive canonical storage deltas from committed REVM state, including actual
  original values, rollback, and repeated writes.
- [x] Attribute delegatecall storage to the storage context rather than the code
  address.
- [x] Load caller and target account attributes from the pinned database; preserve
  nonce/code/balance and restore database ownership on execution errors.
- [x] Keep startup funding out of new root-based campaign proof baselines.
  Imported legacy artifacts and arbitrary descendant snapshots still require
  original-state reconstruction; see ADR 0009.
- [x] Validate historical chain/hardfork/block/fee semantics explicitly, including
  comparison with an independent local execution client (Anvil, `--ignored` suite).
- [x] Preserve "a failed transaction leaves caller state untouched" without
  cloning the whole cache: the caller entry is snapshotted before any database
  access and restored on error (`crates/rustyfuzz-evm/src/executor.rs`).
- [x] Separate proof and exploration block-position policy: proof requires the
  exact pinned block, exploration may advance at or after it
  (`EnvironmentPolicy::resolve` vs `resolve_advancing`).

Gate: executable regressions cover cold storage, reverted frames, repeated
writes, proxies, existing callers, validation failures, funding-dependent
exploration, and both block-position policies. All pass.

## 2. Search integration — done

- [x] Non-root snapshot selection connected to mutation with replayable lineage
  and pruning safety.
- [x] Scheduler score ownership and starvation correction.
- [x] ABI types, values and actor dictionaries bound to the concrete target.
- [x] Deterministic per-transaction time advance, so sequences span a realistic
  window instead of one instant. Reachability is proven by test: a timelock that
  rejects every transaction under a static block environment succeeds once the
  sequence advances (`crates/rustyfuzz-evm/tests/time_warp.rs`).

Gate: a campaign discovers a withheld multi-step violation using a non-root
snapshot and reconstructs it from original state. Time-dependent reachability is
covered by the executable test above; the full campaign demonstration is
exercised by `tests/snapshot_exploration.rs` and `tests/benchmarks.rs`.

## 3. Evidence and attack execution — partially open

- [x] Unify finding lifecycle and typed violation predicates; preserve the
  predicate through minimization.
- [x] Separate economic pressure from measured per-token profit.
- [x] Fix the dead access-control signal: ownership takeover was only ever
  detected in the EIP-1967 admin slot, because nothing emitted an
  `influenced: true` dataflow waypoint and that branch could never fire. Now
  emitted for slots written from `msg.sender`, `msg.value` or calldata, with a
  regression test that fails on the previous behaviour
  (`tests/access_control_oracle.rs`).
- [ ] Executable callback/flashloan attacker harnesses with full Foundry setup,
  handler and invariant semantics. **Open.** The current attacker is expressed as
  generated transactions, not as a compiled contract, so reentrancy-shaped bugs
  that require an attacker *contract* with a `receive`/callback are not
  reachable. This needs a contract-generation path, not a patch.

Gate for the open item: a fresh process reproduces a reentrancy finding that
requires an attacker contract, against original pinned state.

## 4. Performance and usability — measured, one structural item open

- [x] Profile representative campaigns. `perf` is unusable on the reference
  machine (`perf_event_paranoid=4`), so an in-process harness was built instead:
  `crates/rustyfuzz-evm/benches/exec_throughput.rs`.
- [x] Coverage path signature derived incrementally instead of scanning the whole
  256 KiB map per transaction: 155 µs → 0.24 µs per transaction, byte-identical
  output.
- [x] Removed per-transaction `CacheDB` clones and the duplicate base-state copy
  in the harness.
- [x] Removed the per-transaction cache walk that rebuilt the initialized-slot
  set; it now grows with execution.
- [x] Build profiles (`release` LTO, `profiling` with symbols) and a mimalloc
  global allocator.
- [x] Build pressure: `.cargo/config.toml` pins one job, no incremental cache and
  no debug info, taking a clean build from 13.7 GiB to 1.3 GiB.
- [ ] Share the base state instead of cloning it once per input. **Open.** At
  50k cached slots one `CacheDB` clone is ~2.2 ms and is now the largest
  remaining per-input cost. Doing it properly means `Arc`-sharing immutable fork
  accounts with a per-input overlay, which changes snapshot ownership,
  checkpointing and artifact persistence. That is a design change, not a tuning
  change, and is not attempted under this pass.
- [ ] RPC keep-alive, request batching and prestate pre-warming. **Open.** Not
  attempted because it cannot be validated honestly here: the network path needs
  a live provider, and asserting an improvement from code reading alone would
  repeat the weakness this plan exists to avoid.

Gate: report measured throughput, discovery yield, memory, disk, and RPC use.
Throughput, memory and disk are measured (`docs/perf/results.md`). Discovery
yield and RPC use are not.

## 5. Competitive validation — pending

Keep oracle controls, supplied exploit replay, guided discovery, and held-out
blind discovery separate. Compare pinned competitors under matched budgets and
publish repeated runs and ablations. Synchronize capability documentation with
the implementation.

Gate: reproducible discovery results, independently replayable findings, and
global false-signal accounting on safe targets; no leadership claims based only
on feature counts or supplied exploit replay.

**No claim of leadership is made anywhere in this repository.** The speedups in
`docs/perf/results.md` are measured against this tool's own previous behaviour on
a synthetic target, which says nothing about comparative bug-finding.
