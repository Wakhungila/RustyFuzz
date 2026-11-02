# Execution throughput: measured results

Machine: reference workstation, 12 logical cores, ~6.6 GiB RAM. `perf_event_paranoid=4`,
so no hardware profiling was available; all numbers come from
`cargo bench -p rustyfuzz-evm --bench exec_throughput`, which measures the same
public entry point campaigns use (`EvmExecutor::execute_with_result`).

Method: median of 5 timed samples after warm-up. Each input runs 8 transactions
against an accumulating `CacheDB`, and the base state is cloned once per input —
the shape the campaign harness actually uses. The "previous shape" table
reproduces the removed per-transaction deep copy **inside the same binary and
run**, so no difference is attributable to machine or compiler drift.

## Headline: coverage post-processing

| path | µs per transaction |
|------|--------------------|
| full 256 KiB map scan (removed) | 155.4 |
| touched-index signature (current) | 0.24 |

Deriving the path signature by scanning the whole coverage map cost ~155 µs **per
transaction** — 640x more than the replacement. On small targets it was ~95% of
total execution time. The signature is now derived from the indices the inspector
actually wrote, and is byte-identical to the old definition (unit tests assert
`transaction_path_hash(map) == stable_path_hash(map)` for the same bytes).

A single execution of the storage-heavy synthetic target, map included, now costs
**8.7 µs**; it was ~224 µs before these changes.

## End-to-end against the original baseline

The baseline in `docs/perf/baseline-b3bafb4.md` was captured before any change,
with one clone *per transaction* and the full-map scan. Comparing that to the
current build, same machine, same fixture:

| fixture | baseline execs/sec | current | improvement |
|---------|--------------------|---------|-------------|
| bare | 30,924 | 204,680 | 6.6x |
| warm-1k | 18,308 | 45,653 | 2.5x |
| warm-10k | 1,697 | 5,933 | 3.5x |
| warm-50k | 357 | 567 | 1.6x |

Per-execution cost at 50k cached slots fell from 2,800 µs to 1,764 µs. Most of
the constant-time gain is the coverage fix; the cache-size-dependent gain is the
clone removal.

## Headline: per-transaction state copies

`CacheDB::clone` cost grows with cached state, so cloning per transaction made
throughput a function of fork size:

| cached slots | µs per copy |
|--------------|-------------|
| 0 | 0.07 |
| 1,000 | 6.3 |
| 10,000 | 478 |
| 50,000 | 2,155 |

Throughput, executions/second:

| fixture | cached slots | previous shape | current | speedup |
|---------|--------------|----------------|---------|---------|
| bare | 0 | 202,673 | 207,858 | 1.03x |
| warm-1k | 1,000 | 33,397 | 43,913 | 1.31x |
| warm-10k | 10,000 | 2,291 | 5,900 | 2.57x |
| warm-50k | 50,000 | 419 | 524 | 1.25x |

### Honest reading of this table

The clone removal is real but is no longer the dominant term at large cache
sizes, because one unavoidable clone per input remains (the campaign must not
mutate the snapshot). At 50k slots that single copy costs ~2.2 ms against ~15 ms
of execution per input, so removing the other seven copies yields 1.25x there and
2.57x at 10k slots.

**The next structural win is sharing the base state instead of cloning it** — for
example `Arc`-sharing immutable fork accounts and keeping a per-input overlay.
That is a larger design change (it touches snapshot ownership, checkpointing, and
artifact persistence) and was not attempted here.

## Build configuration

`.cargo/config.toml` pins `jobs = 1`, `incremental = false`, and `debug = 0` for
dev/test. On this machine those settings took a clean build from 13.7 GiB of
artifacts to 1.3 GiB (5m22s), and parallel jobs previously exhausted memory
before saturating the CPU. `[profile.profiling]` in the root manifest restores
symbols when a real profiler is available.

## What these numbers do *not* claim

- They are synthetic-target measurements, not campaign results. They say nothing
  about bug-finding rate.
- No comparison against ityfuzz was run. A throughput number on a synthetic
  target is not evidence of competitive superiority, and this document does not
  claim any.
- `target-cpu=native` was not used. Add
  `RUSTFLAGS="-C target-cpu=native"` for local runs; the shipped binary stays
  portable on purpose.

## Regression fixed during this work

A pre-existing latent race became reproducible under the new build settings:
several tests set and clear the same `RUSTYFUZZ_*` environment variables, while
the configuration fingerprint deliberately hashes the *presence* of those
variables. Running the suite in parallel therefore produced a nondeterministic
`config_hash` and an intermittent failure (observed in
`observed_startup_mode_update_recomputes_authoritative_config_hash`, and as a
knock-on failure in `rustyfuzz-operations`).

Fixed by a single per-test-process environment lock (`src/test_support.rs`,
included by both crate roots via `#[path]`) held for the whole duration of every
test that touches those variables. Verified by 10 consecutive `--lib` runs and 6
consecutive `--workspace` runs with zero failures; before the fix, roughly one
in three runs failed.
