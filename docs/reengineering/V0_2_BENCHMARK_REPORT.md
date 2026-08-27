# RustyFuzz v0.2 Benchmark Report

Status: measured 2026-08-27 on the development workstation used throughout
this migration. Small sample sizes; numbers are indicative, not certified.
No comparison claims are made against tools we did not run here.

## Environment

| Item | Value |
| --- | --- |
| OS | Linux (serge), x86_64-unknown-linux-gnu |
| Rust stable | 1.97.1 |
| Sanitizer nightly | nightly-2026-08-01 |
| Commit | `bbe7014` (reengineering-stage-5, pre-RC) |
| Build profile | release |

## Measured: InputId derivation throughput

Hot-path identity cost, single thread (4-tx sequence, typical campaign size):

| Path | Throughput |
| --- | --- |
| `semantic_input_hash()` v1 contract (keccak over canonical bytes) | **≈ 743k derivations/sec** |
| Pre-2B identity path equivalent (serde_json serialize + keccak) | ≈ 364k ops/sec |

The semantic-id contract is ~2x cheaper than hashing serialized JSON it
replaced, in addition to its correctness properties. Release build,
`std::hint::black_box` guarded loop, warmup included.

## Test-suite timings (release)

| Suite | Result | Wall time |
| --- | --- | --- |
| benchmarks integration (corpus/replay/snapshot/mutator/E2E smoke) | 38 passed / 1 ignored | ≈0.00–0.10s suite overhead; sub-second per fixture class |
| full workspace test (debug) | 202+19+9+6+2+1 across crates | <30s including builds |

## Executions/sec

Full-campaign exec/s depends on target bytecode, fork state residency, and
sequence depth; the retained telemetry line
(`RustyFuzz telemetry: ... execs_per_sec_30s=..., execs_per_sec_avg=...`)
emits per-run measurements into logs and should be the source of truth per
campaign. We deliberately do not quote a synthetic number here — running the
benchmark fixtures against `config.toml`-provided RPC state varies by tens of
percent between runs.

## Memory observations

Structures with explicit bounds:

- waypoint backpressure (per-tx + total caps) — unchanged from Stage 1;
- snapshot corpus `prune_to_limit(max_snapshots)` on every insertion;
- metadata sidecar bounded at 65,536 entries with eviction (Stage 2B.1);
- event sink bounded at 4,096 with drop accounting.

Known unbounded-by-design: LibAFL `InMemoryCorpus` growth over a campaign
(evicts nothing); fork caches are directory-bounded by disk policy.

## Known limitations

- Time-to-signal figures require per-target forks and network state; only
  deterministic synthetic-fixture discovery is CI-stable (see 5.2).
- Single-machine sample; no variance reduction beyond repeated trials.
