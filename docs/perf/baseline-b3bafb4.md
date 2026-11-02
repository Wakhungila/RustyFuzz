# Execution throughput baseline — pre-optimization

Machine: reference workstation, 12 logical cores, `perf_event_paranoid=4` (no
hardware profiling available). Harness: `cargo bench -p rustyfuzz-evm --bench
exec_throughput`. Numbers are the median of 5 trials after 32 warm-up executions.

Each measured iteration clones a cold `CacheDB` snapshot and then executes one
transaction against a synthetic storage-heavy target (8 loop iterations, 2 SLOAD
+ 2 SSTORE per iteration). The clone is inside the measurement because the
campaign harness performs exactly that clone per input.

| fixture   | cached slots | µs/exec | execs/sec |
|-----------|--------------|---------|-----------|
| bare      | 0            | 32.34   | 30,924    |
| warm-1k   | 1,000        | 54.62   | 18,308    |
| warm-10k  | 10,000       | 589.41  | 1,697     |
| warm-50k  | 50,000       | 2,800.65| 357       |

Cost growth from 0 to 50,000 cached slots: **86.6x**.

## Interpretation

Execution cost is essentially constant (~32 µs). Everything above that line is
per-transaction state copying. A real mainnet fork warms far past 50,000 slots,
so the campaign's effective throughput is set by cache size rather than by the
EVM. This is the dominant cost in the tool and the first thing to remove.
