# Benchmarking

Status: CURRENT plus TARGET notes.

## Current v0.1 State

Benchmark manifests and deterministic fixtures live under `benchmarks/`.
The default CI-compatible benchmark smoke is:

```bash
cargo test --test benchmarks --release
```

Stage 0.5 result:

```text
38 passed, 1 ignored
```

Current benchmark classes include local fixtures, cached-fork/blind
rediscovery fixtures, historical fixtures, live-fork manifests, and Daedaluzz
fixtures.

## Target v0.2 Measurements

Future benchmark reports should keep orchestration outside the fuzzing kernel
and record:

- executions/sec;
- time to first new edge;
- time to target coverage;
- state corpus growth;
- coverage;
- interesting-input rate;
- interesting-state rate;
- time to known bug;
- false-positive rate;
- memory peak;
- disk writes;
- RPC reads;
- mutation-strategy effectiveness.

No performance improvement is claimed without measured evidence.
