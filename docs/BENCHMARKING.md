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

## Local comparison campaigns

The target-matched vulnerable/safe control-pair runner is
`benchmarks/comparison/run.py`. RustyFuzz comparison campaigns run against the
shared local Anvil deployment with chain ID 1 and Cancun-compatible block
semantics. The runner checks target bytecode at the pinned block and validates
each campaign's fork provenance and execution records before reporting metrics.
Campaign output is isolated by run ID; prior results are not removed.

RustyFuzz comparison runs are measurement-only: promotion is disabled so proof
generation failures do not contaminate execution, coverage, or state-exploration
measurements. These runs cannot establish a confirmed finding or a clean
negative. Their status is `measurement_only`; a zero-candidate result must not
be presented as a vulnerability verdict. The mint pair uses the EVM
authorization oracle rather than a blanket `totalSupply == 0` predicate, which
would also fail for legitimate authorized minting.

The per-sequence report includes execution outcomes, ABI-recognized target
calls, successful target calls, coverage/trace novelty, sequence depth, state
novelty, and candidate counts. `coverage_edges_max_sequence` is the maximum
edge count for one sequence, not a campaign-wide unique-edge union.

Historical vulnerable/safe EVM fixtures are exercised offline by
`cargo test --test benchmarks`. They are replayable validation fixtures, not a
claim that a live deployed protocol was fuzzed. Mainnet-fork manifests require
separate authorization, pinned-state validation, and an isolated local fork;
the benchmark runner must never submit generated transactions to a live chain.

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
