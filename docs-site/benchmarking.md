---
title: "Benchmarking"
section: "Reference"
nav_order: 12
description: "Measure discovery and reproduction separately, with explicit fixture context and honest failure accounting."
---

## Run a fixture suite

```bash
rusty-fuzz validate \
  --benchmarks benchmarks/blind \
  --output reports/blind-validation.json
```

For historical fork fixtures, configure the required RPC access and use `benchmarks/historical`. Live validation needs a provider that can serve the state touched by the fixture. Do not interpret a fixture that could not execute as a successful negative test.

## Understand fixture categories

| Category | What it measures |
|---|---|
| Local fixture | Engine behavior on a controlled deployment |
| Cached-fork fixture | Execution against a supplied state snapshot |
| Historical replay | Reproduction of a known transaction sequence |
| Blind rediscovery | Search from allowed benign hints under a bounded budget |
| Provider-side replay | Remote `eth_call` evidence when explicitly configured |

Replaying known exploit calldata does not demonstrate blind discovery. Provider-side replay can validate real fork-state behavior while lacking the local storage-diff evidence available from full REVM replay.

## Read status before aggregating

Reports distinguish outcomes such as `found`, `not_found`, `failed_execution`, `not_run_*`, and `skipped_by_config`. Evidence strength and replay/minimization/PoC outcomes must be considered alongside discovery status.

Keep unavailable and skipped fixtures visible. Excluding them silently can make a weak benchmark appear complete.

## Make comparisons reproducible

Record source revision, toolchain, fixture revision, fork provenance, seed, worker count, execution and wall-clock budgets, and relevant cache state. Compare like-for-like fixtures and policy settings. Report time and execution count together when RPC latency affects throughput.

Avoid publishing a discovery-rate or performance claim without the underlying report and a precise description of the allowed starting information.
