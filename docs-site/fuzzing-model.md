---
title: "Fuzzing model"
section: "Core concepts"
nav_order: 4
description: "How executable inputs, snapshots, feedback, and scheduling work together to explore contract state."
---

## The execution loop

1. Select a retained input or interesting snapshot.
2. Generate or mutate a transaction sequence using ABI information and available guidance.
3. Execute the sequence through REVM against its base state.
4. Observe coverage, transaction outcomes, storage changes, calls, and oracle signals.
5. Score novelty and useful pressure, then retain inputs or state for further search.

The root campaign runtime connects this loop to LibAFL. Snapshot exploration lets later sequences start from previously reached states instead of repeatedly reconstructing every precondition from the initial fork.

## Semantic input identity

`EvmInput` contains `txs` and `base_snapshot_id`. The identity contract hashes the schema tag, snapshot ID, and ordered transaction fields: calldata, caller, target, and value.

Coverage, waypoints, mutation provenance, scheduler scores, and oracle output are metadata outside that identity. Re-observing an input with different feedback therefore does not create a different semantic input.

**Input identity is not post-state equivalence.** Different transaction sequences can reach the same state and still have different input IDs. Snapshot state fingerprints are a separate mechanism.

## Snapshot identity and lineage

A snapshot handle identifies a retained snapshot. A state fingerprint describes its contents. Parent relationships and the producing input record how a state was reached; they are useful for reproducing a sequence of state transitions.

Keep snapshot and fork-cache provenance with the input. A transaction sequence alone may be insufficient to reproduce a state-dependent observation.

## Feedback and scheduling

| Signal | What it contributes | Interpretation limit |
|---|---|---|
| Coverage | New edges and execution paths | More coverage does not prove correctness |
| State novelty | Storage transitions and reachable state | Novel state may be harmless |
| Call observations | Interactions and execution structure | A suspicious call pattern needs context |
| Oracle pressure | Protocol invariant or economic signals | Oracles emit evidence, not final proof |
| Comparison/concolic guidance | Values that may cross branch boundaries | Guidance depends on tracked expressions |

ABI-aware mutation helps produce meaningful calls. Actor variation, sequence composition, and boundary values help explore multi-step behavior. Scheduling combines these observations with campaign policy; it does not exhaustively enumerate all possible executions.

## Determinism has a context

Use a fixed RNG seed, execution settings, and fork provenance when reproducing a campaign. Deterministic replay is meaningful for the same executable input and environment. Different block state, missing cache entries, changed code, or different assumptions can invalidate a comparison.

For focused comparisons, use a single worker and a bounded budget. See [Configuration]({{ '/configuration.html' | relative_url }}) and [Benchmarking]({{ '/benchmarking.html' | relative_url }}).

## Exploration and proof

Exploration may allow explicitly requested synthetic state for local smoke tests. A realistic proof must satisfy stricter provenance and validation requirements. Never treat an exploration shortcut as evidence that the same behavior is reachable on the deployed target.
