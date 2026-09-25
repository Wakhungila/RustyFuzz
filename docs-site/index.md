---
title: "Explore state. Build evidence."
section: "Start here"
nav_order: 1
nav_title: Overview
description: "RustyFuzz is a stateful EVM fuzzer for finding multi-transaction contract failures and investigating them through reproducible execution."
---

<div class="hero-actions"><a class="primary" href="{{ '/getting-started.html' | relative_url }}">Run your first campaign →</a><a href="{{ '/fuzzing-model.html' | relative_url }}">Understand the engine</a></div>

<div class="workflow" aria-label="Campaign workflow"><div><span>01 / PREPARE</span><b>Pin the environment</b><p>Choose a target, fork block, ABI, and starting seeds.</p></div><div><span>02 / EXPLORE</span><b>Search contract state</b><p>Mutate transaction sequences using execution feedback.</p></div><div><span>03 / VALIDATE</span><b>Challenge each signal</b><p>Replay, minimize, and apply an explicit proof policy.</p></div><div><span>04 / INSPECT</span><b>Keep the evidence</b><p>Review versioned artifacts and verify their integrity.</p></div></div>

## A workflow for stateful security research

A contract can behave correctly on a single call and fail after a sequence of deposits, transfers, price changes, or governance actions. RustyFuzz explores those sequences against EVM state using REVM execution and a LibAFL-based campaign runtime.

Coverage, storage changes, call observations, and protocol oracle signals guide the search. Interesting inputs and snapshots become starting points for further exploration. A signal is the beginning of an investigation: replay and proof policy determine how strongly the result can be reported.

<div class="guide-grid"><a class="guide-card" href="{{ '/target-preparation.html' | relative_url }}"><span>Practical guide</span><strong>Prepare a real target ↗</strong><p>Bring an ABI, historical seeds, and a pinned fork into a campaign.</p></a><a class="guide-card" href="{{ '/finding-lifecycle.html' | relative_url }}"><span>Core concept</span><strong>Know what a finding means ↗</strong><p>Distinguish oracle signals, replay evidence, and policy-validated proof.</p></a><a class="guide-card" href="{{ '/operations.html' | relative_url }}"><span>Operations</span><strong>Inspect and recover runs ↗</strong><p>Verify evidence, inspect metrics, and exercise encrypted backup recovery.</p></a><a class="guide-card" href="{{ '/architecture.html' | relative_url }}"><span>Engineering</span><strong>Navigate the codebase ↗</strong><p>Understand workspace boundaries and the orchestration still in the root crate.</p></a></div>

## Choose the right entry point

| Your goal | Start with | What to inspect |
|---|---|---|
| Investigate a deployed contract | `prove-live` | Fork provenance, promotion results, and campaign summary |
| Control the exploration settings | `fuzz` | Input corpus, snapshots, execution bounds, and feedback |
| Reproduce a retained input | `replay --input` | Replay outcome under the recorded state |
| Evaluate discovery behavior | `validate` | Fixture category, execution status, and evidence strength |
| Generate research hypotheses | `satori` | Unvalidated proposals and independent validation results |

## Supported scope

EVM is the supported backend. Satori is an experimental research workflow; SVM and SGX are unsupported build paths. The workspace is being extracted into focused crates, while substantial campaign orchestration remains in the root package.

A completed campaign with no confirmed findings is **not a certificate that the target is secure**. Results depend on reachable state, seed quality, oracle coverage, resource limits, and proof requirements. See [Finding lifecycle]({{ '/finding-lifecycle.html' | relative_url }}) for how to interpret evidence.
