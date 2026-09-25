---
title: "Artifacts and provenance"
section: "Core concepts"
nav_order: 6
description: "Keep the execution context and evidence together so another run can inspect and reproduce the result."
---

## Canonical run layout

`rustyfuzz-artifacts::RunLayout` owns the canonical mapping under `.rustyfuzz/runs/<run-id>/`:

```text
.rustyfuzz/runs/<run-id>/
├── config.json
├── terminal_status.json
├── inputs/
├── snapshots/
├── candidates/
├── rejected/
├── proved/
├── minimized/
├── fork-cache/
├── reports/
└── telemetry/
```

Directories are created according to the layout; not every campaign produces records in every directory. Legacy corpus/report paths and Satori outputs can still exist outside this tree. Preserve the files actually referenced by your run rather than assuming one directory contains every workflow's output.

## What to retain

| Evidence | Why it matters |
|---|---|
| Sanitized effective configuration | Reconstructs campaign settings and assumptions |
| Input and base snapshot | Defines the executable sequence and starting point |
| Fork provenance and required cache | Identifies chain state and supports replay |
| Promotion and rejection records | Explains how evidence was classified |
| Summary and terminal status | Separates a finished run from a partial or failed one |
| Toolchain/source revision | Helps explain behavior changes between builds |

Semantic input IDs identify executable input data. Evidence digests detect changes to the corresponding files. Neither is a substitute for preserving the environment needed for replay.

## Verify before consuming

```bash
rusty-fuzz ops verify --run-id "$RUN_ID" --json
```

The operations layer checks canonical summary/evidence integrity under size and inventory limits. Missing or altered evidence must be investigated. Do not edit evidence in place to make verification pass; preserve the original and rerun or document the failure.

## Terminal state is separate from findings

Run terminal states include `completed`, `partial`, `cancelled`, and `failed`; an incomplete record is nonterminal. A completed run can have no findings, unproven candidates, or confirmed findings. A stopped process is not sufficient evidence that finalization completed.

## Share deliberately

Sanitized RPC metadata does not make every output public. Calldata, source-derived context, addresses, traces, and research hypotheses can be sensitive. Inspect an export before publishing it. Use [Operations]({{ '/operations.html' | relative_url }}) for encrypted backup and recovery.
