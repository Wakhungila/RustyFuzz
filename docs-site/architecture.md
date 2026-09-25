---
title: "Architecture"
section: "Reference"
nav_order: 11
description: "The current workspace boundaries, execution flow, and areas where extraction is still in progress."
---

## Execution flow

```text
CLI / configuration
        │
        ▼
Root campaign orchestration ────────► artifact persistence
        │                                  │
        ▼                                  ▼
Inputs + mutation + scheduling       manifests / evidence / telemetry
        │                                  │
        ▼                                  ▼
REVM executor + fork database         operations verification / recovery
        │
        ▼
Coverage / storage / calls / oracle signals
        │
        └────► feedback → retention → replay / minimization / promotion
```

The workspace separates reusable engine and domain components, but the root package still connects campaigns, mutation strategies, protocol oracles, and proof orchestration. This is the implementation boundary, not a claim that the monolith extraction is complete.

## Workspace map

| Package | Current responsibility |
|---|---|
| `rusty-fuzz` | CLI, campaign orchestration, promotion, benchmarks, and Satori |
| `rustyfuzz-core` | Typed IDs, lifecycle, execution/snapshot metadata, signals, and proposals |
| `rustyfuzz-evm` | REVM executor, fork database, inspector, coverage, and transaction representation |
| `rustyfuzz-engine` | Semantic input model, scheduler/scoring modules, budgets, telemetry, and events |
| `rustyfuzz-artifacts` | Canonical run layout, manifests, and filesystem utilities |
| `rustyfuzz-operations` | Inventory, integrity, metrics, alerts, backup, restore, and recovery |
| `rustyfuzz-testkit` | Shared test fixtures and helpers |

There are no separate `rustyfuzz-ai`, `rustyfuzz-cli`, or `rustyfuzz-oracles` workspace members in the current manifest. Older target-architecture notes describe intended boundaries rather than completed packages.

## Navigate the source

| Area | Entry points |
|---|---|
| Commands and dispatch | `src/cli/commands.rs`, `src/cli/handlers.rs` |
| Campaign execution | `src/engine/fuzz_engine.rs` |
| Promotion policy | `src/engine/promotion.rs`, `src/common/verifier.rs` |
| Semantic identity | `crates/rustyfuzz-engine/src/input.rs` |
| Canonical lifecycle | `crates/rustyfuzz-core/src/finding.rs` |
| EVM execution and fork reads | `crates/rustyfuzz-evm/src/executor.rs`, `fork_db.rs` |
| Artifact paths | `crates/rustyfuzz-artifacts/src/layout.rs` |
| Operations | `src/cli/ops_handlers.rs`, `crates/rustyfuzz-operations/src/` |
| AI research | `src/satori/`, `crates/rustyfuzz-core/src/proposal.rs` |

## Boundaries that matter

Executable input identity excludes feedback. Snapshot handles differ from state fingerprints. Oracle signals differ from validated findings. AI proposals require validation. Persistence records the evidence needed to investigate those transitions.

These distinctions prevent a new score, generated explanation, or updated observation from silently changing the meaning of an executable input or a proof claim.

## Build scope

The root package defaults to EVM. Optional features include `llm`, `z3`, and `notifier`. SVM and SGX are unsupported paths. Inspect `Cargo.toml` and the current build guards before treating an experimental module as a supported backend.
