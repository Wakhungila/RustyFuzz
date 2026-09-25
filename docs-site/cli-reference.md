---
title: "CLI reference"
section: "Reference"
nav_order: 10
description: "A task-oriented command map, with syntax taken from the current Clap definitions."
---

## Discover the interface

```bash
rusty-fuzz --help
rusty-fuzz fuzz --help
rusty-fuzz prove-live --help
rusty-fuzz ops --help
```

The compiled binary's help is the exhaustive flag reference for that build. This page covers the command surface and key distinctions; defaults can differ between subcommands.

## Exploration and preparation

| Command | Purpose | Key arguments |
|---|---|---|
| `fuzz` | Run a configurable EVM campaign | `--contract`, `--abi`, `--max-execs`, `--duration-secs` |
| `prove-live` | Prepare, run, and promote on a real fork | `--target`, `--rpc-url`, `--block`, `--campaign-id` |
| `abi-ingest` | Import target interface metadata | `--file`, `--target`, `--bundle-id` |
| `bytecode-analyze` | Analyze runtime bytecode | `--file`, `--output` |
| `seed` | Discover historical seed transactions | `--target`, `--bundle-id`, `--max-seeds`, `--search-depth` |
| `seed-ingest` | Import an existing transaction export | `--file`, `--bundle-id`, `--fork-block` |
| `setup` | Produce target setup context | `--bundle-id`, `--target`, `--abi` |
| `invariants` | Generate invariant guidance | `--target`, `--setup-report`, `--abi-report` |

`fuzz` reads its RPC/fork settings through configuration; do not assume it accepts the `--rpc-url` and `--block` options exposed by `prove-live`.

## Reproduction and research

| Command | Syntax or key arguments |
|---|---|
| Replay | `replay --input ID [--fork-cache-id ID] [--live]` |
| Minimize | `minimize --input-id ID [--fork-cache-id ID]` |
| Report | `report --input-id ID [--reason TEXT]` |
| Promote | `promote --input-id ID [--strict-proof] [--require-foundry-poc]` |
| Run a generated job | `job run FILE [--abi FILE] [--seed-bundle ID]` |
| Validate fixtures | `validate --benchmarks DIRECTORY [--output FILE]` |
| Satori | `satori --help` |

Replay uses a named `--input` argument, not a positional input. Promotion policy is described in [Finding lifecycle]({{ '/finding-lifecycle.html' | relative_url }}).

## Operations command tree

```text
ops
├── status       [--run-id ID] [--json]
├── campaigns    [--state STATE] [--json]
├── metrics
├── events       [--run-id ID] [--severity LEVEL] [--limit N] [--json]
├── alerts       [--active] [--json]
├── verify       [--run-id ID] [--backup PATH] [--json]
├── backup
│   ├── create   --output PATH [--run-id ID] [--strict]
│   ├── list
│   ├── verify   PATH
│   └── restore  PATH --target DIRECTORY
└── drill
    └── restore  PATH --target DIRECTORY [--keep-payload]
```

See [Operations and recovery]({{ '/operations.html' | relative_url }}) for passphrase handling and isolated restore examples.

## Source of truth

Command definitions live in `src/cli/commands.rs`. Campaign setup and exit handling live in `src/cli/helpers.rs`; operations dispatch lives in `src/cli/ops_handlers.rs`. Satori has its own nested CLI. Check these boundaries when updating documentation alongside code changes.
