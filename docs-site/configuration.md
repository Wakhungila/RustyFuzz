---
title: "Configuration"
section: "Run & operate"
nav_order: 7
description: "Make execution bounds, fork assumptions, and reproducibility settings explicit."
---

## Start from a local configuration

Campaign and preparation commands load `config.toml` from the working directory; the current loader requires this file. Operations commands use their own local project configuration. Use `config.toml.example` as a field reference, but replace its example addresses, ABI paths, and seed paths with files for your target. Command-specific CLI overrides take precedence where implemented.

A small starting configuration for `fuzz` is:

```toml
chain = "evm"
rpc_url = "https://your-archive-rpc.example"
fork_block = 22000000
timeout_secs = 60
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false

[hardened_defi]
single_process = true
deterministic = true
rng_seed = 42
```

Choose a block where your target exists. Keep credentials in local configuration or your secret-management workflow; do not commit a real endpoint token. Shell variables in command examples are expanded by the shell, not by TOML.

## Bound a campaign

```bash
rusty-fuzz fuzz \
  --contract "$TARGET" \
  --abi abi/Target.json \
  --require-rpc-fork \
  --single-process \
  --deterministic --rng-seed 42 \
  --duration-secs 300 \
  --max-execs 100000 \
  --wall-timeout-secs 600 \
  --campaign-id target-study-001
```

Execution count and duration bound the search. The wall timeout bounds process lifetime. An artifact limit controls retained output; it does not replace an execution budget. Use `--unbounded` only when you intentionally want an open-ended campaign.

## Choose the right controls

| Control | Purpose |
|---|---|
| `--require-rpc-fork` | Require real fork initialization |
| `--require-seed-bundle` | Fail when the required seed bundle is unavailable |
| `--allow-synthetic-fallback` | Explicit exploration fallback for local testing |
| `--deterministic`, `--rng-seed` | Fix random search behavior |
| `--single-process`, `--cores` | Control worker topology |
| `--campaign-id` | Name the run and separate its artifacts |
| `--strict-proof`, `--no-synthetic-proof` | Tighten promotion requirements |

`fuzz` and `prove-live` do not expose identical options or defaults. In particular, `prove-live` enables strict proof, minimization, heuristic rejection, and Foundry PoC requirements by default. Check each command's `--help`.

## Runtime environment controls

| Variable | Scope |
|---|---|
| `RUSTYFUZZ_EXEC_TIMEOUT_SECS` | Per-input execution timeout |
| `RUSTYFUZZ_EXEC_RPC_BUDGET` | RPC budget during input execution |
| `RUSTYFUZZ_STARTUP_RPC_TIMEOUT_SECS` | Fork startup probe timeout |
| `RUSTYFUZZ_CORES` | Worker selection override |
| `RUSTYFUZZ_OPS_BACKUP_PASSPHRASE` | Noninteractive backup/restore passphrase |
| `RUST_LOG` | Rust logging filter |

`prove-live` supplies a per-input timeout derived from campaign duration (clamped to 5–15 seconds) and an execution RPC budget of 4 when those environment variables are unset. Review budgets before diagnosing a slow archive provider as an engine failure.

## Reproduce a run

Retain the RNG seed, fork block and provenance, executable revision, ABI/seed inputs, worker settings, and effective configuration. Changing the provider or running against “latest” can change the execution environment even when the transaction sequence is unchanged.
