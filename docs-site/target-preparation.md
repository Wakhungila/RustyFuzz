---
title: "Target preparation"
section: "Start here"
nav_order: 3
description: "Build a useful starting point from contract interfaces, fork state, and historical transactions."
---

## Pin the execution context

Record the target, chain, fork block, and RPC provider before comparing runs. The endpoint must return the historical code and storage needed by the campaign. For proxies, distinguish the execution address from the implementation whose ABI describes callable functions.

Use the `TARGET`, `RPC_URL`, and `FORK_BLOCK` variables from [Getting started]({{ '/getting-started.html' | relative_url }}). The following commands use `target-study` as a reusable bundle ID.

## Supply an ABI

```bash
rusty-fuzz abi-ingest \
  --file abi/Target.json \
  --target "$TARGET" \
  --bundle-id target-study
```

ABI metadata supplies selectors and argument types for structured mutation. You can also pass `--abi abi/Target.json` directly to `fuzz` or `prove-live`.

When verified source or an ABI is unavailable, inspect runtime bytecode:

```bash
rusty-fuzz bytecode-analyze \
  --file runtime-bytecode.hex \
  --output reports/bytecode/target.json
```

Bytecode analysis can identify selectors and proxy patterns. A weak or unknown classification is a valid outcome; it should not be treated as complete interface recovery.

## Discover historical seeds

```bash
rusty-fuzz seed \
  --target "$TARGET" \
  --rpc-url "$RPC_URL" \
  --bundle-id target-study \
  --start-block "$FORK_BLOCK" \
  --max-seeds 32 \
  --search-depth 5000 \
  --rate-limit-rps 2 \
  --resume \
  --seed-output-manifest reports/seeds/target-study.json
```

The rate option is an alias for `--seed-max-blocks-per-second`: it controls block scanning, not a guarantee about total RPC requests per second. Review the scan manifest for range, selectors, and discovered accounts. Seeds can improve reachability without proving a vulnerability.

## Import existing transactions

```bash
rusty-fuzz seed-ingest \
  --file seeds/transactions.json \
  --bundle-id target-study \
  --target "$TARGET" \
  --fork-block "$FORK_BLOCK"
```

Supported inputs include RustyFuzz historical JSON, explorer-style transaction exports, and generic transaction arrays. Preserve calldata, sender, destination, value, and block information. Supply `--chain-id` when needed to identify the chain explicitly.

## Inspect setup and invariant guidance

```bash
rusty-fuzz setup \
  --bundle-id target-study \
  --target "$TARGET" \
  --abi abi/Target.json \
  --output reports/setup/target.json

rusty-fuzz invariants \
  --target "$TARGET" \
  --setup-report reports/setup/target.json \
  --output reports/invariants/target.toml
```

Setup reports collect target context and bounded probe plans. Generated invariants and hypotheses require review against the protocol's intended behavior. They guide search; they do not establish correctness or automatically prove findings.

## Require the intended starting state

For the lower-level `fuzz` command, configure `rpc_url`, `fork_block`, and `mainnet_seed_bundle` in local `config.toml`, then use `--require-rpc-fork` and, when the bundle is mandatory, `--require-seed-bundle`.

A synthetic seed is not the same as synthetic fork state. Inspect both seed provenance and execution assumptions when deciding whether a result represents the deployed protocol.
