---
title: "Getting started"
section: "Start here"
nav_order: 2
description: "Build the CLI, run a bounded campaign against a pinned fork, and inspect the evidence it produces."
---

## Prerequisites

Use a current Rust toolchain with Cargo and a native build toolchain. A real-fork campaign needs an RPC endpoint that can serve state at your chosen block. Install Foundry and ensure `forge` is available when using `prove-live`, whose strict defaults require Foundry PoC validation.

Prepare a deployed target address and a fork block where its code exists. An ABI file improves mutation quality and avoids depending on explorer ABI discovery.

## Build from source

```bash
git clone https://github.com/Wakhungila/RustyFuzz.git
cd RustyFuzz
cargo build --locked --release --bin rusty-fuzz
export PATH="$PWD/target/release:$PATH"
rusty-fuzz --help
```

The default feature is `evm`. Add `--features llm` only if you need the optional model-backed Satori workflow. Use the [CLI reference]({{ '/cli-reference.html' | relative_url }}) to check the interface of your build.

## Create local configuration

Before running a campaign, create `config.toml` in your working directory with the required fields below. The RPC URL and block can be overridden by `prove-live`; lower-level commands use the configured values.

```toml
chain = "evm"
rpc_url = "https://your-archive-rpc.example"
fork_block = 22000000
timeout_secs = 60
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
```

Replace the endpoint and block for your target. Keep an existing local configuration if you already have one; do not overwrite its credentials. The full template is `config.toml.example`, which also contains optional ABI and seed paths that need customization.

## Run a bounded proof campaign

Set the following variables to your own endpoint, deployed contract, and historical block. `TARGET` must be a full 20-byte EVM address; `FORK_BLOCK` must be a block number.

```bash
export RPC_URL="https://your-archive-rpc.example"
export TARGET="0xYOUR_DEPLOYED_CONTRACT_ADDRESS"
export FORK_BLOCK="YOUR_BLOCK_NUMBER"

rusty-fuzz prove-live \
  --target "$TARGET" \
  --rpc-url "$RPC_URL" \
  --block "$FORK_BLOCK" \
  --campaign-id first-campaign \
  --duration-secs 300 \
  --max-execs 100000 \
  --deterministic --rng-seed 42
```

Add `--abi abi/Target.json` if you have the target's ABI. The placeholders above must be replaced before running. Choose a fresh campaign ID for each independent run.

`prove-live` combines target preparation, bounded execution, and promotion under strict proof defaults. RPC failures, missing state, or validation failures must be investigated; they do not count as a clean result.

## Read the outcome

The following codes describe `prove-live` campaign summaries, not every RustyFuzz command:

| Exit | Interpretation | Next action |
|---|---|---|
| `0` | No confirmed findings or reported promotion failures in the summary | Review coverage and campaign bounds |
| `10` | At least one confirmed finding | Inspect the proof and reproduction artifacts |
| `11` | Candidates or unproven leads remain | Triage the evidence and unmet requirements |
| `20` | Replay failure, missing required PoC, or rejected candidates | Read rejection and validation details |
| Other nonzero | Setup, execution, or command failure | Investigate the error before drawing conclusions |

When confirmed findings and failures coexist, code `10` takes precedence. Read the full summary rather than inferring everything from the exit code.

## Inspect and verify

```bash
rusty-fuzz ops status --run-id first-campaign --json
rusty-fuzz ops events --run-id first-campaign --limit 20 --json
rusty-fuzz ops verify --run-id first-campaign --json
```

Canonical run data lives under `.rustyfuzz/runs/first-campaign/`. Preserve the run, its configuration and fork provenance, and any required corpus/cache data. [Artifacts and provenance]({{ '/artifacts.html' | relative_url }}) explains what to retain.

## Continue the investigation

Use [Target preparation]({{ '/target-preparation.html' | relative_url }}) to improve the starting corpus. Use [Finding lifecycle]({{ '/finding-lifecycle.html' | relative_url }}) to replay and promote a specific input. If startup or validation fails, follow [Troubleshooting]({{ '/troubleshooting.html' | relative_url }}).
