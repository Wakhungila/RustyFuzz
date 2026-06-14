# Spend Permissions Audit Status

## Scope

Reviewed targets:

- SpendPermissionManager on Base: `0xf85210B21cC50302F477BA56686d2019dC9b67Ad`
- SpendRouter on Base: `0x1a672dE48c82278b2F1BB68d7b9141634dD6BE29`
- PublicERC6492Validator on Base: `0xcfCE48B757601F3f351CB6f434CB0517aEEE293D`

## Fork Access

- `BASE_RPC_URL`: missing.
- Supplied endpoint chain ID: `1`, not Base `8453`.
- Supplied endpoint block number at check time: `25315915`.
- Base fork validation is blocked. No public-chain transactions were sent.

## Completed Work

- Retrieved BaseScan verified source pages for all three targets.
- Extracted verified Solidity source, ABI, deployed bytecode, metadata, runtime hashes, and public interaction seed rows.
- Confirmed BaseScan exact-match verification for all three targets.
- Compared official `coinbase/spend-permissions` raw source against extracted source.
- Built a Foundry workspace under `audits/coinbase-cantina/foundry`.
- Ran local Foundry tests for signature domain separation, period boundaries, router metadata validation, invalid permission controls, revocation validity, and over-limit spend rejection.
- Extracted 54 public BaseScan seed rows into `seeds/spend-permissions/`.

## Foundry Results

Passing local non-fork tests:

```text
forge test --match-path 'test/{SpendPermissionSignature,SpendPermissionPeriod,SpendRouter,SpendPermissionInvariant,NegativeControls}.t.sol' -vvv
result: 12 passed, 0 failed
log: audits/coinbase-cantina/logs/forge/non-fork-local-tests.vvv.log
```

Fork validation:

```text
forge test --match-path test/SpendPermissionFork.t.sol -vvvv
result: fail-closed
reason: BASE_RPC_URL missing; Base fork validation blocked
log: audits/coinbase-cantina/logs/forge/SpendPermissionFork.vvvv.log
```

## RustyFuzz Campaign Attempts

All strict campaign attempts were blocked before execution because no valid Base fork RPC was available and synthetic fallback was disabled.

| Campaign | Target | Status | Blocker log |
|---|---|---|---|
| `coinbase-spend-manager-auth` | SpendPermissionManager | blocked | `audits/coinbase-cantina/campaigns/spend-permissions-manager-auth.log` |
| `coinbase-spend-router-routing` | SpendRouter | blocked | `audits/coinbase-cantina/campaigns/spend-router-routing.log` |
| `coinbase-spend-erc6492-validation` | PublicERC6492Validator | blocked | `audits/coinbase-cantina/campaigns/spend-erc6492-validation.log` |

Observed blocker text: RustyFuzz selected the available Ethereum RPC host and failed to fetch Base target bytecode with synthetic fallback disabled.

## Current Finding Status

No candidate is realistically proved.

Static review and local tests rejected several replay/substitution/boundary hypotheses, but Base fork replay, historical trace ingestion, RustyFuzz exploration, deterministic replay, minimization, and proof validation remain blocked without a valid Base RPC endpoint.

## Commands To Resume

Set a real Base RPC endpoint:

```bash
export BASE_RPC_URL='<base-mainnet-rpc>'
cast chain-id --rpc-url "$BASE_RPC_URL"
cast block-number --rpc-url "$BASE_RPC_URL"
cd audits/coinbase-cantina/foundry
forge test --match-path test/SpendPermissionFork.t.sol -vvvv
```

Then resume strict campaigns from repository root:

```bash
RUST_LOG=info timeout -k 30s 90s cargo run --bin rusty-fuzz -- fuzz --chain base --contract 0xf85210B21cC50302F477BA56686d2019dC9b67Ad --abi audits/coinbase-cantina/targets/base/spend-permissions/abi/SpendPermissionManager.json --max-execs 4 --campaign-id coinbase-spend-manager-auth --strict-proof --reject-heuristics --require-minimized --require-foundry-poc --no-synthetic-proof --no-synthetic-fallback --poc-out audits/coinbase-cantina/campaigns/spend-permissions/poc

RUST_LOG=info timeout -k 30s 90s cargo run --bin rusty-fuzz -- fuzz --chain base --contract 0x1a672dE48c82278b2F1BB68d7b9141634dD6BE29 --abi audits/coinbase-cantina/targets/base/spend-permissions/abi/SpendRouter.json --max-execs 4 --campaign-id coinbase-spend-router-routing --strict-proof --reject-heuristics --require-minimized --require-foundry-poc --no-synthetic-proof --no-synthetic-fallback --poc-out audits/coinbase-cantina/campaigns/spend-permissions/poc

RUST_LOG=info timeout -k 30s 90s cargo run --bin rusty-fuzz -- fuzz --chain base --contract 0xcfCE48B757601F3f351CB6f434CB0517aEEE293D --abi audits/coinbase-cantina/targets/base/spend-permissions/abi/PublicERC6492Validator.json --max-execs 4 --campaign-id coinbase-spend-erc6492-validation --strict-proof --reject-heuristics --require-minimized --require-foundry-poc --no-synthetic-proof --no-synthetic-fallback --poc-out audits/coinbase-cantina/campaigns/spend-permissions/poc
```
