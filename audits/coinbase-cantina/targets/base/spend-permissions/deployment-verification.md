# Deployment Verification

Target block context: Base fork validation is blocked because `BASE_RPC_URL` is not set. The endpoint supplied during this audit returned chain ID `1`, not Base chain ID `8453`. Public BaseScan pages were retrieved on 2026-06-14 and are saved under `logs/`.

## Contracts

| Contract | Address | Deployment pattern | Runtime bytes | Runtime hash | Source status |
|---|---:|---|---:|---|---|
| SpendPermissionManager | `0xf85210B21cC50302F477BA56686d2019dC9b67Ad` | immutable deployment, no proxy indicators in verified source | 12610 | `0x2e9e272aa2f685632aae292aaf8bca67f22e4494ec831959bc6e9ff071378bea` | BaseScan exact-match verified |
| SpendRouter | `0x1a672dE48c82278b2F1BB68d7b9141634dD6BE29` | immutable deployment, constructor-bound manager | 7216 | `0x55cd7a6cb8e76d5404d6678f552f3df3428bea3669ab6748c347f52015bc5ced` | BaseScan exact-match verified |
| PublicERC6492Validator | `0xcfCE48B757601F3f351CB6f434CB0517aEEE293D` | immutable deployment, stateless validator wrapper | 597 | `0x94a000eab18fdda0465241bd0e82487463fb2e539854a3645542e57ed8dde484` | BaseScan exact-match verified |

Runtime bytecode and ABI artifacts are stored in `bytecode/` and `abi/`. Extracted verified source is stored in `contracts/`.

## Source Provenance

- `SpendRouter.sol` and `PublicERC6492Validator.sol` match the current raw files in `coinbase/spend-permissions`.
- `SpendPermissionManager.sol` differs from the current raw repository only by MagicSpend import path/comment spelling (`magic-spend` versus `magicspend`). The BaseScan verified source is treated as canonical for this deployment.
- Compiler settings observed in BaseScan pages: Solidity `v0.8.28+commit.7893614a`, optimizer enabled with `999999` runs, EVM version `cancun`, `viaIR=false`.

## Dependencies

Coinbase-controlled or scope-relevant:

- `src/SpendPermissionManager.sol`
- `src/SpendRouter.sol`
- `src/PublicERC6492Validator.sol`
- `smart-wallet/CoinbaseSmartWallet.sol` as the execution surface invoked by `_execute`
- `magic-spend/MagicSpend.sol` for `spendWithWithdraw` flows

Third-party libraries:

- OpenZeppelin interfaces/utilities: ERC-20, ERC-721, ERC-1271, ERC-165, SafeERC20, Address.
- Solady utilities: EIP712, SafeTransferLib, SignatureCheckerLib, Multicallable.
- Account abstraction interfaces and WebAuthn dependencies pulled through Coinbase Smart Wallet.

## Proxy / Slot Resolution

The verified source for all three targets has constructors and immutable variables, and no proxy fallback, no delegatecall dispatch proxy shell, and no EIP-1967 storage-slot management. EIP-1967 implementation/admin/beacon slot reads remain blocked until a valid Base RPC is provided, but source and runtime shape indicate these targets are immutable deployments rather than proxies.

Required fork validation still blocked:

```bash
test -n "$BASE_RPC_URL" && echo "BASE_RPC_URL=set" || echo "BASE_RPC_URL=missing"
cast chain-id --rpc-url "$BASE_RPC_URL"
cast block-number --rpc-url "$BASE_RPC_URL"
cd audits/coinbase-cantina/foundry
forge test --match-path test/SpendPermissionFork.t.sol -vvvv
```
