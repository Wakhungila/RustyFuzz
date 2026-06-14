# External Calls

SpendPermissionManager:

- `_approve` calls `ERC165Checker.supportsInterface(token, IERC721.interfaceId)` for non-native tokens. Purpose: reject ERC-721 tokens.
- `approveWithSignature` and `approveBatchWithSignature` call `PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(account, hash, signature)`.
- `_transferFrom` native path calls `CoinbaseSmartWallet(account).execute(address(this), value, "")`, then forwards ETH to recipient/spender.
- `_transferFrom` ERC-20 path calls `CoinbaseSmartWallet(account).execute(token, 0, approve(manager, value))`, then `safeTransferFrom(account, recipient, value)`.
- `spendWithWithdraw` calls wallet execution to `MAGIC_SPEND.withdraw(withdrawRequest)` before `_transferFrom`.

SpendRouter:

- Calls `SpendPermissionManager` for approve/spend/revoke operations.
- Forwards tokens or ETH to decoded recipient after manager spend succeeds.
- Accepts ETH only from the manager.

PublicERC6492Validator:

- Calls Solady signature validation. ERC-6492 validation may execute deploy/prepare calldata from the supplied signature wrapper before ERC-1271 validation.

Review focus:

- Manager updates spend accounting before transfer, but transaction atomicity reverts the write if downstream calls fail.
- Router validates executor before manager call and recipient before routing.
- PublicERC6492Validator is intentionally permissionless and not reentrancy safe; safety depends on callers not granting it privileged state and on manager using it only for signature validation.
