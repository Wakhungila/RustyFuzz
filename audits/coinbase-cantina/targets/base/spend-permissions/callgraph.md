# Call Graph

## SpendPermissionManager

- `approve(permission)`: external, `msg.sender == permission.account`; validates permission fields through `_approve`; writes `_isApproved[hash]`; emits `SpendPermissionApproved`.
- `approveWithSignature(permission, signature)`: external; validates `getHash(permission)` through `PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects`; calls `_approve`.
- `approveBatchWithSignature(batch, signature)`: external; validates `getBatchHash(batch)` through validator; loops batch details into `_approve`.
- `approveWithRevoke(permissionToApprove, permissionToRevoke, expectedLastUpdatedPeriod)`: external, `msg.sender == permissionToApprove.account`; requires same account; checks exact last period snapshot; revokes old permission; approves new permission.
- `revoke(permission)`: external, `msg.sender == permission.account`; writes `_isRevoked[hash]`.
- `revokeAsSpender(permission)`: external, `msg.sender == permission.spender`; writes `_isRevoked[hash]`.
- `spend(permission, value)`: external, `msg.sender == permission.spender`; calls `_useSpendPermission` before `_transferFrom`.
- `spendWithWithdraw(permission, value, withdrawRequest)`: external, `msg.sender == permission.spender`; checks withdraw asset, amount, nonce postfix; calls `_useSpendPermission`; executes MagicSpend withdrawal through wallet; then `_transferFrom`.
- `getCurrentPeriod(permission)`: view; enforces `start <= block.timestamp < end`; computes recurring period by `(timestamp - start) % period`.
- `getHash(permission)`: view; EIP-712 typed-data hash over all permission fields and `keccak256(extraData)`.
- `getBatchHash(batch)`: view; EIP-712 typed-data hash over account, period, start, end, and packed per-permission detail hashes.

Internal edges:

- `_approve` checks token nonzero, ERC-721 rejection, spender nonzero, period nonzero, allowance nonzero, `start < end`, revoked state, approved state.
- `_useSpendPermission` checks value nonzero, `isValid`, active period, cumulative allowance, then writes `_lastUpdatedPeriod[hash]` before asset transfer.
- `_transferFrom` native path executes wallet call to send ETH to manager, then forwards ETH to recipient/spender.
- `_transferFrom` ERC-20 path executes wallet approval to manager for exact value, then manager calls `safeTransferFrom(account, recipient, value)`.
- `_execute` calls `CoinbaseSmartWallet(payable(account)).execute(target, value, data)`.

## SpendRouter

- `spendAndRoute(permission, value)`: validates `(executor, recipient)` from `extraData`; requires `msg.sender == executor`; calls manager `spend`; emits `SpendRouted`; transfers funds from router to recipient.
- `spendAndRouteWithSignature(permission, value, signature)`: same as above, first calls manager `approveWithSignature`.
- `spendWithWithdrawAndRoute(permission, value, withdrawRequest)`: same routing, calls manager `spendWithWithdraw`.
- `spendWithWithdrawAndRouteWithSignature(...)`: approval + withdraw + routing.
- `revokeAsSpender(permission)`: decodes executor from `extraData`; requires `msg.sender == executor`; calls manager `revokeAsSpender`.
- `encodeExtraData(executor, recipient)`: pure; rejects zero executor/recipient; returns ABI encoding.
- `decodeExtraData(extraData)`: pure; requires exactly 64 bytes; ABI-decodes `(address,address)`.
- `receive()`: accepts ETH only from `PERMISSION_MANAGER`.

## PublicERC6492Validator

- `isValidSignatureNowAllowSideEffects(account, hash, signature)`: public nonpayable wrapper around Solady `SignatureCheckerLib.isValidERC6492SignatureNowAllowSideEffects`. It intentionally permits deployment/preparation side effects and is documented as not reentrancy safe.
