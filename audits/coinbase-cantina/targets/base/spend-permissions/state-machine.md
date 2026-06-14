# State Machine

Permission identity is `hash = getHash(SpendPermission)`.

States:

- `Unapproved`: `_isApproved[hash] == false`, `_isRevoked[hash] == false`.
- `Approved`: `_isApproved[hash] == true`, `_isRevoked[hash] == false`.
- `Revoked`: `_isRevoked[hash] == true`. This is terminal for approval/use because `_approve` returns false for revoked permissions and `isValid` requires not revoked.
- `ActivePeriod`: `Approved` and `start <= block.timestamp < end`.
- `OutOfWindow`: timestamp before `start` or at/after `end`; spend reverts through `getCurrentPeriod`.

Transitions:

- `Unapproved -> Approved`: `approve`, `approveWithSignature`, or `approveBatchWithSignature`.
- `Approved -> Approved`: repeat approval returns true and emits no second approval event.
- `Unapproved|Approved -> Revoked`: `revoke`, `revokeAsSpender`, or router `revokeAsSpender`.
- `Approved + ActivePeriod -> Approved + UpdatedPeriodSpend`: `spend` or `spendWithWithdraw`, if cumulative spend remains within allowance.
- `Approved + ActivePeriod -> revert/no state update`: zero value, exceeded allowance, failed transfer, invalid wallet execution, mismatched withdraw request, or invalid nonce postfix.

Ordering property:

`_useSpendPermission` writes `_lastUpdatedPeriod` before external token/wallet transfer, but the whole transaction reverts if the later external call reverts. This local behavior was tested in `SpendPermissionInvariant.t.sol`.
