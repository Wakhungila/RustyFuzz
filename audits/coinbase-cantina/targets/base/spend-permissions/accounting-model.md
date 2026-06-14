# Accounting Model

Core identity:

```text
permissionId = getHash(permission)
approved = _isApproved[permissionId]
revoked = _isRevoked[permissionId]
last = _lastUpdatedPeriod[permissionId]
```

Current period:

```text
require(block.timestamp >= start)
require(block.timestamp < end)

if last.spend != 0 && block.timestamp < last.end:
    current = last
else:
    progress = (block.timestamp - start) % period
    current.start = block.timestamp - progress
    current.end = min(end, current.start + period)
    current.spend = 0
```

Spend:

```text
require(value > 0)
require(approved && !revoked)
current = getCurrentPeriod(permission)
totalSpend = current.spend + value
require(totalSpend <= type(uint160).max)
require(totalSpend <= allowance)
_lastUpdatedPeriod[permissionId] = { current.start, current.end, totalSpend }
transfer account -> spender or account -> router -> recipient
```

Boundary results covered by Foundry:

- `block.timestamp == start`: active, period starts at `start`.
- `block.timestamp == end`: inactive, reverts with `AfterSpendPermissionEnd`.
- one second before rollover: still old period.
- exact rollover second: new period starts.
- zero period: approval rejects with `ZeroPeriod`.
- zero allowance: approval rejects with `ZeroAllowance`.
- exact over-limit spend: reverts before transfer and does not update period spend.
- revocation after approval makes `isValid(permission) == false`.

Open fork-dependent checks:

- Real Coinbase Smart Wallet execution behavior for ERC-20 approval and native transfer.
- MagicSpend withdraw preconditions and nonce postfix behavior against deployed MagicSpend.
- Historical interaction replay and calldata-level period usage reconstruction.
