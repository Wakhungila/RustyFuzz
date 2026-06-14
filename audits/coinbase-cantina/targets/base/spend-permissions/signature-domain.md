# Signature Domain

SpendPermissionManager inherits Solady `EIP712`.

Domain:

- name: `Spend Permission Manager`
- version: `1`
- chain ID: current `block.chainid`
- verifying contract: manager address

Single permission digest:

```text
hash = _hashTypedData(
  keccak256(abi.encode(
    SPEND_PERMISSION_TYPEHASH,
    account,
    spender,
    token,
    allowance,
    period,
    start,
    end,
    salt,
    keccak256(extraData)
  ))
)
```

Batch digest:

```text
detailHash[i] = keccak256(abi.encode(
  PERMISSION_DETAILS_TYPEHASH,
  spender,
  token,
  allowance,
  salt,
  keccak256(extraData)
))

batchHash = _hashTypedData(
  keccak256(abi.encode(
    SPEND_PERMISSION_BATCH_TYPEHASH,
    account,
    period,
    start,
    end,
    keccak256(abi.encodePacked(detailHash[]))
  ))
)
```

Local tests confirm the digest changes when account, spender, token, extraData, verifying contract, or chain ID changes. ERC-1271 and ERC-6492 live-path validation still requires Base fork traces and realistic wallet fixtures.
