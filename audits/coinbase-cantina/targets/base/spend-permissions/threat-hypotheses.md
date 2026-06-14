# Threat Hypotheses

Status legend: `PROVED`, `REPRODUCED-BUT-NOT-EXPLOITABLE`, `REJECTED`, `BLOCKED-BY-MISSING-DATA`, `NEEDS-FURTHER-TESTING`.

| # | Hypothesis | Status | Evidence |
|---:|---|---|---|
| 1 | Signature replay | NEEDS-FURTHER-TESTING | Digest includes all permission fields; no replay found in static review. Needs ERC-1271/6492 fork fixtures. |
| 2 | Cross-chain replay | REJECTED | Local test shows chain ID changes `getHash`. |
| 3 | Cross-account replay | REJECTED | Local test shows account changes `getHash`. |
| 4 | Cross-contract replay | REJECTED | Local test shows verifying contract changes `getHash`. |
| 5 | Nonce reuse | NEEDS-FURTHER-TESTING | Permission identity uses `salt`; MagicSpend path uses withdraw nonce postfix. Needs historical replay. |
| 6 | Permission-hash collision | REJECTED | Uses ABI-encoded typed struct and `keccak256(extraData)`, not packed ambiguous fields. |
| 7 | Incorrect EIP-712 domain separation | REJECTED | Domain name/version in source; tests confirm chain and contract separation. |
| 8 | ERC-1271 validation differences | NEEDS-FURTHER-TESTING | Public validator delegates to Solady checker; needs malicious/edge ERC-1271 wallet fixtures. |
| 9 | ERC-6492 counterfactual-signature confusion | NEEDS-FURTHER-TESTING | Validator intentionally allows side effects; needs fork/local counterfactual wallet tests. |
| 10 | Undeployed-wallet signature abuse | NEEDS-FURTHER-TESTING | Same as ERC-6492; no static bypass identified. |
| 11 | Permission owner substitution | REJECTED | Owner/account is in signed hash and direct approve requires `msg.sender == account`. |
| 12 | Spender substitution | REJECTED | Spender is in signed hash and `spend` requires `msg.sender == spender`. |
| 13 | Token substitution | REJECTED | Token is in signed hash and transfer uses that token. |
| 14 | Recipient substitution | REJECTED for router extraData model | Router recipient is in `extraData`, and `extraData` hash is signed. |
| 15 | SpendRouter metadata or `extraData` confusion | REJECTED for malformed length | Router requires exactly 64 bytes and ABI-decodes two addresses; tests cover malformed data. |
| 16 | Recipient redirection | REJECTED | Recipient is signed via `extraData`; zero recipient rejected by router execution path. |
| 17 | Partial-spend accounting errors | NEEDS-FURTHER-TESTING | Static math is straightforward; local over-limit negative control passes. Needs multiple successful transfer fixtures. |
| 18 | Spend-limit bypass | REJECTED for pre-transfer over-limit | Test confirms over-limit reverts before period write. |
| 19 | Period rollover bypass | REJECTED for boundary math | Tests cover start, end, and exact rollover boundaries. |
| 20 | Timestamp boundary bypass | REJECTED for local model | `start` inclusive, `end` exclusive behavior tested. |
| 21 | Revocation bypass | REJECTED for local model | Revoked permission makes `isValid` false; spend requires `isValid`. |
| 22 | Reentrancy through token or wallet execution | NEEDS-FURTHER-TESTING | Accounting write precedes transfer, but callback fixtures are still needed for wallet/token behavior. |
| 23 | State update after external interaction | REJECTED for spend accounting | `_useSpendPermission` writes before external transfer; transaction reverts if transfer fails. |
| 24 | Batched-call accounting inconsistency | NEEDS-FURTHER-TESTING | Router inherits `Multicallable`; batch interactions need dedicated sequence tests. |
| 25 | Fee-on-transfer behavior | REJECTED as supported finding class | Router source explicitly says fee-on-transfer ERC-20s are unsupported. |
| 26 | Malicious ERC-1271 wallet behavior | NEEDS-FURTHER-TESTING | Requires fixture that returns valid magic while mutating state/reentering. |
| 27 | Malformed signature parsing | NEEDS-FURTHER-TESTING | Delegated to Solady checker; needs edge signature fixtures. |
| 28 | Malformed permission structures | REJECTED for validation fields | Zero token/spender/allowance/period and invalid start/end rejected in tests. |
| 29 | Nonce namespace collision | NEEDS-FURTHER-TESTING | `salt` is user supplied; MagicSpend postfix guard present. Needs campaign/historical validation. |
| 30 | Chain-ID or verifying-contract confusion | REJECTED | Local tests confirm both affect digest. |

No hypothesis is marked `PROVED` in this phase.
