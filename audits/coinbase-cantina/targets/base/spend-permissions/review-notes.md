# Review Notes

## High-Signal Observations

- Permission identity includes account, spender, token, allowance, period, start, end, salt, and `keccak256(extraData)`.
- Router recipient and executor are authorized through signed `extraData`, not loose runtime parameters.
- Direct permission approval is account-gated.
- Spending is spender-gated.
- Router execution is executor-gated before manager spend.
- Router recipient zero address is rejected.
- Period end is exclusive and start is inclusive.
- Spend accounting is updated before external asset transfer, but transaction atomicity reverts the update if transfer fails.
- Revocation is terminal for use and future approval of the same permission hash.
- ERC-721 tokens are rejected during approval via ERC-165 check.
- Fee-on-transfer ERC-20 behavior is explicitly unsupported by router source and should not be treated as an in-scope vulnerability by itself.

## Areas Still Requiring Fork or Deeper Fixtures

- ERC-1271 wallets that mutate state, reenter, or return magic values conditionally.
- ERC-6492 deployment/preparation side effects from undeployed smart wallets.
- CoinbaseSmartWallet `execute` behavior on deployed accounts.
- MagicSpend withdraw request validation and nonce-postfix behavior against deployed MagicSpend.
- Real historical calldata decoding and internal trace reconstruction.
- Router `multicall` sequence behavior with approval/spend/revoke combinations.
- Reentrant ERC-20 and native-transfer callback scenarios.

## Current Conclusion

No proved issue at this stage. The audit has not reached the required proof pipeline because Base fork access is blocked. The local source-level tests support rejection of several replay/substitution/boundary hypotheses but do not replace realistic fork validation.
