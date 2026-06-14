# Spend Permissions Invariants

- Revoked or expired permissions cannot be spent.
- A permission valid for one wallet, chain, nonce, token, recipient, spender, or period cannot authorize another.
- Cumulative spend cannot exceed authorized amount per period.
- A spender cannot redirect funds through SpendRouter outside the permission.
- Partial spends must update accounting exactly once.
