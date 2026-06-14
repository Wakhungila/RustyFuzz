# Storage Map

SpendPermissionManager:

- `_isApproved[bytes32 hash] -> bool`: approval status keyed by EIP-712 permission hash.
- `_isRevoked[bytes32 hash] -> bool`: terminal revocation status keyed by the same hash.
- `_lastUpdatedPeriod[bytes32 hash] -> PeriodSpend`: last period start, end, and cumulative spend.
- `_expectedReceiveAmount`: transient storage flag for native-token receive path only.
- `PUBLIC_ERC6492_VALIDATOR`: immutable constructor argument.
- `MAGIC_SPEND`: immutable constructor argument.

SpendRouter:

- `PERMISSION_MANAGER`: immutable constructor argument.
- No mutable storage in verified source.

PublicERC6492Validator:

- No mutable storage in verified source.

No EIP-1967 implementation/admin/beacon slots are present in verified source. Onchain slot reads remain blocked without a Base RPC endpoint.
