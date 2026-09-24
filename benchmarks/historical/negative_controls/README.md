# Executable negative controls

These ten `executable_evm` controls load compiled Solidity runtime bytecode into
`CacheDB<ForkDb>` and execute their transaction sequences with
`EvmExecutor::proof`. Actor balances come from the fixture; the executor does not
inject caller funds or cap transaction values. The resulting real storage diffs,
coverage, statuses, and call traces enter `ProtocolOraclePack::default()`.
There is no `outcome` flag, synthetic finding injection, or finding suppression
in this path. The older `local_fixture` synthetic path remains for other packs.

## Schema version 1

Each fixture is JSON (the loader also accepts structured TOML). Unknown fields,
unsupported versions, malformed hex, duplicate accounts/initial slots, missing
code, undeclared callers/targets, backwards timestamps, and unsupported chain IDs
are errors. Accounts and transactions are ordered arrays.

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `1` |
| `bytecode_kind` | `runtime`; init-code deployment is not implemented |
| `target`, `attacker`, `victim` | Explicit 20-byte addresses; target must agree with the manifest |
| `environment` | `chain_id`, `block_number`, initial `timestamp`, `gas_limit`, `base_fee` |
| `accounts[]` | `address`, native `balance`, `nonce`, `runtime_bytecode`, `storage[]` |
| `accounts[].storage[]` | `slot`, `value`, both U256 hexadecimal strings |
| `transactions[]` | `caller`, `to`, hex `calldata`, native `value`, `timestamp`, `expected_status`, nullable `expected_output`, `expected_storage[]` |
| `transactions[].expected_storage[]` | Assertions on the called account's committed `slot`/`value` after that transaction |
| `expected_safe_behavior` | Human-readable explanation, never an oracle input or result override |

Runtime bytecode is loaded directly; storage is initialized explicitly instead
of running constructors. Schema v1 uses the executor's mainnet chain ID 1 and
REVM's default fork rules. Solidity compilation targets Shanghai. The executor
uses its existing 10,000,000 transaction gas limit and 1 gwei gas price. Transaction
timestamps are explicit to exercise the timelock before and after its deadline.
An expected revert means successful validation of a rejected attack, not an EVM
execution error. A halt, unexpected status/output, or incorrect committed storage
fails the control loudly.

The fixture hash in the report is Keccak-256 of the parsed schema reserialized
with `serde_json`, not a hash of source-file whitespace. The runtime code hash is
Keccak-256 of the primary target's code. The fixture hash also binds helper token
bytecode, initial state, expected behavior, and the complete transaction sequence.

## Contract behavior

- **ERC20 owner mint:** authorized mint succeeds, unauthorized mint reverts, victim
  balance increases and attacker balance remains zero.
- **ERC20 burn-only:** burn reduces supply and balance equally; calling the absent
  mint entry point reverts.
- **ERC4626 zero donation:** two equal ERC20-backed deposits with a zero donation
  in between receive equal shares.
- **ERC4626 virtual offset:** one-asset attacker deposit, 1000-asset donation, victim
  deposit, and attacker redemption. Virtual assets/shares preserve nonzero victim
  shares and leave the attacker below their starting asset balance.
- **AMM balanced swap:** actual token0 prepayment and token1 payout; the pool checks
  its real ERC20 balances against a nondecreasing reserve product.
- **AMM no flashloan:** explicit flash-loan and callback-swap requests revert;
  reserves remain unchanged.
- **Lending healthy liquidation:** a 100-token debt against 200-token collateral at
  75% LTV rejects liquidation and preserves debt/custody balances.
- **Lending repaid borrow:** transfer 100 real tokens to the borrower, repay through
  transferFrom, restore debt to zero and pool token balance to its initial value.
- **Governance delay:** authorize proposal/vote/queue; early execute reverts, execute
  at ETA succeeds. `executed` and `voted` occupy bytes 0 and 1 of storage slot 3.
- **Governance quorum:** unauthorized propose/vote and quorum-free queue/execute
  revert without setting ETA or executed state.

These are minimal mechanism contracts, not full ERC4626 implementations, deployed
protocol replicas, or a general proof that the oracles have no false positives.
The AMM has no fees and the lender uses a single explicitly seeded borrower.
The controls test the listed paths and starting states only.

## Rebuilding and running

From the repository root, with solc 0.8.30 and Foundry `cast` installed:

```sh
python3 benchmarks/historical/negative_controls/build_fixtures.py
cargo run --release --locked --bin rusty-fuzz -- validate \
  --benchmarks benchmarks/historical/negative_controls \
  --output /tmp/rustyfuzz-negative-controls-executable.json
```

The generator compiles checked-in `contracts/Controls.sol` with optimization and
Shanghai EVM targeting, computes ABI calldata and mapping slots, and writes all
ten fixture JSON files. Validation itself needs neither solc nor RPC access.

## Report interpretation

`runtime` records schema version, fixture/hash, target code hash, execution
backend, and each executed transaction's caller, target, calldata, timestamp,
status, output, gas, coverage edges, storage-diff count, and call-trace count.
The fixture binds the remaining transaction/environment fields. Full runtime
objects are also returned by `ExecutableFixture::execute` for execution tests.

Every actual oracle finding is partitioned into `matching_signals` and
`unmatched_signals` with the existing vulnerability-class matcher. A matching
signal makes `found=true` regardless of proof generation, so proof gating cannot
hide a false positive. Unmatched cross-pack heuristics remain in the JSON.
No candidate, proof status, proof artifact, or PoC is constructed by this mode.

For each family, the false-positive rate is the number of executed controls with
at least one matching signal divided by the number of executed controls. Failed
or unexecuted controls are not safe negatives. The generic report calibration's
`pass_rate` still measures vulnerability discovery, not this false-positive rate.

## Oracle regression exercised by the controls

The delayed-governance control initially produced a `GovernanceTakeover` signal:
`observed 4 executes but only 2 proposes`. The executor trace contains both root
transaction and call frames. More importantly, the oracle counted the reverted
early execute attempt as if it had succeeded. The source enforces ETA, the early
call reverts with executed=false, and the later call succeeds only at ETA.

Governance sequence checks now use successful completed calls; prior votes must
also be successful, completed, and on the same target. Reverted attempts cannot
be used as successful proposals, votes, queues, or executions. The regression
checks the actual early/late EVM statuses. A separate deliberately unguarded EVM
witness verifies that a matching governance signal still produces `found=true`
without a proof, candidate, or PoC.

The owner-mint control still exposes unmatched bridge heuristics; the repaid
borrow exposes an unmatched generic-accounting heuristic, and delayed execution
exposes an unmatched access-control heuristic. These remain visible and are not
claims of exploitable vulnerabilities or fixes to those other oracle classes.

## Unmatched-signal review (Gate 2)

The four unmatched signals on the negative pack were reviewed against
`VulnerabilityClass::matches_finding`. None are class-matcher false negatives
for the control's own class:

| Control | Unmatched signal | Why it must stay unmatched |
| --- | --- | --- |
| `negative-erc20-owner-mint` | Bridge outbound/finalize on `mint` without lock/burn | Owner mint is authorized; matching it to `Erc20MintInflation` would invent a false positive |
| `negative-erc20-owner-mint` | Bridge finalization without prove/relay | Same mint selector, different oracle class; not an ERC20 supply-inflation claim |
| `negative-governance-delayed-execute` | Access-control `PrivilegeEscalation` on `execute` after ETA | Timelock held; the call is the authorized post-delay execution, not a bypass |
| `negative-lending-repaid-borrow` | Generic `AccountingDesync` on large aggregate movement | Repay conserves debt; class is `LiquidationAbuse`, not stale accounting |

The ERC20 pack now flags successful `mint(address,uint256)` only when no mint
rejection was observed (open supply-inflation path). Owner-mint negatives retain
a rejected unauthorized attempt, so they stay clear. The ERC4626 pack classifies
`convertToShares == 0` for nonzero input as `VaultDonationAttack` (share-price
inflation), not mere rounding.

## Vulnerable counterparts

Deliberately broken counterparts live under
`benchmarks/historical/gate2_positive_controls/` (never in this pack). They
reuse the same mechanism contracts with the defense removed and must produce a
matching signal for their class:

```sh
python3 benchmarks/historical/gate2_positive_controls/build_fixtures.py
cargo test --test benchmarks gate2_vulnerable_counterparts_trigger_each_protected_class
```
