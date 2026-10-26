# State audit before historical capture — 2026-10-26

Measured against Ethereum mainnet archive state via `eth-mainnet.g.alchemy.com`
(`RUSTYFUZZ_RPC_API_KEY` blanked; the allowlist origin was set). Every value below was read
from the chain; nothing here is inferred from a fixture or a document.

Why this file exists: the plan said "capture a genuine pre-exploit snapshot for Audius and
Euler, then replay". Before building anything else on that, the *state the replay needs* has
to be identified. Doing that turned up three facts that change what the capture must
contain, and one that changes what the fixtures mean.

---

## 1. The fork pins are correct, but they are one block before the transaction

| case | fixture `fork_block` | transaction's actual block |
|---|---|---|
| Audius | 15,201,793 | **15,201,794** |
| Euler | 16,817,995 | **16,817,996** |

This is not an error. The fixture's `setup_requirements` says "the block before the first
public Audius attack transaction", and pre-exploit state is exactly what a replay needs. But
it means a capture pinned at `fork_block` **cannot** find the transaction, and a capture
pinned at the transaction's block has already had the exploit applied.

Consequence for the capture tool: the pre-exploit snapshot must be taken at
`transaction.blockNumber - 1`, and the transaction is then replayed *into* it. `capture`
takes `--block` explicitly for this reason and refuses a `--fixture`-derived block, since
only the caller knows which of the two blocks is meant.

---

## 2. The Audius fixture's `target` is the attacker's contract, not the vulnerable system

`0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569` is the fixture's `target`. Its on-chain
behaviour at the pin:

- 4,035 bytes of code, dispatching `0x5bc7c6ac` (the transaction's selector), and also
  `0x23b872dd`, `0xa9059cbb`, `0x095ea7b3`, `0x18cbafe5`, `0x70a08231`, `0x543db4c4`,
  `0x485cc955`, `0x616c6c65` — i.e. token and router calls, plus `Ownable`.
- It contains the string `Ownable: caller is not the owner` and reads ownership from
  **slot 0**.
- Slot 0 at the pre-exploit block is `0x0000...a0c7bd318d69424603cbf91e9969870f21b8ab4c`,
  which is **the transaction's own sender**. The attacker already owns this contract one
  block before the exploit.

So `0xbdbb…` is the attacker's exploit contract. It is the thing doing the attacking, not
the thing being attacked. The governance system it manipulates is elsewhere.

### Where the state actually changes

The transaction emits 5 logs from 3 contracts, and the fixture's target emits none:

| emitter | code size | EIP-1967 impl slot `0x3608…2bbc` |
|---|---|---|
| `0x4deca517d6817b6510798b7328f2314d3003abac` (governance proxy) | 1,069 | `0x35dd16df…0ae5e8` |
| `0x4d7968ebfd390d5e7926cb3587c39eff2f9fb225` (discovery proxy) | 1,069 | `0xf24aeab6…141057` |
| `0xe6d97b2099f142513be7a2a068be040656ae4591` | 1,069 | `0xea10fd35…26702f` |
| `0xbdbb…` (fixture target) | 4,035 | **zero** — not a proxy |

All three 1,069-byte contracts are the same Audius admin-upgradeable proxy, confirmed by
disassembling the runtime: it dispatches `0x3659cfe6` (`upgradeTo`), `0x5c60da1b`
(`implementation()`), `0x91f52f7c`, `0x1a31c07c`, and reverts with
`AudiusAdminUpgradeabilityProxy: Caller must be current proxy admin`. Its implementation
pointer lives in the EIP-1967 slot.

**Neither the governance proxy's nor the discovery proxy's implementation pointer changed
across the exploit block.** Slots 0–7 of the governance proxy are also unchanged. The
reinit call in this transaction therefore did **not** install a new implementation, contrary
to what the case name ("reinitialization") invites a reader to assume.

---

## 3. What this means for the two historical cases

**Audius.** A snapshot centred on the fixture's `target` captures the attacker contract and
its owner slot — useful, but it does not contain the governance state the exploit mutates.
A replay of this transaction against such a snapshot can succeed while proving nothing about
the governance system, which is the worst outcome: a green result that measures the wrong
thing.

A correct capture needs the three proxy accounts above, each proxy's EIP-1967 implementation
slot, the implementation code (which must be fetched explicitly — the proxy's own code does
not contain it), the admin slot, and whatever proposal/registry storage the implementation
reads. That last set is **not enumerable**: it lives behind mappings, and this endpoint does
not serve `debug_traceTransaction` (400), so the touched slots cannot be recovered from a
trace either. They must be named by an authored invariant, or read from the implementation's
storage layout.

**Euler.** The transaction's `to` is `0xebc29199…0cbF99`, which is the *exploit contract*,
not the Euler protocol (`0x27182842E098f60e3D576794A5bFFb0777E025d3`, the fixture's target).
Capturing only the transaction's parties would miss the protocol entirely. This is the same
class of problem, one contract worse.

---

## 4. Consequence for the capture tool and the next step

The `capture` command added in `3559c1f` does what it claims — it captured a real snapshot
at 15,201,794 with 2 accounts, 2 code blobs, real provenance and a digest independently
reproduced in Python — but for Audius it produced **0 slots**, because no invariants file
binds slots and the fixture's target has no interesting storage at that block.

That is the honest result, and it is the blocker. A snapshot with no slots cannot evaluate
a predicate, so replaying into it would report `Unknown` for everything and prove nothing.

The next step is therefore **not** "capture and replay Audius". It is:

1. Author the invariant bindings for the Audius governance proxy — at minimum
   `0x3608…2bbc` on each of the three proxies, plus the implementation's admin/proposal
   slots — and let `--invariants` supply them to `capture`.
2. Extend `capture` to fetch an implementation's code when a proxy slot is bound, because
   replaying a proxy call needs the implementation's code and the proxy's own code cannot
   supply it.
3. Only then replay, and compare against the receipt. If the slots named are insufficient,
   the replay will say `Unknown` — which is the answer, not a failure to hide.

Until step 2 exists, a proxy-shaped historical case cannot be replayed offline from a
capture, and claiming otherwise would be claiming a capability the tool does not have.

---

## Reproduction

Chain checks, all read-only:

```
eth_chainId                                      -> 0x1
eth_getBlockByNumber 0xE7FC41 (15,201,793)       -> hash 0xc3cb5c89…a821239
eth_getTransactionByHash 0xfefd829e…7a984        -> blockNumber 15,201,794
eth_getTransactionReceipt same                   -> status 1, gasUsed 730,454, 5 logs
eth_getStorageAt 0xbdbb… slot 0 @15,201,793      -> …a0c7bd318d69424603cbf91e9969870f21b8ab4c
eth_getStorageAt 0x4deca5… 0x3608…2bbc @both     -> …35dd16dfa4ea1522c29ddd087e8f076cad0ae5e8
debug_traceTransaction                           -> HTTP 400 (not served on this plan)
```

Capture:

```
RUSTYFUZZ_RPC_API_KEY= \
RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS=https://eth-mainnet.g.alchemy.com \
  rusty-fuzz capture --rpc-url <endpoint> --block 15201794 \
    --fixture benchmarks/historical/fixtures/audius-governance-reinitialization-2022.json \
    --output /tmp/rf-capture/audius.json
```

Result: 2 accounts, 0 slots, 2 code blobs, `content_digest` reproduced independently.

---

## What is still unmeasured

- Whether the Euler protocol's own state changes in a way a capture can express. Not
  audited yet; the same proxy/implementation analysis applies and has not been done.
- Whether this endpoint serves the L2 or reorg-affected state for either case. Irrelevant
  for block 15.2M on mainnet, but unverified for anything else.
- The five `known_vulnerable` cases remain expectation-only fixtures with no executable
  bytecode. Nothing here changes that; they still cannot be reported as rediscoveries.


---

## 5. Follow-up: the state change was located (2026-10-26, later the same day)

Finding 2 said the governance system is where the exploit acts. Measuring it produced the
specific slot.

Scanning the governance proxy's storage for small counters at the pre-exploit block found:

| slot | value | what it is |
|---|---|---|
| 55 | 3 | guardian count / role constant |
| 57 | 1 | flag |
| **59** | **84** | **proposal counter** |
| 61 | 1 | flag |

Across the exploit block, slot 59 goes **84 → 85**, and it is the only slot in 0–79 that
changes. The two logs emitted by that proxy carry proposal ids `0x54` = 84 and `0x55` = 85,
which corroborates the counter reading rather than merely being consistent with it.

Slot 55 reads 3, and the transaction's own log topics include a `3` — so 55 is plausibly
`guardian`/role storage. It is bound as `guardian` in the invariants file at 160 bits; that
naming is an inference from the log shape, not from a storage layout, and is marked as such
here rather than presented as established.

### What the transaction actually did

Decoding the governance log with topic1 = 85 gives a string array `["Hello", "World"]`.
So this transaction **created proposal 85** with placeholder content. It did not upgrade an
implementation (the EIP-1967 pointers on all three proxies are unchanged), and it did not
write governance slots 0–79 except the counter.

That reading does not match what the case name — "governance reinitialization" — invites a
reader to assume, and it does not match `expected_exploit_shape`, which says
"reinitialize governance proxy state -> submit malicious proposal". Either the fixture's
expectations describe a different transaction than the one it pins, or the reinitialization
happened in an earlier transaction that this fixture does not include. **This needs the
owner's decision, not a guess**: the honest options are to correct the fixture's
expectations, or to extend the fixture to a multi-transaction sequence starting from the
earlier reinitialization.

### What is now capturable, and what is not

Capturable and captured: `guardian` (0x37), `proposalCount` (0x3b), `implementation`
(EIP-1967) on the governance proxy, plus the proxy's code, the implementation's code
(16,882 bytes, fetched by following the pointer automatically) and the attacker contract.

Not capturable: the proposal bodies. They live behind a mapping keyed by proposal id, and
they are not reachable by scanning the linear slot range — verified, slots 60–71 are
unchanged. Recovering them needs either the implementation's storage layout (so the mapping's
base slot is known and `keccak256(abi.encode(85, base))` can be computed) or a
`debug_traceTransaction` this endpoint does not serve.

So the replay's remaining unknown is *which mapping slots the implementation reads*, and that
is a storage-layout question, not a capture question.


---

## 6. First real offline historical replay (2026-10-26)

The Audius case now executes offline. It has never executed before.

```
before:  status=skipped_by_config        executed=0
after:   status=not_found                executed=1
```

`executed: 1` is the substantive change. Everything else below is detail.

### What made it execute

Three fixes, in dependency order:

1. **`*.invariants.json` was being loaded as a manifest.** `validate --benchmarks
   benchmarks/historical` failed with `missing field 'id'` from the moment `8c6ae77`
   added a companion file to that directory. Pre-existing, unrelated to this session's
   work, and it made the whole corpus un-runnable.
2. **`validate` had no way to pin a block.** `fork_block` came only from `config.toml`,
   whose value is a placeholder, so every `mainnet_fork` case returned
   `skipped_by_config`. Added `--rpc-url` and `--fork-block`.
3. **The invariant file's target had to equal the manifest target.** Wrong for this case:
   the manifest target is the attacker's contract, the state is in the governance proxy.
   Relaxed, with the binding target carried into the report so a reader can see which
   contract was measured.

### What the replay does now

Measured with temporary instrumentation, since removed:

| state of the capture | gas used | slots read | predicate outcomes |
|---|---|---|---|
| 4 accounts, governance slots only | 24,316 | 1 | all `Unknown` |
| + attacker contract, token, router, WETH, both impls | 24,316 | 1 | all `Unknown` |
| + attacker owner slot 0 | **131,078** | **16** | `implementation != 0` → **True** |

So a predicate does evaluate against a captured historical snapshot. That was the open
question and it is now answered yes.

### Why it still reverts, stated precisely

The replay's transaction reverts (gas 131,078 against the real 730,454). The attacker
contract's entry point begins with `SLOAD(0)` / `CALLER` / `EQ` — `onlyOwner` on its own
owner slot. Binding that slot raised gas five-fold and moved one predicate from `Unknown`
to `True`, so the capture is being consulted; something later in the call still fails.

The attacker contract embeds six external addresses:

```
0x18aaa7115705e8be94bffebde57af9bfc265b998   AUDIO token
0x4d7968ebfd390d5e7926cb3587c39eff2f9fb225   discovery proxy
0x4deca517d6817b6510798b7328f2314d3003abac   governance proxy
0x7a250d5630b4cf539739df2c5dacb4c659f2488d   Uniswap V2 router
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2   WETH
0xe6d97b2099f142513be7a2a068be040656ae4591   third Audius proxy
```

All six are captured. What is not captured is the storage *those* contracts read when
called — token balances for the attacker's address, WETH balances, router pair addresses,
discovery stakes. Each is a mapping lookup, so each needs its key named or its base slot
derived.

### What this means for the plan

The gap has narrowed from "historical replay is unreachable" to "the replay needs a
specific, enumerable set of slots". Two ways forward, and the second is better:

- Add slots by hand each time the replay reverts, which is slow and case-specific.
- **Derive them from the implementation's storage layout**: with the base slot of
  `balances` known, `keccak256(abi.encode(address, base))` gives the exact slot, and the
  capture can fetch it. That generalises to every case and is the same machinery
  `crates/rustyfuzz-predicate` already has for mapping bindings.

### Corrections to earlier statements in this file

Section 5 said the remaining unknown was "which mapping slots the implementation reads".
That is still true, but the *immediate* blocker is narrower and simpler: the token and WETH
balances of the accounts the attacker contract talks to. Stated here so the next reader
does not chase the harder question first.
