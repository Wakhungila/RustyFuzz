# Live target test: Robinhood Chain `StockFactory` proxy

Date: 2026-10-23. Target:
`0x4783C67b63dE2B358Ac5951a7D41F47A38F3C046` on Robinhood Chain (chain id 4663),
an `ERC1967Proxy` whose implementation reports as `StockFactory`.

This records what RustyFuzz actually did, what blocked it, and what the single
finding it produced is worth. Nothing here is a claim of a discovered
vulnerability.

## Result in one line

The campaign **ran to completion** (200 executions, 100 coverage edges) only
after temporarily removing three hard-coded chain gates; it produced **one
finding, which is a false positive that the tool itself refused to confirm**
(`confirmed_vulnerabilities: 0`). On an unmodified build it **refuses to run at
all** on this chain.

## What blocked a stock build

Three independent, hard-coded assumptions, each failing closed:

1. **Chain id must be 1.** Rejected chain 4663 in three places:
   `crates/rustyfuzz-evm/src/environment.rs` (`EnvironmentPolicy`),
   `src/evm/fork.rs` (twice: `create_fork_db` and `fetch_fork_block_env`), and
   `src/engine/executable_fixture.rs`. Error:
   `unsupported chain Some(4663): chain-specific execution semantics are required`.
2. **RPC API key origin must be allowlisted.** `.env` sets
   `RUSTYFUZZ_RPC_API_KEY` while `RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS` is empty,
   so every request fails with
   `RPC API key origin is not explicitly allowlisted`. The provider in question
   serves unauthenticated requests, so the key is unnecessary here — but the
   failure mode is opaque: the message never names the origin or the variable to
   set.
3. **Post-Cancun headers must carry `excessBlobGas`.** This chain's headers do
   not (see next section), so forking fails with
   `post-Cancun header is missing excess blob gas`.

A fourth, non-blocking gap: `fuzz` has no `--rpc-url` or `--fork-block` flag.
Both come only from `config.toml`, whose checked-in value points at Ethereum
mainnet and an unrelated target. Testing any other chain therefore requires
either editing `config.toml` or running from another working directory with a
replacement file. `--chain` does not select an RPC.

## The chain is not Ethereum

The header is the tell:

```
keys: [baseFeePerGas, difficulty, extraData, gasLimit, gasUsed, hash,
       l1BlockNumber, logsBloom, miner, mixHash, nonce, number, parentHash,
       receiptsRoot, sendCount, sendRoot, sha3Uncles, size, stateRoot,
       timestamp, transactions, transactionsRoot, uncles]
```

`sendCount` / `sendRoot` / `l1BlockNumber` are **Arbitrum Orbit** header fields.
There is no `excessBlobGas`, no `blobGasUsed`, no `parentBeaconBlockRoot`, no
`withdrawalsRoot`. `web3_clientVersion` reports `blockmachine-gateway/v0.1.0`.

This matters beyond the one failing assertion: RustyFuzz derives the hardfork
from Ethereum mainnet block numbers and timestamps (`mainnet_spec`,
`mainnet_blob_fraction`). Applying an Ethereum schedule to an Orbit chain means
the EVM ruleset is wrong in general. The temporary test forced `SpecId::SHANGHAI`
and pre-Cancun blob handling, which is a guess, not a supported configuration.
**The resulting executions are not faithful chain semantics and cannot support a
finding.**

## What the campaign produced

`reports/campaign_summary.md` from the test run:

```
total_executions: 200
total_artifacts: 118
coverage_edges: 100
candidate_findings: 1
promoted_findings: 1
confirmed_vulnerabilities: 0
missing_poc_for_promoted: 1
highest_confidence: 65
```

The single finding is `ProxyUpgradeabilityViolation`, and it is wrong. Evidence
from `finding.md` itself:

- Its first transaction targets `0x1515151515151515151515151515151515151515` —
  an address the fuzzer **invented**; no such account was deployed on the fork.
- Other transactions target the fuzzer's own synthetic addresses
  (`0x1818…`, `0x1616…`).
- Its "oracle evidence" is literally
  `successful upgrade entrypoint 4f1ef286 reached through fuzzed input`. Reaching
  a selector is not an authorization failure; `upgradeToAndCall` is *supposed* to
  exist.
- The tool's own verdict: `realistic proof rejected candidate:
  [ReplayFailed, OracleWeakness]`, and the caveat states replay alone cannot
  prove it.

So the confirmation gate worked. The failure is upstream: the oracle treats
"a privileged selector was reached" as evidence, and the mutator invents target
addresses for transactions that should be constrained to real contracts.

## Root cause of the false positive

No ABI was available for this target:

- Blockscout v1/v2 APIs for this chain are behind Cloudflare or require a paid
  key (`{"error":"Proceed with API key or make a X402 payment"}`).
- The Etherscan v2 key in `.env` returns `Invalid API Key` for chain 4663.
- `abi-ingest` therefore had nothing to bind, and the mutator fell back to
  synthesising calldata against guessed addresses.

Without an ABI the tool cannot know `upgradeToAndCall` requires `onlyOwner`, so
"selector reached" is all it can observe. That is exactly the heuristic-packs
weakness the review flagged: heuristics without a target-supplied predicate
produce false positives.

## The target itself

- Proxy runtime is 163 bytes; implementation
  `0xee351e53bce6aaf106428358838197c91e36ee0e` is 4,926 bytes.
- Eight `PUSH4 … EQ` dispatch selectors: `4f1ef286` (`upgradeToAndCall`),
  `52d1902d` (`proxiableUUID`), `8129fc1c` (`initialize`), plus
  `50c09be3`, `59659e90`, `97bb3ce9`, `ad3cb1cc`, `b2670cc5`.
- It is a UUPS-style upgradeable factory with a string constant
  `"StockFactory: stock already exists"`, i.e. it gates on a registry of
  deployed stock contracts.
- No logs in the last ~60k blocks and no transactions to the proxy in the last
  ~400 blocks: essentially idle, so there is no live traffic to seed from.

## Why this target is close to hopeless anyway

The interesting logic is behind `initialize` + `onlyOwner` upgrade paths on a
proxy that has already been initialized on a live chain. Any bug worth reporting
would be in stock-creation and registry accounting, which needs:
an ABI to call the factory correctly, a real `Stock` implementation address from
the registry to bind as a second target, and handler/invariant definitions.

## What to fix, in priority order

1. **Make the chain assumptions explicit and configurable.** Add a chain profile
   (chain id → spec id, blob pricing, header fields required) instead of
   `chain_id == 1` and mainnet number tables. Refuse Orbit/OP-Stack chains
   honestly when no profile exists, rather than only when the header happens to
   be missing a field.
2. **Name the failure.** `RPC API key origin is not explicitly allowlisted`
   should print the origin and the environment variable, and
   `RUSTYFUZZ_RPC_API_KEY` should be optional when the endpoint needs no auth.
3. **Add `--rpc-url` / `--fork-block` to `fuzz`.** Requiring an edit of a
   shared `config.toml` to point at any other chain is a usability cliff.
4. **Stop inventing target addresses.** Transactions should be constrained to
   the target, its discovered implementation, and its real dependencies.
   `0x1515…` would never have been produced.
5. **Make "selector reached" a lead, not a finding.** A
   `ProxyUpgradeabilityViolation` must require evidence that a non-privileged
   caller *changed* privileged state — a storage write to the owner/admin slot
   by an unauthorized caller — not merely that the entry point executed.
6. **ABI acquisition for non-Etherscan chains.** Without an ABI the tool is
   reduced to blind guessing; failing early with "no ABI, refusing to guess"
   would have saved this whole run.

## Reproducing the blocked path

A stock build against this target, from a directory whose `config.toml` points
at it:

```
cargo run --release -- fuzz \
  --chain evm \
  --contract 0x4783C67b63dE2B358Ac5951a7D41F47A38F3C046 \
  --single-process true --max-execs 300 --require-rpc-fork
```

fails immediately with
`unsupported chain Some(4663): chain-specific execution semantics are required`.
That is the correct fail-closed behaviour, and it is the honest summary of
current support: RustyFuzz can fuzz Ethereum mainnet forks, and does not yet
support this chain.
