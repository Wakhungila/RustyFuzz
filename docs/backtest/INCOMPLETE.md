# INCOMPLETE.md — declared gaps in the Tier-1 corpus

This file exists so that every unknown in the backtest corpus is **declared**, not
guessed. It is the machine-checkable counterpart to
`docs/backtest/BASELINE_REPORT.md` and `docs/reality/FACTS.md` §C7.

Rule for anyone extending the corpus: if a field cannot be established from a real
source, it goes in the table below as `null` with a reason. It is never filled with
a plausible-looking value.

---

## 1. Corpus size shortfall

The circulating plan called for 150 cases. `docs/reality/FACTS.md` §C7 recorded the
real inventory:

| tier | contents | count |
|---|---|---|
| Tier 1 (real, in tree) | 2 historical + 5 `known_vulnerable` | **7** |
| Tier 1b (synthetic controls) | 5 gate2 positive + 11 negative + 3 live | 19 manifests |
| Tier 2 (user-supplied data) | none supplied to date | **0** |

**Shortfall: 143 cases short of the original 150 target.** Tier 2 cases may only be
added from an explicit file path or URL. No fabricated case will be created to close
this gap.

---

## 2. The five `local_fixture` cases: `chain` and `fork_block` are intentionally absent

All five carry `mode = "local_fixture"` and target synthetic addresses in the
`0x6200…0001`–`0x6200…0005` range. Their JSON fixtures describe expected outcomes;
the validator reconstructs observations without deploying or executing bytecode.
There is no chain and no block to record. These differ from the separate
`executable_evm` controls, which do execute bytecode.

`chain = null` and `fork_block = null` below are **deliberate and correct**, not
missing data. Writing a real chain id or a plausible block number here would be
fabrication, and would also silently change what the case measures.

| case id | class | target | chain | fork_block |
|---|---|---|---|---|
| `known-erc20-bad-mint-inflation` | `erc20_mint_inflation` | `0x6200000000000000000000000000000000000001` | **null** (intentional) | **null** (intentional) |
| `known-uninitialized-proxy-takeover` | `access_control_bypass` | `0x6200000000000000000000000000000000000002` | **null** (intentional) | **null** (intentional) |
| `known-read-only-reentrancy` | `reentrancy` | `0x6200000000000000000000000000000000000003` | **null** (intentional) | **null** (intentional) |
| `known-flashloan-price-manipulation` | `amm_invariant_violation` | `0x6200000000000000000000000000000000000004` | **null** (intentional) | **null** (intentional) |
| `known-bridge-nonce-replay` | `bridge_replay_finalization_bug` | `0x6200000000000000000000000000000000000005` | **null** (intentional) | **null** (intentional) |

Verified absent, not zero and not defaulted:

```
$ for f in benchmarks/historical/known_vulnerable/*.toml; do grep -c '^chain' $f; done
0
0
0
0
0
```

The manifests simply omit both keys. `BenchmarkManifest` deserialises them as
`Option`, so absence and `null` are equivalent at runtime — but this file records the
intent explicitly so a later reader does not "fix" it by inventing values.

### Why this matters for measurement

These five cases demonstrate behavior against **reconstructed fixture observations**.
They do not demonstrate an oracle firing on executed bytecode or a real deployed
protocol being exploited.
`BASELINE_REPORT.md` reports them separately from the two historical cases for
exactly this reason, and their five `not_found` results are counted as false
positives against a pre-recorded expectation, not against a live contract.

---

## 3. The two historical cases: real chain data, but not executable as written

| case id | chain | fork_block | target | status |
|---|---|---|---|---|
| `historical-audius-governance-reinitialization-2022` | `evm` (id 1) | `15201793` | `0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569` | **Inconclusive** |
| `historical-euler-finance-donate-liquidation-2023` | `evm` (id 1) | `16817995` | `0x27182842E098f60e3D576794A5bFFb0777E025d3` | **Inconclusive** |

Both have complete, real metadata. Both are unreachable for a different reason:

```
$ python3 -c 'import json;print(json.load(open("benchmarks/historical/fixtures/audius-governance-reinitialization-2022.json"))["provider_replay_only"])'
True
$ python3 -c 'import json;print(json.load(open("benchmarks/historical/fixtures/euler-finance-donate-liquidation-2023.json"))["provider_replay_only"])'
True
```

The runner rejects that mode by design (`src/engine/benchmark.rs:1889-1892`):

> `provider_replay_only is unsupported: independent eth_call requests do not
> preserve sequence state or prove an invariant; use local EVM replay with a
> pinned fork/cache`

**Declared gap:** these two need a cached fork snapshot (or a transaction-list
fixture) to become executable. That work is not done. They are recorded as
`Inconclusive` with the reason, never as `Missed` and never as rediscovered.

Both blocks were confirmed reachable on the configured mainnet endpoint, so the
blockers are the fixture format, not the data.

---

## 4. Fields that are absent for every case

| field | status | note |
|---|---|---|
| `source_available` | **not recorded** | The manifests carry `mode` and `fixture` but no explicit "verified source available" boolean. `docs/reality/FACTS.md` §C8 records that blockscout/Etherscan ABI acquisition failed for the non-mainnet target tested; for these mainnet cases it was not attempted. |
| `ground_truth_invariant` | **partially recorded** | The two historical cases have `success_invariant` (free text) and `expected_invariant_family`; the five fixtures have `expected_invariant` prose. None is a machine-checkable predicate — see §C1 of FACTS.md, the invariant layer is a closed enum with no expression language. |
| `expected_loss_usd` | **absent everywhere** | No case records a monetary loss figure. Nothing in the tree supports one, so none is invented. |
| `reference_poc_path` | **absent everywhere** | No case references a PoC file. `BASELINE_REPORT.md` records `missing=[FoundryPocGenerated]` for all five fixtures, which is the same gap seen from the runner's side. |

---

## 5. Known contamination in the tree

Not part of the corpus, recorded so it is not mistaken for data:

- `benchmarks/historical/gate2_positive_controls/__pycache__/build_fixtures.cpython-314.pyc`
- `benchmarks/historical/negative_controls/__pycache__/build_fixtures.cpython-314.pyc`

Two compiled Python artifacts are checked into the tree. They are build residue from
`build_fixtures.py`, not benchmark inputs. Removing them is a separate cleanup that
was not performed here.

---

## 6. What is deliberately **not** in this file

- No estimated or reconstructed fork blocks.
- No guessed chain ids for the `local_fixture` cases.
- No placeholder addresses.
- No ground-truth invariants invented to make a case look measurable.

If a future contributor needs one of those values, it must arrive from a real
source, and this file is where the absence gets recorded until it does.
