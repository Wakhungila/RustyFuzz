# ROADMAP_v1.1 — revised four-week structure

Supersedes the four-week structure in the circulating 30-day plan.
Derived from `docs/reality/FACTS.md`; every correction is recorded in
`docs/backtest/BRIEF_CORRECTIONS.md`.

**Ground rule:** this roadmap never references a component that `docs/reality/FACTS.md`
marks as nonexistent. Where a capability must be built, it is listed as *build*, with a
scope estimate — not as "wire up" or "enable".

**Non-claims carried forward from FACTS.md and the performance report:** no claim of
superiority over ItyFuzz or Echidna; no claim that synthetic throughput predicts
bug-finding; no claim that LLM output is a vulnerability.

---

## What changed versus v1.0, and why

| v1.0 arrangement | v1.1 arrangement | reason (FACTS cite) |
|---|---|---|
| W4 = backtest, false positives handled in W3 | **W1 = oracle correctness + scoring rubric + Tier-1 baseline** | every rediscovery number computed before the FP gate is meaningless (§C5) |
| W2 = Satori emits `InvariantOracle` impls (1 day) | **W2 = build predicate IR + evaluator + binding, then one fixture end-to-end** | the trait does not exist (§C2); the invariant layer is a closed enum (§C1) |
| "LLM: OpenAI o3" | OpenCode Zen free models only unless a provider layer is built | (§C3) |
| "Foundry `invariant_*` as primary oracle" | **removed**; Foundry integration is selector discovery + counters only | (§C4) |
| Day 12 = extend storage-novelty | folded into W2 after the binding layer exists | (§C1, §C2) |
| corpus = 150 cases | **Tier 1 = 7 real cases**; Tier 2 only from explicit user-supplied data | (§C7) |
| Day 1 diff must be clean | Day 1 acceptance = doc cites paths+lines; no source modification | tree has 27 M + 15 ?? |

---

## W1 — Oracle correctness, scoring rubric, Tier-1 baseline

**Goal:** make every later number trustworthy. Nothing here adds bug-finding
capability; it makes the measurement honest.

### 1.1 False-positive gate (done in this session, recorded for completeness)

The proxy-upgrade oracle emitted `High` for any successful call to
`upgradeTo`/`upgradeToAndCall` (FACTS.md §C5). It now requires:

1. the caller is **not** the recorded admin/owner (EIP-1967 admin slot read or
   written, admin getter output, or `owner()` at slot 0), and
2. the **implementation slot actually changed** in the same transaction.

When privilege is unobservable the finding is suppressed: a deliberate false
negative, because this oracle gates credibility.

Live evidence: against Robinhood Chain proxy `0x4783C67b...` the campaign went from
`candidate_findings: 1` / `highest_confidence: 65` to `candidate_findings: 0` /
`highest_confidence: 0`, with `total_executions` (200), `coverage_edges` (100) and
`total_artifacts` (118) unchanged.

**Verify:** `cargo test -p rusty-fuzz --lib proxy_upgrade` → 4 passed.

### 1.2 Scoring rubric that makes a false positive unable to count

Build `rustyfuzz-backtest` (the crate does not exist; FACTS.md §C8).

```rust
enum PocOutcome { Pass, Fail, Inconclusive }
enum CaseResult { Rediscovered, NovelFinding, Missed, Inconclusive }
```

Counting rule: a case enters the rediscovery numerator **only** if
(a) the minimized sequence replays deterministically, **and**
(b) the generated PoC compiles and demonstrates the violation under the target's own
test suite.

Everything else is excluded from the numerator and reported separately:
`Fail` → counted in the false-positive rate; `Inconclusive` → counted in an
"unmeasured" bucket that must appear in every table.

`--strict` fails the run if any finding is `Inconclusive`.

**Acceptance:** a unit test with one `Pass` and one `Inconclusive` asserts
`rediscovery_rate == 1/N`, not `2/N`, and reports the false-positive rate as its own
metric.

**Scope:** ~2–3 days. This is new code, not a flag.

### 1.3 Tier-1 baseline

Run the pipeline on exactly the cases that exist. **7 case manifests:** 2 historical
(`audius-governance-reinitialization-2022`, `euler-finance-donate-liquidation-2023`)
plus 5 `known_vulnerable` (`known-bridge-nonce-replay`,
`known-erc20-bad-mint-inflation`, `known-flashloan-price-manipulation`,
`known-read-only-reentrancy`, `known-uninitialized-proxy-takeover`).

Per case record: result, time-to-first-finding, PoC outcome, exact command. Cases
that cannot run (missing RPC, missing source, missing fork block) become
`Inconclusive` **with the reason**. No invented addresses or blocks.

**Acceptance:** `docs/backtest/BASELINE_REPORT.json` exists, its first paragraph
states the real case count, and a summary table plus reproduce command are recorded.

**Honest expectation:** with 7 cases and no PoC generator, most cases will be
`Inconclusive`. That is the correct result to publish. A 0% or 1/7 rediscovery rate
is more defensible than a fabricated 150-case table.

---

## W2 — Predicate IR, evaluator, single-fixture end-to-end

**Goal:** prove one real invariant can be expressed, evaluated, and violated — or
prove it cannot, with evidence.

Everything in this week is **build**, not wiring (FACTS.md §C1, §C2).

### 2.1 Expression IR

Support at minimum: integer arithmetic (+ − × ÷, with an explicit rounding policy),
comparison (< ≤ = ≥ >), boolean composition (∧ ∨ ¬), `sum` over a tracked account
set, and named symbols. No general-purpose language; a bounded IR is easier to
make total and to reason about.

**Scope estimate: 3–5 days** including a parser and a typed error for every rejected
input (no panics — FACTS.md's own conventions require typed errors, and the existing
`AiProposal` seam already models "unvalidated → validated").

### 2.2 Storage-slot evaluation

Resolve a symbol to a storage value **as of a point in a transaction sequence**.

Constraint that shapes the design: `SequenceExecutionResult` carries
`storage_diffs` and `storage_reads` only — there is no state snapshot (FACTS.md §C5
records this for the proxy oracle; it applies here too). So the evaluator can only
see values the sequence actually read or wrote. Two consequences, both must be
stated in any report:

- a predicate over a slot the sequence never touched is **unevaluable**, not "true";
- unevaluable predicates must produce `Inconclusive`, never a pass.

**Scope estimate: 3–4 days.**

### 2.3 Slot→variable binding

Given a predicate and a target, produce `(address, slot)` bindings. Accept bindings
from three sources, in descending trust: an explicit manifest, a storage layout
JSON, or an LLM proposal that is then *verified* against observed reads. Unverified
bindings are rejected — this is the same seam as `AiProposal::unvalidated() →
validate()` (`crates/rustyfuzz-core/src/proposal.rs:25,42,98`).

**Scope estimate: 2–3 days.**

### 2.4 `InvariantOracle` trait and one end-to-end fixture

Add the trait and register it in the campaign loop. Then prove it on a single
fixture with two cases:

- a deliberately false invariant → exactly one `Rediscovered` finding that replays;
- a true invariant → no finding.

**Acceptance:** the end-to-end fixture passes both cases, and a written statement of
what remains unimplemented (rounding policy coverage, account-set quantification).

**Explicitly out of scope this week:** storage-novelty weighting by referenced slot
(Correction 4). It depends on 2.3 and is scheduled in W2's tail only if 2.1–2.4 land
early.

**If W2 slips:** the correct outcome is to publish "predicate support not delivered"
in W4, not to relabel enum variants as predicates.

---

## W3 — Zero-config CLI and multi-chain profile

**Goal:** make the tool runnable against a live target without editing a shared
config file, and make its chain assumptions explicit instead of hard-coded.

Prerequisites recorded in FACTS.md §C8:

- no `target` / `test` / `backtest` subcommand exists today (see the `--help`
  listing recorded there);
- `fuzz` has no `--rpc-url` or `--fork-block`; `rpc_url` appears only on `Seed` and
  `ProveLive` (FACTS.md §C8);
- chain support is Ethereum-mainnet-only: `EnvironmentPolicy` rejects
  `chain_id != 1`, and `mainnet_spec` / `mainnet_blob_fraction` are mainnet
  number/timestamp tables.

### 3.1 `rustyfuzz target <address> --chain <id> --block <n>`

Fork at the block, fetch bytecode, start a campaign with no user-written harness.
This is new CLI surface, and a new code path from "address" to "campaign".

**Scope estimate: 3–4 days.**

### 3.2 Chain profiles

Replace `chain_id == 1` with an explicit profile: `{chain_id → spec id, blob pricing,
required header fields}`. Unknown chains are **refused with a message naming the
missing profile**, instead of failing later on a missing header field.

This is the honest resolution of the live-target test recorded in
`docs/target-test-robinhood-stockfactory.md`: Robinhood Chain (id 4663) is an
Arbitrum Orbit chain with no `excessBlobGas`, and importing an Ethereum hardfork
schedule for it produces executions whose semantics are not faithful. Either a
profile exists and is validated, or the tool refuses.

**Scope estimate: 3–5 days** for Ethereum + one documented non-mainnet profile, plus
tests proving an unknown chain is refused rather than mis-executed.

### 3.3 ABI acquisition honesty

If no ABI can be obtained, **fail early and say so**. The live-target test showed the
tool otherwise falls back to synthesising calldata against guessed addresses
(`0x1515...`), producing findings with no evidentiary value.

**Scope estimate: 1 day.**

---

## W4 — Corpus expansion (real data only) and the honest report

**Goal:** publish numbers that survive scrutiny, including the ones that look bad.

### 4.1 Corpus expansion — gate

Tier 2 cases may be added **only** when supplied as an explicit file path or URL.
No synthetic JSON may stand in for a real case. If no Tier 2 data is supplied by
this point, W4 proceeds with 7 cases and says so.

### 4.2 Stratified report over whatever exists

Report per class, and flag any class with fewer than 10 cases as underpowered. With
7 cases, every class is underpowered; the report must say that rather than present a
per-class rate as if it were meaningful.

### 4.3 Failure taxonomy

Every miss classified as one of: **predicate/binding failure**, **search failure**,
**replay failure**, **infrastructure failure**. Counts plus representative case IDs.
This is the most useful output of the month.

### 4.4 Public report, with the caveats section

Must state, in the first paragraph: the real case count, that the corpus is not 150,
that no head-to-head against ItyFuzz or Echidna was run, and that synthetic
throughput is not competitive evidence.

External numbers may be quoted only with a source, and only where the dataset
overlaps; no superiority claim otherwise.

---

## Deliverables and gates

| week | deliverable | gate |
|---|---|---|
| W1 | FP gate + `rustyfuzz-backtest` rubric + `BASELINE_REPORT.json` | `rediscovery_rate == 1/N` test passes; report states real case count |
| W2 | IR + evaluator + binding + `InvariantOracle` + one fixture | false invariant fires and replays; true invariant silent |
| W3 | `target` subcommand + chain profiles + early ABI failure | unknown chain refused by name; no invented addresses |
| W4 | stratified report + failure taxonomy + caveats | every miss classified; caveats in first paragraph |

## Standing constraints

- Deterministic replay is the only confirmation path.
- AI output is a proposal until validated against observed state.
- No fabricated corpus data, fork blocks, or addresses.
- No superiority claim without a same-corpus, same-budget comparison.
- A number that is bad is reported as bad, not adjusted.

## What this roadmap deliberately does not include

- **Kani proofs.** `rust-toolchain.toml:2` pins `channel = "1.97.1"` stable
  (FACTS.md §C6), so Kani cannot run on this pin. Adding it is a new CI job and
  toolchain matrix, and should be scoped separately.
- **Native EVM engine.** Long-term direction, not a four-week item. REVM remains the
  execution engine; replacing it is a multi-month project with its own compatibility
  burden.
- **A 150-case backtest.** Not achievable with available data (FACTS.md §C7).
- **Structure-aware RLP/MPT/proof generators.** RustyFuzz fuzzes the contract layer;
  chain-layer object generators have low marginal value for DeFi logic bugs and
  should be deprioritised against predicate support.
