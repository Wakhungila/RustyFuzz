# BRIEF_CORRECTIONS.md

Corrections to the circulating 30-day plan, derived from `docs/reality/FACTS.md`.

Every correction below cites the FACTS.md section that establishes it. No claim in
the revised roadmap (`ROADMAP_v1.1.md`) references a component that FACTS.md marks
as nonexistent.

Status: **no source changes** produced this file, per task scope. It records what
must change in planning, not what changed in code.

---

## Correction 1 — "Satori emits `InvariantOracle` impls"

**Original claim:** Satori can be upgraded to emit `InvariantOracle`
implementations, treated as a one-day wiring task (Day 8–9).

**Correction:** There is no such trait.

FACTS.md §C2:

> `rg -n "trait InvariantOracle" --type rust .` → **no output**.
> …
> **the trait itself does not exist; must be built.**

The only similarly named item is a *struct*, not an abstraction to implement
(FACTS.md §C2):

> ./src/common/oracle/defi.rs:323:pub struct UniswapV3InvariantOracle {
> ./src/common/oracle/defi.rs:327:impl VulnerabilityOracle for UniswapV3InvariantOracle {

**What must actually be built**, per FACTS.md §C1: the current invariant layer is a
closed 10-variant enum judged against pre-set booleans.

> 52: pub enum TargetInvariantKind {
> 53:     MaxSharePriceIncreaseBps,
> …
> 398:             TargetInvariantKind::RequireNoAccountingAnomaly => report.accounting_anomaly,

There is no expression parser, no storage-slot evaluation, and no slot→variable
binding in that path. Predicate support therefore requires, from scratch:

1. an expression IR with (at minimum) arithmetic, comparison, boolean composition,
   and sum over tracked accounts;
2. an evaluator that can resolve a symbol to a storage slot value at a given point
   in a transaction sequence;
3. a binding layer mapping predicate symbols to (address, slot) pairs — which the
   LLM or the user must supply, since the slot layout is not derivable from ABI
   alone for proxies and packed structs;
4. an `InvariantOracle` trait plus registration in the campaign loop.

**Scope:** 1–2 weeks of work, not one day. This is a workstream, not a wiring task.
It is scheduled as W2 in ROADMAP_v1.1.

---

## Correction 2 — "LLM: OpenAI o3"

**Original claim:** Satori uses OpenAI o3 behind `--features llm`.

**Correction:** It uses OpenCode Zen free chat models.

FACTS.md §C3:

> 6: pub const DEFAULT_MODEL: &str = "big-pickle";
> 13: pub const FREE_CHAT_MODELS: &[&str] = &[
> 14:     "big-pickle",
> 15:     "space-bunny-free",
> …
> 37:             "unsupported free Zen chat model; select one of: {} (no paid fallback)",

> 1: //! OpenCode Zen's documented free chat-completion models. No paid fallback.

**Consequence for planning:** switching providers is a **protocol-layer change**,
not a configuration change. The client enforces a hard-coded allowlist and its
module doc states there is no paid fallback. FACTS.md §C3 records this explicitly:

> **DISPROVED claim:** "Satori uses OpenAI o3 behind `--features llm`." It does not.

Plans must stop describing model choice as a flag flip. Any budget or capability
assumption based on a frontier paid model is also unsupported: the available models
are free-tier chat models with an enforced whitelist.

---

## Correction 3 — "Foundry `invariant_*` as primary oracle"

**Original claim:** Foundry invariants are executed as the primary oracle, with
`foundry_ingest.rs` as "the right seam".

**Correction:** Foundry invariant functions are parsed and never executed, and the
ABI entries produced from the harness are empty.

FACTS.md §C4:

> 4846:                 abi_registry.functions.entry(selector_hex).or_default();

> `.or_default()` on `HashMap<[u8; 4], Vec<DynSolType>>` … inserts an **empty
> `Vec<DynSolType>`**. No parameter types are ever populated from the harness.

Every consumer of `invariant_functions` (FACTS.md §C4 table) is one of: a
`log::info!` counter, or a `names.push(...)` used for scoring heuristics:

> 83:             for invariant in &harness.invariant_functions {
> 84:                 names.push(invariant.name.clone());
> 85:             }

> **Consequence:** no `invariant_*` function is ever **called**. There is zero
> Foundry invariant execution.

**Action:** remove all claims of Foundry invariant execution from the roadmap and
from any external description. Foundry integration today is selector discovery plus
log counters. If Foundry invariants are wanted as an oracle, that is a separate
build (execute the invariant function against post-sequence state), and it must not
be described as existing.

---

## Correction 4 — "Day 12 extends storage-novelty"

**Original claim:** Day 12 extends the storage-novelty scheduler to weight
invariant-referenced slots. Presented as a standalone day.

**Correction:** It is blocked behind the predicate IR and is not a standalone day.

Reasoning, from FACTS.md §C1: "weight the slots an invariant references" requires
that invariants *have* referenced slots. Today an invariant is one of 10 enum
variants with optional numeric thresholds (FACTS.md §C1):

> 39: pub struct TargetInvariantRule {
> 40:     pub id: String,
> 41:     pub kind: TargetInvariantKind,
> 42:     #[serde(default)]
> 43:     pub max_bps: Option<u64>,

There is no field holding slot references, because there is no predicate to
reference them. Slot→variable binding is deliverable #3 of Correction 1.

**Action:** fold this into the W2 workstream as a follow-on step after the binding
layer exists, and state the dependency explicitly. It is not schedulable before
then.

---

## Correction 5 — Corpus size 150

**Original claim:** Curate a 150-case backtest corpus from DeFiHackLabs/DVBench and
the DeFi-Security-Incident database.

**Correction:** 150 cannot be met with available data. FACTS.md §C7 recorded the
real inventory:

> `find benchmarks -type f | wc -l` → **66**
> **Totals that matter:** real historical cases = **2**. Known-vulnerable labelled
> fixtures = **5**.

Concretely, the two independent historical cases are (FACTS.md §C7):

```
benchmarks/historical/audius-governance-reinitialization-2022.toml
benchmarks/historical/euler-finance-donate-liquidation-2023.toml
```

and the five `known_vulnerable` fixtures are (FACTS.md §C7):

```
benchmarks/historical/known_vulnerable/known-bridge-nonce-replay.toml
benchmarks/historical/known_vulnerable/known-erc20-bad-mint-inflation.toml
benchmarks/historical/known_vulnerable/known-flashloan-price-manipulation.toml
benchmarks/historical/known_vulnerable/known-read-only-reentrancy.toml
benchmarks/historical/known_vulnerable/known-uninitialized-proxy-takeover.toml
```

The `benchmarks/blind/` copies are the same two cases, not additional cases
(FACTS.md §C7). `benchmarks/daedaluzz/fixtures/StopContract.json` is a **single
fixture**, not a corpus (FACTS.md §C7).

**Revised corpus definition:**

- **Tier 1 — real cases present in the tree: 7 case manifests** (2 historical + 5
  known_vulnerable). These are the only cases with an honest claim to real-world
  provenance.
- **Tier 1b — synthetic controls: 5 gate2 positive controls + 11 negative controls
  + 3 live.** These are useful for oracle correctness (they are designed to fire or
  not fire) but they are **not** historical discoveries and must be reported
  separately, never folded into a rediscovery rate.
- **Tier 2 — only data the user explicitly supplies, as a file path or URL.** No
  Tier 2 case exists today. Nothing may be fabricated to reach a number.

**Action:** the roadmap states the corpus as 7 Tier-1 cases and reports the
shortfall openly. Any target of 150 is removed until real data arrives by explicit
hand-off.

---

## Correction 6 — the plan's own Day 1 acceptance criterion is unsatisfiable

**Original claim:** Day 1 produces `BASELINE.md` and "`git diff --stat` shows only
the new doc."

**Correction:** The working tree is already dirty with pre-existing work, so that
acceptance cannot pass. FACTS.md records the capture:

> `git rev-parse HEAD` → `b3bafb44d297f3fae357659fa0f647327ecbe4da`
> `git status --short` → 27 modified (`M`), 15 untracked (`??`) … `git diff --stat`
> → `27 files changed, 1845 insertions(+), 386 deletions(-)`

**Action:** Day 1 acceptance is restated as "the doc cites file paths and line
numbers for every claim; no source file is modified by this task." Tracking the
pre-existing dirtiness is a separate, explicit decision that only the repository
owner can make.

---

## Correction 7 — the false-positive gate is now implemented, and it changed an oracle contract

**Original plan:** treated false-positive control as a Week 3 hardening item
("generic-oracle fallback quality", Day 16).

**Correction:** the single most damaging false positive was in the *proxy upgrade*
oracle and has been fixed in this session, ahead of the plan. FACTS.md §C5 recorded
the defect:

> 1013:         for call in calls_with_selectors(execution, &upgrade_selectors) {
> 1014:             if call.success {
> …
> 1018:                     severity: ProtocolSeverity::High,

> The only predicate is `if call.success`.

The fix requires an observably unprivileged caller **and** an actual implementation
slot write. When privilege is unobservable, the finding is suppressed by design
(FACTS.md §C5 records that the result carries `storage_diffs`/`storage_reads` only —
there is no state snapshot to consult).

**Action for the roadmap:** false-positive control moves to **W1**, because every
rediscovery number computed before it is meaningless. This is the ordering change
that most affects the schedule.

---

## Summary table of corrections

| # | Original claim | Corrected position | FACTS cite | Schedule impact |
|---|----------------|--------------------|------------|-----------------|
| 1 | Satori emits `InvariantOracle` impls | Trait does not exist; build IR + evaluator + binding | §C1, §C2 | 1–2 weeks, now W2 |
| 2 | LLM is OpenAI o3 | OpenCode Zen free models, `big-pickle`, whitelist, no paid fallback | §C3 | provider swap = protocol work |
| 3 | Foundry `invariant_*` is the primary oracle | Names parsed only; never executed; empty ABI entries | §C4 | claim removed entirely |
| 4 | Day 12 extends storage-novelty standalone | Blocked behind the predicate IR | §C1 | folded into W2 |
| 5 | 150-case corpus | 7 Tier-1 real cases exist; Tier 2 only from user-supplied data | §C7 | target replaced, shortfall stated |
| 6 | Day 1: diff shows only the new doc | Tree already dirty (27 M, 15 ??) | capture in FACTS.md | Day 1 acceptance restated |
| 7 | False positives are a W3 concern | Proxy oracle FP was real and is now fixed; FP control is W1 | §C5 | **W1 now gates credibility** |
