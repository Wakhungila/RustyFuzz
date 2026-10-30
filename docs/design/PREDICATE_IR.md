# PREDICATE_IR.md — design for a predicate layer over RustyFuzz

**Status: design only. No evaluator code has been written.**
Awaiting owner review before implementation (Gate 6).

This document specifies what must be built so that an invariant can be expressed as
a *predicate* rather than selected from a fixed enum. It contains no implementation.

---

## 0. Why this document exists, and what is false about the original plan

The circulating plan described "Satori emits `InvariantOracle` impls" as a one-day
wiring task. `docs/reality/FACTS.md` records why that is wrong:

- §C2: `rg -n "trait InvariantOracle" --glob '*.rs' .` returns **no match**. The
  trait does not exist. The only similarly named item is a *struct*,
  `src/common/oracle/defi.rs:323 pub struct UniswapV3InvariantOracle`, implementing
  the unrelated `VulnerabilityOracle` trait.
- §C1: the invariant layer is a closed 10-variant enum judged against pre-set
  booleans:

  ```rust
  52: pub enum TargetInvariantKind {
  53:     MaxSharePriceIncreaseBps,
  ...
  393:             TargetInvariantKind::MaxReservePriceMoveBps => report.price_impact_pressure,
  394:             TargetInvariantKind::NoBadDebtIncrease => report.debt_or_collateral_pressure,
  ```

  with the booleans declared on the report
  (`src/engine/economic_delta.rs:34-39 pub accounting_anomaly: bool,` …).

There is no expression parser, no slot evaluation, and no slot→variable binding
anywhere in that path. **Everything below is new code.** The scope estimate is
1–2 weeks; the per-component breakdown is in §8.

---

## 1. Scope and non-goals

### In scope

- A bounded expression language for boolean predicates over contract state.
- A typed AST and a resolver that binds symbols to `(address, slot)` locations.
- An evaluator that answers TRUE / FALSE / **UNKNOWN** at a point in a transaction
  sequence, using only evidence the sequence actually produced.
- An `InvariantOracle` trait and its registration point in the campaign loop.
- A machine-checkable manifest format so a predicate is data, not code.

### Explicit non-goals

- **Not a scripting language.** No loops, no recursion, no user-defined functions, no
  I/O, no time-travel. A bounded IR is total by construction and cheap to reason
  about; a general language reintroduces the halting problem into the oracle.
- **Not a Solidity parser.** Binding a predicate to a real contract's layout is a
  separate problem (§4.4).
- **Not a symbolic executor.** The evaluator computes a concrete value from concrete
  observations. It does not solve for inputs.
- **Not a replacement for the existing enum.** The 10 variants stay. Predicates are
  additive.
- **No LLM in the trusted path.** An LLM may *propose* a predicate; §7 says exactly
  how a proposal becomes trusted.

---

## 2. Expression grammar

Deliberately small. Everything expressible is expressible in this grammar; nothing
outside it exists.

```ebnf
predicate   := expr
expr        := or_expr
or_expr     := and_expr ( "||" and_expr )*
and_expr    := not_expr ( "&&" not_expr )*
not_expr    := "!" not_expr | cmp_expr
cmp_expr    := arith ( cmp_op arith )?
cmp_op      := "==" | "!=" | "<=" | ">=" | "<" | ">"
arith       := term ( ("+" | "-") term )*
term        := factor ( ("*" | "/" | "%") factor )*
factor      := "-" factor
             | "sum" "(" symbol ")"
             | "count" "(" symbol ")"
             | "old" "(" symbol ")"          (* value before the current tx *)
             | "delta" "(" symbol ")"        (* new - old for the current tx *)
             | "requires_no_overflow" "(" arith ")"
             | "block" "." ("number" | "timestamp")
             | "(" expr ")"
             | literal
             | symbol
literal     := decimal | "0x" hex | "true" | "false"
symbol      := ident ("." ident)*           (* dotted, resolved by the binder *)
```

### Design notes

- **`sum`/`count` are first-class**, because the motivating class of bug is exactly
  `sum(userBalances) == totalSupply` (§6). Without them, the canonical invariant of
  this domain is inexpressible and the whole layer is pointless.
- **`old`/`delta` are explicit** rather than implicit. Whether a predicate means
  "before this transaction" or "after" must never be inferred; a pre/post-accounting
  bug is precisely a mismatch between the two.
- **No string type.** No predicate in scope compares bytes or strings. If one is
  ever needed, it is a new decision, not an accident of implementation.
- **Booleans and integers are separate sorts** (§3), so `if x` is a type error.
- **`requires_no_overflow` is an operator, not a mode.** Arithmetic always wraps
  (EVM `ADD`/`SUB`/`MUL`); the operator is how an auditor *asserts* that a specific
  expression must not wrap. Putting the check at the call site rather than in a
  global setting means the intent appears in the finding text, and means a predicate
  that does not care about overflow is not burdened with it. See §3 item 2.

---

## 3. Types

Three sorts only.

| sort | literals | operators | notes |
|---|---|---|---|
| `Int` | `0`, `42`, `0x…` | `+ - * / %`, comparisons | **256-bit unsigned**, matching EVM words |
| `Bool` | `true`, `false` | `&& \|\| !`, comparisons | result of a predicate |
| `Slot` | — | only via `old`/`delta`/`sum`/`count` | not first-class in arithmetic |

### Arithmetic semantics — **DECIDED** (owner ruling, 2026-10-23)

The single most likely source of silent divergence from a target's own behaviour is
arithmetic. **Resolved: the predicate models what the contract does, not ideal
mathematics.**

The four items this section previously listed were:

| # | item | status |
|---|---|---|
| 1 | **Width** — 256-bit wrapping vs checked→`Unknown` | **DECIDED: wrapping** |
| 2 | **Division by zero** | **DECIDED: `0`, plus a counter** |
| 3 | **Rounding on `/`** — truncating toward zero vs floor | **moot**: `Int` is unsigned, so truncate and floor agree |
| 4 | **`%` sign** — EVM `MOD` on unsigned | **moot**: unsigned operands, no sign ambiguity |

Items 3 and 4 need no ruling. They were listed as open in the first revision because
the earlier draft assumed a signed type; now that `Int` is explicitly unsigned, the
distinction they raised cannot arise. Both are written out below so the reasoning is
on the record rather than implied.

#### 1. Overflow / underflow: **256-bit wrapping**, EVM-faithful

`+`, `-`, `*` wrap modulo 2^256, exactly as EVM `ADD`/`SUB`/`MUL`.

Rationale accepted from review: the predicate must model contract execution
semantics. If a contract legitimately relies on wrapping (assembly, pre-0.8 Solidity,
intentional modulo arithmetic), checked arithmetic would produce a **false negative**
— the predicate reports `Unknown` while the contract's behaviour is well-defined
wrapping. That trades correctness for safety in the wrong direction.

Consequence for `-`: there is no "underflow error". `0 - 1` is `2^256 - 1`. This is
EVM `SUB` behaviour and must not be special-cased. (It is also why an auditor
comparing balances must think about which side is larger; the IR will not do it for
them.)

#### 2. `requires_no_overflow(expr)` — explicit overflow intent

Because the default is permissive, the *interesting* case becomes expressible
instead of being the default:

```
requires_no_overflow(totalSupply + amount) && totalSupply + amount == expected
```

Semantics: evaluates its `arith` operand twice — once in wrapping 256-bit mode
(defining the value the contract would compute) and once in a widened mode. It is
`True` when the widened result fits in 256 bits, `False` when it wrapped, and
`Unknown` when any leaf is `Unknown`.

Rules:

- **`False` is a violation, not an error.** An auditor writing
  `requires_no_overflow(...)` is asserting "this must not wrap"; a wrap is exactly
  the finding they asked for.
- It appears in the finding evidence verbatim, so the intent is visible in the
  report. A finding says "the auditor required no overflow here, and it overflowed",
  which is a different claim from "an invariant broke".
- Nesting is allowed but pointless; the evaluator reports the outermost verdict.
- It does **not** change the value used elsewhere in the predicate: the operand is
  still evaluated wrapping for every other use. `requires_no_overflow` is a *check
  on* the arithmetic, never a replacement for it.

#### 3. Division / modulo by zero: **returns `0`**, EVM-faithful, plus a counter

`x / 0` and `x % 0` both yield `0`, matching EVM `DIV`/`MOD`.

Because a predicate that divides by zero is almost always mis-specified, each
occurrence increments **`division_by_zero_observed`** on the finding, so the auditor
sees the predicate was degenerate without the evaluator fabricating a value or
silently suppressing the result.

**A non-zero counter changes the verdict (owner ruling, 2026-10-25).** The counter is
not merely diagnostic. Division by zero can hide bugs: a predicate like `a / b <= X`
*passes* when `b == 0`, because EVM `DIV` yields `0` and `0 <= X` holds. Reporting a
plain `True` there would be the evaluator actively suppressing a real chance that the
contract is broken.

Therefore, when `division_by_zero_observed > 0`:

- a would-be `True` is reported as **`Satisfied(div0 observed)`**, never a plain pass;
- a would-be `False` still stands as a violation, because a violated predicate is not
  made more reliable by arithmetic degeneracy — but the counter is carried into the
  evidence;
- the counter appears **in the finding text**, not buried in a metrics blob, so a
  reader sees it without opening JSON.

The distinction between `True` and `Satisfied(div0 observed)` matters because the
scheduler treats them differently (§5.1): only a clean `True` is a pass. A
div0-degraded satisfaction is "no signal", the same as `Unknown`.

#### 4. Rounding on `/`: truncating toward zero (EVM `DIV`)

Truncating toward zero, matching EVM `DIV`.

Because `Int` is unsigned there are no negatives for truncate-vs-floor to disagree
on — with one subtlety worth stating: unary minus produces a *wrapped* value (§3
item 1), so `(-1) / 2` is `(2^256 - 1) / 2`, a large positive number halved. That is
EVM-consistent (`SUB 0 1` then `DIV`), and it is a good reason not to use unary minus
in a predicate.

#### 5. `%` sign: EVM `MOD` on unsigned

EVM `MOD`, unsigned operands, no sign ambiguity — the result takes the sign of the
dividend in languages that have signed modulo, which this type does not.

---

## 4. Storage-slot evaluation model

### 4.1 The hard constraint that shapes everything

`SequenceExecutionResult` carries:

- `storage_diffs: Vec<StorageDiff>` — committed writes with `old_value`,
  `new_value`, `slot`, `address`, `tx_index`;
- `storage_reads: Vec<StorageAccess>` — loads actually performed, with `value`.

It does **not** carry a state snapshot. FACTS.md §C5 records this from the proxy
oracle's side; it is structural, not incidental. Therefore:

> **A symbol can be evaluated only if the sequence read or wrote its slot, or the slot
> can be re-read from post-sequence state. Otherwise the result is UNEVALUABLE — not
> TRUE, not FALSE.**

`storage_diffs` and `storage_reads` describe what the sequence *observed*, not what
state *is*. The on-demand re-read in §4.3 closes that gap for current values; it
cannot close it for historical ones, which is why `old()` and `delta()` remain
`Unknown` when no write at index `i` exists.

### 4.2 Value resolution for a symbol at transaction index `i`

Resolution is a **four-step** procedure. It is *not* a scan of the trace, because a
scan is what forced the previous draft into accepting weak evidence.

```
resolve(symbol, i):
  1. if a write to (address, slot) exists at tx_index <= i:
         value = new_value of the LATEST such write          -> Authoritative
  2. else if a read of (address, slot) exists at tx_index == i
        AND no write to that slot occurred after it:
         value = that read's value                            -> Authoritative
  3. else:  RE-READ from live post-sequence state (§4.3)
         if the re-read succeeds                              -> Authoritative
         else                                                 -> UNKNOWN
```

The re-read in step 3 is what makes the model both sound *and* complete enough to be
useful. It is affordable: see §4.3 for the measured cost path.

`old(sym)` resolves to the `old_value` of the write at index `i`; if there is no
write at `i`, `old` is `UNKNOWN` (there is no transition to speak of — and it cannot
be re-read, because "the value immediately before this transaction" is not a property
of current state).
`delta(sym)` is `new - old`, hence `UNKNOWN` whenever either side is.

### 4.3 Evidence strength — `Stale` is `Unknown`, with no asymmetry

**Owner ruling (2026-10-23): stale reads produce `Unknown` for BOTH satisfaction and
violation.** The previous revision of this document proposed allowing stale evidence
to prove *satisfaction* while forbidding it for *violation*. That was wrong, and the
reasoning behind it was backwards.

A stale `True` is as dangerous as a stale `False`. If the predicate is `X == Y` and a
stale read yields `X_old == Y`, the evaluator has **not** proven the predicate holds:
`X` may have changed since. Letting the fuzzer believe a property holds when it does
not means the search stops looking for the bug — the failure is silent, and it
suppresses findings rather than inventing them, which makes it harder to notice.
"Absence of proof is never proof" cuts in both directions.

| source | confidence | usable for `True` | usable for `False` |
|---|---|---|---|
| write at or before `i` | `Authoritative` | yes | yes |
| read at exactly `i`, no later write to that slot | `Authoritative` | yes | yes |
| read before `i` with an intervening write | `Stale` | **no** | **no** |
| successful re-read from post-sequence state (below) | `Authoritative` | yes | yes |
| re-read unavailable | — | `Unknown` | `Unknown` |

`Stale` is therefore `Unknown`, full stop. No partial trust, no asymmetry to reason
about, no class of predicate that silently degrades.

#### On-demand re-read: how `Stale` becomes decidable

When resolution would land on stale evidence, the evaluator takes a **fresh read from
the post-sequence state**. If the slot has been written since the last observation,
that fresh read is `Authoritative` — it observes the final value directly.

This is sound because the predicate is checked at end-of-sequence position `i`, and
post-sequence state *is* the state at that position. It is not sound for `old()`,
which needs a value that current state cannot recover (§4.2).

**Cost — measured, not assumed.** The previous draft implied re-reads were
expensive and used that to justify loosening the evidence model. That was the wrong
trade: the fix is to make re-reads cheap, and they already are.

The oracle layer already has live state: `VulnerabilityOracle::check` receives
`before: &Snapshot, after: &Snapshot` (`src/common/oracle/mod.rs:5`) and
`Snapshot.state: Arc<RwLock<ChainState>>` (`src/common/types.rs:27`).

Re-reading one slot is a cached-map lookup, not a network call:

```
revm-database-43.0.1/src/in_memory_db.rs:425-428
        match self.cache.accounts.get(&address) {
            Some(acc_entry) => match acc_entry.storage.get(&index) {
                Some(entry) => Ok(*entry),          <- pure HashMap hit
```

and the fork backend returns early on a cache hit, so no RPC is issued:

```
crates/rustyfuzz-evm/src/fork_db.rs:1106-1108
        if let Some(value) = self.inner.storage.lock().get(&(address, index)).copied() {
            return Ok(value);
        }
```

A slot the sequence already touched is therefore a hash lookup plus a lock; a slot it
never touched may fall through to the fork cache, which is also in memory, and only an
out-of-cache miss on a live fork would reach the network — the same cost the executor
already pays for any first access. The evaluator must never perform I/O on the
finding path, so the re-read is subject to the same node budget and RPC budget rules
as ordinary execution (§5 item 9), and a budget exhaustion yields `Unknown`.

**Re-read must be recorded.** Every re-read appends to the finding evidence
`(address, slot, value, "re-read@post-sequence")`, so a reviewer can tell an
`Authoritative` verdict that came from the trace from one that came from current
state. Without that record the provenance of the verdict would be unauditable.

### 4.4 Binding symbols to slots

The binder maps `symbol → (address, slot)`. It is the part that cannot be derived
from an ABI alone, and it is where honesty is required.

Sources, in descending trust:

1. **Explicit manifest** (recommended): the user writes `slot` locations.
2. **Storage layout JSON** (solc `--storage-layout`): deterministic, machine-read.
3. **Verifier check against observed traces**: an LLM or heuristic proposes
   `symbol → slot`; the binder accepts it **only** if that slot appears in the
   sequence's reads or writes. A proposal for a slot the execution never touched is
   rejected, because it cannot be evidence of anything.

**Packed slots.** Solidity packs small values into one 256-bit slot. Two symbols may
share a slot at different bit offsets. The binding therefore carries a bit range:

```
Binding { address, slot, offset_bits, width_bits }
```

Without this, `bool initialized` at bit 0 and `address owner` at bits 96..256 in the
same slot would be conflated — a correctness bug that would silently invalidate every
access-control predicate. **Packed-slot support is mandatory, not a refinement.**

**Mappings and dynamic arrays.** A mapping entry's slot is
`keccak256(h(k) . p)` and cannot be enumerated. Two supported shapes:

- `sum(map[addr])` over a **known finite key set** supplied in the manifest
  (e.g. the actor set the fuzzer uses). This is the `sum(userBalances)` case (§6).
- A mapping accessed at an **observed key**: the key must appear in a `StorageRead`/
  `StorageWrite` waypoint with a derived-slot derivation
  (`Waypoint::MappingDerivation`, which already exists — `src/common/oracle/security.rs:206`
  area consumes it).

If neither holds, `sum(map)` is `UNKNOWN`. It is never `0`.

### 4.5 Deliberately unsupported

- Reading slots from *other* contracts than the bound address (delegatecall storage
  attribution is already handled upstream; the binder does not re-derive it).
- Transient storage (EIP-1153) — separate slot space, would need its own binding kind.
  Flagged as an extension, not silently omitted.
- Writing `block.timestamp` or `block.number` from a predicate. They are **read-only**
  (owner ruling, §9 item 6): a predicate may read the block environment as the
  sequence observed it, but it may never set it. Setting would let an invariant
  fabricate the very condition it checks.

---

## 5. Evaluator failure modes

Every one of these is a first-class, typed outcome. **No path panics, and no path
returns a default that could be mistaken for evidence.**

| # | condition | outcome |
|---|---|---|
| 1 | symbol unbound in the manifest | `Error::UnboundSymbol` (compile-time, before fuzzing) |
| 2 | symbol bound, slot never touched by the sequence | `Unknown` | 
| 3 | only `Stale` evidence, and the re-read also fails (§4.3) | `Unknown` — for **both** satisfaction and violation |
| 4 | division or modulo by zero | **`0`** (EVM `DIV`/`MOD`), plus `division_by_zero_observed += 1` on the finding |
| 5 | `sum` over a mapping with no enumerable key set | `Unknown` |
| 6 | `sum`/`count` over an empty key set | `0` — **explicitly not `Unknown`**, because a genuinely empty set sums to zero |
| 7 | type error (Bool used as Int, etc.) | `Error::TypeMismatch` at compile time |
| 8 | `old`/`delta` with no write at the current index | `Unknown` |
| 9 | evaluation cost exceeds the node budget | `Unknown` + a budget-exceeded counter |
| 9b | re-read (§4.3) hits the RPC budget on a cache miss | `Unknown` + `reread_budget_exhausted += 1`; never blocks or retries inline |
| 10 | unparseable predicate | `Error::Parse` with byte offset |
| 11 | 256-bit add/sub/mul overflow | **wraps** (§3 item 1); becomes a violation only when the predicate wraps operands in `requires_no_overflow(...)` |
| 12 | bit range out of bounds in a `Binding` | `Error::BadBinding` at compile time |
| 12b | `offset_bits`/`width_bits` omitted in a manifest | **`Error::BadBinding` at manifest load**, before any fuzzing. Message: `binding X: offset_bits/width_bits required (no default)` |
| 13 | `sum` over a mapping where some keys were never observed | `Unknown`, plus `unobserved_keys` **and `observed_keys` counts** in the metric, so "checked 3 keys" is distinguishable from "checked 3,000" |

### The tri-state rule

The evaluator returns `True` / `False` / `Unknown`. The campaign loop must obey:

| evaluator | finding emitted? |
|---|---|
| `False` (predicate violated) | **yes**, subject to replay + PoC |
| `True` | no |
| `Unknown` | **no** — and counted in an `unevaluable` metric reported alongside rediscovery |

`Unknown` must never be folded into either `True` or `False`. Collapsing it into
`False` invents findings; collapsing it into `True` hides them. The existing rubric in
`crates/rustyfuzz-backtest` already models exactly this distinction
(`PocOutcome::Inconclusive` is outside the numerator), and the predicate layer must
feed it rather than bypass it.

### 5.1 `Unknown` is "no signal" — the scheduler rule

Owner ruling (2026-10-25): **`Unknown` must never auto-promote to a finding OR to a
pass.** Treat it as no signal.

The scheduler today has no notion of `Unknown` at all — scoring is driven by
`CampaignScore` with no tri-state concept (`crates/rustyfuzz-engine/src/scheduler/mod.rs`).
So this has to be built, and it has three obligations:

| verdict | finding? | scheduler signal? |
|---|---|---|
| `False` (violated) | **yes** — subject to replay + PoC | strong positive |
| `True` (clean pass) | no | weak negative: the property holds here |
| `Satisfied(div0 observed)` | no | **no signal** — not a pass |
| `Unknown` | **no** | **no signal** — not a pass, not a penalty |

Concretely, `Unknown` must not:

- increment a "satisfied" or "clean" counter;
- raise a novelty or priority score;
- be recorded as evidence that a property holds;
- suppress a future evaluation of the same predicate on a later sequence.

And it must:

- be counted in the `unevaluable` metric reported alongside rediscovery;
- carry why it was unknown (`UnobservedKeys { observed, unobserved }`,
  `StaleEvidence`, `BudgetExceeded`, `NoWriteAtCurrentIndex`, …) so the gap is
  diagnosable rather than opaque.

The reason for the strictness: an `Unknown` that scores as a pass gives the search a
false reason to stop looking, which is the same failure mode as the stale-`True` the
owner rejected in §4.3 — and it is worse, because it is invisible in the report.

---

## 6. Worked example: `sum(userBalances) == totalSupply`

The invariant from the motivating case (a global accumulator not updated during a
repair path). This is the smallest example that exercises `sum`, binding, and
`old`/`delta`.

### 6.1 The predicate

```
sum(userBalances) == totalSupply
```

### 6.2 The fixture

A minimal ERC-20-like token deployed on the local-fixture path (no fork needed, so
`chain = null`, `fork_block = null`, consistent with `INCOMPLETE.md` §2):

```solidity
contract Balances {
    address[3] public users;                 // slots 0,1,2 (packed? no: address = 20 bytes, one per slot)
    uint256 public totalSupply;              // slot 3
    mapping(address => uint256) balances;    // slot 4
}
```

### 6.3 Concrete slot layout

`mapping(address => uint256)` at slot 4, key = `users[i]`:

```
slot_i = keccak256(abi.encode(users[i], uint256(4)))
```

With the actor set fixed at three addresses the fuzzer actually uses
(`0x000…A11ce`, `0x000…B0b`, `0x000…C0ol`) the binder holds three concrete keys, so
`sum` is over a **finite known key set** (§4.4).

### 6.4 The binding manifest

```json
{
  "target": "0x00000000000000000000000000000000000000aa",
  "symbols": {
    "totalSupply":   { "kind": "slot", "address": "0x…aa", "slot": "0x3",
                       "offset_bits": 0, "width_bits": 256 },
    "userBalances":  { "kind": "mapping", "address": "0x…aa", "base_slot": "0x4",
                       "key_type": "address",
                       "keys": ["0x…A11ce", "0x…B0b", "0x…C0ol"],
                       "offset_bits": 0, "width_bits": 256 }
  }
}
```

Note `offset_bits`/`width_bits` are present even where the whole slot is used: the
binder always carries a bit range, so packed and unpacked slots take the same code
path.

### 6.5 Evaluation trace

Suppose tx 0 transfers from `A11ce` to `B0b`, and tx 1 calls a `repay()` that writes
`totalSupply` but forgets the per-user balances.

| tx | slot | write? | resolution step | value |
|---|---|---|---|---|
| 0 | `balances[A11ce]` | old 100 → new 40 | 1 (write ≤ i) | 40, `Authoritative` |
| 0 | `balances[B0b]` | old 0 → new 60 | 1 (write ≤ i) | 60, `Authoritative` |
| 0 | `totalSupply` | unchanged, **read** 100 | 2 (read at i, no later write) | 100, `Authoritative` |
| 1 | `totalSupply` | old 100 → new 40 | 1 (write ≤ i) | 40, `Authoritative` |
| 1 | `balances[A11ce]` | last write at tx 0 | 3 (**re-read**) | 40, `Authoritative` |
| 1 | `balances[B0b]` | last write at tx 0 | 3 (**re-read**) | 60, `Authoritative` |
| 1 | `balances[C0ol]` | never touched | 3 (**re-read**) | 0, `Authoritative` |

At tx 1 the three balance terms land on step 3 and are **re-read from post-sequence
state**, which is `Authoritative` (§4.3). The `sum` is therefore decidable:
`40 + 60 + 0 = 100` against `totalSupply = 40` → `100 == 40` is `False` → violation.

**Note how the ruling changed this example.** The previous revision had
`balances[C0ol]` force the whole `sum` to `Unknown`, and concluded that a harness must
read every key to make the case decidable. With the re-read the harness needs no such
discipline: an untouched slot resolves to its current value. The earlier conclusion
was a consequence of the weak-evidence model, not a property worth preserving.

Each term's evidence records which step produced it, so a reviewer can distinguish
"observed in the trace" from "re-read at post-sequence", as §4.3 requires.

### 6.6 What the finding must carry

The emitted evidence must be sufficient to re-derive the result without the
evaluator: the predicate text, the resolved value of every term with its
`(address, slot, tx_index, source)`, the arithmetic, and the verdict. A finding that
says only "invariant violated" is not evidence.

Arithmetic and coverage diagnostics are part of that evidence, because each one tells
a reviewer that the predicate itself may be degenerate:

| counter | source | what a reviewer should conclude |
|---|---|---|
| `division_by_zero_observed` | §3 item 3 | the predicate divided by zero; distrust the predicate before the contract |
| `overflow_checked_sites` | §3 item 2 | how many `requires_no_overflow(...)` checks the verdict depends on |
| `overflow_violations` | §3 item 2 | `> 0` means an auditor-declared no-overflow requirement was broken |
| `observed_keys` | §9 item 4 | how many mapping keys the `sum` actually covered |
| `unobserved_keys` | §9 item 4 | how many it could not; `> 0` forces `Unknown` |

**Placement rule (owner ruling, §9 item 8):** a counter is written **only when
non-default**, but it is **always declared in the schema**. So a consumer distinguishes
"counter was zero" from "this evaluator version does not have that counter" without
guessing.

`division_by_zero_observed` additionally appears **in the human-readable finding text**,
not only in the structured blob, because it changes the verdict (`True` becomes
`Satisfied(div0 observed)`) and a reader must see why on the face of the report.

A `False` verdict with `division_by_zero_observed > 0` still stands as a violation
(§5): arithmetic degeneracy does not make a violated predicate more reliable, but it
does not erase a violation either. Its evidence carries the counter so the claim can be
challenged on sight. Same principle as `Unknown` in the tri-state rule: make the
weakness visible rather than silently correct for it.

---

## 7. How a proposal becomes trusted

Unchanged from the existing seam (`crates/rustyfuzz-core/src/proposal.rs:25 pub
struct AiProposal`, `:67 pub fn validate`, `:98 AiProposal::unvalidated(`).

```
LLM output  →  AiProposal::unvalidated(...)        (never trusted, never a finding)
            →  parse into the IR                   (syntax errors rejected here)
            →  type check                          (§3; errors rejected here)
            →  bind symbols to slots               (§4.4; unverifiable bindings rejected)
            →  deterministic replay of the sequence (§7.1)
            →  rubric: PocOutcome::Pass required for rediscovery
```

An LLM proposal that cannot be parsed, type-checked, *and bound to slots that the
execution actually touched* is discarded. It never reaches the oracle.

### 7.1 Why replay is not optional

A predicate can be wrong in a way that looks right: it may reference the wrong slot,
compare the wrong pair, or encode the wrong direction. Only replaying the exact
sequence and re-deriving the same verdict shows the artefact, not the prose, carries
the claim. This is the same rule the performance work already enforces and the rubric
already scores.

---

## 8. Per-component estimate

Assuming one engineer, no parallelisation, and the existing test suite as the gate.

| # | component | days | notes |
|---|---|---|---|
| 1 | Lexer + parser for §2, typed AST, `Error::Parse` with offsets | 2 | no external parser crate; hand-written recursive descent |
| 2 | Type checker (§3) + wrapping arithmetic + div/mod-by-zero counter | 1 | policy now decided; no blocking question |
| 3 | Binding model incl. packed bit ranges (§4.4) | 2 | the packed-slot case is where bugs hide |
| 4 | Mapping binding: finite key set + observed-key derivation | 2 | reuses `Waypoint::MappingDerivation` |
| 5 | Value resolution: 4-step + on-demand re-read (§4.2, §4.3) | 3 | re-read provenance must be recorded per slot; own tests |
| 6 | Evaluator returning tri-state + all 15 failure modes (§5) | 2 | no panics |
| 6b | `requires_no_overflow`: widened-mode re-evaluation + per-site counters | 1 | must not change the wrapping value used elsewhere (§3 item 2) |
| 7 | `InvariantOracle` trait + campaign-loop registration | 1 | additive; must not disturb existing oracles |
| 7b | `Unknown` is "no signal" in the scheduler (§5.1) | 2 | the scheduler has no tri-state today; this is new plumbing, not a flag |
| 8 | Finding evidence serialisation (§6.6) | 1 | needed for replay to be checkable |
| 9 | End-to-end fixture: false predicate fires, true predicate silent (§6) | 2 | the acceptance gate for the whole layer |
| 10 | Docs + `INCOMPLETE.md` update for unevaluable predicates | 1 | |

**Total: 20 engineer-days ≈ 2 weeks of elapsed work** with review cycles. This
matches `BRIEF_CORRECTIONS.md` correction 1 and `ROADMAP_v1.1.md` W2.

Growth over the first estimate, itemised: +1 for component 6b
(`requires_no_overflow` needs a widened re-evaluation path), +1 for component 5
(dropping `Stale` means implementing the re-read and per-slot provenance), +2 for
component 7b (`Unknown` must not score as a passing signal, and the scheduler has no
tri-state concept to hook into — `crates/rustyfuzz-engine/src/scheduler/mod.rs` has
no `Unknown` anywhere). None of these is a flag.

Components 1–7 (plus 6b) are the minimum for a single end-to-end proof; 8–10 are
required before any number is published from a predicate.

Increases over the first estimate: component 6b (+1 day) because
`requires_no_overflow` needs a second evaluation path in widened arithmetic plus two
counters in the finding evidence (§6.6); component 5 (+1 day) because dropping `Stale`
entirely means implementing the on-demand re-read and recording per-slot provenance,
rather than accepting the weaker evidence and moving on. Neither is a flag.

---

## 9. Rulings

**All items decided by owner ruling, 2026-10-25.** Nothing here blocks implementation.

| # | question | ruling |
|---|---|---|
| 1 | Overflow policy | **256-bit wrapping** for add/sub/mul, plus explicit `requires_no_overflow(expr)` |
| 2 | Division / modulo by zero | **returns `0`** (EVM), counter `division_by_zero_observed`; **non-zero counter degrades a pass** to `Satisfied(div0 observed)` |
| 3 | `Stale` reads | **`Unknown` for both** satisfaction and violation, with on-demand re-read |
| 4 | `sum` over an unobserved key | **`Unknown`** + `unevaluable` metric carrying **both `observed_keys` and `unobserved_keys`** counts. The harness is **not** required to read every key — mappings cannot be enumerated, and requiring it would make `sum` unusable |
| 5 | Bit-range omitted | **Refuse the binding, at manifest load, not at evaluation.** A predicate that only breaks mid-campaign wastes the run. Error text: `binding X: offset_bits/width_bits required (no default)` |
| 6 | `block.timestamp` in v1 | **Include, read-only.** A predicate may read it; it may not set it. Deterministic advancement by the time warp is the condition that makes this safe |
| 7 | `requires_no_overflow` naming | **Long form.** It appears in finding text a human reads, so clarity beats brevity. An alias can be added later without breaking anything |
| 8 | Counter placement | **Only when non-default, but always declared in the schema.** Consumers never guess whether a counter was omitted or unsupported |

Two items from earlier rounds that are worth restating because they are easy to
lose in implementation:

- **Division by zero must not masquerade as a clean pass.** `a / b <= X` passes when
  `b == 0`, because EVM `DIV` yields `0`. A predicate with a non-zero div0 counter
  reports `Satisfied(div0 observed)`, and that counter appears **in the finding
  text**, not in a metrics blob (§3 item 3).
- **`Unknown` is never a signal.** It must not promote to a finding, must not count
  as a pass, and must not raise scheduler priority (§5.1).

Items 3 and 4 of the original arithmetic list (rounding on `/`, `%` sign) were never
open — they are moot under an unsigned `Int` (§3).

## 10. What this document does not claim

- It does not claim the layer exists. It does not.
- It does not claim this finds bugs. It makes a class of property *expressible*; the
  bug-finding evidence still has to come from running it and reporting the result
  through the rubric.
- It does not change any existing oracle. The 10-variant enum stays as-is; the proxy
  upgrade fix from this session is independent of it.
