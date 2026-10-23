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

The counter is diagnostic only. It does not by itself downgrade, suppress, or promote
a finding — the tri-state rule (§5) is unchanged, and a `False` verdict still stands
as a violation. What it does is make the degenerate case *legible*: a reviewer
looking at a finding with `division_by_zero_observed > 0` knows to distrust the
predicate before distrusting the contract.

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
- Slots whose value depends on `block.timestamp` at evaluation time (time warp).
  The evaluator reads what the sequence produced, not what the clock says.

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

Two arithmetic diagnostics are part of that evidence, because both indicate the
predicate itself may be degenerate or may be asserting overflow intent:

| counter | source | what a reviewer should conclude |
|---|---|---|
| `division_by_zero_observed` | §3 item 3 | the predicate divided by zero; distrust the predicate before the contract |
| `overflow_checked_sites` | §3 item 2 | how many `requires_no_overflow(...)` checks the verdict depends on |
| `overflow_violations` | §3 item 2 | `> 0` means an auditor-declared no-overflow requirement was broken |

A `False` verdict with `division_by_zero_observed > 0` is still reported as a
violation per §5, but its evidence must show the counter so the claim can be
challenged on sight. This is the same principle as `UNKNOWN` in the tri-state rule:
make the weakness visible rather than silently correct for it.

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
| 6 | Evaluator returning tri-state + all 12 failure modes (§5) | 2 | no panics |
| 6b | `requires_no_overflow`: widened-mode re-evaluation + per-site counters | 1 | must not change the wrapping value used elsewhere (§3 item 2) |
| 7 | `InvariantOracle` trait + campaign-loop registration | 1 | additive; must not disturb existing oracles |
| 8 | Finding evidence serialisation (§6.6) | 1 | needed for replay to be checkable |
| 9 | End-to-end fixture: false predicate fires, true predicate silent (§6) | 2 | the acceptance gate for the whole layer |
| 10 | Docs + `INCOMPLETE.md` update for unevaluable predicates | 1 | |

**Total: 18 engineer-days ≈ 1–2 weeks of elapsed work** with review cycles. This
matches `BRIEF_CORRECTIONS.md` correction 1 and `ROADMAP_v1.1.md` W2.

Components 1–7 (plus 6b) are the minimum for a single end-to-end proof; 8–10 are
required before any number is published from a predicate.

Increases over the first estimate: component 6b (+1 day) because
`requires_no_overflow` needs a second evaluation path in widened arithmetic plus two
counters in the finding evidence (§6.6); component 5 (+1 day) because dropping `Stale`
entirely means implementing the on-demand re-read and recording per-slot provenance,
rather than accepting the weaker evidence and moving on. Neither is a flag.

---

## 9. Open questions for owner review

These block implementation and should be answered before code is written:

**Answered by owner ruling (2026-10-23):**

1. ~~**Overflow policy (§3)**~~ → **DECIDED: 256-bit wrapping**, with an explicit
   `requires_no_overflow(expr)` operator for auditors who want overflow itself to be
   the finding. Rationale: a predicate models contract semantics; checked arithmetic
   would suppress real findings wherever a contract wraps intentionally.
2. ~~**Division / modulo by zero (§3, §5 item 4)**~~ → **DECIDED: returns `0`**
   (EVM-faithful), accompanied by a `division_by_zero_observed` counter on the
   finding so a mis-specified predicate is visible rather than silently handled.
3. ~~**`Stale` reads (§4.3)**~~ → **DECIDED: `Unknown` for both satisfaction and
   violation.** The agent's proposal to allow stale evidence for satisfaction only was
   rejected: a stale `True` is as dangerous as a stale `False`, because it makes the
   search stop looking. The fix is the on-demand re-read in §4.3 (a cached hash
   lookup, not a network call), not a looser evidence model.

Items 3 and 4 of the original list (rounding on `/`, `%` sign) are **not open** —
they are moot under an unsigned `Int` and are explained in §3.

**Still open, needing a ruling before implementation** (referenced by name, not
number, so this list cannot drift out of sync with §3):

- **`sum` over an unobserved key (§5 item 5):** is `Unknown` acceptable, or should
  the harness be *required* to read every key before a `sum` is allowed at all?
  *Recommendation: `Unknown`, with an `unevaluable` metric so the gap is visible.*
- **Bit-range default:** when a manifest omits `offset_bits`/`width_bits`, default to
  the full slot, or refuse the binding? *Recommendation: refuse — silence about
  packing is how access-control predicates break.*
- **Scope of `block.timestamp`:** include it (§2 grammar) given that the time warp
  already advances it deterministically, or leave it out of v1? *Recommendation:
  include; it is already deterministic and several classes need it.*
- **`requires_no_overflow` naming:** keep the long form, or alias it to a shorter
  operator (e.g. `no_ovf(...)`)? It appears in every finding that uses it, so the
  name is part of the report a human reads. *Recommendation: keep the long form —
  the finding text should be self-explanatory without a legend.*
- **Counter placement (§6.6):** are `division_by_zero_observed`,
  `overflow_checked_sites` and `overflow_violations` carried on every finding, or only
  when non-default? *Recommendation: only when non-default, but always present in the
  serialised schema so a consumer never guesses.*

---

## 10. What this document does not claim

- It does not claim the layer exists. It does not.
- It does not claim this finds bugs. It makes a class of property *expressible*; the
  bug-finding evidence still has to come from running it and reporting the result
  through the rubric.
- It does not change any existing oracle. The 10-variant enum stays as-is; the proxy
  upgrade fix from this session is independent of it.
