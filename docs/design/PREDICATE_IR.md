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

---

## 3. Types

Three sorts only.

| sort | literals | operators | notes |
|---|---|---|---|
| `Int` | `0`, `42`, `0x…` | `+ - * / %`, comparisons | **256-bit unsigned**, matching EVM words |
| `Bool` | `true`, `false` | `&& \|\| !`, comparisons | result of a predicate |
| `Slot` | — | only via `old`/`delta`/`sum`/`count` | not first-class in arithmetic |

### Arithmetic semantics (must be pinned before implementation)

The single most likely source of silent divergence from a target's own behaviour is
arithmetic. Decide and document:

1. **Width**: 256-bit wrapping, or checked with overflow → `Unknown`? *Recommendation:
   wrapping, matching the EVM*, because the target's Solidity would also wrap in an
   `unchecked` block and a predicate must not disagree with the contract it audits.
2. **Division by zero**: *Recommendation:* `Unknown`, never `0` and never `TRUE`.
   Silently returning a value would fabricate evidence.
3. **Rounding on `/`**: truncating toward zero (EVM `DIV`), not floor. These differ
   for negatives; the target has no negatives, so this only matters for the `-`
   operator.
4. **`%` sign**: EVM `MOD` on unsigned values — no sign ambiguity.

**Open question for review:** whether overflow should be `Unknown` (strict, may
suppress real findings) or wrapped (permissive, may match the target). This is a
genuine trade-off and the owner should choose it.

---

## 4. Storage-slot evaluation model

### 4.1 The hard constraint that shapes everything

`SequenceExecutionResult` carries:

- `storage_diffs: Vec<StorageDiff>` — committed writes with `old_value`,
  `new_value`, `slot`, `address`, `tx_index`;
- `storage_reads: Vec<StorageAccess>` — loads actually performed, with `value`.

It does **not** carry a state snapshot. FACTS.md §C5 records this from the proxy
oracle's side; it is structural, not incidental. Therefore:

> **A predicate can only be evaluated over slots the sequence actually read or wrote.
> A predicate referencing a slot that was never touched is UNEVALUABLE — not TRUE,
> not FALSE.**

This is the central design constraint and the main source of `Unknown` results.

### 4.2 Value resolution for a symbol at transaction index `i`

For a symbol bound to `(address, slot)`:

```
if a write to (address, slot) exists at tx_index <= i:
    value = the new_value of the LATEST such write
else if a read of (address, slot) exists at tx_index == i:
    value = that read's value
else if a read exists at any tx_index <= i:
    value = the latest such read's value      # weaker evidence; see 4.3
else:
    UNKNOWN
```

`old(sym)` resolves to the `old_value` of the write at index `i`; if there is no
write at `i`, `old` is `UNKNOWN` (there is no transition to speak of).
`delta(sym)` is `new - old`, hence `UNKNOWN` whenever either side is.

### 4.3 Evidence strength — a distinction that must not be erased

A value known from a **write** is authoritative: the sequence stored it.
A value known from a **read** is a point-in-time observation: the slot may have
changed between the read and the moment the predicate is checked.

Therefore each resolution carries a confidence:

| source | confidence | usable for a violation claim? |
|---|---|---|
| write at or before `i` | `Authoritative` | yes |
| read at exactly `i` | `Observed` | yes |
| read before `i` | `Stale` | **no** — yields `Unknown` for a *violation*, may be used for a *satisfaction* |

`Stale` is deliberately asymmetric: a stale value must never be used to claim a bug
(the value may have moved), but using one to say "this looked fine" is harmless
because the default is already not-a-finding. Absence of proof is never proof.

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
| 3 | only `Stale` evidence available for a violation | `Unknown` |
| 4 | division or modulo by zero | `Unknown` |
| 5 | `sum` over a mapping with no enumerable key set | `Unknown` |
| 6 | `sum`/`count` over an empty key set | `0` — **explicitly not `Unknown`**, because a genuinely empty set sums to zero |
| 7 | type error (Bool used as Int, etc.) | `Error::TypeMismatch` at compile time |
| 8 | `old`/`delta` with no write at the current index | `Unknown` |
| 9 | evaluation cost exceeds the node budget | `Unknown` + a budget-exceeded counter |
| 10 | unparseable predicate | `Error::Parse` with byte offset |
| 11 | 256-bit multiplication overflow | per §3 decision (wrapping or `Unknown`) |
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

| tx | slot | write? | resolved value |
|---|---|---|---|
| 0 | `balances[A11ce]` | old 100 → new 40 | 40 |
| 0 | `balances[B0b]` | old 0 → new 60 | 60 |
| 0 | `totalSupply` | unchanged, **read** 100 | 100 (Observed) |
| 1 | `totalSupply` | old 100 → new 40 | 40 |
| 1 | `balances[*]` | **never touched** | `Stale`/`Unknown` |

At tx 1: `sum(userBalances)` resolves `balances[A11ce]` from a tx-0 write (40),
`balances[B0b]` from a tx-0 write (60), `balances[C0ol]` → never touched → the whole
`sum` is `Unknown`.

**This is the correct outcome and it is also the limitation made visible:** the
predicate cannot claim a violation at tx 1 because one term is unobserved. To make
the case decidable, the harness must read all three balances at tx 1 (which a real
handler would do when checking the invariant). The design therefore forces the
harness to observe what it claims — a property worth having.

If all three *are* read at tx 1 (40 + 60 + 0) and `totalSupply` is 40, then
`100 == 40` is `False` → violation, with per-term evidence recorded.

### 6.6 What the finding must carry

The emitted evidence must be sufficient to re-derive the result without the
evaluator: the predicate text, the resolved value of every term with its
`(address, slot, tx_index, source)`, the arithmetic, and the verdict. A finding that
says only "invariant violated" is not evidence.

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
| 2 | Type checker (§3) + arithmetic decision + overflow policy | 1 | blocks on the open question in §3 |
| 3 | Binding model incl. packed bit ranges (§4.4) | 2 | the packed-slot case is where bugs hide |
| 4 | Mapping binding: finite key set + observed-key derivation | 2 | reuses `Waypoint::MappingDerivation` |
| 5 | Value resolution with evidence strength (§4.2, §4.3) | 2 | the `Stale` asymmetry is subtle; needs its own tests |
| 6 | Evaluator returning tri-state + all 12 failure modes (§5) | 2 | no panics |
| 7 | `InvariantOracle` trait + campaign-loop registration | 1 | additive; must not disturb existing oracles |
| 8 | Finding evidence serialisation (§6.6) | 1 | needed for replay to be checkable |
| 9 | End-to-end fixture: false predicate fires, true predicate silent (§6) | 2 | the acceptance gate for the whole layer |
| 10 | Docs + `INCOMPLETE.md` update for unevaluable predicates | 1 | |

**Total: 16 engineer-days ≈ 1–2 weeks of elapsed work** with review cycles. This
matches `BRIEF_CORRECTIONS.md` correction 1 and `ROADMAP_v1.1.md` W2.

Components 1–7 are the minimum for a single end-to-end proof; 8–10 are required
before any number is published from a predicate.

---

## 9. Open questions for owner review

These block implementation and should be answered before code is written:

1. **Overflow policy (§3):** 256-bit wrapping (matches EVM, may match the target) or
   checked → `Unknown` (strict, may suppress findings)? *Recommendation: wrapping.*
2. **`Stale` reads (§4.3):** accept them for *satisfaction* only, as proposed, or
   reject them entirely? *Recommendation: as proposed.*
3. **`sum` over an unobserved key (§5 item 5):** is `Unknown` acceptable, or should
   the harness be *required* to read every key before a `sum` is allowed at all?
   *Recommendation: `Unknown`, with an `unevaluable` metric so the gap is visible.*
4. **Bit-range default:** when a manifest omits `offset_bits`/`width_bits`, default to
   the full slot, or refuse the binding? *Recommendation: refuse — silence about
   packing is how access-control predicates break.*
5. **Scope of `block.timestamp`:** include it (§2 grammar) given that the time warp
   already advances it deterministically, or leave it out of v1? *Recommendation:
   include; it is already deterministic and several classes need it.*

---

## 10. What this document does not claim

- It does not claim the layer exists. It does not.
- It does not claim this finds bugs. It makes a class of property *expressible*; the
  bug-finding evidence still has to come from running it and reporting the result
  through the rubric.
- It does not change any existing oracle. The 10-variant enum stays as-is; the proxy
  upgrade fix from this session is independent of it.
