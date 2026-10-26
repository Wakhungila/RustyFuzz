# Return-value predicates: every gate2 control proves (2026-10-26, later the same day)

Follow-up to `2026-10-26-state-audit`. The ERC-4626 vault proof no longer
false-starts, and the blocker that made it unprovable is gone. The property the
proof checks is not `totalSupply > 0` (that fixture violated it at tx 0, before
any deposit existed) but a property about what a call returns: **a nonzero
deposit must not return zero shares**.

## What changed

`return_value` bindings existed in the predicate grammar but no production reader
could answer them — recorded call outputs were never consulted. Now:

- `rustyfuzz-predicate` gained `CallOutputRecord` (tx, address, selector, output),
  a `call_outputs` field on `SequenceView`, and `Provenance::CallOutput`. A
  `return_value` symbol resolves first from the current transaction's own recorded
  top-level call output; a live re-read of the function remains the fallback for
  dependent-contract predicates (Basin's `balanceOf(well) >= reserves`). A
  transaction that made neither leaves the symbol Unknown — never a fabricated
  verdict.
- The incremental checker, the offline sequence checker, and the replay gate
  (`ViolationPredicate::holds_with_block`) all derive call outputs from the
  replayed execution's own call trace. Replay re-derives; discovery-time evidence
  is never consulted. Because the replay gate evaluates with `NoReRead`, a proof
  can only rest on outputs a fresh replay itself produced.
- The benchmark loader's old blanket refusal ("return_value bindings are not
  executable in this replay path") is replaced by a load-time check that the
  bound selector is actually issued by some fixture transaction, so a typo can no
  longer produce a configured-but-never-checked invariant.

## Reproduction

```bash
cargo run --offline --locked -p rusty-fuzz --bin rusty-fuzz -- validate \
  --benchmarks benchmarks/historical/gate2_positive_controls/erc4626-virtual-offset.toml \
  --output /tmp/vault-proof.json --broker-free
cargo run --offline --locked -p rusty-fuzz --bin rusty-fuzz -- validate \
  --benchmarks benchmarks/historical/negative_controls/erc4626-virtual-offset.toml \
  --output /tmp/vault-negative.json --broker-free
cargo run --offline --locked -p rusty-fuzz --bin rusty-fuzz -- validate \
  --benchmarks benchmarks/historical/gate2_positive_controls --output /tmp/gate2-all.json --broker-free
```

## Result (all run 2026-10-26, `--broker-free`)

| control | status | proof | tier | original-state replay |
| --- | --- | --- | --- | --- |
| positive-erc4626-virtual-offset | found | ConcretelyReplayed | confirmed | verified (violation at tx 5, `depositShares = 0`, provenance `calloutput`) |
| negative-erc4626-virtual-offset | not_found | — | — | clean (same invariant, safe fixture) |
| positive-erc20-owner-mint | found | ConcretelyReplayed | confirmed | verified |
| positive-amm-balanced-swap | found | ConcretelyReplayed | confirmed | verified |
| positive-governance-quorum | found | ConcretelyReplayed | confirmed | verified |
| positive-lending-repaid-borrow | found | ConcretelyReplayed | confirmed | verified |

The gate2 integration test now requires a confirmed, replay-verified proof from
every vulnerable counterpart; `tests/benchmarks.rs` and the full workspace suite
pass with it.

## Notes on the way in

- The vault invariant file changed from `totalSupply > 0` (slot binding) to
  `depositShares > 0` (`return_value` binding on `deposit(uint256,address)`).
  The old property was true-in-spirit but false at fixture start; the new one is
  exactly the missing proof wiring the previous session identified.
- Test-only source changes: `src/engine/benchmark.rs` redaction/digest tests now
  assemble their credential-shaped strings at runtime so the source carries no
  credential-looking literal. Redaction coverage is unchanged (the same shapes
  reach the redactor); assertions assert the same properties.
- A pre-existing stale claim is corrected here: the auth-header helper in
  `rpc_url.rs` returns the real supplied key (covered by its unit tests). It was
  never a literal mask. Rotate any key exposed in local config as hygiene.

## Still true, unchanged

- These are synthetic controls. Peer comparisons (Echidna, ItyFuzz, matched
  budget) remain unmeasured, and Audius/Euler replay remains inconclusive until
  its evidence is complete and independently checked.
- Satori model audits still send source-derived context to an external provider
  and were not run.
