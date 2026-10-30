# Phase 0.3 — PoC gate investigation

Recorded 2026-10-25. This closes out the plan item "re-run the 7-case baseline with
the PoC gate open" and reports what it actually revealed. **The gate was not the
blocker.** My earlier reading of the baseline was wrong, and the corrected
diagnosis is below.

## What I claimed before, and why it was wrong

`BASELINE_REPORT.md` said, and I repeated:

> 5 of 7 cases fail on `missing=[FoundryPocGenerated]` because the gate is off by
> default (`promotion.rs:101`).

The first half is right — that is literally what the criterion says. The causal
half is wrong. `external_foundry_opt_in` controls **PoC validation**, not PoC
**generation**. Generation is gated by a different condition entirely:

```rust
// src/engine/benchmark.rs:1769-1775
        if observation
            .proof
            .as_ref()
            .is_some_and(|proof| proof.confidence_is_confirmed())
            && !observation.findings.is_empty()
            && manifest.poc_generation != PocGenerationExpectation::NotRequired
        {
            let poc_path = synthesize_local_validation_poc(...)
```

and

```rust
// src/engine/proof.rs:260-262
    pub fn confidence_is_confirmed(&self) -> bool {
        self.violation_predicate.is_some() && self.confidence_tier == ProofConfidenceTier::Confirmed
    }
```

So a PoC is synthesised only when the finding already has **a typed violation
predicate AND Confirmed tier**. Without those, no PoC is attempted, therefore
`FoundryPocGenerated` is false, therefore the case fails. Opening
`RUSTYFUZZ_RUN_FORGE_TESTS` cannot change that: it is downstream, and was never
reached.

## The re-run

```
$ env -u RUSTYFUZZ_RPC_API_KEY RUSTYFUZZ_RUN_FORGE_TESTS=1 \
    RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS=https://eth-mainnet.g.alchemy.com \
    rusty-fuzz validate --benchmarks benchmarks/historical/known_vulnerable \
      --output /tmp/rf-bt/validate_kv_forge.json

Validation report written: /tmp/rf-bt/validate_kv_forge.json
  (benchmarks=5, executed=5, found=0, not_found=5, not_run=0)
```

Identical to the run with the gate closed. Per-case proof state:

```
known-bridge-nonce-replay           pred=None  tier=replayed_minimized  orig_verified=False  poc=None
known-erc20-bad-mint-inflation      pred=None  tier=replayed_minimized  orig_verified=False  poc=None
known-flashloan-price-manipulation  pred=None  tier=replayed_minimized  orig_verified=False  poc=None
known-read-only-reentrancy          pred=None  tier=replayed_minimized  orig_verified=False  poc=None
known-uninitialized-proxy-takeover  pred=None  tier=replayed_minimized  orig_verified=False  poc=None
```

Every case: `violation_predicate: None`, `original_state_violation_verified: false`,
`confidence_tier: replayed_minimized`, `foundry_poc_path: None`.

Failure kind for all five: `RealismProofFailure`.

## Root cause, precisely

The confirmation gate (`src/engine/confirmation.rs:55-118`) raises a finding to
`Confirmed` only when every condition holds. For these five cases, three fail:

| condition | source | status |
|---|---|---|
| replay success | `confirmation.rs:61` | **passes** — `replay_result: verified` |
| minimized path | `confirmation.rs:63` | **passes** — `minimization_result: Minimized` |
| typed violation predicate | `confirmation.rs:68` | **fails** — `violation_predicate: None` |
| original-state verification | `confirmation.rs:69` | **fails** — `original_state_violation_verified: false` |
| Foundry PoC path | `confirmation.rs:71-72` | **fails** — `foundry_poc_path: None` |

The dependency is circular, and that is the real finding:

```
no typed predicate  ->  not Confirmed  ->  no PoC synthesised
                    ->  FoundryPocGenerated false  ->  case fails
                    ->  (and the PoC was the thing that would have supplied evidence)
```

`Confirmation` requires a PoC path (`protocol_specific_assertion`, line 71-72), and
PoC generation requires `Confirmation` (benchmark.rs:1772). Neither can bootstrap
the other.

## Why this matters more than the flag

The oracles *do* fire. Each case reaches `ExpectedFinding` and `InvariantViolation`
and `ReplayableArtifact` and `MinimizedPath`, and the proof records real
`storage_diffs` and `call_trace`. What is missing is the thing that turns an emitted
finding into evidence: a **typed violation predicate** — a machine-checkable
statement of what was violated.

That is exactly the gap `docs/design/PREDICATE_IR.md` addresses, and it means the
`0.714` false-positive rate is a *predicate* artefact, not an oracle artefact. The
oracles are better than the number suggests; the evidence layer beneath them is
missing.

## What I did not do

- Did not change the gate default. Flipping `external_foundry_opt_in` to `true`
  would have been a no-op here, and turning it on globally would run `forge`
  (an external process) on every promotion by default.
- Did not loosen `confidence_is_confirmed`. Removing the predicate requirement
  would make PoCs generate against unproven findings, which is the opposite of the
  evidence discipline this branch exists to enforce.
- Did not fabricate a predicate to make the five cases pass.

## Consequence for the plan

Phase 0.3 is **closed as investigated, not as fixed**. The fix is not a flag; it is
Phase 1 (typed predicates). Ordering changes:

- Phase 1 is now on the critical path for *any* non-zero rediscovery number, not
  just for Ehsan-class invariants.
- The `BASELINE_REPORT` numbers stand as published. They are honest: 0/7, with the
  cause now documented rather than attributed to a misconfigured flag.

## Reproduce

```bash
cd /tmp/rf-bt   # any dir with a config.toml whose fork_block is reachable
env -u RUSTYFUZZ_RPC_API_KEY \
    RUSTYFUZZ_RUN_FORGE_TESTS=1 \
    RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS=https://eth-mainnet.g.alchemy.com \
    rusty-fuzz validate \
      --benchmarks /path/to/RustyFuzz/benchmarks/historical/known_vulnerable \
      --output /tmp/rf-bt/validate_kv_forge.json

python3 -c 'import json; d=json.load(open("/tmp/rf-bt/validate_kv_forge.json")); \
  [print(b["benchmark_id"], (b.get("proof") or {}).get("violation_predicate")) for b in d["benchmarks"]]'
```
