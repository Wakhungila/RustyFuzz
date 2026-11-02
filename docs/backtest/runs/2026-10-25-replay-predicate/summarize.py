"""Regenerate the gate report from the retained validation outputs."""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
measurement = json.loads((ROOT / "measurement.json").read_text())
cases = []
for group in ("known_vulnerable", "historical"):
    source = f"validate_{group}.json"
    report = json.loads((ROOT / source).read_text())
    for result in report["benchmarks"]:
        proof = result.get("proof")
        has_predicate = proof.get("violation_predicate") is not None if proof else None
        generated = result["foundry_poc_generated"]
        # No PoC exists in this run. Do not infer validation success from an
        # environment opt-in or a fixture's foundry_poc_generated expectation.
        assert not generated, "A generated PoC needs its validation result inspected"
        unsupported = "provider_replay_only is unsupported" in result["reason"]
        if group == "known_vulnerable":
            assert proof and not has_predicate, "Revisit the missing-predicate diagnosis"
            assert not proof["original_state_violation_verified"]
        else:
            assert unsupported and proof is None, "Revisit the historical replay diagnosis"
        cases.append({
            "case_id": result["benchmark_id"],
            "source": source,
            "scope": "expectation_only_fixture" if group == "known_vulnerable" else "historical_replay_blocked",
            "validator_status": result["status"],
            "validator_executed": result["executed"],
            "evm_sequence_executed": False,
            "reason": result["reason"],
            "predicate_available": has_predicate,
            "original_state_violation_verified": proof["original_state_violation_verified"] if proof else None,
            "original_state_verification_attempted": False,
            "confirmation_tier": proof["confidence_tier"] if proof else None,
            "confirmed": bool(has_predicate and proof["confidence_tier"] == "confirmed") if proof else None,
            "recorded_replay_result": proof["replay_result"] if proof else None,
            "poc_generated": generated,
            "poc_validation": "not_attempted",
            "first_blocker": "predicate_unavailable" if proof else "unsupported_provider_replay_only",
            "missing_criteria": result["missing_criteria"],
        })

# This summary describes this retained seven-case run. If its inputs change,
# require a fresh diagnosis instead of retaining the prose conclusions below.
assert len(cases) == 7
assert sum(c["scope"] == "expectation_only_fixture" for c in cases) == 5
assert all(c["validator_status"] == "not_found" for c in cases if c["scope"] == "expectation_only_fixture")
assert all(c["validator_status"] == "failed_execution" for c in cases if c["scope"] == "historical_replay_blocked")
aggregate = json.loads((ROOT / "baseline_report.json").read_text())["report"]
assert (aggregate["rediscovered"], aggregate["missed"], aggregate["inconclusive"]) == (0, 5, 2)
assert {c["case_id"] for c in aggregate["cases"]} == {c["case_id"] for c in cases}

decision = {
    "priority": "benchmark_proof_path",
    "reason": "All five fixture proofs lack predicates; neither historical EVM replay executes. No original-state predicate replay was attempted, so neither search quality nor PoC compatibility was measured.",
    "next_implementation": "Connect authored predicates and binding manifests to stateful executable benchmark replay, preserve their evidence on candidates, and run original-state verification before confirmation. Supply verified replay material for historical fixtures; keep legacy expectation fixtures explicitly synthetic.",
    "acceptance": [
        "An existing executable vulnerable control reaches predicate evaluation and original-state replay; its safe counterpart does not confirm.",
        "Recorded violating terms with a satisfied fresh replay are rejected.",
        "Confirmation tier is assigned from actual gate evaluation, never from a fixture expectation.",
        "PoC generation and validation are reported separately, with not-attempted distinct from failure.",
    ],
    "deferred": ["action grammar until executable search is measured", "target-suite PoCs until proof confirmation is reached", "Z3 pending explicit owner approval"],
}
output = {"schema_version": 1, "measurement": "measurement.json", "cases": cases, "decision": decision}
(ROOT / "gates.json").write_text(json.dumps(output, indent=2) + "\n")

lines = [
    "# Baseline rerun after predicate replay verification",
    "",
    f"Measured 2026-10-25 (Africa/Nairobi), runtime commit `{measurement['runtime_commit']}`.",
    "The RPC answered as Ethereum mainnet and returned pinned block 15201793 with the hash in [measurement.json](measurement.json). The repository config was left untouched; a temporary config used this verified block instead of the unreachable root pin.",
    "",
    "The seven-case rubric remains **0 rediscovered, 5 misses against fixture expectations, 2 inconclusive historical cases**. These are not five failed on-chain rediscoveries. Raw outputs and provenance are retained beside this report; the aggregate is in [baseline_report.json](baseline_report.json).",
    "",
    "## Five expectation-only fixtures",
    "",
    "The validator reconstructs synthetic observations from the fixture descriptions. Its `executed: true`, recorded replay success, and signal timing/counts do not measure EVM execution or fuzz-search performance. In particular, the source fixture's `foundry_poc_generated: true` is an expectation, not an observed PoC.",
    "",
    "| Case | Predicate | Original-state check | Tier | PoC generation | PoC validation |",
    "|---|---|---|---|---|---|",
]
for case in cases:
    if case["scope"] == "expectation_only_fixture":
        lines.append(f"| `{case['case_id']}` | absent | not attempted; verified=false | `{case['confirmation_tier']}` | not reached | not attempted |")
lines += [
    "",
    "All five have `replay_result: verified` for reconstructed observations and lack a typed `violation_predicate`. They therefore cannot verify the original-state violation or become confirmed. Their only missing named success criterion is `foundry_poc_generated`, but the first blocker is predicate availability. The generic runner reason mentioning replay failure must not be read as an attempted original-state replay rejection.",
    "",
    "## Historical cases",
    "",
    "| Case | First blocker | Predicate / original-state check / tier | PoC generation / validation |",
    "|---|---|---|---|",
]
for case in cases:
    if case["scope"] == "historical_replay_blocked":
        lines.append(f"| `{case['case_id']}` | unsupported `provider_replay_only` | not reached / not attempted / unavailable | not reached / not attempted |")
lines += [
    "",
    "Neither historical sequence executed. Independent provider calls cannot establish committed state across a transaction sequence; the runner rejects this fixture mode. The raw failure results use `SyntheticRegression` as a fallback evidence class, which does not describe historical execution. The historical manifests and explicit execution failure determine the scope here.",
    "",
    "## Implementation decision",
    "",
    "**Finish the benchmark proof path first.** This measurement establishes missing predicate construction and unsupported replay setup, rather than a failed invariant replay, a failed target-suite PoC, or a search-grammar miss.",
    "",
    decision["next_implementation"],
    "",
    "Acceptance checks:",
    "",
] + [f"- {item}" for item in decision["acceptance"]] + [
    "",
    "The local fixture path in `src/engine/benchmark.rs::execute_local_fixture` builds proofs from synthetic observations and calls `verify_against`; it neither loads the invariant registry nor calls `verify_original_state`. Adding invariant checking to the campaign therefore cannot change these five fixture results. The `ExecutableEvm` branch currently records matching signals without building a proof. That is the integration seam to address; declarations in a fixture must not be promoted into proof.",
    "",
    "Action grammar and target-suite PoCs remain downstream. Z3 remains disabled pending explicit owner approval.",
    "",
    "## Reproduction",
    "",
    "Use the configured RPC with `RUSTYFUZZ_RPC_API_KEY` unset and the allowed origin recorded in `measurement.json`. In a temporary copy of the root config, set `fork_block = 15201793`; keep endpoint credentials out of reports. Build the dev binary with the single-job/debug-disabled environment from the handoff, then run the two validate commands listed in `measurement.json` with absolute repository paths. `RUSTYFUZZ_RUN_FORGE_TESTS=1` was set; no PoC reached validation.",
    "",
    "Regenerate the aggregate with the retained validation files using `cargo run --offline --locked -p rustyfuzz-backtest --bin baseline_report -- <historical.json> <known_vulnerable.json> <baseline_report.json>`, setting `GIT_COMMIT_HASH` and `GIT_WORKING_TREE` to the measured source identity. Regenerate this gate analysis with `python3 docs/backtest/runs/2026-10-25-replay-predicate/summarize.py`.",
]
(ROOT / "GATES.md").write_text("\n".join(lines) + "\n")
print(f"Wrote gates.json and GATES.md for {len(cases)} cases")
