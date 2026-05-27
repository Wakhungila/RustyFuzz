# Satori

Satori is RustyFuzz's AI-guided semantic audit harness. It ingests a smart-contract repository, builds deterministic protocol context, selects critical functions, asks OpenAI `o3` for bounded hypotheses, converts useful hypotheses into RustyFuzz job JSON and Foundry PoC scaffolds, and emits reports that clearly separate hypotheses from validated findings.

## What Satori Is

- A repo modeling, packetization, and audit-control layer for RustyFuzz.
- A compact-context `o3` client behind the `llm` feature.
- A deterministic artifact generator for jobs, PoC scaffolds, memory, and reports.
- A safety gate: model output is treated as hypothesis until local evidence exists.

## What Satori Is Not

- It is not live exploit automation.
- It does not broadcast transactions.
- It does not use private keys.
- It does not mark hypotheses as findings without local replay, Foundry, or RustyFuzz evidence.

## Safety Model

`o3` proposes hypotheses. RustyFuzz, Foundry, local fixtures, and fork-safe replay decide truth. If a path requires live execution or missing target data, Satori marks it `NeedsMoreContext` or `PlausibleUnvalidated`, not confirmed.

## Commands

No LLM:

```bash
cargo run -- satori ingest ./protocol
cargo run -- satori graph ./protocol
cargo run -- satori packets ./protocol --max-critical-functions 8
```

With `o3`:

```bash
export OPENAI_API_KEY="..."

cargo run --features llm -- satori audit ./protocol \
  --model o3 \
  --max-critical-functions 8 \
  --max-hypotheses-per-function 2 \
  --min-confidence 0.40 \
  --validate true \
  --generate-jobs true
```

Report:

```bash
cargo run -- satori report <run_id>
```

## Artifact Layout

```text
satori/runs/<run_id>/
  run.json
  project.json
  static_analysis.json
  critical_functions.json
  graph.json
  packets/
  hypotheses.json
  jobs/
  jobs.json
  foundry_poc/
  foundry_pocs.json
  validation_verdicts.json
  report.json
  report.md

satori/cache/
satori/memory/events.jsonl
satori/reports/latest.md
```

## Verdict Statuses

- `NeedsMoreContext`: Missing ABI, address, fork, concrete target bindings, or local fixture state.
- `PlausibleUnvalidated`: Hypothesis exists but no deterministic evidence exists.
- `JobGenerated`: RustyFuzz job JSON was produced.
- `FoundryPocGenerated`: Foundry scaffold was produced; this is not proof.
- `FoundryCompiled`: Generated test compiled locally.
- `FoundryTestSignal`: Foundry produced a relevant local test signal.
- `RustyFuzzSignal`: RustyFuzz produced a relevant local signal.
- `ValidatedLocal`: Deterministic local evidence supports the hypothesis.
- `ValidatedMinimized`: A minimized local sequence still supports the hypothesis.
- `ValidatedEconomicImpact`: Replay/minimization plus economic evidence supports the issue.

## Current Validation Path

Satori v1 generates RustyFuzz job specs and Foundry scaffolds. It inspects whether concrete replay context exists and reports missing context explicitly. It does not call a full RustyFuzz campaign adapter yet; that is the next integration step.

## How To Wire Jobs Into RustyFuzz

Use the generated `satori/runs/<run_id>/jobs/*.rustyfuzz.json` as a machine-readable plan. Each job includes actor roles, sequence template, mutation focus, invariants, objective, success condition, and fork hints when available.

## Limitations

- Static extraction is layered but still heuristic when Slither/Foundry artifacts are unavailable.
- The o3 API path requires `--features llm` and `OPENAI_API_KEY`.
- Foundry scaffolds may need manual contract bindings before they compile.
- Direct RustyFuzz campaign execution from job JSON is planned but not fully wired in v1.

## Next Steps

1. Add a direct RustyFuzz campaign adapter for `RustyFuzzJobSpec`.
2. Replace more source heuristics with Slither or compiler AST data.
3. Add SQLite memory after JSONL proves useful.
4. Expand deterministic DeFi detectors for ERC4626, lending, AMM, governance, bridge, and upgradeability.
5. Benchmark Satori on historical fixtures and track time-to-signal, cost-to-signal, false positives, and validated findings.
