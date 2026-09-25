---
title: "Finding lifecycle"
section: "Core concepts"
nav_order: 5
description: "Understand the evidence behind a result before deciding whether it is reportable."
---

## From signal to proof

```text
Signal → Candidate → Replayed → Minimized → Proved
             └──────── rejection from intermediate stages ───────→ Rejected
```

The canonical lifecycle is defined in `rustyfuzz-core`. Promotion also retains compatibility stages such as `PocGenerated` and `Confirmed`: generated PoCs map to the minimized stage, while confirmed promotion maps to proved.

| Stage | What it establishes |
|---|---|
| Signal | An oracle or analysis produced an observation |
| Candidate | The observation has been selected for investigation |
| Replayed | The input reproduced under the required replay conditions |
| Minimized | Reduction preserved the finding predicate |
| Proved | The configured deterministic validation policy succeeded |
| Rejected | An intermediate validation or evidence requirement failed |

“Proved” is scoped to that policy and recorded environment. It is not a mathematical proof of every security claim about a protocol.

## Replay a retained input

```bash
rusty-fuzz replay --input "$INPUT_ID"
```

Use `--fork-cache-id "$CACHE_ID"` when selecting a specific cache. `--live` requests live replay behavior. Compare the recorded fork context before interpreting divergence.

## Minimize and promote

```bash
rusty-fuzz minimize --input-id "$INPUT_ID"

rusty-fuzz promote \
  --input-id "$INPUT_ID" \
  --strict-proof \
  --no-synthetic-proof \
  --require-minimized \
  --require-foundry-poc \
  --reject-heuristics
```

Set `INPUT_ID` to an input retained by your campaign. A minimizer seeks a smaller reproducing sequence under its predicate and budget; do not assume the result is a globally shortest exploit.

Promotion combines replay, reduction, realism checks, and PoC policy. Generating Solidity or getting a tool to print success is insufficient without the required checks and evidence.

## Review the evidence

Check the target, fork block, input identity, assumptions, replay comparison, minimized sequence, and PoC validation result. Separate what an oracle observed from the protocol invariant you believe it violates.

A rejection can mean that a candidate failed reproduction, lacked evidence, or did not meet policy. An unproven lead can still be useful research, but must retain that label. Read [Artifacts and provenance]({{ '/artifacts.html' | relative_url }}) to locate the supporting records.

## AI proposals follow the same boundary

Satori proposals and generated narratives cannot advance a finding directly to proved. The proposal boundary requires explicit validation, and execution evidence remains authoritative. See [Satori]({{ '/satori.html' | relative_url }}).
