---
title: "Satori research workflow"
section: "Reference"
nav_order: 13
description: "Experimental repository analysis and hypothesis generation, with a strict boundary between proposals and evidence."
---

## What Satori does

Satori ingests Solidity/Vyper project context, builds structural information, prepares focused packets, and can produce hypotheses, RustyFuzz jobs, and Foundry PoC scaffolds. Model-backed reasoning is optional and gated by the `llm` feature.

Its outputs are research inputs. A hypothesis, confidence score, or generated test is not a confirmed vulnerability.

## Start without a model

```bash
rusty-fuzz satori ingest ./protocol
rusty-fuzz satori graph ./protocol
rusty-fuzz satori packets ./protocol
```

Use `rusty-fuzz satori --help` and subcommand help to inspect the controls in your build. Review generated context before sending source-derived information to an external model provider.

## Enable optional reasoning

```bash
cargo build --locked --release --bin rusty-fuzz --features llm
rusty-fuzz satori audit --help
```

Configure provider credentials through your local secret-management process. Scope the repository, hypothesis budget, validation, and generated-job settings explicitly. Do not assume model output is trustworthy because it is formatted as a report.

## Run a generated RustyFuzz job

```bash
rusty-fuzz job run path/to/job.rustyfuzz.json \
  --abi abi/Target.json
```

Review job target, fork context, hypotheses, and resource bounds first. Job execution and local validation decide whether a proposal is rejected, remains heuristic, or gains supporting evidence.

## Validation and containment

The core proposal API separates unvalidated proposals from explicitly validated data. Foundry and other external tools execute code and belong inside a controlled environment. Keep untrusted protocol repositories and generated projects away from unrelated secrets and privileged host resources.

Satori outputs can appear under `satori/` independently of canonical campaign artifacts. Preserve the actual referenced files when sharing a research run.
