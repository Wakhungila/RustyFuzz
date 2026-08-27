# Stage 4C: AI Trust Boundary & Provider Neutrality

Status: COMPLETE for review (seam + audit; full crate extraction deferred).

## Current State (audited)

Satori (`src/satori/**`, ~1100 lines) already implements the important parts:

- response cache keyed by model+prompt (`satori/cache.rs`);
- budget tracking of calls/tokens with reports (`satori/budget.rs`);
- provider call isolated behind one module (`satori/reasoning/o3_client.rs`),
  gated by the `llm` cargo feature, retry/backoff included;
- OpenAI API key read from env at call time — never persisted.

Gaps vs target architecture: hardcoded single provider endpoint,
pipeline-coupled (not a reusable advisory surface), budget enforced after
call accounting rather than pre-call admission.

## Delivered This Stage

`rustyfuzz_core::proposal` — the trust seam, dependency-free and final-path
stable:

- `AiProposal::unvalidated(...)`: the ONLY constructor. No code path can
  create a "pre-validated" AI proposal.
- `validate(accepted, detail)`: deterministic validation applied outside the
  AI path records `Accepted{detail}` / `Rejected{detail}`.
- Provenance fields: provider, model, kind (`ProposalKind` covering all 7
  target tasks), request/response hashes (bodies stay out of artifacts).
- Invariant #4 encoded in types: an unvalidated proposal must not influence
  fuzzing decisions; validation status is data, not aspiration.

## Adoption Path

Oracle/advisor consumers migrate from raw Satori strings to `AiProposal`
when Stage 4 oracle crate lands. Existing pipeline behavior unchanged this
stage; no fuzzing outcome can be affected because nothing consumes
`AiProposal` yet except tests.

## Tests

- core: proposals start unvalidated; explicit accept/reject transitions.
