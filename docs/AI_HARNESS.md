# AI Harness

Status: CURRENT experimental Satori plus TARGET AI boundary.

## Current v0.1 State

Satori exists under `src/satori/**`, `satori/**`, and `prompts/satori/**`.
It provides useful project ingestion, analysis, packet, memory, prompt, and
reporting pieces, but it is still experimental and not part of the stable EVM
fuzzing kernel.

Known current limitations:

- provider coupling around the current client path;
- runtime directories under `satori/`;
- after-the-fact budget accounting rather than enforceable reservation;
- AI output is not a production proof primitive.

## Target v0.2 Boundary

AI is optional control-plane assistance. The fuzzing engine must remain fully
functional when AI is disabled or unavailable.

Target rule:

```text
AI proposes.
RustyFuzz validates.
```

Target provider API:

```rust
#[async_trait::async_trait]
pub trait AiProvider: Send + Sync {
    async fn infer(&self, request: AiRequest) -> Result<AiResponse, AiError>;
}
```

Target tasks include seed suggestions, invariant suggestions, coverage-gap
analysis, mutation-strategy suggestions, harness generation, finding
explanation, and candidate triage. Proposals require deterministic validation
before they can affect corpus or proof state.

Stage 1 does not refactor Satori.
