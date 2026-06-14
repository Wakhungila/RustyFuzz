# Finding Lifecycle

RustyFuzz findings use this status model:

- `Lead`: heuristic signal or oracle evidence that is not proven.
- `Replayed`: deterministic replay succeeded.
- `Minimized`: replayed evidence survived sequence minimization.
- `Proved`: realistic fork proof succeeded without exploration-only assumptions.
- `Rejected`: replay, minimization, proof, scope, or oracle checks failed.

A finding must not be treated as a real vulnerability until proof mode validates
the exact minimized sequence.

## Promotion Pipeline

The promotion path is:

`Candidate -> Replay -> Minimize -> Realism proof -> PoC validation -> Report`.

Every stage may reject the finding. Rejections are preserved in the finding JSON
instead of hidden.

Strict audit flags:

- `--strict-proof`: enables all fail-closed proof requirements.
- `--no-synthetic-proof`: rejects synthetic fallback evidence.
- `--require-foundry-poc`: requires a validated Foundry PoC before reportable proof.
- `--require-minimized`: rejects findings that cannot produce a minimized sequence.
- `--reject-heuristics`: rejects replay/proof failures instead of keeping them as leads.
- `--max-finding-noise 0`: rejects non-proved findings in that promotion path.

`prove-live` defaults to strict proof settings. General `fuzz` can still emit leads,
but those leads cannot become `Proved` without realistic fork proof.
