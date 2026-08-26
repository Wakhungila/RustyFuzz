# Finding Lifecycle

Status: CURRENT plus TARGET notes.

## Current v0.1 State

The source currently has more than one lifecycle model:

- `common::oracle::FindingStatus`: `Lead`, `Replayed`, `Minimized`, `Proved`, `Rejected`.
- `engine::promotion::FindingLifecycleStage`: `Candidate`, `Replayed`, `Minimized`, `PocGenerated`, `Confirmed`, `Rejected`.
- older documentation also used `Signal`, `Candidate`, `Confirmed`, and `Rejected`.

This is a known architecture defect. Stage 1 documents it; it does not change
the implementation.

## Target v0.2 Lifecycle

Target canonical lifecycle:

```text
Signal -> Candidate -> Replayed -> Minimized -> Proved
```

`Rejected` is available from intermediate states.

Target rules:

- `Signal`: raw oracle, coverage, economic, or heuristic evidence.
- `Candidate`: signal grouped into a finding candidate with structured evidence.
- `Replayed`: deterministic replay succeeded for the candidate sequence/state.
- `Minimized`: the required predicate survived minimization.
- `Proved`: machine-verifiable proof policy succeeded without exploration-only assumptions.
- `Rejected`: replay, minimization, proof, scope, or evidence policy failed.

AI or human-readable strings must never directly mark a finding as proved.
Exploration, replay, minimization, PoC generation, PoC validation, proof, and
reporting should remain separate operations.
