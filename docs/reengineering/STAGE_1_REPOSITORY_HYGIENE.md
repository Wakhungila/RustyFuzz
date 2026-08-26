# Stage 1 Repository Hygiene Report

Date: 2026-08-26
Scope: repository hygiene and architecture documentation only.

Stage 0.5 checkpoint was preserved before Stage 1:

```text
commit: 99ac76e chore: establish RustyFuzz reengineering baseline
tag: reengineering-stage-0.5
```

No production module restructuring, Cargo workspace creation, `EvmInput`
redesign, fuzzing-semantic change, executor change, scheduler/mutator/oracle
change, proof-policy change, or Satori refactor was performed.

## Files Changed

- `.gitignore`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT.md`
- `docs/CONTRIBUTING.md`
- `docs/SECURITY.md`
- `docs/FUZZING_MODEL.md`
- `docs/FINDING_LIFECYCLE.md`
- `docs/AI_HARNESS.md`
- `docs/ARTIFACT_FORMAT.md`
- `docs/BENCHMARKING.md`
- `docs/CONFIGURATION.md`
- `docs/COMPARISON.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/architecture.md`
- `docs/benchmarking.md`
- `docs/engineering-status.md`
- `docs/finding-lifecycle.md`
- `docs/adr/README.md`
- `docs/adr/0001-evm-first-architecture.md`
- `docs/adr/0002-cargo-workspace-boundaries.md`
- `docs/adr/0003-semantic-input-vs-testcase-metadata.md`
- `docs/adr/0004-snapshot-first-state-exploration.md`
- `docs/adr/0005-finding-lifecycle.md`
- `docs/adr/0006-artifact-schema-versioning.md`
- `docs/adr/0007-ai-trust-boundary.md`
- `docs/adr/0008-svm-sgx-quarantine.md`
- `docs/reengineering/RUNTIME_DATA_POLICY.md`
- `docs/reengineering/STAGE_2_PLAN.md`
- `docs/reengineering/STAGE_1_REPOSITORY_HYGIENE.md`

## Files And Directories Classified

Classification policy is recorded in
`docs/reengineering/RUNTIME_DATA_POLICY.md`.

Summary:

- `SOURCE`: `src/**`, manifests, workflows, docs, config examples, prompts.
- `DETERMINISTIC_TEST_FIXTURE`: `tests/**` fixtures and benchmark smoke fixtures.
- `HISTORICAL_DATASET`: `audits/**`, `saved-runs/*.tar.gz`, historical/live benchmark manifests.
- `GENERATED_RUNTIME_DATA`: `.rustyfuzz/**`, `corpus/**`, most `reports/**`, crash/finding/artifact/replay/minimized/coverage outputs, generated benchmark results, temporary Foundry output.
- `LOCAL_CACHE`: fork caches, AI cache, DB/cache/profile outputs.
- `EXPERIMENTAL`: Satori runtime areas, hybrid/SVM/SGX policy material, audit datasets.

No historical material was deleted or moved.

## Generated-Data Policy

Stage 1 defines `.rustyfuzz/` as the future canonical runtime root:

```text
.rustyfuzz/
  runs/
  cache/
  datasets/
  tmp/
```

Future campaign layout:

```text
.rustyfuzz/
  runs/
    <run-id>/
      manifest.json
      config.json
      inputs/
      snapshots/
      candidates/
      rejected/
      proved/
      minimized/
      fork-cache/
      reports/
      telemetry/
      ai/
```

Production code has not been migrated to this layout. `RunLayout` is deferred to
the artifact subsystem stage.

## Documentation Changes

Canonical hierarchy prepared:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT.md`
- `docs/CONTRIBUTING.md`
- `docs/SECURITY.md`
- `docs/FUZZING_MODEL.md`
- `docs/FINDING_LIFECYCLE.md`
- `docs/AI_HARNESS.md`
- `docs/ARTIFACT_FORMAT.md`
- `docs/BENCHMARKING.md`
- `docs/CONFIGURATION.md`
- `docs/adr/`
- `docs/reengineering/`

`docs/ARCHITECTURE.md` now separates:

- `Current Architecture - v0.1`;
- `Target Architecture - v0.2`.

It includes Mermaid diagrams for:

- current high-level module dependencies;
- target crate dependency direction.

Lowercase historical docs were marked `SUPERSEDED` instead of deleted:

- `docs/architecture.md`
- `docs/benchmarking.md`
- `docs/finding-lifecycle.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/engineering-status.md`

`docs/COMPARISON.md` is marked historical/superseded as a production-readiness
source of truth.

## CI Decision

`.github/workflows/ci.yml` remains the intended canonical CI workflow.
`.github/workflows/rust.yml` remains in place for now.

Reason:

- local repository data cannot establish whether branch protection depends on
  the legacy workflow/check name `Rust / build`;
- deleting it now could break required checks even though it is functionally
  redundant with `ci.yml`.

Safe consolidation step for later/manual review:

1. Inspect repository branch protection required check names in GitHub.
2. If `Rust / build` is not required, delete `.github/workflows/rust.yml`.
3. If `Rust / build` is required, either update branch protection to canonical
   `RustyFuzz CI` jobs or preserve the check name during consolidation.
4. Do not weaken the Stage 0.5 gates.

Canonical CI requirements remain:

- fmt;
- Clippy with `-D warnings`;
- check;
- tests;
- docs;
- feature checks;
- release build;
- sanitizer;
- benchmark smoke.

## ADRs Created

- `0001-evm-first-architecture.md`
- `0002-cargo-workspace-boundaries.md`
- `0003-semantic-input-vs-testcase-metadata.md`
- `0004-snapshot-first-state-exploration.md`
- `0005-finding-lifecycle.md`
- `0006-artifact-schema-versioning.md`
- `0007-ai-trust-boundary.md`
- `0008-svm-sgx-quarantine.md`

ADR-0003 records the Stage 2 target that semantic `EvmInput` identity contains
only execution-defining data, while coverage, waypoints, comparison feedback,
mutation provenance, state novelty, scheduling score, and parent relationships
belong in metadata.

## Unsupported Configurations Documented

- SVM: intentionally unsupported and future-quarantined.
- SGX: unsupported shim only.
- `--no-default-features`: unsupported in the current v0.1 monolith because EVM
  types cross current `common`, `engine`, `oracle`, and `hybrid` boundaries.

No attempt was made to repair these in Stage 1.

## Gitignore Verification

Ignored as intended:

```text
.gitignore:16:/.rustyfuzz/  .rustyfuzz/runs/example/manifest.json
.gitignore:17:/corpus/      corpus/generated/input.json
.gitignore:19:/reports/*    reports/generated/report.json
.gitignore:38:/satori/cache/*       satori/cache/generated.json
.gitignore:53:/benchmarks/results/  benchmarks/results/run.json
```

Not ignored as intended. `git check-ignore -v` returned exit code 1 with no
matching rule for:

```text
docs/reengineering/STAGE_1_REPOSITORY_HYGIENE.md
docs/ARCHITECTURE.md
benchmarks/daedaluzz/fixtures/new.json
benchmarks/historical/fixtures/new.json
tests/fixtures/satori/new.sol
tests/new_integration.rs
```

This means deterministic fixtures, docs, and new tests remain trackable.

## Commands Executed

```bash
git status --short
git log -1 --oneline
git tag --list 'reengineering-*'
git add -A
env GIT_AUTHOR_NAME=Codex GIT_AUTHOR_EMAIL=codex@local GIT_COMMITTER_NAME=Codex GIT_COMMITTER_EMAIL=codex@local git commit -m "chore: establish RustyFuzz reengineering baseline"
git tag reengineering-stage-0.5
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo test --test benchmarks --release
python3 -c 'import pathlib, yaml; paths=[pathlib.Path(".github/workflows/ci.yml"), pathlib.Path(".github/workflows/rust.yml")]; [yaml.safe_load(path.read_text()) for path in paths]; print("validated", ", ".join(str(path) for path in paths))'
git check-ignore -v .rustyfuzz/runs/example/manifest.json
git check-ignore -v corpus/generated/input.json
git check-ignore -v reports/generated/report.json
git check-ignore -v satori/cache/generated.json
git check-ignore -v benchmarks/results/run.json
git check-ignore -v docs/reengineering/STAGE_1_REPOSITORY_HYGIENE.md
git check-ignore -v docs/ARCHITECTURE.md
git check-ignore -v benchmarks/daedaluzz/fixtures/new.json
git check-ignore -v benchmarks/historical/fixtures/new.json
git check-ignore -v tests/fixtures/satori/new.sol
git check-ignore -v tests/new_integration.rs
git diff --check
git status --short
```

## Results

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | pass |
| `cargo check --workspace` | pass |
| `cargo test --workspace` | pass: 181 lib, 4 binary, 38/39 benchmark integration with 1 ignored, 1 smoke, 1 doctest |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo build --workspace --release` | pass |
| `cargo doc --workspace --no-deps` | pass |
| `cargo test --test benchmarks --release` | pass: 38 passed, 1 ignored |
| GitHub workflow YAML parse with PyYAML 6.0.3 | pass |
| `git diff --check` | pass |

Repeated dependency warning remains:

```text
proc-macro-error2 v2.0.1 contains code that will be rejected by a future version of Rust
```

## Behavioral Changes

No runtime/fuzzing behavior changed.

Repository behavior changed only through `.gitignore`:

- future `.rustyfuzz/` runtime output is ignored;
- generated Satori runtime subdirectories are ignored while placeholders remain trackable;
- generated benchmark result directories are ignored;
- docs, tests, and benchmark fixtures are no longer hidden by overbroad ignore rules.

## Known Risks

- `.github/workflows/rust.yml` remains duplicated pending branch-protection review.
- Historical data under `audits/` and `saved-runs/` remains tracked until a later explicit dataset migration.
- Existing production code still writes to legacy runtime paths; `.rustyfuzz/` is target documentation only.
- Lowercase/historical docs still contain old context, but they are marked superseded where they could mislead.
- `--no-default-features` and `svm` remain unsupported.

## Stage 2 Readiness Decision

Stage 1 is ready for review.

The repository is now prepared for Stage 2A with:

- a clean Stage 0.5 checkpoint;
- green mandatory gates preserved;
- canonical docs separating CURRENT from TARGET;
- ADR foundations for the approved architecture;
- generated-data policy;
- `.rustyfuzz/` target layout documented;
- `EvmInput` redesign documented but not implemented;
- unsupported SVM/SGX/no-default configurations documented.

Do not begin Stage 2 automatically. The next approved step should be Stage 2A:
extract `rustyfuzz-core` stable IDs and semantic domain types.
