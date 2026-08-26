# Runtime Data Policy

Status: Stage 1 policy. No runtime code migration has been implemented.

## Canonical Future Runtime Root

Future RustyFuzz runtime output belongs under:

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

Stage 1 only documents this target and updates `.gitignore`. `RunLayout` and
artifact migration belong to the later artifact subsystem stage.

## Directory Classification

Classification values:

- `SOURCE`: product source, docs, prompts, or config examples.
- `DETERMINISTIC_TEST_FIXTURE`: small fixture required by deterministic tests or benchmark smoke.
- `HISTORICAL_DATASET`: curated historical input/scope/archive material useful for reproducibility but not runtime output.
- `GENERATED_RUNTIME_DATA`: output from fuzzing, reports, PoC generation, or campaigns.
- `LOCAL_CACHE`: local cache or downloaded/generated state.
- `EXPERIMENTAL`: useful research material outside the supported production path.

| Path | Class | Current purpose | Currently tracked | Should remain tracked | Future location | Migration mechanism | CI dependency | Deterministic test dependency |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `src/**` | SOURCE | RustyFuzz production and experimental Rust source. | Yes | Yes | Workspace crates in Stage 2+. | Staged crate extraction, not Stage 1. | Yes | Yes |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | SOURCE | Build manifest, lockfile, pinned stable toolchain. | Yes | Yes | Repository root. | Preserve. | Yes | Yes |
| `.github/workflows/ci.yml` | SOURCE | Canonical CI workflow. | Yes | Yes | Same path. | Stage 1 documents consolidation; no branch-protection-breaking delete. | Yes | No |
| `.github/workflows/rust.yml` | SOURCE | Legacy duplicate build/test workflow. | Yes | Temporarily yes | Fold into `ci.yml` after branch-protection review. | Manual Stage 1/2 follow-up after confirming required check names. | Maybe | No |
| `docs/**` | SOURCE | Canonical and historical documentation. | Yes | Yes | Same path. | Mark superseded docs and keep canonical uppercase docs. | No | No |
| `docs/reengineering/**` | SOURCE | Re-engineering inventory, baseline, plans, and reports. | Yes | Yes | Same path. | Preserve as migration audit trail. | No | No |
| `docs/adr/**` | SOURCE | Architecture decisions. | Yes | Yes | Same path. | New ADR series uses `000N-*`; old ADRs remain historical. | No | No |
| `README.md` | SOURCE | User/developer entry point. | Yes | Yes | Repository root. | Keep concise and link canonical docs. | No | No |
| `config.toml.example` | SOURCE | Sanitized root config example. | Yes | Yes | `configs/examples/` later if desired. | Move only in a docs/config cleanup stage. | No | No |
| `satori/config.example.toml` | SOURCE | Sanitized Satori config example. | Yes | Yes | Future `configs/examples/ai/` or `rustyfuzz-ai` crate docs. | Move during AI extraction. | No | Satori tests do not require it directly. |
| `prompts/satori/**` | SOURCE / EXPERIMENTAL | Satori prompt templates. | Yes | Yes | Future `rustyfuzz-ai` prompt assets. | Move during AI extraction with prompt hashes. | No | Satori parser/tests may rely on prompt shape indirectly. |
| `tests/benchmarks.rs` | DETERMINISTIC_TEST_FIXTURE | Integration/benchmark smoke tests. | Yes | Yes | Split under `tests/**` in later test reorganization. | Split after core/engine boundaries exist. | Yes | Yes |
| `tests/end_to_end_smoke.rs` | DETERMINISTIC_TEST_FIXTURE | Smoke campaign test. | Yes | Yes | `tests/cli` or `tests/campaign` later. | Split after CLI/engine extraction. | Yes | Yes |
| `tests/fixtures/satori/**` | DETERMINISTIC_TEST_FIXTURE | Satori deterministic Solidity fixtures. | Yes | Yes | Future `rustyfuzz-testkit` or `rustyfuzz-ai` fixtures. | Move with testkit/AI extraction. | Yes | Yes |
| `tests/ci.yml` | SOURCE / EXPERIMENTAL | Historical/non-active CI test file. | Yes | Review later | `docs/reengineering` or delete after confirming no use. | Stage 1 documents only. | No active GitHub dependency. | No |
| `benchmarks/blind/**` | DETERMINISTIC_TEST_FIXTURE | Blind rediscovery manifests and cached fixtures. | Yes | Yes | `benchmarks/fixtures/blind/` or external dataset manager later. | Preserve until benchmark suite is reorganized. | Yes, via benchmark tests. | Yes |
| `benchmarks/historical/**` | HISTORICAL_DATASET / DETERMINISTIC_TEST_FIXTURE | Historical exploit manifests and known vulnerable cached fixtures. | Yes | Yes for small fixtures | Future `benchmarks/datasets/` or external dataset manager. | Keep small deterministic fixtures; move bulk datasets only with explicit migration. | Yes, smoke tests reference fixtures. | Yes |
| `benchmarks/live/**` | HISTORICAL_DATASET / EXPERIMENTAL | Live-RPC benchmark manifests and fixtures. | Yes | Yes for manifests/fixtures | Optional external-RPC benchmark dataset. | Keep optional; exclude RPC availability from default CI. | No external RPC in default CI. | Some parser tests may read manifests. |
| `benchmarks/daedaluzz/**` | DETERMINISTIC_TEST_FIXTURE | Daedaluzz fixture material. | Yes | Yes | Benchmark fixture area. | Keep trackable; ignore generated benchmark results separately. | Yes if referenced by tests. | Yes |
| `benchmarks/results/`, `benchmarks/tmp/`, `benchmarks/generated/` | GENERATED_RUNTIME_DATA | Future local benchmark outputs. | No | No | `.rustyfuzz/runs/<run-id>/reports/` or `.rustyfuzz/tmp/`. | Generated only; do not commit. | No | No |
| `audits/**` | HISTORICAL_DATASET / EXPERIMENTAL | Coinbase/Cantina scope, target metadata, Foundry fixtures, seed corpus, bytecode, logs. | Yes | Temporarily yes | `.rustyfuzz/datasets/audits/` or external dataset storage. | Document and move with explicit dataset-management plan; do not delete or rewrite history. | No default CI dependency observed. | No default deterministic test dependency observed. |
| `saved-runs/*.tar.gz` | HISTORICAL_DATASET | Previous campaign archives. | Yes | Temporarily yes | External artifact storage or `.rustyfuzz/datasets/saved-runs/` import. | Preserve until explicit archival policy exists. | No | No |
| `corpus/` | GENERATED_RUNTIME_DATA | Current/future campaign corpus output, seed cursors, fork cache. | Mostly ignored | No, except curated fixtures if added elsewhere | `.rustyfuzz/runs/<run-id>/inputs/`, `snapshots/`, `fork-cache/`. | Later `RunLayout` migration. | No | No |
| `reports/` | GENERATED_RUNTIME_DATA | Validation reports, PoCs, generated campaign output. | One tracked validation artifact plus ignored outputs | Generally no | `.rustyfuzz/runs/<run-id>/reports/`. | Curate deterministic report fixtures into tests if needed; otherwise generated. | No | No |
| `reports/validation/**` | GENERATED_RUNTIME_DATA / HISTORICAL_DATASET | Existing generated validation PoC artifact. | Yes | Review later | Test fixture if deterministic, otherwise `.rustyfuzz/datasets/` or external artifact. | Do not delete in Stage 1. | No default CI dependency observed. | No direct dependency observed. |
| `crashes/`, `findings/`, `artifacts/`, `replays/`, `minimized/`, `coverage/` | GENERATED_RUNTIME_DATA | Local fuzz outputs. | Ignored | No | `.rustyfuzz/runs/<run-id>/...`. | Later artifact subsystem. | No | No |
| `fork-cache/`, `fork_cache/` | LOCAL_CACHE | Current/future fork DB cache output. | Ignored | No | `.rustyfuzz/runs/<run-id>/fork-cache/` or `.rustyfuzz/cache/forks/`. | Later artifact subsystem. | No | No |
| `seed-bundles/`, `seed_bundles/`, `seeds/` | GENERATED_RUNTIME_DATA / HISTORICAL_DATASET | Local seed discovery output. | Ignored except historical audit seeds | No for generated; yes for curated fixtures | `.rustyfuzz/datasets/seeds/` or benchmark fixture area. | Curate deterministic fixtures explicitly. | No | No |
| `satori/cache/**` | LOCAL_CACHE | AI/cache runtime data. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/cache/ai/` later. | Move during AI harness extraction. | No | No |
| `satori/jobs/**` | GENERATED_RUNTIME_DATA | AI job runtime queue/output. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/runs/<run-id>/ai/jobs/`. | Move during AI harness extraction. | No | No |
| `satori/memory/**` | GENERATED_RUNTIME_DATA | Satori runtime memory JSONL location. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/cache/ai/memory/` or run-local `ai/`. | Move during AI harness extraction. | No | No |
| `satori/packets/**` | GENERATED_RUNTIME_DATA | AI context packets. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/runs/<run-id>/ai/packets/`. | Move during AI harness extraction. | No | No |
| `satori/reports/**` | GENERATED_RUNTIME_DATA | AI/generated reports. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/runs/<run-id>/ai/reports/`. | Move during AI harness extraction. | No | No |
| `satori/runs/**` | GENERATED_RUNTIME_DATA | Satori run outputs. | Only `.gitkeep` | Keep placeholder only | `.rustyfuzz/runs/<run-id>/ai/`. | Move during AI harness extraction. | No | No |
| `.rustyfuzz/**` | GENERATED_RUNTIME_DATA / LOCAL_CACHE | Future canonical runtime root. | Ignored | No | Same path for local output only. | Runtime creates it later. | No | No |
| `/tmp/rustyfuzz-*` | GENERATED_RUNTIME_DATA | Current benchmark/temp campaign output. | Outside repo | No | `.rustyfuzz/tmp/` later. | Later artifact subsystem. | No | No |
| `out/`, `broadcast/`, `foundry-cache/`, `foundry-tmp/`, `tmp-foundry/`, `foundry-projects/` | GENERATED_RUNTIME_DATA | Temporary Foundry/PoC output. | Ignored | No | `.rustyfuzz/tmp/foundry/` or run-local `reports/poc/`. | Later artifact subsystem. | No | No |
| `*.log`, `*.tmp`, `*.trace`, `*.db`, `*.sqlite*`, `*.profraw`, `*.profdata` | GENERATED_RUNTIME_DATA / LOCAL_CACHE | Local logs, traces, DBs, profiles. | Ignored unless already tracked | No | `.rustyfuzz/runs/<run-id>/telemetry/` or `.rustyfuzz/cache/`. | Later artifact subsystem. | No | No |

## Migration Policy

- Do not delete tracked historical material in Stage 1.
- Do not rewrite Git history to remove prior archives or generated artifacts.
- Retain small deterministic fixtures needed by tests and benchmark smoke.
- Move bulk historical benchmark/audit datasets only after a dataset-management
  plan exists.
- New campaign output should go under `.rustyfuzz/` once `RunLayout` is
  implemented.
- Until production code migrates, legacy runtime paths remain ignored to prevent
  accidental commits.
