# Artifact Format

Status: CURRENT plus TARGET notes.

## Current v0.1 State

Runtime and artifact paths are currently reconstructed across multiple modules.
Observed current locations include:

```text
corpus/
reports/
satori/runs/
satori/cache/
satori/packets/
satori/reports/
saved-runs/
/tmp/rustyfuzz-daedaluzz/
```

There is no single `RunLayout` owner in v0.1.

## Target Runtime Root

Future runtime root:

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

Target serialized artifacts must include `schema_version` and enough provenance
for deterministic reproduction: RustyFuzz version, git commit, chain id, fork
block, target, bytecode hash, ABI hash, RNG seed, input hash, base snapshot
hash, configuration hash, engine mode, and execution assumptions.

Stage 1 does not implement `RunLayout` or migrate artifact-writing code.
