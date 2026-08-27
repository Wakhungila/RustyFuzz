# Stage 4A: Run Layout & Versioned Manifests (rustyfuzz-artifacts)

Status: COMPLETE for review.

## Delivered

New crate `crates/rustyfuzz-artifacts` (`core <- artifacts`; NO fuzzing
policy ownership; no LibAFL/revm dependencies):

- `fsutil.rs` — atomic write primitive (temp file + fsync + rename +
  best-effort parent fsync). Readers can never observe partial artifacts.
- `layout.rs` — `RunLayout`: authoritative `.rustyfuzz/runs/<run-id>/`
  path mapping (`config.json`, `inputs/`, `snapshots/`, `candidates/`,
  `rejected/`, `proved/`, `minimized/`, `fork-cache/`, `reports/`,
  `telemetry/`) with idempotent materialization.
- `manifest.rs` — versioned `RunManifest` v1 recording: schema version, run
  id, tool version, optional git revision, config hash, mode, backend,
  chain/fork provenance, **sanitized RPC endpoint** (scheme://host[:port]
  only — credentials/query/paths stripped by `sanitize_rpc_endpoint`),
  abi/bytecode hashes, RNG seed, documented assumptions, and environment
  variable NAMES (never values).

## Integration

- Root CLI fuzz command now captures run provenance before engine-config
  values are moved, materializes the `.rustyfuzz` run layout, and persists
  the manifest atomically at startup. Log-only on failure; campaign behavior
  unchanged. Legacy corpus/report dirs untouched this stage (migration of
  runtime outputs into the layout is Stage 4-followup with data-dir policy).
- Config gains a harmless `Clone` derive for fingerprinting.

## Trust/Secret Policy Verified By Tests

- persisted manifest never contains URL credentials or paths
- future schema versions rejected, not guessed
- atomic writes leave no temp files and survive overwrite
