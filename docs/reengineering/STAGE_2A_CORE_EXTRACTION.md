# Stage 2A Core Extraction

Status: COMPLETE for review. Stage 2B has not started.

## Starting Checkpoint

- Stage 1 commit: `d876daa`
- Stage 1 tag: `reengineering-stage-1`
- Stage 0.5 tag retained: `reengineering-stage-0.5`
- Stage 1 worktree verification before Stage 2A: clean

## Files Changed

- `Cargo.toml`
- `Cargo.lock`
- `src/common/types.rs`
- `crates/rustyfuzz-core/Cargo.toml`
- `crates/rustyfuzz-core/src/lib.rs`
- `crates/rustyfuzz-core/src/ids.rs`
- `crates/rustyfuzz-core/src/error.rs`
- `crates/rustyfuzz-core/src/execution.rs`
- `crates/rustyfuzz-core/src/snapshot.rs`
- `crates/rustyfuzz-core/src/finding.rs`
- `crates/rustyfuzz-core/src/metadata.rs`
- `docs/ARCHITECTURE.md`
- `docs/reengineering/STAGE_2_PLAN.md`
- `docs/reengineering/STAGE_2A_CORE_EXTRACTION.md`

## Workspace Changes

The repository is now a Cargo workspace with these members only:

```text
.
crates/rustyfuzz-core
```

The existing root package remains named `rusty-fuzz`. Existing binaries and
`src/**` layout were not renamed or moved.

## rustyfuzz-core Module Tree

```text
crates/rustyfuzz-core/
  Cargo.toml
  src/
    lib.rs
    ids.rs
    execution.rs
    snapshot.rs
    finding.rs
    metadata.rs
    error.rs
```

## Types Introduced

- `InputId`: opaque content-derived testcase identifier type. Stage 2A defines
  the type only; Stage 2B defines final semantic hash derivation.
- `SnapshotId`: numeric assigned snapshot identifier preserving the current
  monolith's snapshot handle during this stage.
- `CampaignId`: assigned human-readable campaign identifier.
- `OracleId`: assigned oracle/rule identifier.
- `FindingId`: assigned finding reference identifier for later evidence/finding
  extraction.
- `EvidenceId`: assigned evidence reference identifier.
- `CoreError` and `CoreResult`: typed core errors for ID parsing and validation.
- `SnapshotMetadata`: dependency-neutral snapshot ancestry metadata only.
- `EvidenceKind` and `EvidenceRef`: dependency-neutral evidence references only.
- `TestcaseMetadata`: minimal destination skeleton for later separation of
  semantic input from execution feedback.

No Stage 2A ID type derives ordering; ordering policies should be added only
where a later artifact, scheduler, or storage contract gives them clear
semantics.

## Types Migrated

- `ExecutionStatus` moved from `src/common/types.rs` to
  `rustyfuzz_core::execution::ExecutionStatus`.

`src/common/types.rs` re-exports `ExecutionStatus` from `rustyfuzz-core`, so
existing code importing `crate::common::types::ExecutionStatus` keeps compiling.

## Types Deliberately Not Migrated

- `EvmInput`: Stage 2B owns the semantic input redesign.
- `SingletonTx`: still uses REVM/Alloy address and integer types.
- `TxExecutionResult` and `SequenceExecutionResult`: still contain EVM-specific
  storage, call, waypoint, and oracle observation payloads.
- `StorageAccess`, `StorageDiff`, `CallObservation`, `Waypoint`, and concolic
  types: still depend on EVM-specific primitives and instrumentation details.
- `Snapshot` and `SnapshotCorpus`: still own REVM state, corpus behavior, and
  scheduler-facing data.
- `FindingStatus` and `FindingLifecycleStage`: Stage 2D owns canonical lifecycle
  migration.
- Satori types, artifact layout, scheduler metadata, mutators, and oracle
  implementations.

## Compatibility Re-exports

`src/common/types.rs` now contains temporary compatibility shims:

- `pub use rustyfuzz_core::ExecutionStatus;`
- `pub use rustyfuzz_core::{CampaignId, InputId, OracleId, SnapshotId};`

Each shim is marked with a `TODO(stage-2x)` comment describing the later removal
or replacement point. No circular re-export was introduced.

## Serialization Compatibility Analysis

- `ExecutionStatus` keeps the same serde enum representation as the previous
  monolith definition:
  - `Success` serializes as `"Success"`;
  - `Revert` serializes as `"Revert"`;
  - `Halt("reason")` serializes as `{"Halt":"reason"}`.
- ID types use transparent serde representations:
  - string IDs serialize as JSON strings;
  - `SnapshotId` serializes as a JSON number.
- `SnapshotMetadata`, `EvidenceRef`, and `TestcaseMetadata` are new types and do
  not replace existing persisted schemas yet.
- Current `EvmInput` serialization and current corpus input hashing were not
  changed.

## Dependency Audit

Expected policy:

- `rustyfuzz-core` may depend on `serde` and `thiserror`.
- `serde_json` is a dev-dependency for serialization tests only.
- `rustyfuzz-core` must not depend on REVM, Alloy, LibAFL, network stacks, AI
  SDKs, or CLI frameworks.

Observed `cargo tree -p rustyfuzz-core`:

```text
rustyfuzz-core v0.1.0
├── serde v1.0.228
└── thiserror v2.0.18
[dev-dependencies]
└── serde_json v1.0.149
```

Observed `cargo tree -i rustyfuzz-core`:

```text
rustyfuzz-core v0.1.0
└── rusty-fuzz v0.1.0
```

The reverse dependency direction is correct: the root monolith depends on
`rustyfuzz-core`; `rustyfuzz-core` does not depend on the root package.

Source scan result:

- No `rustyfuzz-core` imports of REVM, Alloy, LibAFL, `reqwest`, `tokio`,
  `clap`, foundry tooling, Satori, or `crate::{evm,engine,common}`.
- The only forbidden-term match in `crates/rustyfuzz-core` was rustdoc text
  documenting the dependency ban.

## Commands Executed

Stage 2A validation correction before Stage 2B:

```text
cargo test -p rustyfuzz-core -- --list                 PASS (11 unit tests, 0 doctests)
cargo test -p rustyfuzz-core                           PASS (11 unit tests, 0 doctests)
cargo test -p rustyfuzz-core --lib                     PASS (11 unit tests)
cargo test -p rustyfuzz-core --tests                   PASS (11 unit tests; no separate integration files)
cargo test -p rustyfuzz-core --doc                     PASS (0 doctests)
```

The 11 `rustyfuzz-core` tests are unit tests defined under
`crates/rustyfuzz-core/src/**`. There are currently no
`crates/rustyfuzz-core/tests/**` integration tests and no doctests.

Pre-edit Stage 1 checkpoint:

```text
git status --short                                      PASS (clean)
git log -2 --oneline                                   PASS
git tag --list 'reengineering-*'                       PASS
cargo fmt --all -- --check                             PASS
cargo check --workspace                                PASS
cargo test --workspace                                 PASS
cargo clippy --workspace --all-targets -- -D warnings  PASS
```

Post-core immediate checks:

```text
cargo check --workspace                                PASS
cargo test --workspace                                 PASS
```

Final Stage 2A gate:

```text
cargo fmt --all -- --check                             PASS
cargo check --workspace                                PASS
cargo test --workspace                                 PASS
cargo clippy --workspace --all-targets -- -D warnings  PASS
cargo build --workspace --release                      PASS
cargo doc --workspace --no-deps                        PASS
cargo test --test benchmarks --release                 PASS (38 passed / 1 ignored)
```

Additional validation:

```text
python3 YAML parser over .github/workflows/*.yml        PASS (2 workflow files)
cargo tree -p rustyfuzz-core                            PASS
cargo tree -i rustyfuzz-core                            PASS
cargo metadata --no-deps --format-version 1             PASS (members: ., crates/rustyfuzz-core)
git diff --check                                        PASS
```

Sanitizer validation:

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test --workspace \
  --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result: FAIL at workspace scope after passing root library tests, root bin
tests, and `tests/benchmarks.rs`. The failure is in
`tests/end_to_end_smoke.rs` with an AddressSanitizer runtime check failure:
`AddressSanitizer failed to deallocate 0x800000 ... unable to unmap`.

Fallback explicit production-member sanitizer commands:

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result: PASS (181 passed).

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --bins \
  --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result: PASS (4 passed across `src/main.rs`; `src/bin/benchmark.rs` has 0
tests).

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rusty-fuzz --test benchmarks \
  --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result: PASS (38 passed / 1 ignored).

```text
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test -p rustyfuzz-core --lib \
  --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result: PASS (11 passed).

## Behavioral Changes

No fuzzing/runtime behavior changed intentionally.

The only production type migration is ownership of `ExecutionStatus`; the
existing public import path remains available through a compatibility re-export.

## Known Risks

- `SnapshotId` remains a numeric assigned handle for Stage 2A. Stage 2C must
  decide final snapshot identity and state hash semantics.
- `InputId` is defined but not yet derived from semantic input. Stage 2B owns
  the invariant that input identity excludes execution feedback.
- Existing lifecycle duplication remains by design until Stage 2D.
- `--no-default-features` and `svm` remain unsupported as documented in Stage 1.
- Existing future-incompatibility warnings from transitive dependencies remain
  outside Stage 2A scope:
  - stable path: `proc-macro-error2 v2.0.1`;
  - sanitizer path: `nix v0.30.1`, `proc-macro-error2 v2.0.1`.
- Full workspace ASan is not currently a usable mandatory gate because
  `tests/end_to_end_smoke.rs` trips an ASan runtime `unable to unmap` check.
  The Stage 0.5 configured ASan scope remains green, and the new
  `rustyfuzz-core` member is also ASan-clean.

## Remaining Conceptual Cycles

- `src/common/**` still depends on EVM/REVM state and cannot be treated as
  core-clean.
- `src/engine/**`, `src/evm/**`, and `src/common/oracle/**` still share finding,
  execution, snapshot, and artifact concepts through the monolith.
- Runtime paths still have no single owner; artifact extraction is a later stage.

## Readiness Decision for Stage 2B

READY FOR REVIEW.

The stable mandatory gates are green, the configured sanitizer coverage remains
green for the root production library, and `rustyfuzz-core` has its own passing
sanitizer run. Stage 2B should not begin until this report is reviewed,
especially the documented full-workspace ASan limitation for
`tests/end_to_end_smoke.rs`.
