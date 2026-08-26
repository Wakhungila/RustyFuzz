# RustyFuzz Stage 0.5 Stabilization

Date: 2026-08-26
Scope: stabilization gate only.

No Stage 1 repository hygiene migration, production module moves, Cargo workspace creation, fuzzing architecture refactor, SVM repair, or `EvmInput` redesign was performed.

## Files Changed

- `rust-toolchain.toml`
- `.github/workflows/ci.yml`
- `.github/workflows/rust.yml`
- `.gitignore`
- `docs/reengineering/BASELINE.md`
- `docs/reengineering/STAGE_0_5_STABILIZATION.md`
- `src/bin/benchmark.rs`
- `src/common/verifier.rs`
- `src/engine/abi_ingest.rs`
- `src/engine/bounded_search.rs`
- `src/engine/bytecode_analysis.rs`
- `src/engine/control_flow.rs`
- `src/engine/exploit_path.rs`
- `src/engine/exploit_synthesizer.rs`
- `src/engine/fork_setup.rs`
- `src/engine/fuzz_engine.rs`
- `src/engine/ordering_mutations.rs`
- `src/engine/permission_model.rs`
- `src/engine/protocol_model.rs`
- `src/engine/scoring.rs`
- `src/engine/seed_intelligence.rs`
- `src/engine/state_machine_inference.rs`
- `src/engine/state_transition_checker.rs`
- `src/engine/temporal_constraints.rs`
- `src/evm/economic.rs`
- `src/evm/fuzz.rs`
- `src/hybrid/taint.rs`
- `src/main.rs`
- `src/satori/ingest/project.rs`
- `tests/benchmarks.rs`
- `tests/end_to_end_smoke.rs`

## Clippy Resolutions

The Stage 0 failing gate was:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Stage 0.5 fixed the lint categories mechanically:

| Lint category | Resolution |
| --- | --- |
| `unnecessary_sort_by` | Replaced comparator closures with `sort_by_key`, using `std::cmp::Reverse` for descending order. |
| `redundant_closure` | Passed function items directly to iterator adapters. |
| `manual_range_patterns` | Replaced repeated OR patterns with an inclusive range pattern. |
| `if_same_then_else` | Removed a duplicated branch and kept the identical increment. |
| `collapsible_match` / `collapsible_if` | Collapsed nested conditions into match guards or combined boolean expressions. |
| `too_many_arguments` | Replaced a private telemetry helper's long argument list with a private `ExecutionTelemetryRecord` struct. |
| `question_mark` | Replaced local `let Some(..) else { return None; }` patterns with `?`. |
| `unnecessary_cast` | Removed casts from `usize` to `usize`. |
| `unwrap_or_default` | Replaced `or_insert_with(DefaultType::new)` with `or_default()`. |
| `items_after_test_module` | Moved test modules to the end of their files. |
| `clone_on_copy` | Dereferenced copied `U256` values instead of cloning. |
| `unnecessary_map_or` | Used `Option::is_none_or`. |
| `unused_enumerate_index` | Removed unused `enumerate()`. |
| `new_without_default` | Derived `Default` for `PriceAnalyzer` and made `new()` delegate to it. |
| `ptr_arg` | Changed a helper from `&PathBuf` to `&Path`; moved `PathBuf` import into tests. |
| `field_reassign_with_default` | Built test/config structs with struct literals plus `..Default::default()`. |
| `manual_clamp` | Replaced `.max(...).min(...)` with `.clamp(...)`. |
| `print_literal` | Printed the banner as a direct literal instead of formatting a literal through `{}`. |
| `dead_code` | Removed a private helper made unused by the duplicate-branch cleanup. |

No broad `#[allow(...)]` or global Clippy weakening was added.

## Toolchain Decision

Main project toolchain is pinned in `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.97.1"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

Local active toolchain after pinning:

```text
1.97.1-x86_64-unknown-linux-gnu (overridden by rust-toolchain.toml)

rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
```

The main compiler is stable. Nightly is used only for the sanitizer job.

## CI Changes

`.github/workflows/ci.yml`:

- normal jobs now use `dtolnay/rust-toolchain@1.97.1`;
- Clippy job now runs `cargo clippy --workspace --all-targets -- -D warnings`;
- check job now runs `cargo check --workspace`;
- sanitizer job now uses `dtolnay/rust-toolchain@nightly-2026-08-01`;
- sanitizer command now uses `cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std`;
- build matrix no longer carries a floating `stable` Rust entry.

`.github/workflows/rust.yml`:

- pinned to `dtolnay/rust-toolchain@1.97.1`;
- otherwise left intact pending Stage 1 consolidation review.

Workflow responsibilities after review:

| Workflow | Current responsibility | Stage 1 consolidation proposal |
| --- | --- | --- |
| `.github/workflows/ci.yml` | Primary CI: fmt, Clippy, check, tests, features, sanitizer, benchmarks, release build. | Keep as the canonical workflow and split/rename jobs if needed. |
| `.github/workflows/rust.yml` | Legacy duplicate: build, Z3 check, tests on `main`. | Delete or fold into `ci.yml` after confirming branch protection does not require the `Rust / build` check name. |

## Sanitizer Status

Pinned sanitizer toolchain:

```text
nightly-2026-08-01-x86_64-unknown-linux-gnu
rustc 1.99.0-nightly (ad3d0bc14 2026-07-31)
```

Local sanitizer command executed:

```bash
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std
```

Result:

```text
pass
181 library tests passed
```

Note: an earlier warm-up `cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std` also passed but did not include sanitizer env vars, so it is not counted as the sanitizer proof.

## Commands Executed

Stable mandatory gate:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Additional stabilization checks:

```bash
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo test --test benchmarks --release
cargo check --features z3
cargo check --features llm
cargo check --features notifier
cargo check --features sgx
cargo check --features svm
cargo check --no-default-features
python3 -c 'import pathlib, yaml; paths=[pathlib.Path(".github/workflows/ci.yml"), pathlib.Path(".github/workflows/rust.yml")]; [yaml.safe_load(path.read_text()) for path in paths]; print("validated", ", ".join(str(path) for path in paths))'
rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy
rustup toolchain install nightly-2026-08-01 --profile minimal --component rust-src
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std
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
| `cargo check --features z3` | pass |
| `cargo check --features llm` | pass |
| `cargo check --features notifier` | pass |
| `cargo check --features sgx` | pass |
| `cargo check --features svm` | intentional fail |
| `cargo check --no-default-features` | expected fail |
| workflow YAML parse with PyYAML 6.0.3 | pass |
| pinned nightly ASan library test | pass |

Repeated future-incompatibility warnings remain from dependencies:

```text
proc-macro-error2 v2.0.1
nix v0.30.1 in the nightly build-std/sanitizer path
```

## Known Unsupported Configurations

`cargo check --no-default-features` is unsupported in the current v0.1 monolith. It fails because common, engine, oracle, EVM, and hybrid modules directly reference REVM/Alloy/EVM types while the `evm` feature removes the corresponding modules and optional dependencies. This is a Stage 2 core/workspace extraction issue, not a Stage 0.5 lint cleanup issue.

`cargo check --features svm` remains intentionally unsupported. The crate-root compile guard fails with:

```text
The `svm` feature is intentionally unsupported: the Solana/Mollusk executor is quarantined until rebuilt and tested. Use the default EVM engine.
```

Stage 0 observed that a cold SVM feature build can still resolve/download optional Solana dependencies before reaching the intentional compile failure. The later fix should quarantine SVM outside the supported dependency graph rather than making the prototype production-functional.

## Behavioral Risk Assessment

Risk is low but not zero:

- most Rust edits are idiomatic Clippy rewrites with equivalent behavior;
- the private telemetry helper now accepts a private struct instead of eight separate arguments, but it records the same values at the same call sites;
- test modules were reordered only to satisfy item-order linting;
- test/config fixtures now use struct literals instead of mutating default values;
- no fuzzing input semantics, corpus layout, scheduler policy, mutator behavior, executor behavior, oracle policy, artifact schema, or AI behavior was intentionally changed.

## Readiness Decision

Stage 0.5 is ready for review.

Mandatory stable-toolchain gates are green:

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Do not begin Stage 1 automatically. The next approved step should be a short Stage 1 repository hygiene/documentation pass, then Stage 2 should target `rustyfuzz-core` and the clean semantic `EvmInput` model.
