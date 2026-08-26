# Development

Status: CURRENT.

RustyFuzz currently builds as one Cargo package pinned to Rust 1.97.1 by
`rust-toolchain.toml`.

Required local gate before architectural changes:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Additional Stage 0.5 stabilization checks:

```bash
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo test --test benchmarks --release
cargo check --features z3
cargo check --features llm
cargo check --features notifier
cargo check --features sgx
```

Known unsupported commands:

```bash
cargo check --features svm
cargo check --no-default-features
```

`svm` is intentionally compile-blocked. `--no-default-features` is not coherent
until Stage 2 extracts a REVM-free core crate.

Sanitizer check:

```bash
env RUSTFLAGS=-Zsanitizer=address ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-08-01 test --lib --target x86_64-unknown-linux-gnu -Zbuild-std
```

The sanitizer job uses a pinned nightly separately from the stable project
toolchain.

## Runtime Data

Future runtime output belongs under `.rustyfuzz/`. Current production code still
writes to legacy paths such as `corpus/`, `reports/`, Satori runtime
directories, and benchmark temp locations. Do not commit generated campaign
output. See `docs/reengineering/RUNTIME_DATA_POLICY.md`.
