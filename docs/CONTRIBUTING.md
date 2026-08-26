# Contributing

Status: CURRENT policy for the re-engineering branch.

Before changing production Rust code:

- read `docs/reengineering/CODEBASE_INVENTORY.md`;
- preserve the Stage 0.5 green gate;
- keep changes small and reviewable;
- do not combine module moves, behavior changes, and new features in one patch;
- do not make unsupported SVM/SGX code part of the supported build graph;
- do not rely on external RPC availability for default tests.

Required validation:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

For architecture work, document decisions in `docs/adr/` before implementing
them. Target architecture claims must be labeled TARGET until implemented.
