# Architecture

RustyFuzz is currently an EVM-first research engine.

- CLI entrypoints live in `src/main.rs`.
- Campaign orchestration lives in `src/engine/fuzz_engine.rs`.
- EVM execution lives in `src/evm/executor.rs`.
- Deterministic replay and realistic proof validation live in `src/common/verifier.rs`.
- Persistent corpus, campaign artifacts, and evolving snapshots live in `src/evm/corpus.rs`.
- Seed discovery lives in `src/evm/seed_ingester.rs`.
- Protocol finding promotion lives in `src/engine/promotion.rs`.

Execution is split into exploration and proof modes. Exploration may use synthetic
funding and value bounding to discover candidate behavior. Proof mode does not.

SVM is quarantined as unsupported. SGX has an unsupported status shim only.
