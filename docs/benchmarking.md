# Benchmarking

> **SUPERSEDED:** This lowercase document is retained for historical context.
> The canonical benchmarking document is `docs/BENCHMARKING.md`.

Benchmark manifests live under `benchmarks/`.

A benchmark should define:

- expected bug class,
- target address or fixture contract,
- required seeds or fixture state,
- expected oracle,
- replay expectation,
- proof expectation,
- PoC artifact expectation.

Failure reports should distinguish seed discovery, search, oracle, replay, proof
realism, and PoC generation failures.
