# Security

Status: CURRENT project policy.

RustyFuzz is a defensive smart-contract fuzzing tool. Repository work should
focus on engine correctness, deterministic replay, artifact integrity, and
evidence quality.

Do not use this repository workstream for:

- bug-bounty hunting;
- target exploitation;
- live attack activity;
- unrelated security testing.

Operational guidance:

- Do not commit RPC credentials, API keys, private keys, or `.env` files.
- Do not serialize secrets into run artifacts.
- Sanitize RPC URLs before logging or persisting them.
- Keep external-RPC tests optional and out of mandatory CI.
- Treat generated PoC projects as artifacts until explicitly curated as fixtures.

Report suspected vulnerabilities in RustyFuzz itself through the repository's
normal private disclosure channel once one is configured. Until then, avoid
publishing exploit-ready details in public issue text.

## Dependency vulnerability acceptance

The repository has a formal, fail-closed dependency policy at
`security/vulnerability-policy.json`. The previous `RUSTSEC-2025-0055` exception
was removed by upgrading REVM to `43.0.3`, which moves the Arkworks dependency
path to the patched `tracing-subscriber 0.3.23` line. The current supported EVM
graph has no accepted vulnerability exception.

`scripts/validate_vulnerability_policy.py` validates the policy against both
`cargo audit --json` output and `cargo metadata`. It rejects any vulnerability,
the reintroduced vulnerable package/version, a non-EVM build scope, or any
global cargo-audit ignore.
