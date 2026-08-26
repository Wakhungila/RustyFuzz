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
