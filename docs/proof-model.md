# Proof Model

Proof mode is implemented by `RealismVerifier` and `EvmExecutor::proof()`.

Proof execution:

- does not fund callers,
- does not cap transaction value,
- does not invent allowances,
- does not invent privileged roles,
- runs against the provided pinned fork state,
- replays the exact transaction sequence twice and rejects nondeterminism.

Current rejection reasons include missing balance, nondeterminism, replay failure,
synthetic-funding dependency, missing allowance, privileged role dependency, oracle
weakness, minimization loss, and out-of-scope evidence.
