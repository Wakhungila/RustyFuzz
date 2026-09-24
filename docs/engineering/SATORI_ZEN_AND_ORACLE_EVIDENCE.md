# Zen and executable oracle evidence

Satori uses OpenCode Zen chat completions, with `big-pickle` as its default.
Build with `--features llm` and provide `OPENCODE_API_KEY` in the process environment.
`cargo run --features llm --locked --bin rusty-fuzz -- satori model PATH --model big-pickle`
executes model analysis. `opencode/big-pickle` is also accepted.

The supported free chat model IDs are defined in `src/satori/reasoning/zen_client.rs`,
reviewed against https://opencode.ai/docs/zen/ on 2026-09-23. Paid, unknown, Responses,
and SystemOne models are rejected. There is no paid fallback. Free availability and
pricing are controlled by the provider; the allowlist is not a permanent price
promise. Use a Zen account without paid credits/auto-reload if zero spending must
be enforced independently of future provider price changes.

Zen's documentation states that some free offerings may use collected data to
improve models. Audit source snippets are sent to Zen when model analysis runs.
The client uses a fixed HTTPS endpoint, disallows redirects, limits response size
to 1 MiB, bounds request time, retries only rate limits/server errors, requires a
complete JSON object, and namespaces its atomic cache by provider/protocol/model.
HTTP error bodies and credentials are not included in application errors.
A model hypothesis still requires independent execution and economic/invariant
confirmation. Switching providers does not make a model response exploit proof.

## Authorization observations

The mint rule requires a successful preceding `canMint(address)` call on the same
token, identifying the mint caller, returning ABI false. A subsequent successful
nonzero mint with increasing token storage contradicts that explicit policy.
Intervening target storage changes invalidate the policy observation. An unrelated
revert never changes authorization. No owner, admin, or minter role is invented.

This is an explicit contract-policy adapter, not universal ERC20 role discovery:
`canMint` is not part of ERC20. Unknown policies cannot establish unauthorized
minting. A non-owner can be a legitimate minter; `owner()` alone is insufficient.
A policy contradiction is a heuristic requiring supply/balance confirmation;
malicious/incorrect policy views or delegated authorization require further analysis.

The vault rule requires a successful nonzero deposit, an actual transferFrom into
the vault, and zero returned shares. A standalone conversion quote returning zero
is not an exploit. The executable positive fixture separately asserts zero victim
shares and attacker asset gain. Reserve movement and no-debt-write lending rules
remain heuristics, not general economic proofs.

## Historical evidence

Stateful replay must execute locally against a pinned fork or explicit cached
state. `provider_replay_only` fails with an actionable error. Local replay errors
are not replaced with independent eth_call requests. The old synthetic coverage
edge and manifest-derived historical finding functions have been removed.
A manifest class is a matching criterion, never evidence that an exploit occurred.

## Scope of measurements

The paired suites execute ten safe and five deliberately vulnerable mechanism
fixtures. They are regression evidence, not a historical discovery benchmark.
They do not establish time-to-discovery, seed robustness, full protocol coverage,
or economic proof across deployed contracts. Do not count repeated deterministic
fixture replay as independent randomized fuzzing trials.

Unmatched bridge signals on mint, access-control signals on permissionless
post-timelock execution, and generic accounting signals on repayment remain visible.
They are not proof of those vulnerabilities. Primary-class false-positive rates
must not be described as absence of all oracle noise.

Production effectiveness still requires independent exploit/patch pairs at pinned
chain states, campaign runs over multiple recorded RNG seeds and fixed budgets,
wall-clock/execution time to first independently confirmed finding, and both
false-positive and missed-vulnerability rates. No such measurement is inferred
from a successful build, fixture assertion, or generated PoC scaffold.

Research references: https://arxiv.org/abs/2306.17135 (ItyFuzz snapshot/waypoint
exploration) and the author's list at
https://arxiv.org/search/cs?searchtype=author&query=Shou,+C . The router threat model
at https://arxiv.org/abs/2604.08407 motivates treating provider responses as
untrusted proposals, not privileged instructions or validation evidence.
