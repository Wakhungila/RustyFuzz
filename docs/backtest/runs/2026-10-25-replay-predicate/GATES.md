# Baseline rerun after predicate replay verification

Measured 2026-10-25 (Africa/Nairobi), runtime commit `39b25e6346e88fc5efb6588eae98d1ef524c021e`.
The RPC answered as Ethereum mainnet and returned pinned block 15201793 with the hash in [measurement.json](measurement.json). The repository config was left untouched; a temporary config used this verified block instead of the unreachable root pin.

The seven-case rubric remains **0 rediscovered, 5 misses against fixture expectations, 2 inconclusive historical cases**. These are not five failed on-chain rediscoveries. Raw outputs and provenance are retained beside this report; the aggregate is in [baseline_report.json](baseline_report.json).

## Five expectation-only fixtures

The validator reconstructs synthetic observations from the fixture descriptions. Its `executed: true`, recorded replay success, and signal timing/counts do not measure EVM execution or fuzz-search performance. In particular, the source fixture's `foundry_poc_generated: true` is an expectation, not an observed PoC.

| Case | Predicate | Original-state check | Tier | PoC generation | PoC validation |
|---|---|---|---|---|---|
| `known-bridge-nonce-replay` | absent | not attempted; verified=false | `replayed_minimized` | not reached | not attempted |
| `known-erc20-bad-mint-inflation` | absent | not attempted; verified=false | `replayed_minimized` | not reached | not attempted |
| `known-flashloan-price-manipulation` | absent | not attempted; verified=false | `replayed_minimized` | not reached | not attempted |
| `known-read-only-reentrancy` | absent | not attempted; verified=false | `replayed_minimized` | not reached | not attempted |
| `known-uninitialized-proxy-takeover` | absent | not attempted; verified=false | `replayed_minimized` | not reached | not attempted |

All five have `replay_result: verified` for reconstructed observations and lack a typed `violation_predicate`. They therefore cannot verify the original-state violation or become confirmed. Their only missing named success criterion is `foundry_poc_generated`, but the first blocker is predicate availability. The generic runner reason mentioning replay failure must not be read as an attempted original-state replay rejection.

## Historical cases

| Case | First blocker | Predicate / original-state check / tier | PoC generation / validation |
|---|---|---|---|
| `historical-audius-governance-reinitialization-2022` | unsupported `provider_replay_only` | not reached / not attempted / unavailable | not reached / not attempted |
| `historical-euler-finance-donate-liquidation-2023` | unsupported `provider_replay_only` | not reached / not attempted / unavailable | not reached / not attempted |

Neither historical sequence executed. Independent provider calls cannot establish committed state across a transaction sequence; the runner rejects this fixture mode. The raw failure results use `SyntheticRegression` as a fallback evidence class, which does not describe historical execution. The historical manifests and explicit execution failure determine the scope here.

## Implementation decision

**Finish the benchmark proof path first.** This measurement establishes missing predicate construction and unsupported replay setup, rather than a failed invariant replay, a failed target-suite PoC, or a search-grammar miss.

Connect authored predicates and binding manifests to stateful executable benchmark replay, preserve their evidence on candidates, and run original-state verification before confirmation. Supply verified replay material for historical fixtures; keep legacy expectation fixtures explicitly synthetic.

Acceptance checks:

- An existing executable vulnerable control reaches predicate evaluation and original-state replay; its safe counterpart does not confirm.
- Recorded violating terms with a satisfied fresh replay are rejected.
- Confirmation tier is assigned from actual gate evaluation, never from a fixture expectation.
- PoC generation and validation are reported separately, with not-attempted distinct from failure.

The local fixture path in `src/engine/benchmark.rs::execute_local_fixture` builds proofs from synthetic observations and calls `verify_against`; it neither loads the invariant registry nor calls `verify_original_state`. Adding invariant checking to the campaign therefore cannot change these five fixture results. The `ExecutableEvm` branch currently records matching signals without building a proof. That is the integration seam to address; declarations in a fixture must not be promoted into proof.

Action grammar and target-suite PoCs remain downstream. Z3 remains disabled pending explicit owner approval.

## Reproduction

Use the configured RPC with `RUSTYFUZZ_RPC_API_KEY` unset and the allowed origin recorded in `measurement.json`. In a temporary copy of the root config, set `fork_block = 15201793`; keep endpoint credentials out of reports. Build the dev binary with the single-job/debug-disabled environment from the handoff, then run the two validate commands listed in `measurement.json` with absolute repository paths. `RUSTYFUZZ_RUN_FORGE_TESTS=1` was set; no PoC reached validation.

Regenerate the aggregate with the retained validation files using `cargo run --offline --locked -p rustyfuzz-backtest --bin baseline_report -- <historical.json> <known_vulnerable.json> <baseline_report.json>`, setting `GIT_COMMIT_HASH` and `GIT_WORKING_TREE` to the measured source identity. Regenerate this gate analysis with `python3 docs/backtest/runs/2026-10-25-replay-predicate/summarize.py`.
