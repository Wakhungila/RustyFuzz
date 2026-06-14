# Snapshot Scheduling Plan

Practical target: tune snapshot scheduling against known-bug benchmark classes before running Coinbase campaigns.

## Current RustyFuzz Position

RustyFuzz now stores post-transaction snapshots as first-class fuzz states and scores them with component signals: coverage, branch distance, comparison distance, oracle proximity, asset-delta proximity, storage-slot sensitivity, call-depth novelty, selector novelty, revert reason novelty, event novelty, and state-transition rarity.

The new scheduler profile hook derives `SnapshotScoreWeights` from known-bug metadata. This lets benchmark manifests and targeted campaigns emphasize different state frontiers:

- Spend-permission and allowance bugs: storage-slot sensitivity, selector novelty, branch frontier, oracle proximity.
- ERC4626/share/donation/accounting bugs: asset deltas, oracle proximity, storage sensitivity, rare state transitions.
- Access-control/proxy/upgrade bugs: branch distance, comparison distance, selector novelty, implementation/admin storage sensitivity.
- Bridge replay/finalization bugs: selector novelty, call depth, rare state transitions, event novelty.
- Oracle/price bugs: oracle proximity, event novelty, call depth, comparison distance.

## Coinbase Initial Use

The first selected product-family campaign is Spend Permissions because it exercises authorization, signature-domain, replay, allowance, router, and ERC-6492 surfaces without requiring a whole-scope fuzz campaign.

The Spend Permissions campaign should use a scheduler profile equivalent to `SnapshotScoreWeights::for_known_bug_class("spend permission allowance replay router")` and must keep any exploration-only findings at lead grade until replay, minimization, realistic proof, and PoC generation all succeed.

## Comparison To ItyFuzz

ItyFuzz's practical advantage is snapshot evolution: it treats intermediate states as search frontiers and spends energy on states near exploit waypoints. RustyFuzz is now closer on mechanics, but the live-audit value comes from stricter proof gating: snapshots can generate leads, but promotion still requires deterministic replay, minimization, realistic-fork proof, and a generated test artifact.

The immediate tuning goal is therefore not higher raw candidate volume. It is better state selection for known bug classes while preserving the false-positive firewall.
