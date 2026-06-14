# ADR 004: Oracle-Based Vulnerability Detection

## Status
Accepted

## Context
RustyFuzz needs to detect vulnerabilities in smart contracts. Approaches include:
1. Generic crash/panic detection
2. Property-based testing with invariants
3. Oracle-based detection using domain-specific vulnerability patterns

## Decision
RustyFuzz adopts oracle-based vulnerability detection as the primary detection mechanism, implementing:
- Protocol-specific oracles (ERC20, ERC4626, AMM, Governance, Lending)
- General-purpose oracles (Reentrancy, Access Control, Integer Overflow)
- Oracle pack system for composing multiple detectors
- Economic pressure tracking for financial vulnerabilities

## Rationale
1. **Precision**: Oracle-based detection provides higher precision than generic crash detection
2. **Domain Knowledge**: Encodes security researcher expertise into reusable detectors
3. **Composability**: Oracle pack system allows combining multiple detectors
4. **Actionable Findings**: Oracles provide structured evidence (storage diffs, call traces) for PoC generation
5. **Economic Focus**: Financial vulnerability detection aligns with DeFi security priorities

## Consequences
### Positive
- Higher-quality findings with structured evidence
- Reusable detection logic across different protocols
- Enables automatic PoC generation from oracle observations
- Supports economic impact analysis via profit/loss tracking

### Negative
- Requires manual oracle implementation for new vulnerability types
- May miss novel vulnerability patterns not covered by existing oracles
- Oracle maintenance burden as protocols evolve
- False positives possible if oracle logic is too broad

## Alternatives Considered
1. **Generic Crash Detection**: Would miss many DeFi-specific vulnerabilities that don't cause crashes
2. **Pure Property-Based Testing**: Would require extensive invariant specification for each protocol
3. **ML-Based Detection**: Would require large training datasets and may lack explainability

## Implementation Notes
- ProtocolOraclePack provides pre-configured oracles for common DeFi primitives
- VulnerabilityOracle trait allows custom oracle implementation
- Oracle observations are persisted in corpus for offline analysis
- Oracle findings drive Foundry PoC generation with specific assertions
