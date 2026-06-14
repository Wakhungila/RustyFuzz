# ADR 003: Fork-Based Execution

## Status
Accepted

## Context
RustyFuzz needs to execute EVM transactions to detect vulnerabilities. Two primary approaches exist:
1. In-memory execution with manual state management
2. Fork-based execution using RPC endpoints to snapshot chain state

## Decision
RustyFuzz adopts fork-based execution as the primary execution model, using RPC endpoints to:
- Snapshot chain state at specific block heights
- Execute transactions in a forked environment
- Revert state after each execution
- Cache fork state for replay and offline analysis

## Rationale
1. **Realism**: Fork-based execution provides realistic gas costs, precompiles, and chain state
2. **Efficiency**: Avoids manual state setup for complex protocols with extensive dependencies
3. **Reproducibility**: Enables deterministic replay of findings against historical chain state
4. **Scalability**: Fork caching allows offline analysis without continuous RPC access
5. **Mainnet Testing**: Directly tests against deployed contracts rather than local deployments

## Consequences
### Positive
- More realistic execution environment compared to in-memory execution
- Enables testing against actual mainnet state and deployed contracts
- Fork caching reduces RPC dependency for replay and analysis
- Supports historical vulnerability replay (e.g., Euler Finance exploit)

### Negative
- Requires RPC endpoint access (may have rate limits or costs)
- Slower than pure in-memory execution due to network latency
- Dependent on RPC endpoint reliability and availability
- Fork state can become stale if not refreshed

## Alternatives Considered
1. **Pure In-Memory Execution**: Would be faster but less realistic and require extensive manual state setup
2. **Anvil/Hardhat Local Forks**: Would require running local nodes, adding operational complexity
3. **Hybrid Approach**: Would increase complexity without clear benefits over fork-based

## Implementation Notes
- ForkDb implements fork state caching and offline replay support
- PersistentCorpus stores fork cache alongside execution inputs
- Supports multiple RPC endpoints for redundancy
- Implements fork cache invalidation based on block number
