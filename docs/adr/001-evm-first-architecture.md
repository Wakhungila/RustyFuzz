# ADR 001: EVM-First Architecture

## Status
Accepted

## Context
RustyFuzz is designed to be a multi-chain fuzzer supporting EVM, Solana (SVM), and potentially other VMs. However, the initial implementation focuses primarily on EVM-based smart contracts.

## Decision
RustyFuzz adopts an EVM-first architecture with the following characteristics:
- EVM execution engine is the primary and most mature component
- SVM and SGX support are marked as experimental and disabled by default
- All core fuzzing infrastructure (LibAFL integration, corpus management, oracles) is designed around EVM semantics
- Future SVM/SGX support will follow the same architectural patterns established for EVM

## Rationale
1. **Market Demand**: EVM-based DeFi protocols represent the largest target market for smart contract fuzzing tools
2. **Maturity of Tooling**: EVM has the most mature ecosystem (revm, foundry, hardhat) to build upon
3. **Complexity**: EVM smart contracts exhibit complex economic interactions that benefit most from fuzzing
4. **Resource Constraints**: Limited development resources necessitate focusing on one VM first
5. **Learning Curve**: EVM is more widely understood by security researchers, lowering adoption barriers

## Consequences
### Positive
- Faster time-to-market for EVM-focused features
- Higher quality EVM implementation due to focused development
- Clear migration path for future VM support (SVM, SGX)

### Negative
- SVM and SGX features remain experimental and incomplete
- Potential technical debt when adding multi-VM support later
- May limit initial adoption in non-EVM ecosystems

## Alternatives Considered
1. **Multi-VM from Start**: Would have required significantly more development time and resources
2. **SVM-First**: Less market demand and tooling maturity compared to EVM
3. **Plugin Architecture**: Would add complexity without clear benefit for initial release

## Migration Path
See docs/SVM_MIGRATION.md and docs/SGX_MIGRATION.md for detailed steps to re-enable SVM and SGX support.
