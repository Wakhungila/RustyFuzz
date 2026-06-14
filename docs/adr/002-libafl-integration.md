# ADR 002: LibAFL Integration

## Status
Accepted

## Context
RustyFuzz needs a fuzzing engine to drive mutation, corpus management, and coverage-guided exploration. Several options exist including writing a custom engine, using AFL++, or integrating with LibAFL.

## Decision
RustyFuzz integrates with LibAFL as its primary fuzzing engine, leveraging LibAFL's:
- Coverage-guided mutation strategies
- Corpus management and minimization
- Multi-process fuzzing capabilities
- Feedback mechanisms

## Rationale
1. **Native Rust Integration**: LibAFL is written in Rust, enabling seamless integration without FFI overhead
2. **Maturity**: LibAFL is actively maintained and used in production by major projects
3. **Flexibility**: LibAFL's trait-based design allows custom feedback mechanisms and mutators
4. **Performance**: LibAFL is optimized for performance with minimal overhead
5. **Community**: Active community and documentation reduce development time

## Consequences
### Positive
- Leverages battle-tested fuzzing infrastructure
- Enables advanced features like multi-process fuzzing out of the box
- Reduces maintenance burden for core fuzzing logic

### Negative
- Dependency on external library with potential API changes
- Learning curve for LibAFL's trait system
- Some LibAFL features may not align perfectly with EVM-specific needs

## Alternatives Considered
1. **Custom Fuzzing Engine**: Would require significant development effort and maintenance
2. **AFL++ Integration**: Would require FFI bindings and has less Rust-native support
3. **Honggfuzz Integration**: Similar limitations to AFL++

## Implementation Notes
- RustyFuzz implements custom feedback mechanisms (EvmCoverageFeedback, EvmStateNoveltyFeedback) using LibAFL's traits
- UsesState trait migration was required due to LibAFL API changes (see feedback.rs)
- Custom mutators are implemented for EVM-specific mutations (calldata, addresses, values)
