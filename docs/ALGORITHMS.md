# Algorithm Explanations

This document explains the key algorithms used in RustyFuzz for concolic solving and dependency analysis.

## Concolic Solving

### Overview

Concolic (concrete-symbolic) solving in RustyFuzz combines concrete execution with symbolic reasoning to generate input mutations that explore alternative execution paths. The algorithm analyzes execution waypoints (comparisons, branches, arithmetic operations) and computes input values that would flip these conditions.

### Algorithm Steps

1. **Waypoint Collection**: During execution, the inspector records waypoints for:
   - Branch decisions (taken/not taken)
   - Comparison operations (EQ, LT, GT, etc.)
   - Arithmetic operations (ADD, SUB, MUL, DIV)
   - Taint sources (calldata, storage, caller, msg.value)

2. **Symbolic Expression Tracking**: For each tainted value, the solver builds a symbolic expression tree:
   ```
   Source → Add(Source, Constant(5)) → Mul(Source, Constant(2))
   ```

3. **Constraint Solving**: For each waypoint, the solver computes a target value:
   - **Comparison Flip**: If `x < y` was false, compute `x = y - 1`
   - **Branch Flip**: If branch was taken, compute input to not take it
   - **Arithmetic Boundary**: Compute values near overflow/underflow points

4. **Expression Backtracking**: The solver backtracks through symbolic expressions to find the source input:
   ```
   Target: x = 42
   Expression: x = calldata + 5
   Solution: calldata = 42 - 5 = 37
   ```

5. **Hint Generation**: The solver produces `ConcolicHint` objects containing:
   - Target value (as 32-byte word)
   - Repair target (calldata, caller, or msg.value)
   - Strategy (flip comparison, flip branch, arithmetic boundary)

### Example

```rust
// Execution waypoint: LT comparison at PC 100
Waypoint::Comparison {
    op: 0x10,  // LT
    lhs: U256::from(10),
    rhs: U256::from(20),
    condition: false,  // 10 < 20 was false (impossible, but for illustration)
    taint_source: Some(TaintSource::Calldata(4)),
    tainted_operand: ComparisonOperand::Lhs,
    ...
}

// Solver computes: to make 10 < 20 true, we need lhs >= 20
// Since lhs is tainted from calldata, we set calldata[4] = 20
```

### Timeout Enforcement

The concolic solver includes timeout enforcement to prevent unbounded solving:
- Default timeout: 1 second per solving operation
- Timeout checked before and during complex solving
- Returns `None` if timeout exceeded

## Dependency Analysis

### Overview

Dependency analysis identifies dataflow relationships between storage slots and calldata parameters. This enables the fuzzer to understand which inputs affect which contract state, enabling more targeted mutations.

### Algorithm Steps

1. **Storage Access Tracking**: During execution, track all storage reads and writes:
   ```
   StorageRead { slot: 0x0, value: 100, pc: 100 }
   StorageWrite { slot: 0x0, value: 200, pc: 200 }
   ```

2. **Taint Propagation**: Track how tainted values flow through the EVM:
   - Calldata parameters are initially tainted
   - Storage reads inherit taint from calldata that wrote them
   - Arithmetic operations propagate taint through expressions

3. **Dependency Graph Construction**: Build a graph of dependencies:
   ```
   calldata[4] → storage[0x0] → calldata[8]
   ```

4. **Flow Template Generation**: Generate template inputs that exercise specific dataflow paths:
   - Identify critical storage slots
   - Generate inputs that modify those slots
   - Chain operations to create complex dependencies

### Example

```rust
// Execution trace:
// 1. User calls transfer(amount) with calldata[4] = amount
// 2. Contract reads balances[caller] from storage[0x0]
// 3. Contract writes balances[caller] -= amount
// 4. Contract emits Transfer event

// Dependency graph:
// calldata[4] (amount) → storage[0x0] (balances[caller])

// Flow template:
// Generate input that sets amount to boundary values
// to test balance underflow/overflow conditions
```

## Mutation Strategies

### Overview

RustyFuzz implements domain-specific mutation strategies that understand EVM semantics:

1. **ABI-Aware Mutations**: Mutate calldata according to function signatures:
   - Parse function selector and argument types
   - Mutate individual arguments with type-aware strategies
   - Preserve ABI structure while exploring values

2. **Concolic Mutations**: Apply concolic hints to explore new paths:
   - Flip comparison conditions
   - Flip branch decisions
   - Explore arithmetic boundaries

3. **Semantic Chaining**: Chain transactions based on contract relationships:
   - Identify downstream contracts (e.g., DEX pairs)
   - Generate calls that follow protocol flow
   - Build multi-step exploit sequences

4. **Economic Pressure**: Mutate values to trigger economic vulnerabilities:
   - Set amounts near protocol limits
   - Manipulate oracle prices
   - Create flashloan scenarios

5. **MEV Patterns**: Generate MEV-specific transaction sequences:
   - Sandwich attacks (frontrun + victim + backrun)
   - Oracle manipulation
   - Arbitrage opportunities

## Backpressure Mechanisms

### Overview

To prevent resource exhaustion, RustyFuzz implements backpressure mechanisms:

1. **Sequence Length Limit**: Maximum 100 transactions per input
   - Enforced in all mutation strategies
   - Prevents unbounded sequence growth

2. **Waypoint Accumulation Limit**: Maximum 1000 waypoints per transaction
   - Truncates oldest waypoints when limit exceeded
   - Keeps most recent waypoints (more relevant for concolic solving)

3. **Total Waypoint Limit**: Maximum 10000 waypoints across all transactions
   - Removes waypoints from earlier transactions when limit exceeded
   - Prioritizes recent execution context

4. **Memory Usage Monitoring**: Maximum 2GB memory usage
   - Monitors via /proc/self/status on Linux
   - Triggers backpressure when limit approached

5. **Decode Cache Limit**: Maximum 10000 entries
   - LRU cache for decoded calldata
   - Evicts least recently used entries

## Performance Considerations

### Concolic Solving

- **Complexity**: O(n) where n is number of waypoints
- **Timeout**: 1 second default to prevent hanging
- **Caching**: ABI types and decoded values cached

### Dependency Analysis

- **Complexity**: O(m) where m is number of storage accesses
- **Optimization**: Only track tainted storage slots
- **Pruning**: Remove irrelevant dependencies

### Mutation

- **Complexity**: O(k) where k is number of transactions
- **Parallelism**: Multiple workers can mutate independently
- **Prioritization**: Concolic hints prioritized over random mutations
