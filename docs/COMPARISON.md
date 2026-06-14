# RustyFuzz vs ityfuzz Comparison

## Overview

This document provides a technical comparison between RustyFuzz and ityfuzz, two EVM fuzzing tools for smart contract security research.

## Architecture

### RustyFuzz

- **Language**: Rust
- **Fuzzing Engine**: LibAFL
- **EVM Execution**: revm (Rust EVM implementation)
- **State Management**: Fork-based with CacheDB wrapper for determinism
- **Mutation**: ABI-aware with concolic hints
- **Feedback**: Multi-signal (coverage, state novelty, oracle findings, economic pressure)
- **Scheduler**: Custom LibAFL scheduler (CampaignScore)

### ityfuzz

- **Language**: Rust
- **Fuzzing Engine**: Custom AFL-style implementation
- **EVM Execution**: revm
- **State Management**: Fork-based
- **Mutation**: Grammar-based with EVM-specific mutations
- **Feedback**: Coverage-based
- **Scheduler**: Standard AFL scheduler

## Key Differences

### State Management

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Fork Caching | Persistent CacheDB with lazy RPC loading | Fork-based with state snapshots |
| Offline Execution | Full offline support after initial caching | Limited offline support |
| State Replay | Deterministic replay against cached state | Replay against snapshots |
| RPC Integration | Lazy loading with differential verification | Direct RPC calls |

### Mutation Strategies

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| ABI Awareness | Dynamic type mutation through alloy-dyn-abi | Grammar-based mutations |
| Concolic Solving | Deterministic taint-guided expression solver | Limited concolic support |
| Semantic Chaining | Data flow across transactions | Transaction-level mutations |
| MEV Patterns | Flashloan wrapping, sandwich attacks | Basic transaction sequences |
| Value Mutation | Boundary-aware (min/max, powers of 2) | Random value mutation |

### Feedback Signals

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Coverage | AFL-style edge coverage with hitcount bucketing | Basic edge coverage |
| State Novelty | Storage transitions, read/write patterns, call-graph edges | Limited state tracking |
| Oracle Detection | Protocol-specific oracles (ERC20, ERC4626, AMM, lending) | Generic oracle detection |
| Economic Pressure | Balance deltas, share inflation/deflation | Not implemented |
| Scheduling | Custom CampaignScore with multiple factors | Standard AFL energy scheduling |

### Protocol Oracles

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| ERC20 | Token balance accounting, allowance behavior | Basic token checks |
| ERC4626 | Share inflation, rounding, redemption desynchronization | Not implemented |
| AMM | Reserve asymmetry, oracle price staleness | Basic AMM checks |
| Lending | Bad-debt accumulation, liquidation paths | Basic lending checks |
| Governance | Timelock bypass, vote manipulation | Not implemented |

### Crash Handling

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Minimization | Sequence minimization to shortest reproduction | Basic minimization |
| PoC Generation | Foundry PoC scaffolds with assertions | Simple transaction replay |
| Evidence | Oracle evidence, storage diffs, call traces | Limited evidence |
| Replay Verification | Differential replay (cached vs live RPC) | Basic replay verification |

### Configuration

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Configuration File | TOML-based config.toml | CLI arguments only |
| Campaign Isolation | Campaign-specific directories with campaign_id | Limited isolation |
| Seed Bundles | Persistent seed bundles with metadata | Basic seed files |
| ABI Integration | Dynamic ABI ingestion and caching | Limited ABI support |

### Performance

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Execution Speed | Deterministic revm with CacheDB | revm with snapshots |
| Memory Usage | Backpressure mechanisms (waypoint limits, memory monitoring) | Basic memory management |
| Parallelism | LibAFL brokered multi-core with shared corpus | Multi-process with shared memory |
| RPC Rate Limiting | Configurable rate limiting for seed discovery | Not implemented |

### Development Features

| Feature | RustyFuzz | ityfuzz |
|---------|-----------|---------|
| Benchmarking | Comprehensive validation framework (local, live-fork, cached-fork, historical) | Basic benchmarking |
| Seed Intelligence | Semantic seed analysis with confidence scoring | Limited seed analysis |
| Target Profiling | ABI, bytecode, and harness-based profiling | Basic target analysis |
| Invariant Generation | Protocol-specific invariant manifests | Not implemented |
| AI Integration | Satori AI audit harness (optional) | Not implemented |

## Use Case Comparison

### RustyFuzz Strengths

- **Multi-transaction exploits**: Designed for state-machine bugs where state carries meaning across transactions
- **Protocol-specific detection**: Specialized oracles for DeFi protocols (AMM, lending, governance)
- **Economic attack detection**: Economic delta scoring for profit/loss analysis
- **Reproducible findings**: Deterministic execution with comprehensive evidence
- **Advanced mutation**: Concolic hints and semantic chaining for complex path exploration
- **Production readiness**: CI-friendly operation with structured output and validation gates

### ityfuzz Strengths

- **Simplicity**: Easier to set up and use for basic fuzzing
- **Speed**: Faster execution for simple use cases
- **Grammar-based**: Well-suited for grammar-based contract testing
- **Lightweight**: Lower resource requirements

## When to Use Each

### Use RustyFuzz When

- Testing complex DeFi protocols with multi-transaction flows
- Need protocol-specific oracle detection (ERC4626, AMM, lending, governance)
- Require economic attack detection and profit/loss analysis
- Need reproducible findings with comprehensive evidence
- Testing against forked mainnet state with offline capability
- Require advanced mutation strategies (concolic, semantic chaining)
- Need CI/CD integration with validation gates

### Use ityfuzz When

- Performing basic fuzzing of simple contracts
- Need quick results with minimal setup
- Testing grammar-based contracts
- Resource-constrained environments
- Single-transaction vulnerability testing
- Learning EVM fuzzing concepts

## Technical Implementation Details

### RustyFuzz Implementation

```rust
// Core execution flow
EvmInput (sequence of transactions)
  ↓
[ABI-aware mutation + concolic hints]
  ↓
[Deterministic revm executor against CacheDB state]
  ↓
SequenceExecutionResult (canonical artifact)
  ├─ per-tx gas, status, output
  ├─ cumulative coverage hash
  ├─ storage reads/writes/diffs
  ├─ call/create trace
  ├─ oracle findings
  └─ branch/value frontier evidence
  ↓
[Coverage + State novelty + Oracle pressure + Concolic hints]
  ↓
[Campaign scoring and LibAFL scheduler]
  ↓
[Persistent corpus + replay + minimization + PoC generation]
```

### ityfuzz Implementation

```
Input generation
  ↓
[Grammar-based mutation]
  ↓
[revm execution]
  ↓
[Coverage feedback]
  ↓
[AFL scheduling]
  ↓
[Corpus management]
```

## Resource Requirements

### RustyFuzz

- **Memory**: Minimum 2GB (configurable backpressure)
- **CPU**: Multi-core recommended (LibAFL brokered)
- **Storage**: Corpus, fork caches, reports (varies by campaign)
- **Network**: RPC endpoint for initial fork caching

### ityfuzz

- **Memory**: Lower baseline requirements
- **CPU**: Multi-process support
- **Storage**: Corpus and crash files
- **Network**: RPC endpoint for fork setup

## Limitations

### RustyFuzz Limitations

- Complexity: Steeper learning curve for advanced features
- Resource usage: Higher memory and CPU requirements
- Setup time: Requires ABI ingestion and seed discovery for optimal results
- Protocol-specific: Optimized for EVM/DeFi, not general-purpose

### ityfuzz Limitations

- Limited multi-transaction support
- Basic mutation strategies
- No protocol-specific oracles
- Limited economic attack detection
- Less comprehensive evidence collection

## Conclusion

RustyFuzz and ityfuzz serve different use cases in the EVM fuzzing ecosystem:

- **RustyFuzz**: Production-grade fuzzer for complex DeFi protocols with multi-transaction exploits, protocol-specific detection, and comprehensive evidence collection
- **ityfuzz**: Lightweight fuzzer for basic contract testing with simpler setup and faster execution

The choice between them depends on the complexity of the target protocol, the depth of analysis required, and available resources.
