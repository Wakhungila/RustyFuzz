---
name: RustyFuzz
description: High-performance causal state-tree fuzzer for the Ethereum Virtual Machine
---
# RustyFuzz

RustyFuzz is a state-of-the-art, coverage-guided fuzzer optimized for deep-state exploration of the Ethereum Virtual Machine (EVM) and the Solana Virtual Machine (SVM). Built on the `revm` and `mollusk-svm` engines, it implements causal scheduling and taint-guided concolic execution to identify complex logical and economic vulnerabilities.

## Technical Architecture

### Core Engine
The engine utilizes a custom implementation of `revm::Inspector` for real-time trace analysis.
*   **Execution**: Leverages `revm` for high-throughput transaction processing.
*   **Coverage**: Implements edge hashing (prev_pc XOR curr_pc) via a 64KB bit-vector to track unique execution paths.
*   **Causal Tracking**: Monitors SLOAD/SSTORE operations to establish dataflow dependencies between storage slots and transaction inputs.

### Causal State Management
Unlike linear fuzzers, RustyFuzz maintains a non-linear state tree.
*   **Snapshot Corpus**: Stores complete EVM state snapshots (including `CacheDB`) as nodes in a tree, allowing the fuzzer to branch from any historical state.
*   **Power Scheduling**: Selects snapshots for mutation based on a coverage-weighted algorithm, prioritizing branches that exhibit high code coverage or frequent interaction with "hot" storage slots.
*   **Minimization**: Features a dual-stage minimizer that reduces transaction sequences to the minimal set required to trigger a specific vulnerability (delta debugging) and prunes the corpus of redundant coverage bits.

### Advanced Mutation Strategies
The `EvmMutator` implements several high-fidelity mutation types:
*   **Structural**: Appends or modifies transaction sequences to explore multi-step exploit vectors.
*   **ABI-Aware**: Decodes calldata using provided function selectors and applies type-specific mutations (e.g., boundary values for `uint256`, address randomization, array resizing).
*   **Anchor-Aware (SVM)**: Identifies and mutates 8-byte instruction discriminators and Borsh-serialized account data.
*   **Semantic**: Randomizes callers and account signers to discover unauthorized access vulnerabilities.
*   **Discovery**: Automatically targets contracts discovered within the EVM state during execution.

### Taint-Guided Concolic Solving
Integrated Z3 support enables solving for complex branch constraints.
*   **Taint Propagation**: Tracks calldata provenance through the EVM stack during execution.
*   **Waypoint Capture**: Records comparison operations (LT, GT, EQ) and their symbolic counterparts.
*   **Hint Generation**: Utilizes the Z3 SMT solver to generate precise calldata bytes that satisfy branch conditions, bypassing "magic number" checks.

### Hardware-Backed Security (SGX)
RustyFuzz supports execution within Intel SGX enclaves using `sgx_tstd`.
*   **Confidential Execution**: Keeps the execution state, inspector logic, and discovered coverage data encrypted in memory to prevent leakage on host systems.
*   **Attestation**: Generates hardware-backed reports (EREPORT) that bind a discovered exploit to the enclave's MRENCLAVE identity, providing cryptographic proof of a vulnerability finding.

## Vulnerability Oracles

RustyFuzz implements high-fidelity oracles for detecting sophisticated DeFi exploits:
*   **Read-Only Reentrancy**: Detects temporal inconsistencies by monitoring `STATICCALL` output changes within a single execution sequence.
*   **Economic Profit Oracle**: Tracks fuzzer-controlled balance mappings (ETH and ERC20 storage slots) to identify unauthorized value extraction.
*   **Reentrancy Oracle**: Identifies state-change violations where storage is modified at call depths greater than the entry point.
*   **Systemic State Corruption**: Heuristic detection of "god-mode" exploits that modify a disproportionate amount of contract state.
*   **Solvency and Invariants**: Pluggable modules for monitoring protocol-specific invariants like total assets vs. liabilities.

## Implementation Status

| Component | Status | Description |
| :--- | :--- | :--- |
| EVM Execution | Production | Full Cancun spec support via `revm`. |
| Causal Inspector | Production | Taint tracking and storage read/write sets. |
| Snapshot Corpus | Production | Tree-based state exploration with power scheduling. |
| ABI Mutator | Production | Support for `alloy-dyn-abi` types. |
| Concolic Solver | Beta | Z3 integration (requires `z3` feature). |
| SGX Executor | Alpha | Hardware-backed execution and sealing. |
| SVM Support | Beta | Integration with `mollusk-svm` for Solana. |
| SVM Differential | Beta | Parallel comparison of Mollusk execution with live RPC simulation. |

## Setup and Build

### Prerequisites
*   **Rust**: Stable toolchain (1.75+).
*   **Z3**: Required for concolic solver features (`libz3-dev` on Linux).
*   **SGX SDK**: Required for hardware-backed execution features.

### Installation
```bash
git clone https://github.com/your-repo/RustyFuzz.git
cd RustyFuzz
```

### Compilation
Standard build:
```bash
cargo build --release
```

Build with concolic solving and AI-guidance:
```bash
cargo build --release --features "z3 llm"
```

## Usage

RustyFuzz expects a configuration specifying the target environment and initial state forking.

```rust
use rusty_fuzz::config::Config;
use rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config {
        rpc_url: "https://eth-mainnet.g.alchemy.com/v2/...".to_string(),
        fork_block: Some(19000000),
        ..Default::default()
    };

    run_fuzz_campaign(&config).await
}
```

## License
Distributed under the MIT License.