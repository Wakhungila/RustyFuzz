
# RustyFuzz: High-Performance Hybrid Fuzzer for EVM Smart Contracts

![Rust](https://www.pinterest.com/pin/315603886389784971/)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

RustyFuzz is a cutting-edge, coverage-guided fuzzer designed to uncover vulnerabilities in Ethereum Virtual Machine (EVM) smart contracts. Built entirely in Rust, it leverages the `revm` execution engine for unparalleled performance and aims to integrate `LibAFL` for advanced fuzzing strategies.

## Introduction

Smart contracts are immutable once deployed, making their security paramount. Traditional testing often falls short in exploring the vast state space of complex contracts. RustyFuzz addresses this by employing a hybrid approach: combining the speed and control of an in-process EVM executor with sophisticated fuzzing techniques to systematically explore contract behavior and identify subtle bugs.

Our goal is to provide a robust, extensible, and high-performance fuzzer that can be adapted for various smart contract platforms, starting with EVM and with future plans for SVM (Solana Virtual Machine).

## Features

*   **High-Performance EVM Execution**: Utilizes `revm`, a blazing-fast EVM interpreter written in Rust, for efficient transaction execution and state manipulation.
*   **Coverage-Guided Fuzzing**: Employs a custom `revm::Inspector` to collect fine-grained code coverage (Program Counter and Opcode hits), guiding the fuzzer towards unexplored code paths.
*   **State Forking & Snapshotting**: Supports initializing the EVM state by forking from a live RPC endpoint, allowing fuzzing against realistic on-chain conditions. State snapshots enable efficient rollback and exploration of different execution paths.
*   **Intelligent Input Mutation**: Implements custom mutators for `SingletonTx` (transactions) to intelligently alter calldata, transaction value, and other parameters, maximizing the chances of hitting interesting states.
*   **Vulnerability Oracles**: Integrates pluggable oracles (e.g., ReentrancyOracle) to automatically detect common smart contract vulnerabilities during execution.
*   **Proof-of-Concept (PoC) Synthesis**: Generates actionable proofs-of-concept for discovered vulnerabilities, aiding in reproduction and remediation.
*   **Extensible Architecture**: Designed with `LibAFL` integration in mind, allowing for easy adoption of advanced fuzzing techniques, schedulers, and mutators.
*   **Rust-Native**: Benefits from Rust's memory safety, performance, and robust ecosystem.

## Setup & Installation

### Prerequisites

*   **Rust Toolchain**: Install Rust and Cargo using `rustup`:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    Ensure you have a recent stable Rust version.
*   **RPC Endpoint**: An Ethereum RPC URL (e.g., Infura, Alchemy, local Anvil/Ganache) is required for state forking.

### Cloning the Repository

```bash
git clone https://github.com/your-username/RustyFuzz.git
cd RustyFuzz
```

### Environment Variables

Create a `.env` file in the project root to configure your RPC endpoint and any API keys. 

```dotenv
# .env
# Ethereum RPC URL for forking or direct interaction
# Example: https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID
RPC_URL="YOUR_RPC_URL_HERE"

# API Key for services like Etherscan (if used for contract verification, etc.)
# ETHERSCAN_API_KEY="YOUR_ETHERSCAN_API_KEY_HERE"

# API Key for LLM guidance (if 'llm' feature is enabled)
# LLM_API_KEY="YOUR_LLM_API_KEY_HERE"
```

### Building the Project

```bash
cargo build --release
```

To enable optional features like `z3` (for symbolic execution/constraint solving) or `llm` (for AI-guided fuzzing), use:

```bash
cargo build --release --features "z3 llm"
```

## Usage

RustyFuzz is designed to be integrated into a larger fuzzing harness. The primary entry point for a fuzzing campaign is the `run_fuzz_campaign` function.

### Basic Fuzzing Campaign (Conceptual)

A typical fuzzing campaign involves:

1.  **Initialization**: Setting up the initial EVM state by forking from a specified RPC URL and block number.
2.  **Corpus Management**: Maintaining a collection of "interesting" transactions (`SingletonTx`) that have yielded new coverage or unique behavior.
3.  **Mutation**: Selecting a transaction from the corpus and applying various mutations (e.g., altering calldata, value, sender).
4.  **Execution**: Executing the mutated transaction on the EVM, collecting coverage, and updating the state.
5.  **Feedback & Oracle Checks**: Analyzing the execution trace and coverage to determine if the new transaction is "interesting" (e.g., found new code paths, triggered an oracle).
6.  **Reporting**: If a vulnerability is found, generating a detailed report and a reproducible Proof-of-Concept.

```rust
// Example of how a fuzzing campaign might be initiated (simplified)
use rusty_fuzz::config::Config;
use rusty_fuzz::engine::fuzz_engine::run_fuzz_campaign;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from environment variables or a config file
    let config = Config {
        chain: "ethereum".to_string(),
        rpc_url: std::env::var("RPC_URL").expect("RPC_URL must be set"),
        fork_block: Some(18000000), // Example block number
        // ... other configuration options
    };

    run_fuzz_campaign(&config).await
}
```

## Key Concepts

*   **`EvmExecutor`**: The core component responsible for executing `SingletonTx` instances using `revm`. It integrates the `CoverageInspector` to gather execution traces.
*   **`CoverageInspector`**: A custom `revm::Inspector` that records which EVM opcodes and program counters are hit during transaction execution, storing this information in a `bitvec` for efficient comparison.
*   **`Snapshot`**: Represents a complete state of the EVM at a given point, including the `CacheDB` (EVM state), collected `coverage`, and `waypoints` (points of interest during execution).
*   **`SingletonTx`**: A simplified representation of an Ethereum transaction, focusing on essential fuzzer-controlled parameters like `input` (calldata), `caller`, and `value`.
*   **`EvmCoverageFeedback`**: A `LibAFL` feedback mechanism (currently a stub) that will compare the coverage of a new execution against the global coverage map to determine if the input is "interesting."
*   **`mutate_tx`**: A custom mutator function that applies various transformations to a `SingletonTx` to generate new inputs for the fuzzer.

## Roadmap & Future Enhancements

*   **Full LibAFL Integration**: Implement a complete `LibAFL` harness, including `Fuzzer`, `Executor`, `Scheduler`, `Observers`, and `Feedback` mechanisms.
*   **Advanced Mutators**: Develop more sophisticated mutators for EVM-specific data structures (e.g., ABI-aware calldata mutation, storage slot manipulation).
*   **Symbolic Execution Integration**: Leverage the `z3` feature for concolic execution to generate inputs that satisfy specific path constraints.
*   **LLM-Guided Fuzzing**: Explore using Large Language Models (LLMs) to generate intelligent transaction sequences or vulnerability-specific inputs.
*   **SVM Support**: Extend the fuzzer to support Solana Virtual Machine (SVM) smart contracts.
*   **Detailed Reporting**: Enhance vulnerability reporting with more context, call stacks, and state differences.

## 🤝 Contributing

Contributions are welcome! Feel free to open issues for bug reports or feature requests, and submit pull requests.
