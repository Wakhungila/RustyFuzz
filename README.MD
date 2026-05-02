# RustyFuzz
High-performance hybrid fuzzer for EVM and SVM smart contracts. Inspired by ItyFuzz (snapshot-based fuzzing with dataflow & comparison waypoints). 


## Features (Planned / Partial)
- EVM execution via `revm`
- SVM execution via `mollusk-svm`
- Snapshot + Copy-on-Write state
- Coverage-guided + hybrid concolic fuzzing
- Vulnerability oracles (reentrancy, flash loans, overflows, etc.)
- Mempool monitoring + mitigation bot skeleton
- PoC generation (Forge/Anvil compatible)

## Quick Start
```bash
cargo run -- --help
cargo run -- fuzz --chain evm --contract 0x... --rpc https://...
