# Configuration Guide

This guide provides recommended configuration values for different use cases of RustyFuzz.

## Use Cases

### 1. Quick Security Audit

**Goal**: Rapid vulnerability assessment of a single contract

**Recommended Configuration**:
```rust
Config {
    rpc_url: "https://mainnet.infura.io/v3/YOUR_KEY".to_string(),
    fork_block: 0,  // Latest block
    target_contract: Some(contract_address),
    corpus_dir: "./corpus".to_string(),
    report_dir: "./reports".to_string(),
    cores: Some(Cores::Multi(4)),  // 4 cores
    max_execs: Some(100_000),  // 100k executions
    duration_secs: Some(300),  // 5 minutes
    artifact_limit: Some(50),
    campaign_id: Some("quick-audit".to_string()),
    hardened_defi: HardenedDefiConfig {
        deterministic: true,
        rng_seed: Some(42),
        ..Default::default()
    },
    ..Default::default()
}
```

**Rationale**:
- 4 cores provide good parallelism without overwhelming the RPC
- 100k executions is sufficient for quick vulnerability discovery
- 5-minute timeout for rapid assessment
- Deterministic mode for reproducible results

### 2. Deep Protocol Analysis

**Goal**: Comprehensive fuzzing of complex DeFi protocols

**Recommended Configuration**:
```rust
Config {
    rpc_url: "https://mainnet.infura.io/v3/YOUR_KEY".to_string(),
    fork_block: 0,
    target_contract: Some(contract_address),
    corpus_dir: "./corpus".to_string(),
    report_dir: "./reports".to_string(),
    cores: Some(Cores::Multi(16)),  // 16 cores
    max_execs: Some(10_000_000),  // 10M executions
    duration_secs: Some(3600),  // 1 hour
    artifact_limit: Some(500),
    campaign_id: Some("deep-analysis".to_string()),
    hardened_defi: HardenedDefiConfig {
        deterministic: false,  // Non-deterministic for better exploration
        enable_concolic: true,
        enable_dependency_analysis: true,
        ..Default::default()
    },
    require_seed_bundle: true,  // Use real transaction seeds
    ..Default::default()
}
```

**Rationale**:
- 16 cores for maximum parallelism
- 10M executions for deep exploration
- 1-hour timeout for thorough analysis
- Concolic solving enabled for path exploration
- Dependency analysis for state-aware mutations
- Seed bundles for realistic starting inputs

### 3. CI/CD Integration

**Goal**: Automated security testing in CI pipeline

**Recommended Configuration**:
```rust
Config {
    rpc_url: "https://mainnet.infura.io/v3/YOUR_KEY".to_string(),
    fork_block: 0,
    target_contract: Some(contract_address),
    corpus_dir: "./corpus".to_string(),
    report_dir: "./reports".to_string(),
    cores: Some(Cores::Single),  // Single core for CI
    max_execs: Some(10_000),  // 10k executions
    duration_secs: Some(60),  // 1 minute
    artifact_limit: Some(10),
    campaign_id: Some("ci-test".to_string()),
    hardened_defi: HardenedDefiConfig {
        deterministic: true,
        rng_seed: Some(42),
        single_process: true,
        ..Default::default()
    },
    ..Default::default()
}
```

**Rationale**:
- Single core to avoid overwhelming CI resources
- 10k executions for quick feedback
- 1-minute timeout for fast CI cycles
- Deterministic for reproducible CI results
- Single process to avoid multi-process complexity

### 4. Local Development

**Goal**: Interactive fuzzing during contract development

**Recommended Configuration**:
```rust
Config {
    rpc_url: "http://localhost:8545".to_string(),  // Local anvil
    fork_block: 0,
    target_contract: Some(contract_address),
    corpus_dir: "./corpus".to_string(),
    report_dir: "./reports".to_string(),
    cores: Some(Cores::Multi(2)),  // 2 cores
    max_execs: None,  // No limit, run until stopped
    duration_secs: None,  // No time limit
    artifact_limit: Some(100),
    campaign_id: Some("dev".to_string()),
    hardened_defi: HardenedDefiConfig {
        deterministic: false,
        enable_concolic: true,
        ..Default::default()
    },
    allow_synthetic_fallback: true,  // Allow offline mode
    ..Default::default()
}
```

**Rationale**:
- Local RPC for fast feedback
- No execution/time limits for interactive use
- Concolic solving for path exploration
- Synthetic fallback for offline development

## Configuration Parameters

### Core Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rpc_url` | String | Required | RPC endpoint for fork creation |
| `fork_block` | u64 | 0 | Block number to fork from (0 = latest) |
| `target_contract` | Option<Address> | None | Primary contract to target |
| `corpus_dir` | String | Required | Directory for corpus storage |
| `report_dir` | String | Required | Directory for report output |
| `cores` | Option<Cores> | None | Number of cores (None = auto-detect) |
| `max_execs` | Option<u64> | None | Maximum executions (None = unlimited) |
| `duration_secs` | Option<u64> | None | Maximum duration in seconds (None = unlimited) |
| `artifact_limit` | Option<u64> | None | Maximum artifacts to collect |
| `campaign_id` | Option<String> | None | Unique identifier for campaign isolation |

### Hardened DeFi Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `deterministic` | bool | false | Use deterministic RNG for reproducibility |
| `rng_seed` | Option<u64> | None | Seed for deterministic RNG |
| `enable_concolic` | bool | true | Enable concolic solving |
| `enable_dependency_analysis` | bool | true | Enable dependency analysis |
| `single_process` | bool | false | Run in single-process mode |

### Resource Limits

| Parameter | Value | Description |
|-----------|-------|-------------|
| `MAX_SEQUENCE_LENGTH` | 100 | Maximum transactions per input |
| `MAX_WAYPOINTS_PER_TX` | 1000 | Maximum waypoints per transaction |
| `MAX_TOTAL_WAYPOINTS` | 10000 | Maximum total waypoints per input |
| `MAX_MEMORY_USAGE_BYTES` | 2GB | Maximum memory usage before backpressure |
| `MAX_DECODE_CACHE_SIZE` | 10000 | Maximum entries in decode cache |
| `MAX_CALLDATA_SIZE` | 128KB | Maximum calldata size per transaction |

## RPC Configuration

### Public RPC Endpoints

For production use, consider using:
- **Infura**: `https://mainnet.infura.io/v3/YOUR_KEY`
- **Alchemy**: `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY`
- **Cloudflare**: `https://cloudflare-eth.com`

**Rate Limits**:
- Infura: 100k requests/day (free tier)
- Alchemy: 300M compute units/month (free tier)
- Cloudflare: No rate limit (best effort)

### Local RPC

For development, use Anvil or Hardhat:
```bash
# Anvil
anvil --fork-url https://mainnet.infura.io/v3/YOUR_KEY

# Hardhat
npx hardhat node --fork https://mainnet.infura.io/v3/YOUR_KEY
```

**Configuration**:
```rust
rpc_url: "http://localhost:8545".to_string()
```

## Seed Configuration

### Mainnet Seed Bundles

For realistic starting inputs, use mainnet transaction seeds:

```rust
Config {
    mainnet_seed_bundle: Some("path/to/seed_bundle.json".to_string()),
    require_seed_bundle: true,
    ..Default::default()
}
```

**Seed Bundle Sources**:
- DEX transactions (Uniswap, Curve)
- Lending protocol transactions (Aave, Compound)
- Governance transactions
- Bridge transactions

### Synthetic Seeds

For offline testing or when RPC is unavailable:

```rust
Config {
    allow_synthetic_fallback: true,
    require_rpc_fork: false,
    ..Default::default()
}
```

## Oracle Configuration

### Protocol-Specific Oracles

Enable protocol-specific oracles for targeted vulnerability detection:

```rust
// ERC20 token standard
oracle_pack.add_oracle(Box::new(Erc20Oracle::new()));

// ERC4626 vault standard
oracle_pack.add_oracle(Box::new(Erc4626Oracle::new()));

// AMM protocols
oracle_pack.add_oracle(Box::new(AmmOracle::new()));

// Lending protocols
oracle_pack.add_oracle(Box::new(LendingOracle::new()));
```

### General-Purpose Oracles

Always enable general-purpose oracles:

```rust
oracle_pack.add_oracle(Box::new(ReentrancyOracle::new()));
oracle_pack.add_oracle(Box::new(AccessControlOracle::new()));
oracle_pack.add_oracle(Box::new(IntegerOverflowOracle::new()));
```

## Performance Tuning

### Memory Usage

To reduce memory usage:
- Reduce `MAX_DECODE_CACHE_SIZE` to 1000
- Reduce `MAX_TOTAL_WAYPOINTS` to 1000
- Reduce `cores` to 1-2

### Execution Speed

To increase execution speed:
- Use local RPC instead of public RPC
- Enable `single_process` mode to avoid IPC overhead
- Reduce waypoint collection frequency
- Disable concolic solving if not needed

### Coverage vs. Speed Trade-off

**Maximum Coverage**:
```rust
hardened_defi: HardenedDefiConfig {
    enable_concolic: true,
    enable_dependency_analysis: true,
    enable_state_novelty: true,
    ..Default::default()
}
```

**Maximum Speed**:
```rust
hardened_defi: HardenedDefiConfig {
    enable_concolic: false,
    enable_dependency_analysis: false,
    enable_state_novelty: false,
    ..Default::default()
}
```

## Troubleshooting

### RPC Timeouts

**Symptom**: "RPC fork DB setup timed out"

**Solutions**:
1. Increase `startup_rpc_timeout` environment variable
2. Use a faster RPC endpoint
3. Use local RPC with Anvil
4. Enable `allow_synthetic_fallback`

### Memory Exhaustion

**Symptom**: "Memory limit exceeded"

**Solutions**:
1. Reduce `cores` to limit parallelism
2. Reduce `artifact_limit`
3. Reduce waypoint limits
4. Enable backpressure mechanisms

### Slow Execution

**Symptom**: Low executions per second

**Solutions**:
1. Use local RPC instead of public RPC
2. Enable `single_process` mode
3. Disable concolic solving
4. Reduce waypoint collection

### No Vulnerabilities Found

**Symptom**: Campaign completes with zero findings

**Solutions**:
1. Increase `max_execs` or `duration_secs`
2. Enable concolic solving
3. Use mainnet seed bundles
4. Enable more oracle types
5. Verify target contract is correct

## Best Practices

1. **Always use campaign_id** for state isolation between campaigns
2. **Use deterministic mode** for reproducible results in CI
3. **Monitor memory usage** during long-running campaigns
4. **Use seed bundles** for realistic starting inputs
5. **Enable concolic solving** for complex protocols
6. **Configure appropriate timeouts** to prevent hanging
7. **Use local RPC** during development for faster feedback
8. **Review artifacts** regularly to assess campaign progress
9. **Archive corpus** periodically to preserve interesting inputs
10. **Validate RPC connectivity** before starting campaigns
