//! Versioned local EVM fixtures. Expectations validate execution; they never
//! manufacture, remove, or downgrade oracle findings.
use crate::common::oracle::ProtocolFinding;
use crate::common::types::{ChainState, ExecutionStatus, SequenceExecutionResult, SingletonTx};
use anyhow::{ensure, Context, Result};
use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{keccak256, Address, U256},
    state::{AccountInfo, Bytecode},
};
use rustyfuzz_evm::{
    dataflow::DataflowRegistry, executor::EvmExecutor, fork_db::ForkDb, inspector::MAP_SIZE,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableFixture {
    pub schema_version: u32,
    pub bytecode_kind: BytecodeKind,
    pub target: Address,
    pub attacker: Address,
    pub victim: Address,
    pub environment: FixtureEnvironment,
    pub accounts: Vec<FixtureAccount>,
    pub transactions: Vec<FixtureTransaction>,
    pub expected_safe_behavior: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeKind {
    Runtime,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEnvironment {
    pub chain_id: u64,
    pub block_number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureAccount {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub runtime_bytecode: String,
    pub storage: Vec<StorageAssertion>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAssertion {
    pub slot: U256,
    pub value: U256,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureTransaction {
    pub caller: Address,
    pub to: Address,
    pub calldata: String,
    pub value: U256,
    pub timestamp: u64,
    pub expected_status: ExecutionStatus,
    pub expected_output: Option<String>,
    pub expected_storage: Vec<StorageAssertion>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutableEvidence {
    pub schema_version: u32,
    pub fixture: String,
    pub fixture_hash: String,
    pub runtime_code_hash: String,
    pub backend: String,
    pub transactions: Vec<TransactionEvidence>,
    pub matching_signals: Vec<ProtocolFinding>,
    pub unmatched_signals: Vec<ProtocolFinding>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionEvidence {
    pub caller: Address,
    pub to: Address,
    pub calldata: String,
    pub timestamp: u64,
    pub status: ExecutionStatus,
    pub output: String,
    pub gas_used: u64,
    pub coverage_edges: usize,
    pub storage_diffs: usize,
    pub call_traces: usize,
}
fn bytes(value: &str) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .context("hex bytes require 0x prefix")?;
    hex::decode(value).context("malformed hex bytes")
}
impl ExecutableFixture {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read executable fixture {}", path.display()))?;
        let fixture: Self = match path.extension().and_then(|v| v.to_str()) {
            Some("json") => serde_json::from_str(&raw).context("parse executable fixture JSON")?,
            Some("toml") => toml::from_str(&raw).context("parse executable fixture TOML")?,
            _ => anyhow::bail!("executable fixture must be JSON or TOML"),
        };
        fixture.validate()?;
        Ok(fixture)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported executable fixture schema_version"
        );
        ensure!(
            self.environment.chain_id == 1,
            "EvmExecutor supports mainnet chain_id=1 for fixtures"
        );
        ensure!(
            self.environment.gas_limit >= 10_000_000 && self.environment.base_fee <= 1_000_000_000,
            "invalid execution gas environment"
        );
        ensure!(!self.transactions.is_empty(), "fixture has no transactions");
        ensure!(
            !self.expected_safe_behavior.trim().is_empty(),
            "missing safe behavior specification"
        );
        ensure!(
            self.attacker != self.victim,
            "attacker and victim must be distinct"
        );
        let mut addresses = BTreeSet::new();
        for account in &self.accounts {
            ensure!(
                addresses.insert(account.address),
                "duplicate fixture account"
            );
            let code = bytes(&account.runtime_bytecode).context("invalid runtime bytecode")?;
            ensure!(
                code.len() <= 24_576,
                "runtime bytecode exceeds EIP-170 limit"
            );
            let mut slots = BTreeSet::new();
            ensure!(
                account.storage.iter().all(|s| slots.insert(s.slot)),
                "duplicate initial storage slot"
            );
        }
        ensure!(
            addresses.contains(&self.attacker) && addresses.contains(&self.victim),
            "missing funded actor accounts"
        );
        let target = self
            .accounts
            .iter()
            .find(|a| a.address == self.target)
            .context("missing target account")?;
        ensure!(
            !bytes(&target.runtime_bytecode)?.is_empty(),
            "missing target runtime bytecode"
        );
        let mut timestamp = self.environment.timestamp;
        for tx in &self.transactions {
            ensure!(
                addresses.contains(&tx.caller),
                "transaction caller absent from initial accounts"
            );
            let account = self
                .accounts
                .iter()
                .find(|a| a.address == tx.to)
                .context("transaction target absent from initial accounts")?;
            ensure!(
                !bytes(&account.runtime_bytecode)?.is_empty(),
                "transaction target has no runtime bytecode"
            );
            bytes(&tx.calldata).context("invalid transaction calldata")?;
            if let Some(output) = &tx.expected_output {
                bytes(output).context("invalid expected output")?;
            }
            ensure!(
                matches!(
                    tx.expected_status,
                    ExecutionStatus::Success | ExecutionStatus::Revert
                ),
                "expected status must be Success or Revert"
            );
            ensure!(
                tx.timestamp >= timestamp,
                "transaction timestamps must be monotonic"
            );
            timestamp = tx.timestamp;
        }
        Ok(())
    }
    pub fn execute(&self, path: &Path) -> Result<(SequenceExecutionResult, ExecutableEvidence)> {
        self.validate()?;
        let mut db = CacheDB::new(ForkDb::empty());
        for account in &self.accounts {
            db.insert_account_info(
                account.address,
                AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    ..AccountInfo::default()
                }
                .with_code(Bytecode::new_raw(bytes(&account.runtime_bytecode)?.into())),
            );
            for slot in &account.storage {
                db.insert_account_storage(account.address, slot.slot, slot.value)?;
            }
        }
        let mut state = ChainState::Evm(db);
        let mut env = BlockEnv {
            number: U256::from(self.environment.block_number),
            timestamp: U256::from(self.environment.timestamp),
            gas_limit: self.environment.gas_limit,
            basefee: self.environment.base_fee,
            ..BlockEnv::default()
        };
        let executor = EvmExecutor::proof(); // no synthetic caller funding or value cap
        let mut dataflow = DataflowRegistry::new();
        let mut coverage = vec![0u8; MAP_SIZE];
        let mut aggregate = vec![0u8; MAP_SIZE];
        let mut results = Vec::new();
        let mut evidence = Vec::new();
        for (index, tx) in self.transactions.iter().enumerate() {
            env.timestamp = U256::from(tx.timestamp);
            coverage.fill(0);
            let input = SingletonTx {
                input: bytes(&tx.calldata)?,
                caller: tx.caller,
                to: tx.to,
                value: tx.value,
                is_victim: tx.caller == self.victim,
            };
            let result = executor
                .execute_with_result(
                    &mut state,
                    &mut env,
                    &input,
                    &mut coverage,
                    &mut dataflow,
                    &mut Vec::new(),
                    index,
                )
                .with_context(|| format!("execute fixture transaction {index}"))?;
            ensure!(
                result.status == tx.expected_status,
                "transaction {index}: expected {:?}, got {:?}",
                tx.expected_status,
                result.status
            );
            if let Some(output) = &tx.expected_output {
                ensure!(
                    result.output == bytes(output)?,
                    "transaction {index}: return value assertion failed; actual=0x{}",
                    hex::encode(&result.output)
                );
            }
            let ChainState::Evm(db) = &mut state;
            for assertion in &tx.expected_storage {
                let actual = db
                    .cache
                    .accounts
                    .get(&tx.to)
                    .and_then(|a| a.storage.get(&assertion.slot))
                    .copied()
                    .unwrap_or_default();
                ensure!(
                    actual == assertion.value,
                    "transaction {index}: storage assertion failed at {}: expected {}, got {}",
                    assertion.slot,
                    assertion.value,
                    actual
                );
            }
            for (seen, hit) in aggregate.iter_mut().zip(&coverage) {
                *seen = (*seen).max(*hit);
            }
            evidence.push(TransactionEvidence {
                caller: tx.caller,
                to: tx.to,
                calldata: tx.calldata.clone(),
                timestamp: tx.timestamp,
                status: result.status.clone(),
                output: format!("0x{}", hex::encode(&result.output)),
                gas_used: result.gas_used,
                coverage_edges: result.coverage_edges,
                storage_diffs: result.storage_diffs.len(),
                call_traces: result.call_trace.len(),
            });
            results.push(result);
        }
        let execution = SequenceExecutionResult {
            total_gas_used: results.iter().map(|r| r.gas_used).sum(),
            final_coverage_hash: rustyfuzz_evm::coverage::stable_path_hash(&aggregate),
            storage_reads: results
                .iter()
                .flat_map(|r| r.storage_reads.clone())
                .collect(),
            storage_writes: results
                .iter()
                .flat_map(|r| r.storage_writes.clone())
                .collect(),
            storage_diffs: results
                .iter()
                .flat_map(|r| r.storage_diffs.clone())
                .collect(),
            call_trace: results.iter().flat_map(|r| r.call_trace.clone()).collect(),
            oracle_observations: Vec::new(),
            tx_results: results,
        };
        let code = &self
            .accounts
            .iter()
            .find(|a| a.address == self.target)
            .context("missing target")?
            .runtime_bytecode;
        Ok((
            execution,
            ExecutableEvidence {
                schema_version: 1,
                fixture: path.display().to_string(),
                fixture_hash: format!("{:x}", keccak256(serde_json::to_vec(self)?)),
                runtime_code_hash: format!("{:x}", keccak256(bytes(code)?)),
                backend: "EvmExecutor::proof/revm-mainnet-default".into(),
                transactions: evidence,
                matching_signals: Vec::new(),
                unmatched_signals: Vec::new(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &str = "benchmarks/historical/negative_controls/fixtures/erc20-owner-mint.json";

    #[test]
    fn executable_fixture_parses_json_and_toml_and_validates() {
        let fixture = ExecutableFixture::load(Path::new(FIXTURE)).unwrap();
        assert_eq!(fixture.schema_version, 1);
        assert_eq!(fixture.transactions.len(), 4);
        let toml = toml::to_string(&fixture).unwrap();
        let decoded: ExecutableFixture = toml::from_str(&toml).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.target, fixture.target);
    }

    #[test]
    fn malformed_missing_and_empty_bytecode_fail_loudly() {
        let mut fixture = ExecutableFixture::load(Path::new(FIXTURE)).unwrap();
        let index = fixture
            .accounts
            .iter()
            .position(|a| a.address == fixture.target)
            .unwrap();
        fixture.accounts[index].runtime_bytecode = "0xzz".into();
        assert!(fixture
            .validate()
            .unwrap_err()
            .to_string()
            .contains("bytecode"));
        fixture.accounts[index].runtime_bytecode = "0x".into();
        assert!(fixture
            .validate()
            .unwrap_err()
            .to_string()
            .contains("missing target runtime bytecode"));
        let mut json = serde_json::to_value(&fixture).unwrap();
        json["accounts"][index]
            .as_object_mut()
            .unwrap()
            .remove("runtime_bytecode");
        assert!(serde_json::from_value::<ExecutableFixture>(json)
            .unwrap_err()
            .to_string()
            .contains("runtime_bytecode"));
    }

    #[test]
    fn schema_version_and_synthetic_outcome_flags_are_rejected() {
        let mut fixture = ExecutableFixture::load(Path::new(FIXTURE)).unwrap();
        fixture.schema_version = 2;
        assert!(fixture.validate().is_err());
        let mut json = serde_json::to_value(&fixture).unwrap();
        json["schema_version"] = serde_json::json!(1);
        json["outcome"] = serde_json::json!("not_found");
        assert!(serde_json::from_value::<ExecutableFixture>(json)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
    }
}
