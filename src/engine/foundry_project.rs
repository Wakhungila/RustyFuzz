//! Foundry project mode: build artifacts in, a bootstrapped fuzz state out.
//!
//! `foundry_ingest` scans Solidity *source* and can say which `invariant_*`
//! functions exist. It cannot say where the test contract lives, because that
//! requires running the constructor and `setUp()`. This module does that:
//!
//! 1. loads `out/**/*.json` artifacts produced by `forge build`;
//! 2. deploys the test contract from its creation bytecode (constructor runs);
//! 3. runs `setUp()` with Foundry cheatcodes (`rustyfuzz_evm::foundry`);
//! 4. dumps every account the project created into a [`FuzzFixtureState`];
//! 5. exposes the test contract's zero-argument `invariant_*` / `echidna_*`
//!    functions as a [`FoundryInvariantSet`] that the campaign evaluates after
//!    every fuzzed transaction, against a throwaway view of the state.
//!
//! Violation semantics follow Foundry: an invariant function fails when it
//! reverts (including a failed `assert*` cheatcode) or halts. Functions the ABI
//! declares as returning `bool` are Echidna-style properties and also fail on
//! `false`.

use crate::engine::executable_fixture::{FuzzFixtureAccount, FuzzFixtureState};
use anyhow::{anyhow, bail, ensure, Context};
use revm::context::result::{ExecutionResult, Output};
use revm::context::BlockEnv;
use revm::primitives::{keccak256, Address, Bytes, TxKind, U256};
use rustyfuzz_evm::foundry::{execute_with_cheatcodes, DEFAULT_SENDER, HEVM_ADDRESS};
use rustyfuzz_evm::EvmCacheDb;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_ARTIFACT_FILES: usize = 20_000;
const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 8;

/// Caller used for invariant probes. Distinct from every fuzz caller so a probe
/// can never be mistaken for, or interfere with, a fuzzed transaction.
pub const INVARIANT_PROBE_CALLER: Address = Address::new([
    0x1d, 0xe7, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
]);

#[derive(Debug, Clone)]
pub struct AbiFunction {
    pub name: String,
    /// `None` when the function takes arguments (only zero-argument functions
    /// are ever invoked by this module).
    pub selector: Option<[u8; 4]>,
    pub returns_bool: bool,
}

#[derive(Debug, Clone)]
pub struct FoundryArtifact {
    pub name: String,
    pub source: Option<String>,
    pub functions: Vec<AbiFunction>,
    pub creation_code: Vec<u8>,
    pub runtime_code: Vec<u8>,
    /// Library placeholders that were not linked at build time.
    pub unlinked_libraries: bool,
    /// Full ABI (None if it did not parse as a JSON ABI).
    pub abi: Option<alloy_json_abi::JsonAbi>,
}

impl FoundryArtifact {
    pub fn function(&self, name: &str) -> Option<&AbiFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    pub fn invariant_functions(&self) -> Vec<&AbiFunction> {
        self.functions
            .iter()
            .filter(|f| {
                f.selector.is_some()
                    && (f.name.starts_with("invariant_") || f.name.starts_with("echidna_"))
            })
            .collect()
    }
}

fn hex_code(object: Option<&Value>) -> anyhow::Result<(Vec<u8>, bool)> {
    let text = object.and_then(Value::as_str).unwrap_or("");
    let text = text.strip_prefix("0x").unwrap_or(text);
    // forge writes `__$<hash>$__` where a library address must be linked in.
    if text.contains("__$") {
        return Ok((Vec::new(), true));
    }
    Ok((hex::decode(text).context("artifact bytecode is not valid hex")?, false))
}

fn parse_artifact(name: &str, json: &Value) -> anyhow::Result<Option<FoundryArtifact>> {
    let Some(abi) = json.get("abi").and_then(Value::as_array) else {
        return Ok(None);
    };
    let (creation_code, creation_unlinked) = hex_code(json.pointer("/bytecode/object"))?;
    let (runtime_code, runtime_unlinked) = hex_code(json.pointer("/deployedBytecode/object"))?;
    if creation_code.is_empty() && !creation_unlinked {
        // Interfaces and abstract contracts carry no bytecode.
        return Ok(None);
    }

    let mut functions = Vec::new();
    for entry in abi {
        if entry.get("type").and_then(Value::as_str) != Some("function") {
            continue;
        }
        let Some(fname) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let inputs = entry
            .get("inputs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let selector = inputs.is_empty().then(|| {
            let hash = keccak256(format!("{fname}()").as_bytes());
            [hash[0], hash[1], hash[2], hash[3]]
        });
        let outputs = entry
            .get("outputs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let returns_bool = outputs.len() == 1
            && outputs[0].get("type").and_then(Value::as_str) == Some("bool");
        functions.push(AbiFunction {
            name: fname.to_string(),
            selector,
            returns_bool,
        });
    }

    let source = json
        .pointer("/metadata/settings/compilationTarget")
        .and_then(Value::as_object)
        .and_then(|target| target.keys().next().cloned());

    Ok(Some(FoundryArtifact {
        name: name.to_string(),
        source,
        functions,
        creation_code,
        runtime_code,
        unlinked_libraries: creation_unlinked || runtime_unlinked,
        abi: serde_json::from_value(Value::Array(abi.clone())).ok(),
    }))
}

fn collect_json(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    ensure!(depth <= MAX_WALK_DEPTH, "artifact directory nesting exceeds {MAX_WALK_DEPTH}");
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        // A symlink could point outside the project; never follow one.
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("build-info") {
                continue;
            }
            collect_json(&path, depth + 1, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".dbg.json"))
        {
            out.push(path);
            ensure!(out.len() <= MAX_ARTIFACT_FILES, "more than {MAX_ARTIFACT_FILES} artifacts");
        }
    }
    Ok(())
}

/// Loads every contract artifact under `<project_root>/out`.
pub fn load_artifacts(project_root: &Path) -> anyhow::Result<Vec<FoundryArtifact>> {
    let out_dir = project_root.join("out");
    ensure!(
        out_dir.is_dir(),
        "{} does not exist; run `forge build` in the project first",
        out_dir.display()
    );
    let mut files = Vec::new();
    collect_json(&out_dir, 0, &mut files)?;
    files.sort();

    let mut artifacts = Vec::new();
    for file in files {
        let metadata = fs::metadata(&file)?;
        ensure!(
            metadata.len() <= MAX_ARTIFACT_BYTES,
            "artifact {} exceeds {MAX_ARTIFACT_BYTES} bytes",
            file.display()
        );
        let text = fs::read_to_string(&file)?;
        let Ok(json) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let name = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if let Some(artifact) = parse_artifact(name, &json)
            .with_context(|| format!("parsing {}", file.display()))?
        {
            artifacts.push(artifact);
        }
    }
    ensure!(!artifacts.is_empty(), "no contract artifacts found under {}", out_dir.display());
    Ok(artifacts)
}

/// Picks the contract whose `setUp()` and `invariant_*` functions drive the run.
pub fn select_test_contract<'a>(
    artifacts: &'a [FoundryArtifact],
    requested: Option<&str>,
) -> anyhow::Result<&'a FoundryArtifact> {
    if let Some(name) = requested {
        let mut matches = artifacts.iter().filter(|a| a.name == name);
        let first = matches
            .next()
            .ok_or_else(|| anyhow!("no artifact named `{name}` under out/"))?;
        ensure!(
            matches.next().is_none(),
            "`{name}` is ambiguous: more than one artifact has that name"
        );
        return Ok(first);
    }
    let candidates: Vec<&FoundryArtifact> = artifacts
        .iter()
        .filter(|a| !a.invariant_functions().is_empty())
        .collect();
    match candidates.as_slice() {
        [only] => Ok(only),
        [] => bail!("no artifact declares an `invariant_*` or `echidna_*` function"),
        many => bail!(
            "several contracts declare invariants ({}); pick one with --foundry-test",
            many.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

#[derive(Debug, Clone)]
pub struct InvariantFunction {
    pub name: String,
    pub selector: [u8; 4],
    pub returns_bool: bool,
}

#[derive(Debug, Clone)]
pub struct FoundryInvariantViolation {
    pub invariant: String,
    pub detail: String,
}

/// The test contract's invariant functions plus where to call them.
#[derive(Debug, Clone)]
pub struct FoundryInvariantSet {
    pub test_contract: Address,
    pub functions: Vec<InvariantFunction>,
}

impl FoundryInvariantSet {
    /// Evaluates every invariant against `db` without modifying it.
    ///
    /// Returns the first violated invariant. An *error* (as opposed to a
    /// violation) means the probe itself could not run, which must not be
    /// reported as a finding.
    pub fn check(
        &self,
        db: &mut EvmCacheDb,
        block: &BlockEnv,
    ) -> anyhow::Result<Option<FoundryInvariantViolation>> {
        static PROBES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n == 1 || n % 1000 == 0 {
            let vault_bal = db
                .cache
                .accounts
                .get(&self.test_contract)
                .map(|a| a.info.balance);
            log::info!("foundry invariant probes so far: {n} (test contract cached balance {vault_bal:?})");
        }
        for function in &self.functions {
            let run = execute_with_cheatcodes(
                db,
                block,
                INVARIANT_PROBE_CALLER,
                TxKind::Call(self.test_contract),
                Bytes::copy_from_slice(&function.selector),
                U256::ZERO,
                self.test_contract,
                false,
            )?;
            if !run.unsupported.is_empty() {
                // A cheatcode this runner does not implement changes what the
                // invariant means. Failing the probe is the honest outcome;
                // a "pass" would be a guess.
                bail!(
                    "invariant `{}` used unsupported cheatcode(s): {}",
                    function.name,
                    run.unsupported
                        .iter()
                        .map(|s| format!("0x{}", hex::encode(s)))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            match &run.result {
                ExecutionResult::Success { output, .. } => {
                    if function.returns_bool {
                        let bytes = output.data();
                        let holds = bytes.len() >= 32 && bytes[..32].iter().any(|b| *b != 0);
                        if !holds {
                            return Ok(Some(FoundryInvariantViolation {
                                invariant: function.name.clone(),
                                detail: "property returned false".to_string(),
                            }));
                        }
                    }
                }
                ExecutionResult::Revert { output, .. } => {
                    return Ok(Some(FoundryInvariantViolation {
                        invariant: function.name.clone(),
                        detail: format!("reverted: {}", decode_revert(output)),
                    }));
                }
                ExecutionResult::Halt { reason, .. } => {
                    return Ok(Some(FoundryInvariantViolation {
                        invariant: function.name.clone(),
                        detail: format!("halted: {reason:?}"),
                    }));
                }
            }
        }
        Ok(None)
    }
}

fn decode_revert(output: &Bytes) -> String {
    // Error(string)
    if output.len() >= 68 && output[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let len = U256::from_be_slice(&output[36..68]);
        if let Ok(len) = usize::try_from(len) {
            if let Some(text) = output.get(68..68 + len) {
                return String::from_utf8_lossy(text).into_owned();
            }
        }
    }
    if output.is_empty() {
        "empty revert data".to_string()
    } else {
        format!("0x{}", hex::encode(output))
    }
}

/// A contract the project created while bootstrapping.
#[derive(Debug, Clone)]
pub struct DeployedContract {
    pub address: Address,
    pub code_len: usize,
    pub code_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FoundryBootstrap {
    pub test_contract_name: String,
    pub test_contract: Address,
    pub state: FuzzFixtureState,
    pub invariants: FoundryInvariantSet,
    pub deployed: Vec<DeployedContract>,
    /// Block environment after `setUp()` (reflects `vm.warp` / `vm.roll`).
    pub block_env: BlockEnv,
    /// Names of artifact contracts whose runtime code matches a deployed
    /// account, for reporting. Best effort: immutables and library links make
    /// exact matches impossible for some contracts.
    pub identified: Vec<(Address, String)>,
    /// Externally-owned accounts that `setUp` funded or touched (e.g.
    /// `makeAddr("alice")` + `vm.deal`), plus Foundry's default sender. These
    /// seed the caller pool: state set up for them (deposits, allowances) is
    /// only reachable when the fuzzer can transact as them.
    pub actors: Vec<Address>,
    /// ABIs of deployed contracts identified from artifacts. The engine merges
    /// these into its ABI registry so mutation and seeding target the real
    /// external functions instead of generic DeFi templates.
    pub abis: Vec<(Address, alloy_json_abi::JsonAbi)>,
}

/// Names a deployed account after the artifact whose runtime code it matches,
/// ignoring the trailing CBOR metadata hash and zeroed immutable regions.
fn identify(code: &[u8], artifacts: &[FoundryArtifact]) -> Option<String> {
    artifacts
        .iter()
        .filter(|a| !a.runtime_code.is_empty() && a.runtime_code.len() == code.len())
        .find(|a| {
            let cut = code.len().saturating_sub(53);
            a.runtime_code[..cut]
                .iter()
                .zip(&code[..cut])
                .filter(|(x, y)| x != y)
                .count()
                <= 32 * 8
        })
        .map(|a| a.name.clone())
}

/// Deploys and sets up a Foundry project entirely in memory.
pub fn bootstrap(project_root: &Path, test_name: Option<&str>) -> anyhow::Result<FoundryBootstrap> {
    let artifacts = load_artifacts(project_root)?;
    let test = select_test_contract(&artifacts, test_name)?;
    ensure!(
        !test.unlinked_libraries,
        "`{}` has unlinked library placeholders; build with libraries linked (forge links \
         libraries it can deploy automatically) before using project mode",
        test.name
    );

    let mut db: EvmCacheDb = crate::evm::fork::create_in_memory_fork_db_from_fixture(
        &FuzzFixtureState {
            target: Address::ZERO,
            accounts: vec![
                FuzzFixtureAccount {
                    address: DEFAULT_SENDER,
                    balance: U256::from(10u128.pow(30)),
                    nonce: 0,
                    bytecode: Vec::new(),
                    storage: Vec::new(),
                },
                // Solidity's high-level calls guard on extcodesize(target) > 0
                // and revert with empty data otherwise, so the cheatcode
                // address needs non-empty placeholder code (Foundry etches the
                // same). The cheatcode inspector intercepts calls before the
                // code ever runs.
                FuzzFixtureAccount {
                    address: HEVM_ADDRESS,
                    balance: U256::ZERO,
                    nonce: 1,
                    bytecode: vec![0x60, 0x80, 0x60, 0x40],
                    storage: Vec::new(),
                },
            ],
        },
    );
    // Foundry's defaults: block.number 1, block.timestamp 1.
    let mut block_env = crate::evm::fork::create_offline_fallback_block_env(1);
    block_env.timestamp = U256::from(1u64);

    let expected = DEFAULT_SENDER.create(0);
    let deploy = execute_with_cheatcodes(
        &mut db,
        &block_env,
        DEFAULT_SENDER,
        TxKind::Create,
        Bytes::from(test.creation_code.clone()),
        U256::ZERO,
        expected,
        true,
    )
    .with_context(|| format!("deploying {}", test.name))?;
    let test_address = match &deploy.result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(address)),
            ..
        } => *address,
        other => bail!(
            "constructor of {} did not deploy: {}",
            test.name,
            describe_failure(other, &deploy.unsupported)
        ),
    };
    ensure!(
        test_address == expected,
        "test contract deployed at {test_address}, expected {expected}"
    );
    deploy.block_override.apply(&mut block_env);

    if let Some(set_up) = test.function("setUp").and_then(|f| f.selector) {
        let run = execute_with_cheatcodes(
            &mut db,
            &block_env,
            DEFAULT_SENDER,
            TxKind::Call(test_address),
            Bytes::copy_from_slice(&set_up),
            U256::ZERO,
            test_address,
            true,
        )
        .with_context(|| format!("running {}.setUp()", test.name))?;
        match &run.result {
            ExecutionResult::Success { .. } => {}
            other => bail!(
                "{}.setUp() failed: {}",
                test.name,
                describe_failure(other, &run.unsupported)
            ),
        }
        run.block_override.apply(&mut block_env);
    }

    // Dump every account the project produced.
    let mut accounts = Vec::new();
    let mut deployed = Vec::new();
    for (address, account) in &db.cache.accounts {
        if *address == HEVM_ADDRESS {
            continue;
        }
        let code: Vec<u8> = account
            .info
            .code
            .as_ref()
            .map(|c| c.original_bytes().to_vec())
            .or_else(|| {
                db.cache
                    .contracts
                    .get(&account.info.code_hash)
                    .map(|c| c.original_bytes().to_vec())
            })
            .unwrap_or_default();
        let storage: Vec<(U256, U256)> = account
            .storage
            .iter()
            .filter(|(_, v)| **v != U256::ZERO)
            .map(|(k, v)| (*k, *v))
            .collect();
        if code.is_empty() && account.info.balance == U256::ZERO && storage.is_empty() {
            continue;
        }
        if !code.is_empty() {
            deployed.push(DeployedContract {
                address: *address,
                code_len: code.len(),
                code_hash: keccak256(&code).0,
            });
        }
        accounts.push(FuzzFixtureAccount {
            address: *address,
            balance: account.info.balance,
            nonce: account.info.nonce,
            bytecode: code,
            storage,
        });
    }
    accounts.sort_by_key(|a| a.address);
    deployed.sort_by_key(|d| d.address);

    let identified: Vec<(Address, String)> = accounts
        .iter()
        .filter(|a| !a.bytecode.is_empty())
        .filter_map(|a| identify(&a.bytecode, &artifacts).map(|n| (a.address, n)))
        .collect();

    let abis: Vec<(Address, alloy_json_abi::JsonAbi)> = identified
        .iter()
        .filter(|(address, _): &&(Address, String)| *address != test_address)
        .filter_map(|(address, name)| {
            artifacts
                .iter()
                .find(|a| &a.name == name)
                .and_then(|a| a.abi.clone())
                .map(|abi| (*address, abi))
        })
        .collect();

    let actors: Vec<Address> = accounts
        .iter()
        .filter(|a| {
            a.bytecode.is_empty() && a.address != HEVM_ADDRESS && a.address != Address::ZERO
        })
        .map(|a| a.address)
        .collect();

    let functions: Vec<InvariantFunction> = test
        .invariant_functions()
        .into_iter()
        .map(|f| InvariantFunction {
            name: f.name.clone(),
            selector: f.selector.expect("filtered to zero-argument functions"),
            returns_bool: f.returns_bool,
        })
        .collect();
    ensure!(
        !functions.is_empty(),
        "`{}` declares no zero-argument invariant functions",
        test.name
    );

    // Target default: the largest contract that is not the test contract.
    let target = deployed
        .iter()
        .filter(|d| d.address != test_address)
        .max_by_key(|d| d.code_len)
        .map(|d| d.address)
        .unwrap_or(test_address);

    Ok(FoundryBootstrap {
        test_contract_name: test.name.clone(),
        test_contract: test_address,
        state: FuzzFixtureState { target, accounts },
        invariants: FoundryInvariantSet {
            test_contract: test_address,
            functions,
        },
        deployed,
        block_env,
        identified,
        actors,
        abis,
    })
}

fn describe_failure(result: &ExecutionResult, unsupported: &[[u8; 4]]) -> String {
    let base = match result {
        ExecutionResult::Success { .. } => "succeeded".to_string(),
        ExecutionResult::Revert { output, .. } => format!("reverted: {}", decode_revert(output)),
        ExecutionResult::Halt { reason, .. } => format!("halted: {reason:?}"),
    };
    if unsupported.is_empty() {
        base
    } else {
        format!(
            "{base} (unsupported cheatcodes: {})",
            unsupported
                .iter()
                .map(|s| format!("0x{}", hex::encode(s)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}


fn zero_value(ty: &alloy_dyn_abi::DynSolType) -> alloy_dyn_abi::DynSolValue {
    use alloy_dyn_abi::{DynSolType as T, DynSolValue as V};
    match ty {
        T::Bool => V::Bool(false),
        T::Int(bits) => V::Int(revm::primitives::I256::ZERO, *bits),
        T::Uint(bits) => V::Uint(U256::from(10u64).pow(U256::from(18u64)).min(
            if *bits >= 256 { U256::MAX } else { (U256::from(1u8) << *bits) - U256::from(1u8) },
        ), *bits),
        T::FixedBytes(n) => V::FixedBytes(revm::primitives::B256::ZERO, *n),
        T::Address => V::Address(Address::ZERO),
        T::Function => V::Function(alloy_primitives::Function::ZERO),
        T::Bytes => V::Bytes(Vec::new()),
        T::String => V::String(String::new()),
        T::Array(_) => V::Array(Vec::new()),
        T::FixedArray(inner, n) => V::FixedArray((0..*n).map(|_| zero_value(inner)).collect()),
        T::Tuple(fields) => V::Tuple(fields.iter().map(zero_value).collect()),
    }
}

impl FoundryBootstrap {
    /// One single-call seed per (actor x external function) of every identified
    /// deployed contract. Arguments are a benign default (1e18 for integers,
    /// zero otherwise); the mutator specialises them from there. Covering the
    /// full cross-product up front means state that only a specific `setUp`
    /// account owns (a deposit, an allowance) is exercised from the first
    /// corpus pass instead of by luck.
    pub fn actor_function_seeds(&self) -> Vec<crate::engine::seed_intelligence::SeedCandidate> {
        use crate::engine::seed_intelligence::{SeedCandidate, SeedSourceType, SeedTag};
        use alloy_dyn_abi::{DynSolValue, Specifier};
        let mut out = Vec::new();
        for (target, abi) in &self.abis {
            for function in abi.functions() {
                if matches!(
                    function.state_mutability,
                    alloy_json_abi::StateMutability::View | alloy_json_abi::StateMutability::Pure
                ) {
                    continue;
                }
                let Ok(types) = function
                    .inputs
                    .iter()
                    .map(|p| p.resolve())
                    .collect::<Result<Vec<_>, _>>()
                else {
                    continue;
                };
                let args = DynSolValue::Tuple(types.iter().map(zero_value).collect());
                let mut calldata = function.selector().0.to_vec();
                calldata.extend(args.abi_encode_params());
                let value = if matches!(
                    function.state_mutability,
                    alloy_json_abi::StateMutability::Payable
                ) {
                    U256::from(10u64).pow(U256::from(18u64))
                } else {
                    U256::ZERO
                };
                for actor in &self.actors {
                    out.push(SeedCandidate {
                        target: *target,
                        caller: *actor,
                        calldata: calldata.clone(),
                        selector: Some(function.selector().0),
                        value,
                        source_type: SeedSourceType::Foundry,
                        confidence_score: 70,
                        reason: format!("setUp actor {actor} calls {}", function.name),
                        touched_addresses: vec![*target],
                        touched_slots: Vec::new(),
                        prerequisites: Vec::new(),
                        tags: std::collections::BTreeSet::from([SeedTag::Unknown]),
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn artifact(name: &str, abi: Value, creation: &str) -> Value {
        json!({
            "abi": abi,
            "bytecode": {"object": creation},
            "deployedBytecode": {"object": "0x00"},
            "metadata": {"settings": {"compilationTarget": {"test/T.sol": name}}}
        })
    }

    #[test]
    fn invariant_functions_are_found_and_argument_taking_ones_are_ignored() {
        let abi = json!([
            {"type":"function","name":"setUp","inputs":[],"outputs":[]},
            {"type":"function","name":"invariant_solvent","inputs":[],"outputs":[]},
            {"type":"function","name":"invariant_withArgs","inputs":[{"type":"uint256"}],"outputs":[]},
            {"type":"function","name":"echidna_ok","inputs":[],"outputs":[{"type":"bool"}]},
            {"type":"event","name":"Log"}
        ]);
        let parsed = parse_artifact("T", &artifact("T", abi, "0x6000")).unwrap().unwrap();
        let names: Vec<_> = parsed.invariant_functions().iter().map(|f| f.name.clone()).collect();
        assert_eq!(names, ["invariant_solvent", "echidna_ok"]);
        assert!(parsed.function("echidna_ok").unwrap().returns_bool);
        assert!(!parsed.function("invariant_solvent").unwrap().returns_bool);
        assert_eq!(parsed.source.as_deref(), Some("test/T.sol"));
    }

    #[test]
    fn interfaces_without_bytecode_are_skipped_and_unlinked_libraries_flagged() {
        let abi = json!([{"type":"function","name":"f","inputs":[],"outputs":[]}]);
        assert!(parse_artifact("I", &artifact("I", abi.clone(), "0x")).unwrap().is_none());
        let linked = parse_artifact("L", &artifact("L", abi, "0x60__$abcd$__00"))
            .unwrap()
            .unwrap();
        assert!(linked.unlinked_libraries);
    }

    #[test]
    fn selection_requires_an_unambiguous_invariant_contract() {
        let mk = |name: &str, with: bool| FoundryArtifact {
            name: name.into(),
            source: None,
            functions: if with {
                vec![AbiFunction {
                    name: "invariant_x".into(),
                    selector: Some([1, 2, 3, 4]),
                    returns_bool: false,
                }]
            } else {
                vec![]
            },
            creation_code: vec![0],
            runtime_code: vec![0],
            unlinked_libraries: false,
            abi: None,
        };
        let one = [mk("A", true), mk("B", false)];
        assert_eq!(select_test_contract(&one, None).unwrap().name, "A");
        let two = [mk("A", true), mk("B", true)];
        assert!(select_test_contract(&two, None).unwrap_err().to_string().contains("A, B"));
        assert_eq!(select_test_contract(&two, Some("B")).unwrap().name, "B");
        assert!(select_test_contract(&two, Some("C")).is_err());
        let none = [mk("A", false)];
        assert!(select_test_contract(&none, None).is_err());
    }

    #[test]
    fn revert_strings_decode() {
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x20);
        data.extend_from_slice(&U256::from(4).to_be_bytes::<32>());
        data.extend_from_slice(b"nope");
        data.extend_from_slice(&[0u8; 28]);
        assert_eq!(decode_revert(&Bytes::from(data)), "nope");
        assert_eq!(decode_revert(&Bytes::new()), "empty revert data");
    }

    fn fixture(variant: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/foundry_vault").join(variant)
    }

    /// Calls `withdrawAll()` as each setUp actor against a fresh copy of the
    /// post-setUp state and returns the actors for whom the invariant breaks.
    fn violators_after_withdraw_all(variant: &str) -> (FoundryBootstrap, Vec<Address>) {
        let boot = bootstrap(&fixture(variant), None).unwrap();
        let mut db = crate::evm::fork::create_in_memory_fork_db_from_fixture(&boot.state);
        assert!(
            boot.invariants.check(&mut db, &boot.block_env).unwrap().is_none(),
            "invariant must hold in the post-setUp state"
        );
        let selector = keccak256(b"withdrawAll()").0[..4].to_vec();
        let mut broken = Vec::new();
        for actor in &boot.actors {
            let mut copy = db.clone();
            execute_with_cheatcodes(
                &mut copy,
                &boot.block_env,
                *actor,
                TxKind::Call(boot.state.target),
                Bytes::from(selector.clone()),
                U256::ZERO,
                boot.test_contract,
                true,
            )
            .unwrap();
            if boot.invariants.check(&mut copy, &boot.block_env).unwrap().is_some() {
                broken.push(*actor);
            }
        }
        (boot, broken)
    }

    #[test]
    fn project_mode_bootstraps_setup_state_abis_and_actors() {
        let boot = bootstrap(&fixture("buggy"), None).unwrap();
        assert_eq!(boot.test_contract_name, "VaultInvariantTest");
        assert_eq!(boot.invariants.functions.len(), 1);
        assert!(boot.identified.iter().any(|(_, name)| name == "Vault"));
        assert_eq!(boot.abis.len(), 1, "Vault ABI carried out for the mutator");
        // makeAddr("alice") + vm.deal ran during setUp, so alice is an actor.
        assert!(boot.actors.len() >= 2, "actors: {:?}", boot.actors);
        assert!(!boot.actors.contains(&HEVM_ADDRESS));
        assert!(!boot.actor_function_seeds().is_empty());
    }

    #[test]
    fn invariant_fires_only_for_the_depositor_on_the_buggy_vault() {
        let (boot, broken) = violators_after_withdraw_all("buggy");
        // Exactly the account that deposited in setUp can expose the bug: a
        // caller with no deposit withdraws nothing and leaves the books intact.
        assert_eq!(broken.len(), 1, "broken for {broken:?} of {:?}", boot.actors);
    }

    #[test]
    fn invariant_never_fires_on_the_fixed_vault() {
        let (_, broken) = violators_after_withdraw_all("fixed");
        assert!(broken.is_empty(), "false positive for {broken:?}");
    }
}
