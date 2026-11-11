use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, U256},
    state::{AccountInfo, Bytecode},
};
use rusty_fuzz::{
    common::{
        oracle::{FindingStatus, ProtocolFinding, ProtocolOraclePackKind, ProtocolSeverity, VulnType},
        types::{ChainState, EvmInput, SequenceExecutionResult, SingletonTx},
        verifier::{RealismVerifier, ReplayVerifier},
    },
    engine::{
        exploit_path::ExploitPathBuilder,
        invariant_file::InvariantFile,
        invariant_runtime::{IncrementalChecker, SequenceViolation},
        minimizer::Minimizer,
        promotion::select_original_predicate,
        replay_context::ReplayContext,
        scoring::CampaignScore,
    },
    evm::corpus::{CampaignArtifactRecord, CampaignArtifactRequest, PersistentCorpus},
};
use rustyfuzz_evm::{
    dataflow::DataflowRegistry, executor::EvmExecutor, fork_db::ForkDb,
    inspector::MAP_SIZE, time_warp::TimeWarp,
};
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    base: ChainState,
    context: ReplayContext,
    input: EvmInput,
}

impl Fixture {
    fn new(warp: TimeWarp) -> Self {
        let root = std::env::temp_dir().join(format!("rustyfuzz-validation-{}", uuid::Uuid::new_v4()));
        let caller = Address::repeat_byte(0x11);
        let target = Address::repeat_byte(0x22);
        let mut db = CacheDB::new(ForkDb::empty());
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..Default::default()
        });
        // Store the supplied value in slot 1 and the observed timestamp in slot 2.
        db.insert_account_info(target, AccountInfo::default().with_code(Bytecode::new_raw(
            hex::decode("6000356001554260025500").unwrap().into(),
        )));
        let block = BlockEnv { number: U256::from(100), timestamp: U256::from(1000), ..Default::default() };
        let context = ReplayContext::new(&db.db, &block, warp).unwrap();
        let txs = [0u64, 7, 0].into_iter().map(|value| SingletonTx {
            caller, to: target, value: U256::ZERO,
            input: U256::from(value).to_be_bytes::<32>().to_vec(), is_victim: false,
        }).collect();
        Self { root, base: ChainState::Evm(db), context, input: EvmInput::new(txs, 0) }
    }

    fn discover(&self, predicate: &str) -> (SequenceExecutionResult, SequenceViolation) {
        let file = InvariantFile::from_json(&serde_json::json!({
            "target": self.input.txs[0].to.to_string(),
            "symbols": {"x": {"kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256}},
            "invariants": [{"name": "bounded-value", "predicate": predicate}]
        }).to_string()).unwrap();
        let registry = file.build_registry().unwrap();
        let mut state = self.base.clone();
        let mut checker = IncrementalChecker::new();
        let mut coverage = vec![0; MAP_SIZE];
        let mut dataflow = DataflowRegistry::new();
        let mut results = Vec::new();
        for (index, tx) in self.input.txs.iter().enumerate() {
            let mut block = self.context.block_at(index);
            let result = EvmExecutor::exploration().execute_with_result(
                &mut state, &mut block, tx, &mut coverage, &mut dataflow, &mut Vec::new(), index,
            ).unwrap();
            checker.observe(&registry, &result, &state, rustyfuzz_predicate::BlockContext {
                number: rustyfuzz_predicate::Int256(block.number.to_be_bytes()),
                timestamp: rustyfuzz_predicate::Int256(block.timestamp.to_be_bytes()),
            }, 8);
            results.push(result);
        }
        (SequenceExecutionResult::from_tx_results(results), checker.take_violation().unwrap())
    }

    fn persist(&self, text: &str) -> (PersistentCorpus, CampaignArtifactRecord) {
        let (execution, violation) = self.discover(text);
        // An unrelated oracle appearing first must not replace the authored property.
        let findings = vec![ProtocolFinding {
            pack: ProtocolOraclePackKind::Erc20,
            vuln: VulnType::AccountingDesync, severity: ProtocolSeverity::Medium,
            tx_index: Some(0), target: Some(self.input.txs[0].to), evidence: "unrelated signal".into(),
        }, ProtocolFinding {
            pack: ProtocolOraclePackKind::Bridge,
            vuln: VulnType::InvariantViolation(text.into()), severity: ProtocolSeverity::High,
            tx_index: Some(violation.tx_index), target: Some(self.input.txs[0].to), evidence: violation.evidence.summary_line(),
        }];
        let score = CampaignScore { total: 1000, invariant_pressure: 1000, ..Default::default() };
        let mut candidate = ExploitPathBuilder::from_execution(
            &self.input, &execution, &findings, &score,
        ).unwrap();
        violation.attach_to(&mut candidate, &execution, &findings);
        let corpus = PersistentCorpus::new(self.root.to_str().unwrap()).unwrap();
        let ChainState::Evm(db) = &self.base;
        let record = corpus.persist_campaign_artifact(CampaignArtifactRequest {
            replay_context: Some(&self.context), input: &self.input, execution: &execution,
            coverage: &[1], state_novelty_score: 1, base_fork_state: db,
            score: &score, findings: &findings, exploit_candidate: Some(&candidate),
            block_number: 100, target: Some(self.input.txs[0].to), reason: "authored predicate",
        }).unwrap().record;
        (corpus, record)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); }
}

#[test]
fn discovery_persistence_replay_minimization_and_proof_keep_the_same_property() {
    let fixture = Fixture::new(TimeWarp::NONE);
    let (corpus, saved) = fixture.persist("x <= 5");
    let (record, input, execution) = corpus.replay_campaign_artifact(&saved.input_id, None).unwrap();
    assert_eq!(record.recorded_context().unwrap(), &fixture.context);
    assert_eq!(execution, fixture.discover("x <= 5").0);
    let (finding, predicate) = select_original_predicate(&record, &input, &execution).unwrap();
    assert_eq!(finding.unwrap().vuln, VulnType::InvariantViolation("x <= 5".into()));
    let predicate = predicate.unwrap();
    let ChainState::Evm(db) = &fixture.base;
    let executor = EvmExecutor::proof();
    let oracle = rusty_fuzz::common::oracle::security::PanicOracle;
    let minimizer = Minimizer::new(&executor, &oracle, db.clone(), fixture.context.initial_block.clone())
        .with_replay_context(&fixture.context).unwrap();
    let (minimized, minimized_predicate) = minimizer.minimize_violation(&input, &predicate, &fixture.context).unwrap();
    assert_eq!(minimized.txs.len(), 1);
    assert!(matches!(minimized_predicate, rusty_fuzz::common::verifier::ViolationPredicate::InvariantViolated { tx_index: 0, .. }));
    let proof = RealismVerifier::with_time_warp(MAP_SIZE, fixture.context.time_warp)
        .prove_violation(&fixture.base, &fixture.context.initial_block, &minimized, &minimized_predicate);
    assert_eq!(proof.status, FindingStatus::Proved);
    assert!(minimized_predicate.holds_in_context(proof.execution.as_ref().unwrap(), &fixture.context));

    let mut safe = minimized.clone();
    safe.txs[0].input = U256::from(5).to_be_bytes::<32>().to_vec();
    assert!(!RealismVerifier::with_time_warp(MAP_SIZE, fixture.context.time_warp)
        .prove_violation(&fixture.base, &fixture.context.initial_block, &safe, &minimized_predicate).success);
}

#[test]
fn nondefault_time_policy_survives_roundtrip_and_cannot_be_silently_replaced() {
    let fixture = Fixture::new(TimeWarp::from_seconds(37, 0));
    let (corpus, saved) = fixture.persist("x <= 5 || block.timestamp < 1037");
    let (record, input, execution) = corpus.replay_campaign_artifact(&saved.input_id, None).unwrap();
    let predicate = select_original_predicate(&record, &input, &execution).unwrap().1.unwrap();
    let ChainState::Evm(db) = &fixture.base;
    let executor = EvmExecutor::proof();
    let oracle = rusty_fuzz::common::oracle::security::PanicOracle;
    let minimizer = Minimizer::new(&executor, &oracle, db.clone(), fixture.context.initial_block.clone())
        .with_replay_context(&fixture.context).unwrap();
    let (input, predicate) = minimizer.minimize_violation(&input, &predicate, &fixture.context).unwrap();
    assert_eq!(input.txs.len(), 2, "the first transaction establishes the witnessed time");
    assert!(RealismVerifier::with_time_warp(MAP_SIZE, fixture.context.time_warp)
        .prove_violation(&fixture.base, &fixture.context.initial_block, &input, &predicate).success);
    assert!(!RealismVerifier::new(MAP_SIZE)
        .prove_violation(&fixture.base, &fixture.context.initial_block, &input, &predicate).success);
    assert!(Minimizer::new(&executor, &oracle, db.clone(), fixture.context.initial_block.clone())
        .minimize_violation(&input, &predicate, &fixture.context).is_err());
}

#[test]
fn missing_context_changed_evidence_and_rebound_predicates_fail_closed() {
    let fixture = Fixture::new(TimeWarp::NONE);
    let (_, mut record) = fixture.persist("x <= 5");
    let (execution, _) = fixture.discover("x <= 5");
    let mut changed = execution.clone();
    changed.tx_results[1].output.push(1);
    assert!(record.verify_replay(&fixture.input, &changed).is_err());
    let mut other_input = fixture.input.clone();
    other_input.txs[1].caller = Address::repeat_byte(0x33);
    assert!(record.verify_replay(&other_input, &execution).is_err());
    assert!(select_original_predicate(&record, &other_input, &execution).is_err());
    record.findings.retain(|finding| !matches!(finding.vuln, VulnType::InvariantViolation(_)));
    assert!(select_original_predicate(&record, &fixture.input, &execution).is_err());
    record.replay_context = None;
    assert!(record.recorded_context().is_err());
    let ChainState::Evm(db) = &fixture.base;
    let mut context = fixture.context.clone();
    context.chain_id = Some(1);
    assert!(context.validate(&db.db).is_err());
    context = fixture.context.clone();
    context.schema_version += 1;
    assert!(context.validate(&db.db).is_err());
}

#[test]
fn economic_views_describe_the_same_time_advanced_execution() {
    let mut fixture = Fixture::new(TimeWarp::from_seconds(37, 0));
    let ChainState::Evm(db) = &mut fixture.base;
    // balanceOf-shaped calls return slot zero; actions store the timestamp there.
    db.insert_account_info(fixture.input.txs[0].to, AccountInfo::default().with_code(Bytecode::new_raw(
        hex::decode("36602414600b57425f55005b5f545f5260205ff3").unwrap().into(),
    )));
    db.insert_account_storage(fixture.input.txs[0].to, U256::ZERO, U256::ZERO).unwrap();
    fixture.input.txs.truncate(2);
    for tx in &mut fixture.input.txs { tx.input.clear(); }
    let verifier = ReplayVerifier::with_time_warp(MAP_SIZE, fixture.context.time_warp);
    let result = verifier.replay_with_economic_views(&fixture.base, &fixture.context.initial_block, &fixture.input,
        Some(fixture.input.txs[0].to)).unwrap();
    assert_eq!(result.execution, verifier.replay(&fixture.base, &fixture.context.initial_block, &fixture.input).unwrap());
    assert_eq!(result.before.token_balances[0].value, U256::ZERO);
    assert_eq!(result.after.token_balances[0].value, U256::from(1037));
    assert_eq!(result.execution.storage_diffs.last().unwrap().new_value, U256::from(1037));
}
