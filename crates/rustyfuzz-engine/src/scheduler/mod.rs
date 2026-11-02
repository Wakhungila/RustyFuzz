use crate::input::EvmInput;
use crate::scoring::CampaignScore;
use libafl::corpus::{Corpus, CorpusId, HasTestcase};
use libafl::schedulers::{RemovableScheduler, Scheduler};
use libafl::state::HasCorpus;
use libafl::{Error, HasMetadata};
use libafl_bolts::impl_serdeany;
use libafl_bolts::tuples::MatchName;
use parking_lot::RwLock;
use rustyfuzz_core::InputId;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustyFuzzCampaignMetadata {
    pub score: CampaignScore,
    pub scheduled_count: u64,
}

impl RustyFuzzCampaignMetadata {
    pub fn new(score: CampaignScore) -> Self {
        Self {
            score,
            scheduled_count: 0,
        }
    }

    /// Deterministic scheduling priority.
    ///
    /// Pressure ranking (fair turns are assigned separately by the scheduler):
    /// base 1 + total + 2x economic pressure + 2x invariant pressure, decayed
    /// by up to half of `total` across repeated scheduling of the same entry
    /// (`scheduled_count`). This ranking alone does not prevent starvation.
    pub fn scheduling_weight(&self) -> u64 {
        1u64.saturating_add(self.score.total)
            .saturating_add(self.score.economic_pressure.saturating_mul(2))
            .saturating_add(self.score.invariant_pressure.saturating_mul(2))
            .saturating_sub(self.scheduled_count.min(self.score.total / 2))
    }
}

impl_serdeany!(RustyFuzzCampaignMetadata);

#[derive(Debug, Clone)]
pub struct RustyFuzzScheduler {
    fair_turn: bool,
    next_fair_id: u64,
    pending_score: Arc<RwLock<Option<CampaignScore>>>,
    evaluated_score: Option<(InputId, CampaignScore)>,
}

impl RustyFuzzScheduler {
    /// Persist the alternating turn and round-robin cursor, including across
    /// corpus additions/removals. Older queue-cycle tuples are incompatible.
    pub fn checkpoint(&self) -> (u64, u64) {
        (u64::from(self.fair_turn), self.next_fair_id)
    }

    pub fn restore(&mut self, counters: (u64, u64)) {
        self.fair_turn = counters.0 != 0;
        self.next_fair_id = counters.1;
        self.evaluated_score = None;
    }
    pub fn new() -> Self {
        Self {
            fair_turn: false,
            next_fair_id: 0,
            pending_score: Arc::new(RwLock::new(None)),
            evaluated_score: None,
        }
    }

    pub fn with_pending_score(pending_score: Arc<RwLock<Option<CampaignScore>>>) -> Self {
        Self {
            fair_turn: false,
            next_fair_id: 0,
            pending_score,
            evaluated_score: None,
        }
    }

    pub fn attach_score<I, S>(
        state: &mut S,
        id: CorpusId,
        score: CampaignScore,
    ) -> Result<(), Error>
    where
        S: HasTestcase<I>,
    {
        state
            .testcase_mut(id)?
            .add_metadata(RustyFuzzCampaignMetadata::new(score));
        Ok(())
    }
}

impl Default for RustyFuzzScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> RemovableScheduler<I, S> for RustyFuzzScheduler {}

impl<S> Scheduler<EvmInput, S> for RustyFuzzScheduler
where
    S: HasCorpus<EvmInput> + HasTestcase<EvmInput>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        let current_id = *state.corpus().current();
        state
            .corpus()
            .get(id)?
            .borrow_mut()
            .set_parent_id_optional(current_id);
        // LibAFL evaluates before it inserts a retained child. Never attach a
        // child's score to the currently scheduled parent. Consume even a
        // mismatching record so a discarded evaluation cannot score a seed.
        if let Some((input, score)) = self.evaluated_score.take() {
            let mut testcase = state.testcase_mut(id)?;
            let retained = testcase.load_input(state.corpus())?;
            if retained.semantic_input_id() == input {
                testcase.add_metadata(RustyFuzzCampaignMetadata::new(score));
            }
        }
        Ok(())
    }

    fn on_evaluation<OT>(
        &mut self,
        _state: &mut S,
        input: &EvmInput,
        _observers: &OT,
    ) -> Result<(), Error>
    where
        OT: MatchName,
    {
        self.evaluated_score = self
            .pending_score
            .write()
            .take()
            .map(|score| (input.semantic_input_id(), score));
        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        // Any evaluation left here was discarded or recorded as an objective.
        self.evaluated_score = None;
        if state.corpus().count() == 0 {
            return Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented.",
            ));
        }

        // Half of selections provide score-independent exploration. For a
        // stable corpus of N entries, every entry is selected within 2N calls,
        // even when its metadata is absent or another score is saturated.
        let next = if self.fair_turn {
            let next = state
                .corpus()
                .ids()
                .filter(|id| id.0 as u64 >= self.next_fair_id)
                .min_by_key(|id| id.0)
                .or_else(|| state.corpus().ids().min_by_key(|id| id.0))
                .expect("non-empty corpus");
            self.next_fair_id = (next.0 as u64).checked_add(1).unwrap_or(0);
            next
        } else {
            best_campaign_id(state)?.expect("non-empty corpus")
        };
        self.fair_turn = !self.fair_turn;
        self.set_current_scheduled(state, Some(next))?;
        if let Ok(mut testcase) = state.testcase_mut(next) {
            if let Ok(metadata) = testcase.metadata_mut::<RustyFuzzCampaignMetadata>() {
                metadata.scheduled_count = metadata.scheduled_count.saturating_add(1);
            }
            let scheduled_count = testcase.scheduled_count().saturating_add(1);
            testcase.set_scheduled_count(scheduled_count);
        }
        Ok(next)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_id;
        Ok(())
    }
}

fn best_campaign_id<S>(state: &S) -> Result<Option<CorpusId>, Error>
where
    S: HasCorpus<EvmInput>,
{
    let mut best: Option<(CorpusId, u64, u64)> = None;
    for id in state.corpus().ids() {
        let testcase = state.corpus().get(id)?.borrow();
        let candidate = testcase
            .metadata_map()
            .get::<RustyFuzzCampaignMetadata>()
            .map_or((id, 1, 0), |metadata| {
                (id, metadata.scheduling_weight(), metadata.score.total)
            });
        if best
            .as_ref()
            .is_none_or(|current| compare_candidate(candidate, *current) == Ordering::Greater)
        {
            best = Some(candidate);
        }
    }
    Ok(best.map(|(id, _, _)| id))
}

fn compare_candidate(a: (CorpusId, u64, u64), b: (CorpusId, u64, u64)) -> Ordering {
    a.1.cmp(&b.1)
        .then_with(|| a.2.cmp(&b.2))
        .then_with(|| b.0 .0.cmp(&a.0 .0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::CampaignScore;
    use libafl::corpus::{Corpus, HasTestcase, InMemoryCorpus, Testcase};
    use libafl::state::HasCorpus;
    use std::cell::{Ref, RefMut};

    struct TestState {
        corpus: InMemoryCorpus<EvmInput>,
    }

    impl Default for TestState {
        fn default() -> Self {
            Self {
                corpus: InMemoryCorpus::new(),
            }
        }
    }

    impl HasCorpus<EvmInput> for TestState {
        type Corpus = InMemoryCorpus<EvmInput>;

        fn corpus(&self) -> &Self::Corpus {
            &self.corpus
        }

        fn corpus_mut(&mut self) -> &mut Self::Corpus {
            &mut self.corpus
        }
    }

    impl HasTestcase<EvmInput> for TestState {
        fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<EvmInput>>, Error> {
            Ok(self.corpus.get(id)?.borrow())
        }

        fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<EvmInput>>, Error> {
            Ok(self.corpus.get(id)?.borrow_mut())
        }
    }

    fn empty_input() -> EvmInput {
        EvmInput {
            txs: Vec::new(),
            base_snapshot_id: 0,
        }
    }

    fn score(total: u64, economic: u64, invariant: u64) -> CampaignScore {
        CampaignScore {
            total,
            economic_pressure: economic,
            invariant_pressure: invariant,
            counterexample_pressure: 0,
            oracle_pressure: 0,
            state_pressure: 0,
            exploration_pressure: 0,
            explanation: Vec::new(),
        }
    }

    #[test]
    fn scheduling_weight_formula_is_deterministic_and_decaying() {
        let fresh = RustyFuzzCampaignMetadata::new(score(100, 50, 50));
        // 1 + 100 + 2*50 + 2*50 = 301
        assert_eq!(fresh.scheduling_weight(), 301);

        let mut scheduled_out = RustyFuzzCampaignMetadata::new(score(100, 50, 50));
        scheduled_out.scheduled_count = 200; // decay capped at total/2 = 50
        assert_eq!(scheduled_out.scheduling_weight(), 251);

        let zero = RustyFuzzCampaignMetadata::new(score(0, 0, 0));
        assert_eq!(zero.scheduling_weight(), 1);
    }

    #[test]
    fn scheduler_prefers_campaign_metadata_over_fifo_order() {
        let mut state = TestState::default();
        let low = state
            .corpus_mut()
            .add(Testcase::new(empty_input()))
            .expect("add low");
        let high = state
            .corpus_mut()
            .add(Testcase::new(empty_input()))
            .expect("add high");
        RustyFuzzScheduler::attach_score(&mut state, low, score(10, 0, 0)).expect("low score");
        RustyFuzzScheduler::attach_score(&mut state, high, score(100, 50, 50)).expect("high score");

        let mut scheduler = RustyFuzzScheduler::new();
        let selected = scheduler.next(&mut state).expect("next");
        assert_eq!(selected, high);
    }

    fn add(state: &mut TestState, snapshot: u64) -> CorpusId {
        state
            .corpus_mut()
            .add(Testcase::new(EvmInput::new(Vec::new(), snapshot)))
            .unwrap()
    }

    #[test]
    fn fair_turns_bound_starvation_including_unscored_entries() {
        let mut state = TestState::default();
        let high = add(&mut state, 0);
        let low = add(&mut state, 1);
        let missing = add(&mut state, 2);
        RustyFuzzScheduler::attach_score(&mut state, high, score(u64::MAX, u64::MAX, u64::MAX))
            .unwrap();
        RustyFuzzScheduler::attach_score(&mut state, low, score(1, 0, 0)).unwrap();
        let mut scheduler = RustyFuzzScheduler::new();
        for _ in 0..10 {
            let selected: Vec<_> = (0..6)
                .map(|_| scheduler.next(&mut state).unwrap())
                .collect();
            for id in [high, low, missing] {
                assert!(selected.contains(&id), "starved {id:?}: {selected:?}");
            }
        }
    }

    #[test]
    fn fair_cursor_survives_removal_addition_and_restart() {
        let mut state = TestState::default();
        let first = add(&mut state, 0);
        let removed = add(&mut state, 1);
        let third = add(&mut state, 2);
        let mut scheduler = RustyFuzzScheduler::new();
        assert_eq!(scheduler.next(&mut state).unwrap(), first);
        assert_eq!(scheduler.next(&mut state).unwrap(), first);
        state.corpus_mut().remove(removed).unwrap();
        let fourth = add(&mut state, 3);
        RustyFuzzScheduler::attach_score(&mut state, fourth, score(100, 1, 1)).unwrap();
        let corpus_json = serde_json::to_vec(&state.corpus).unwrap();
        let mut restored_state = TestState {
            corpus: serde_json::from_slice(&corpus_json).unwrap(),
        };
        let mut restored = RustyFuzzScheduler::new();
        restored.restore(scheduler.checkpoint());
        let selections: Vec<_> = (0..12)
            .map(|_| {
                let expected = scheduler.next(&mut state).unwrap();
                assert_eq!(restored.next(&mut restored_state).unwrap(), expected);
                assert_eq!(restored.checkpoint(), scheduler.checkpoint());
                expected
            })
            .collect();
        assert!(selections.contains(&third));
        assert!(selections.contains(&fourth));
        assert!(!selections.contains(&removed));
    }

    #[test]
    fn evaluated_score_is_consumed_only_by_matching_retained_child() {
        let mut state = TestState::default();
        let parent = add(&mut state, 0);
        let pending = Arc::new(RwLock::new(Some(score(900, 0, 0))));
        let mut scheduler = RustyFuzzScheduler::with_pending_score(pending.clone());
        scheduler
            .set_current_scheduled(&mut state, Some(parent))
            .unwrap();
        let child = EvmInput::new(Vec::new(), 1);
        scheduler.on_evaluation(&mut state, &child, &()).unwrap();
        assert!(!state
            .testcase(parent)
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());
        let child_id = state.corpus_mut().add(Testcase::new(child)).unwrap();
        scheduler.on_add(&mut state, child_id).unwrap();
        assert_eq!(
            state
                .testcase(child_id)
                .unwrap()
                .metadata::<RustyFuzzCampaignMetadata>()
                .unwrap()
                .score
                .total,
            900
        );

        *pending.write() = Some(score(123, 0, 0));
        scheduler
            .on_evaluation(&mut state, &empty_input(), &())
            .unwrap();
        let imported = add(&mut state, 2);
        scheduler.on_add(&mut state, imported).unwrap();
        assert!(!state
            .testcase(imported)
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());
        let later = add(&mut state, 0);
        scheduler.on_add(&mut state, later).unwrap();
        assert!(!state
            .testcase(later)
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());
    }

    #[test]
    fn next_evaluation_without_score_clears_discarded_score() {
        let mut state = TestState::default();
        let pending = Arc::new(RwLock::new(Some(score(900, 0, 0))));
        let mut scheduler = RustyFuzzScheduler::with_pending_score(pending);
        scheduler
            .on_evaluation(&mut state, &empty_input(), &())
            .unwrap();
        scheduler
            .on_evaluation(&mut state, &empty_input(), &())
            .unwrap();
        let retained = add(&mut state, 0);
        scheduler.on_add(&mut state, retained).unwrap();
        assert!(!state
            .testcase(retained)
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());
    }

    #[test]
    fn std_fuzzer_scores_retained_child_and_drops_discarded_evaluations() {
        use libafl::events::NopEventManager;
        use libafl::executors::nop::NopExecutor;
        use libafl::feedbacks::ConstFeedback;
        use libafl::fuzzer::{Evaluator, HasFeedback, StdFuzzer};
        use libafl::state::StdState;
        use libafl_bolts::rands::StdRand;

        let pending = Arc::new(RwLock::new(None));
        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            StdRand::with_seed(7),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        let mut fuzzer = StdFuzzer::new(
            RustyFuzzScheduler::with_pending_score(pending.clone()),
            feedback,
            objective,
        );
        let mut executor = NopExecutor::ok();
        let mut manager = NopEventManager::new();
        let parent = state
            .corpus_mut()
            .add(Testcase::new(empty_input()))
            .unwrap();
        *state.corpus_mut().current_mut() = Some(parent);
        *pending.write() = Some(score(99, 3, 4));
        let child = EvmInput::new(Vec::new(), 1);
        let (_, retained) = fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, &child)
            .unwrap();
        let retained = retained.expect("interesting child retained");
        assert_eq!(
            state
                .testcase(retained)
                .unwrap()
                .metadata::<RustyFuzzCampaignMetadata>()
                .unwrap()
                .score
                .total,
            99
        );
        assert!(!state
            .testcase(parent)
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());

        *fuzzer.feedback_mut() = ConstFeedback::new(false);
        *pending.write() = Some(score(1234, 0, 0));
        let discarded = EvmInput::new(Vec::new(), 2);
        let (_, id) = fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, &discarded)
            .unwrap();
        assert!(id.is_none());
        *fuzzer.feedback_mut() = ConstFeedback::new(true);
        let child = EvmInput::new(Vec::new(), 3);
        let (_, retained) = fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, &child)
            .unwrap();
        assert!(!state
            .testcase(retained.unwrap())
            .unwrap()
            .has_metadata::<RustyFuzzCampaignMetadata>());
    }
}
