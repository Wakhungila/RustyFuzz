use crate::engine::scoring::CampaignScore;
use crate::evm::fuzz::EvmInput;
use libafl::corpus::{Corpus, CorpusId, HasTestcase};
use libafl::schedulers::{RemovableScheduler, Scheduler};
use libafl::state::HasCorpus;
use libafl::{Error, HasMetadata};
use libafl_bolts::impl_serdeany;
use libafl_bolts::tuples::MatchName;
use parking_lot::RwLock;
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

    pub fn scheduling_weight(&self) -> u64 {
        1 + self.score.total + self.score.economic_pressure * 2 + self.score.invariant_pressure * 2
            - self.scheduled_count.min(self.score.total / 2)
    }
}

impl_serdeany!(RustyFuzzCampaignMetadata);

#[derive(Debug, Clone)]
pub struct RustyFuzzScheduler {
    queue_cycles: u64,
    runs_in_current_cycle: u64,
    pending_score: Arc<RwLock<Option<CampaignScore>>>,
}

impl RustyFuzzScheduler {
    pub fn new() -> Self {
        Self {
            queue_cycles: 0,
            runs_in_current_cycle: 0,
            pending_score: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_pending_score(pending_score: Arc<RwLock<Option<CampaignScore>>>) -> Self {
        Self {
            queue_cycles: 0,
            runs_in_current_cycle: 0,
            pending_score,
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
        Ok(())
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut S,
        _input: &EvmInput,
        _observers: &OT,
    ) -> Result<(), Error>
    where
        OT: MatchName,
    {
        let Some(score) = self.pending_score.write().take() else {
            return Ok(());
        };
        let Some(current) = *state.corpus().current() else {
            return Ok(());
        };
        Self::attach_score(state, current, score)
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            return Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented.",
            ));
        }

        let next = best_campaign_id(state)?.unwrap_or_else(|| {
            state
                .corpus()
                .current()
                .and_then(|id| state.corpus().next(id))
                .unwrap_or_else(|| state.corpus().first().expect("non-empty corpus"))
        });

        self.runs_in_current_cycle += 1;
        if self.runs_in_current_cycle >= state.corpus().count() as u64 {
            self.queue_cycles += 1;
            self.runs_in_current_cycle = 0;
        }
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
        let Some(metadata) = testcase.metadata_map().get::<RustyFuzzCampaignMetadata>() else {
            continue;
        };
        let candidate = (id, metadata.scheduling_weight(), metadata.score.total);
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
    use crate::engine::scoring::CampaignScore;
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
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        }
    }

    fn score(total: u64, economic: u64, invariant: u64) -> CampaignScore {
        CampaignScore {
            total,
            economic_pressure: economic,
            invariant_pressure: invariant,
            oracle_pressure: 0,
            state_pressure: 0,
            exploration_pressure: 0,
            explanation: Vec::new(),
        }
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
}
