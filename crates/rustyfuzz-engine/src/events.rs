//! Bounded cold-path event sink.
//!
//! Global invariant #8: the execution hot path must not synchronously write
//! reports, spawn tooling, or perform other cold IO. The harnesses emit small
//! [`CampaignEvent`]s through an [`EventSink`]; a consumer thread (or future
//! CLI command) drains them. Delivery is best-effort by design: when the
//! bounded queue is full the event is counted and dropped instead of blocking
//! fuzzing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

/// Default bounded queue capacity for campaign event sinks.
pub const DEFAULT_EVENT_SINK_CAPACITY: usize = 4_096;

/// Cold-path campaign events. Kept intentionally small and non-owning of
/// heavyweight payloads (ids/handles only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignEvent {
    /// A post-execution snapshot was retained by the snapshot corpus.
    NewSnapshot { id: u64, parent: u64 },
    /// A campaign artifact (candidate finding) was persisted.
    CandidateFinding { input_id: String },
    /// Periodic campaign checkpoint.
    CampaignCheckpoint { executions: u64, artifacts: u64 },
}

/// Bounded sender/receiver pair with explicit drop accounting.
///
/// Cloneable handle; all clones share one queue and one drop counter.
pub struct EventSink {
    sender: SyncSender<CampaignEvent>,
    dropped: Arc<AtomicU64>,
    capacity: usize,
}

impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink")
            .field("capacity", &self.capacity)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish()
    }
}

impl EventSink {
    /// Creates a sink with the given bounded queue capacity.
    pub fn bounded(capacity: usize) -> (Self, Receiver<CampaignEvent>) {
        let (sender, receiver) = mpsc::sync_channel(capacity.max(1));
        (
            Self {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
                capacity: capacity.max(1),
            },
            receiver,
        )
    }

    /// Non-blocking emit; never blocks the execution hot path.
    pub fn emit(&self, event: CampaignEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Events dropped so far due to backpressure.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Clone for EventSink {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            dropped: Arc::clone(&self.dropped),
            capacity: self.capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_within_capacity_and_counts_drops_beyond() {
        let (sink, rx) = EventSink::bounded(2);
        for id in 0..5u64 {
            sink.emit(CampaignEvent::NewSnapshot { id, parent: 0 });
        }
        assert_eq!(sink.dropped_count(), 3);
        let received: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0], CampaignEvent::NewSnapshot { id: 0, parent: 0 });
    }

    #[test]
    fn clones_share_queue_and_drop_counter() {
        let (sink, _rx) = EventSink::bounded(1);
        let clone = sink.clone();
        clone.emit(CampaignEvent::CandidateFinding {
            input_id: "a".into(),
        });
        clone.emit(CampaignEvent::CampaignCheckpoint {
            executions: 1,
            artifacts: 1,
        });
        assert_eq!(sink.dropped_count(), 1);
        assert_eq!(sink.capacity(), 1);
    }
}
