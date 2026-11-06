//! In-process fan-out of group updates to the devices listening on the
//! group's event stream: its `high_seq` advanced, or its chain grew.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use tokio::sync::broadcast;

/// Slow listeners only ever need the newest values, so a short buffer is
/// enough: a lagging listener skips ahead.
const BUFFER: usize = 8;

/// What changed in a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    /// The newest record sequence number.
    Seq(u64),
    /// The index of the newest membership operation.
    Chain(u64),
}

#[derive(Debug, Default)]
pub struct Events {
    channels: Mutex<HashMap<[u8; 16], broadcast::Sender<Update>>>,
    closed: AtomicBool,
}

impl Events {
    /// Listen to a group. After [`Events::close_all`] the receiver is already
    /// closed, so its stream ends at once.
    pub fn subscribe(&self, group_id: [u8; 16]) -> broadcast::Receiver<Update> {
        if self.closed.load(Ordering::Acquire) {
            return broadcast::channel(1).1;
        }
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(group_id)
            .or_insert_with(|| broadcast::channel(BUFFER).0)
            .subscribe()
    }

    /// Tell the group's listeners about an update; forgets groups nobody
    /// listens to any more.
    pub fn publish(&self, group_id: [u8; 16], update: Update) {
        let mut channels = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sender) = channels.get(&group_id)
            && sender.send(update).is_err()
        {
            channels.remove(&group_id);
        }
    }

    /// Forget groups whose listeners have all gone.
    pub fn prune(&self) {
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, sender| sender.receiver_count() > 0);
    }

    /// End the event streams of one group, e.g. after it is deleted.
    pub fn close_group(&self, group_id: [u8; 16]) {
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&group_id);
    }

    /// End every event stream, so a graceful shutdown does not wait for
    /// listeners that never disconnect on their own.
    pub fn close_all(&self) {
        self.closed.store(true, Ordering::Release);
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    #[cfg(test)]
    fn group_count(&self) -> usize {
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listeners_receive_new_seqs_and_idle_groups_are_forgotten() {
        let events = Events::default();
        let mut listener = events.subscribe([1; 16]);
        events.publish([1; 16], Update::Seq(7));
        assert_eq!(listener.recv().await.unwrap(), Update::Seq(7));
        drop(listener);
        events.publish([1; 16], Update::Chain(2));
        assert_eq!(events.group_count(), 0);
        events.publish([2; 16], Update::Seq(1));
        assert_eq!(events.group_count(), 0, "publishing never creates channels");
    }

    #[tokio::test]
    async fn pruning_drops_only_unheard_groups() {
        let events = Events::default();
        let _kept = events.subscribe([1; 16]);
        drop(events.subscribe([2; 16]));
        events.prune();
        assert_eq!(events.group_count(), 1);
    }

    #[tokio::test]
    async fn closing_ends_current_and_future_listeners() {
        let events = Events::default();
        let mut listener = events.subscribe([1; 16]);
        events.close_all();
        assert_eq!(
            listener.recv().await,
            Err(broadcast::error::RecvError::Closed)
        );
        let mut late = events.subscribe([1; 16]);
        assert_eq!(late.recv().await, Err(broadcast::error::RecvError::Closed));
    }
}
