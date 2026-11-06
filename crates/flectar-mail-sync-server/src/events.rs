//! In-process fan-out of "this group's `high_seq` advanced" to the devices
//! listening on the group's event stream.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use tokio::sync::broadcast;

/// Slow listeners only ever need the newest value, so a short buffer is
/// enough: a lagging listener skips to the latest `high_seq`.
const BUFFER: usize = 8;

#[derive(Debug, Default)]
pub struct Events {
    channels: Mutex<HashMap<[u8; 16], broadcast::Sender<u64>>>,
}

impl Events {
    pub fn subscribe(&self, group_id: [u8; 16]) -> broadcast::Receiver<u64> {
        self.channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(group_id)
            .or_insert_with(|| broadcast::channel(BUFFER).0)
            .subscribe()
    }

    /// Tell the group's listeners about a new `high_seq`; forgets groups
    /// nobody listens to any more.
    pub fn publish(&self, group_id: [u8; 16], high_seq: u64) {
        let mut channels = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sender) = channels.get(&group_id)
            && sender.send(high_seq).is_err()
        {
            channels.remove(&group_id);
        }
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
        events.publish([1; 16], 7);
        assert_eq!(listener.recv().await.unwrap(), 7);
        drop(listener);
        events.publish([1; 16], 8);
        assert_eq!(events.group_count(), 0);
        events.publish([2; 16], 1);
        assert_eq!(events.group_count(), 0, "publishing never creates channels");
    }
}
