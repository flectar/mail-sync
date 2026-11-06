//! An in-memory [`Store`]: a reference for app stores, and what the tests
//! sync. Its merge rule is the simplest one: a deletion from the server
//! wins, otherwise the newer stamp wins.

use crate::client::Secrets;
use crate::clock::Clock;
use crate::engine::{Entry, Mirrored, Pending, Remote, Store};
use crate::error::StoreError;
use crate::identity::ChainOp;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct MemoryStore {
    pub cursor: u64,
    pub seen: u64,
    pub mirror: BTreeMap<[u8; 16], Mirrored>,
    /// At most one pending change per record: the newest.
    pub outbox: BTreeMap<[u8; 16], Pending>,
    /// The app's state.
    pub entries: BTreeMap<[u8; 16], Entry>,
    pub chain: Vec<ChainOp>,
    pub secrets: Option<Secrets>,
}

impl MemoryStore {
    /// A local change: the app's state changes at once, and the change
    /// waits for upload.
    pub fn change(&mut self, clock: &Clock, record_id: [u8; 16], entry: Option<Entry>) {
        match &entry {
            Some(entry) => self.entries.insert(record_id, entry.clone()),
            None => self.entries.remove(&record_id),
        };
        let base_seq = self
            .mirror
            .get(&record_id)
            .map_or(0, |mirrored| mirrored.seq);
        self.outbox.insert(
            record_id,
            Pending {
                record_id,
                base_seq,
                stamp: clock.now(),
                entry,
            },
        );
    }
}

impl Store for MemoryStore {
    fn cursor(&mut self) -> Result<u64, StoreError> {
        Ok(self.cursor)
    }

    fn seen(&mut self) -> Result<u64, StoreError> {
        Ok(self.seen)
    }

    fn set_seen(&mut self, seq: u64) -> Result<(), StoreError> {
        self.seen = seq;
        Ok(())
    }

    fn mirrored(&mut self, record_id: &[u8; 16]) -> Result<Option<Mirrored>, StoreError> {
        Ok(self.mirror.get(record_id).cloned())
    }

    fn mirrored_ids(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        Ok(self.mirror.keys().copied().collect())
    }

    fn apply(&mut self, changes: &[Remote], cursor: u64) -> Result<(), StoreError> {
        for change in changes {
            let previous = self.mirror.get(&change.record_id).and_then(|m| m.stamp);
            self.mirror.insert(
                change.record_id,
                Mirrored {
                    seq: change.seq,
                    stamp: change.stamp.or(previous),
                    entry: change.entry.clone(),
                },
            );
            let local_wins = match (&change.entry, self.outbox.get(&change.record_id)) {
                (None, _) | (_, None) => false,
                (Some(_), Some(pending)) => change.stamp.is_none_or(|stamp| pending.stamp > stamp),
            };
            if local_wins {
                if let Some(pending) = self.outbox.get_mut(&change.record_id) {
                    pending.base_seq = change.seq;
                }
                continue;
            }
            self.outbox.remove(&change.record_id);
            match &change.entry {
                Some(entry) => self.entries.insert(change.record_id, entry.clone()),
                None => self.entries.remove(&change.record_id),
            };
        }
        self.cursor = cursor;
        Ok(())
    }

    fn pending(&mut self, limit: usize) -> Result<Vec<Pending>, StoreError> {
        let mut pending: Vec<Pending> = self.outbox.values().cloned().collect();
        pending.sort_by_key(|change| change.stamp);
        pending.truncate(limit);
        Ok(pending)
    }

    fn committed(&mut self, committed: &[(Pending, u64)]) -> Result<(), StoreError> {
        for (change, seq) in committed {
            self.mirror.insert(
                change.record_id,
                Mirrored {
                    seq: *seq,
                    stamp: Some(change.stamp),
                    entry: change.entry.clone(),
                },
            );
            match self.outbox.get_mut(&change.record_id) {
                Some(newer) if newer.stamp != change.stamp => newer.base_seq = *seq,
                _ => {
                    self.outbox.remove(&change.record_id);
                }
            }
        }
        Ok(())
    }

    fn discard(&mut self, pending: &Pending) -> Result<(), StoreError> {
        if self
            .outbox
            .get(&pending.record_id)
            .is_some_and(|stored| stored.stamp == pending.stamp)
        {
            self.outbox.remove(&pending.record_id);
        }
        Ok(())
    }

    fn forget(&mut self, record_ids: &[[u8; 16]]) -> Result<(), StoreError> {
        for record_id in record_ids {
            self.mirror.remove(record_id);
            // Deleted elsewhere: the deletion wins over local edits.
            if self
                .outbox
                .get(record_id)
                .is_none_or(|pending| pending.base_seq > 0)
            {
                self.outbox.remove(record_id);
                self.entries.remove(record_id);
            }
        }
        Ok(())
    }

    fn requeue(&mut self, record_id: &[u8; 16], base_seq: u64) -> Result<(), StoreError> {
        if let Some(pending) = self.outbox.get_mut(record_id) {
            pending.base_seq = base_seq;
            return Ok(());
        }
        if let Some(mirrored) = self.mirror.get(record_id)
            && let Some(stamp) = mirrored.stamp
        {
            self.outbox.insert(
                *record_id,
                Pending {
                    record_id: *record_id,
                    base_seq,
                    stamp,
                    entry: mirrored.entry.clone(),
                },
            );
        }
        Ok(())
    }

    fn save_chain(&mut self, chain: &[ChainOp]) -> Result<(), StoreError> {
        self.chain = chain.to_vec();
        Ok(())
    }

    fn save_secrets(&mut self, secrets: &Secrets) -> Result<(), StoreError> {
        self.secrets = Some(secrets.clone());
        Ok(())
    }
}
