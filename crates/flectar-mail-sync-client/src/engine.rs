//! Records (SPEC §4.5, §6.5, §6.6, §8): the app's state, sealed into
//! records and kept the same on every device.
//!
//! The app implements [`Store`] on its database and decides how to merge;
//! this module seals and opens records, orders them with [`Stamp`]s, and
//! runs the pull and push protocol, including conflicts, expired cursors
//! and servers that lost data.

use crate::client::{Secrets, SyncClient};
use crate::clock::Stamp;
use crate::error::{Error, Result, StoreError};
use crate::http::CommitOutcome;
use crate::identity::ChainOp;
use crate::sse::Event;
use flectar_mail_sync_crypto::{RootKey, collection_tag, open_record, seal_record};
use flectar_mail_sync_proto::{Bytes, CommitItem, CommitRequest, ErrorCode, Limits, Record};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Rounds of pull and push before a sync gives way to other writers.
const SYNC_ROUNDS: usize = 5;
/// Batches one push sends at most, as a guard against a store that never
/// empties its outbox.
const MAX_BATCHES: usize = 10_000;
const ENVELOPE_VERSION: u32 = 1;

/// A record's content as the app sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// What kind of state the record holds, such as `pref` or `account`.
    pub collection: String,
    /// The version of the collection's body format.
    pub schema: u32,
    pub body: serde_json::Value,
}

/// A server version of a record, handed to [`Store::apply`].
#[derive(Clone, Debug, PartialEq)]
pub struct Remote {
    pub record_id: [u8; 16],
    pub seq: u64,
    /// `None` for deletions: the server keeps no payload for them.
    pub stamp: Option<Stamp>,
    /// `None` if the record was deleted.
    pub entry: Option<Entry>,
}

/// The last server version of a record a store knows: the base of merges.
#[derive(Clone, Debug, PartialEq)]
pub struct Mirrored {
    pub seq: u64,
    /// The newest stamp seen for the record. Stores keep it after a
    /// deletion, so an older version replayed later is recognised.
    pub stamp: Option<Stamp>,
    /// `None` if the record is deleted.
    pub entry: Option<Entry>,
}

/// A local change waiting to be uploaded.
#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub record_id: [u8; 16],
    /// The mirrored `seq` the change was made on; 0 for a new record.
    pub base_seq: u64,
    /// From [`crate::Clock::now`] when the change was made.
    pub stamp: Stamp,
    /// `None` deletes the record.
    pub entry: Option<Entry>,
}

/// Where a device keeps its sync state. The app implements it on its
/// database; each method should be one transaction.
pub trait Store: Send {
    /// The sequence number up to which server changes are applied.
    fn cursor(&mut self) -> std::result::Result<u64, StoreError>;

    /// The highest sequence number this device knows the server reached,
    /// from its reads and its own commits. A server below it lost data.
    fn seen(&mut self) -> std::result::Result<u64, StoreError>;

    fn set_seen(&mut self, seq: u64) -> std::result::Result<(), StoreError>;

    fn mirrored(
        &mut self,
        record_id: &[u8; 16],
    ) -> std::result::Result<Option<Mirrored>, StoreError>;

    fn mirrored_ids(&mut self) -> std::result::Result<Vec<[u8; 16]>, StoreError>;

    /// Apply server changes, then set the cursor. For each change, update
    /// the mirror, merge the change into the app's state, and rebase any
    /// pending change of the record on it (`base_seq` = the change's
    /// `seq`), or drop the pending change if the merge made it moot.
    fn apply(&mut self, changes: &[Remote], cursor: u64) -> std::result::Result<(), StoreError>;

    /// Pending local changes, oldest first, at most `limit`.
    fn pending(&mut self, limit: usize) -> std::result::Result<Vec<Pending>, StoreError>;

    /// These pending changes were stored at the given sequence numbers:
    /// mirror them. If a record changed again meanwhile, keep its newer
    /// pending change and rebase it on the new `seq`.
    fn committed(&mut self, committed: &[(Pending, u64)]) -> std::result::Result<(), StoreError>;

    /// Drop a pending change that needs no upload: the deletion of a record
    /// the server never had.
    fn discard(&mut self, pending: &Pending) -> std::result::Result<(), StoreError>;

    /// Forget mirrored records the server no longer has: they were deleted
    /// and their tombstones expired. New records still pending stay.
    fn forget(&mut self, record_ids: &[[u8; 16]]) -> std::result::Result<(), StoreError>;

    /// Upload the mirrored version of a record again, on `base_seq`: the
    /// server lost it or served an older one. A newer pending change of
    /// the record only gets the new base.
    fn requeue(
        &mut self,
        record_id: &[u8; 16],
        base_seq: u64,
    ) -> std::result::Result<(), StoreError>;

    /// Keep the verified chain, in the app's database.
    fn save_chain(&mut self, chain: &[ChainOp]) -> std::result::Result<(), StoreError>;

    /// Keep the device's secrets, in the OS key store.
    fn save_secrets(&mut self, secrets: &Secrets) -> std::result::Result<(), StoreError>;
}

/// What a sync did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    /// Record versions older than ones this device saw, refused and
    /// uploaded again.
    pub refused: usize,
    /// The server had lost changes this device saw; they were uploaded
    /// again.
    pub restored: bool,
    /// Records that failed to open or parse, and were skipped: a member's
    /// bug, or tampering. One bad record must not stop sync for good.
    pub unreadable: usize,
    pub high_seq: u64,
}

#[derive(Serialize, Deserialize)]
struct WireStamp {
    ms: u64,
    counter: u32,
    device: Bytes,
}

/// The plaintext of a record. Unknown fields from newer versions are
/// ignored; new fields must be safe to drop.
#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    collection: String,
    schema: u32,
    stamp: WireStamp,
    body: serde_json::Value,
}

fn store<T>(result: std::result::Result<T, StoreError>) -> Result<T> {
    result.map_err(Error::Store)
}

fn record_id(record: &Record) -> Result<[u8; 16]> {
    record
        .record_id
        .to_array()
        .ok_or_else(|| Error::Malformed("record id".into()))
}

fn seal(root: &RootKey, group_id: &[u8; 16], epoch: u64, pending: &Pending) -> Result<CommitItem> {
    let Some(entry) = &pending.entry else {
        return Ok(CommitItem {
            record_id: Bytes::from(pending.record_id),
            expected_seq: pending.base_seq,
            deleted: true,
            ..CommitItem::default()
        });
    };
    let plaintext = serde_json::to_vec(&Envelope {
        v: ENVELOPE_VERSION,
        collection: entry.collection.clone(),
        schema: entry.schema,
        stamp: WireStamp {
            ms: pending.stamp.ms,
            counter: pending.stamp.counter,
            device: Bytes::from(pending.stamp.device),
        },
        body: entry.body.clone(),
    })
    .map_err(|error| Error::Malformed(error.to_string()))?;
    let tag = collection_tag(&root.tag_key(epoch), &entry.collection);
    let (nonce, ciphertext) = seal_record(
        &root.record_key(epoch),
        group_id,
        &pending.record_id,
        &tag,
        epoch,
        &plaintext,
    )?;
    Ok(CommitItem {
        record_id: Bytes::from(pending.record_id),
        expected_seq: pending.base_seq,
        deleted: false,
        tag: Some(Bytes::from(tag)),
        epoch: Some(epoch),
        nonce: Some(Bytes::from(nonce)),
        ciphertext: Some(Bytes(ciphertext)),
    })
}

fn open(root: &RootKey, group_id: &[u8; 16], record: &Record) -> Result<(Stamp, Entry)> {
    let malformed = || Error::Malformed("record payload".into());
    let (Some(tag), Some(epoch), Some(nonce), Some(ciphertext)) =
        (&record.tag, record.epoch, &record.nonce, &record.ciphertext)
    else {
        return Err(malformed());
    };
    let tag: [u8; 16] = tag.to_array().ok_or_else(malformed)?;
    let plaintext = open_record(
        &root.record_key(epoch),
        group_id,
        &record_id(record)?,
        &tag,
        epoch,
        &nonce.to_array().ok_or_else(malformed)?,
        ciphertext.as_slice(),
    )?;
    let envelope: Envelope =
        serde_json::from_slice(&plaintext).map_err(|error| Error::Malformed(error.to_string()))?;
    if collection_tag(&root.tag_key(epoch), &envelope.collection) != tag {
        return Err(Error::Untrusted(
            "a record's collection does not match its tag",
        ));
    }
    let stamp = Stamp {
        ms: envelope.stamp.ms,
        counter: envelope.stamp.counter,
        device: envelope.stamp.device.to_array().ok_or_else(malformed)?,
    };
    Ok((
        stamp,
        Entry {
            collection: envelope.collection,
            schema: envelope.schema,
            body: envelope.body,
        },
    ))
}

/// Why the whole group is read again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FullRead {
    /// The cursor is older than the tombstone horizon.
    Expired,
    /// The server's newest seq is below the cursor: it lost changes.
    Rollback,
}

enum Pushed {
    Done,
    Conflicts,
    StaleEpoch,
}

impl SyncClient {
    async fn limits(&self) -> Result<Limits> {
        Ok(self
            .limits
            .get_or_try_init(async || self.http.info().await.map(|info| info.limits))
            .await?
            .clone())
    }

    /// Store the chain and secrets if they changed since they were last
    /// stored.
    async fn persist(&self, store: &mut dyn Store) -> Result<()> {
        let chain = self.chain.lock().await;
        let mut persisted = self.persisted.lock().await;
        let now = (
            chain.ops.len(),
            chain.roots.keys().copied().collect::<Vec<_>>(),
        );
        if persisted.0 != now.0 {
            self::store(store.save_chain(&chain.ops))?;
        }
        if persisted.1 != now.1 {
            self::store(store.save_secrets(&Secrets {
                identity: self.identity.clone(),
                roots: chain.roots.clone(),
            }))?;
        }
        *persisted = now;
        Ok(())
    }

    /// Bring `store` and the server in line: verify the chain, finish a
    /// due key rotation, pull and merge server changes, push local ones.
    pub async fn sync(&self, store: &mut dyn Store) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        self.refresh().await?;
        self.rotate_if_due().await?;
        self.persist(store).await?;
        for _ in 0..SYNC_ROUNDS {
            self.pull(store, &mut report).await?;
            match self.push(store, &mut report).await? {
                Pushed::Done => break,
                Pushed::Conflicts => {}
                Pushed::StaleEpoch => {
                    self.refresh().await?;
                }
            }
        }
        self.persist(store).await?;
        Ok(report)
    }

    async fn pull(&self, store: &mut dyn Store, report: &mut SyncReport) -> Result<()> {
        let group_id = self.identity.group_id();
        let cursor = self::store(store.cursor())?;
        let seen = self::store(store.seen())?.max(cursor);
        let mut since = cursor;
        let mut full = None;
        let mut present = HashSet::new();
        loop {
            let page = match self
                .authed(async |token| self.http.changes(token, &group_id, since, None).await)
                .await
            {
                Err(error) if error.code() == Some(ErrorCode::Gone) && full.is_none() => {
                    full = Some(FullRead::Expired);
                    since = 0;
                    continue;
                }
                other => other?,
            };
            if full.is_none() && page.high_seq < seen {
                tracing::warn!(
                    "the sync server lost changes this device saw; uploading them again"
                );
                full = Some(FullRead::Rollback);
                report.restored = true;
                since = 0;
                continue;
            }
            let mut changes = Vec::with_capacity(page.records.len());
            for record in &page.records {
                let id = record_id(record)?;
                if full.is_some() {
                    present.insert(id);
                }
                if record.deleted {
                    changes.push(Remote {
                        record_id: id,
                        seq: record.seq,
                        stamp: None,
                        entry: None,
                    });
                    continue;
                }
                let (stamp, entry) = match self.open_record(&group_id, record).await {
                    Ok(opened) => opened,
                    Err(error @ (Error::Crypto(_) | Error::Malformed(_) | Error::Untrusted(_))) => {
                        tracing::warn!(%error, seq = record.seq, "skipping a record that does not open");
                        report.unreadable += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                self.clock.observe(&stamp);
                let known = self::store(store.mirrored(&id))?.and_then(|mirrored| mirrored.stamp);
                if known.is_some_and(|known| stamp < known) {
                    // An older version than one this device saw: the server
                    // rolled the record back. Upload ours again.
                    self::store(store.requeue(&id, record.seq))?;
                    report.refused += 1;
                    continue;
                }
                changes.push(Remote {
                    record_id: id,
                    seq: record.seq,
                    stamp: Some(stamp),
                    entry: Some(entry),
                });
            }
            let last = page.records.last().map_or(since, |record| record.seq);
            let next = if page.more {
                last
            } else {
                page.high_seq.max(last)
            };
            self::store(store.apply(&changes, next))?;
            report.pulled += changes.len();
            report.high_seq = page.high_seq;
            if !page.more {
                // After a full read the server's state is the new baseline:
                // what it lost is queued for upload again.
                self::store(store.set_seen(if full.is_some() {
                    page.high_seq
                } else {
                    page.high_seq.max(seen)
                }))?;
                break;
            }
            since = last;
        }
        let Some(full) = full else {
            return Ok(());
        };
        let missing: Vec<[u8; 16]> = self::store(store.mirrored_ids())?
            .into_iter()
            .filter(|id| !present.contains(id))
            .collect();
        match full {
            FullRead::Expired => self::store(store.forget(&missing))?,
            FullRead::Rollback => {
                for id in missing {
                    let mirrored = self::store(store.mirrored(&id))?;
                    if mirrored.is_some_and(|mirrored| mirrored.entry.is_some()) {
                        self::store(store.requeue(&id, 0))?;
                    } else {
                        self::store(store.forget(&[id]))?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn open_record(&self, group_id: &[u8; 16], record: &Record) -> Result<(Stamp, Entry)> {
        let epoch = record
            .epoch
            .ok_or_else(|| Error::Malformed("record epoch".into()))?;
        if epoch > self.chain.lock().await.state.epoch {
            self.refresh().await?;
        }
        open(&self.root_key(epoch).await?, group_id, record)
    }

    async fn push(&self, store: &mut dyn Store, report: &mut SyncReport) -> Result<Pushed> {
        let group_id = self.identity.group_id();
        let limits = self.limits().await?;
        let (epoch, root) = self.current_root().await?;
        // Ciphertext travels as base64 inside JSON; leave room for both.
        let budget = limits.max_request_bytes / 2;
        for _ in 0..MAX_BATCHES {
            let pending = self::store(store.pending(limits.max_batch_records as usize))?;
            if pending.is_empty() {
                return Ok(Pushed::Done);
            }
            let mut items = Vec::new();
            let mut batch = Vec::new();
            let mut bytes = 0u64;
            for change in pending {
                if change.entry.is_none() && change.base_seq == 0 {
                    // Created and deleted before it ever reached the server.
                    self::store(store.discard(&change))?;
                    continue;
                }
                let item = seal(&root, &group_id, epoch, &change)?;
                let size = item
                    .ciphertext
                    .as_ref()
                    .map_or(0, |ciphertext| ciphertext.len() as u64);
                if size > limits.max_record_bytes {
                    return Err(Error::Server {
                        status: 413,
                        code: ErrorCode::PayloadTooLarge,
                        message: format!(
                            "a {} record is larger than the server's limit",
                            change
                                .entry
                                .as_ref()
                                .map_or("", |entry| entry.collection.as_str())
                        ),
                        retry_after: None,
                    });
                }
                if !items.is_empty() && bytes + size > budget {
                    break;
                }
                bytes += size;
                items.push(item);
                batch.push(change);
            }
            if items.is_empty() {
                continue;
            }
            let request = CommitRequest { items };
            match self
                .authed(async |token| self.http.commit(token, &group_id, &request).await)
                .await
            {
                Ok(CommitOutcome::Committed(response)) => {
                    let committed: Vec<(Pending, u64)> = batch
                        .into_iter()
                        .zip(response.results.iter().map(|result| result.seq))
                        .collect();
                    self::store(store.committed(&committed))?;
                    let seen = self::store(store.seen())?;
                    self::store(store.set_seen(seen.max(response.high_seq)))?;
                    report.pushed += committed.len();
                }
                Ok(CommitOutcome::Conflicts(_)) => return Ok(Pushed::Conflicts),
                Err(error) if error.code() == Some(ErrorCode::StaleEpoch) => {
                    return Ok(Pushed::StaleEpoch);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Pushed::Done)
    }

    /// The group's live events: a new `seq` or chain operation. The stream
    /// ends when the server closes it; reconnect with backoff.
    pub async fn events(&self) -> Result<impl Stream<Item = Result<Event>> + Send + use<>> {
        let group_id = self.identity.group_id();
        self.authed(async |token| self.http.events(token, &group_id).await)
            .await
    }
}
