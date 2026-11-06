//! SQLite storage.
//!
//! One writer connection and a small pool of reader connections in WAL mode:
//! readers never block the writer or each other. Callers wait for a
//! connection asynchronously (a semaphore per kind), then run the query on
//! Tokio's blocking pool. `synchronous=NORMAL` keeps the database consistent
//! but can lose the newest commits on power loss; the protocol tolerates that
//! because devices notice a lower `high_seq` and upload again (SPEC §6.4).

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::Semaphore;

const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("the group already exists")]
    GroupExists,
    #[error("the cursor is older than the tombstone horizon")]
    Gone,
    #[error("the group would exceed its storage quota")]
    QuotaExceeded,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("the database task failed: {0}")]
    Task(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A record change ready to store.
#[derive(Clone, Debug)]
pub struct PendingChange {
    pub record_id: [u8; 16],
    pub expected_seq: u64,
    /// `None` deletes the record.
    pub payload: Option<Payload>,
}

#[derive(Clone, Debug)]
pub struct Payload {
    pub tag: Vec<u8>,
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Payload {
    fn size(&self) -> u64 {
        (self.tag.len() + self.nonce.len() + self.ciphertext.len()) as u64
    }
}

#[derive(Debug)]
pub enum CommitOutcome {
    Applied {
        high_seq: u64,
        seqs: Vec<([u8; 16], u64)>,
    },
    /// Records whose `expected_seq` was stale, with their current `seq`.
    Conflicts(Vec<([u8; 16], u64)>),
}

#[derive(Debug)]
pub struct StoredRecord {
    pub record_id: Vec<u8>,
    pub seq: u64,
    pub payload: Option<Payload>,
}

#[derive(Debug)]
pub struct ChangesPage {
    pub records: Vec<StoredRecord>,
    pub high_seq: u64,
    pub more: bool,
}

/// What [`Store::create_group`] stores from a verified genesis operation.
#[derive(Clone, Debug)]
pub struct NewGroup {
    pub group_id: [u8; 16],
    pub op_hash: [u8; 32],
    pub op: Vec<u8>,
    pub signatures: Vec<u8>,
    pub recovery_sign_public_key: [u8; 32],
    pub device_id: [u8; 16],
    pub device_sign_public_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
    write_gate: Semaphore,
    read_gate: Semaphore,
}

fn open_connection(path: &Path, read_only: bool) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    if read_only {
        conn.pragma_update(None, "query_only", "ON")?;
    }
    Ok(conn)
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let applied = usize::try_from(version)
        .map_err(|_| StoreError::Invalid("the database has an invalid schema version"))?;
    if applied > MIGRATIONS.len() {
        return Err(StoreError::Invalid(
            "the database was written by a newer server version",
        ));
    }
    for (index, sql) in (1i64..).zip(MIGRATIONS.iter()).skip(applied) {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", index)?;
        tx.commit()?;
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::Invalid("value out of range"))
}

fn to_u64(value: i64) -> u64 {
    // Columns holding these values are CHECKed to be non-negative.
    u64::try_from(value).unwrap_or(0)
}

impl Store {
    /// Open (creating if needed) the database at `path` and apply migrations.
    pub fn open(path: impl AsRef<Path>, readers: usize) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut writer = open_connection(&path, false)?;
        migrate(&mut writer)?;
        let readers = readers.max(1);
        let pool = (0..readers)
            .map(|_| open_connection(&path, true))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                writer: Mutex::new(writer),
                readers: Mutex::new(pool),
                write_gate: Semaphore::new(1),
                read_gate: Semaphore::new(readers),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    async fn write<T, F>(&self, job: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let _permit = self
            .inner
            .write_gate
            .acquire()
            .await
            .map_err(|error| StoreError::Task(error.to_string()))?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut conn = inner.writer.lock().unwrap_or_else(PoisonError::into_inner);
            job(&mut conn)
        })
        .await
        .map_err(|error| StoreError::Task(error.to_string()))?
    }

    async fn read<T, F>(&self, job: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let _permit = self
            .inner
            .read_gate
            .acquire()
            .await
            .map_err(|error| StoreError::Task(error.to_string()))?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut conn = inner
                .readers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
                .ok_or_else(|| StoreError::Task("no reader connection available".into()))?;
            let result = job(&mut conn);
            inner
                .readers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(conn);
            result
        })
        .await
        .map_err(|error| StoreError::Task(error.to_string()))?
    }

    /// Check that the database answers.
    pub async fn ping(&self) -> Result<()> {
        self.read(|conn| {
            conn.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })
        .await
    }

    pub async fn create_group(&self, group: NewGroup, now_ms: i64) -> Result<()> {
        self.write(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists = tx
                .query_row(
                    "SELECT 1 FROM groups WHERE id = ?1",
                    [&group.group_id[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                return Err(StoreError::GroupExists);
            }
            tx.execute(
                "INSERT INTO groups (id, created_at, epoch, high_seq, recovery_sign_public_key)
                 VALUES (?1, ?2, 1, 0, ?3)",
                params![
                    &group.group_id[..],
                    now_ms,
                    &group.recovery_sign_public_key[..]
                ],
            )?;
            tx.execute(
                "INSERT INTO membership_ops (group_id, idx, hash, op, signatures)
                 VALUES (?1, 0, ?2, ?3, ?4)",
                params![
                    &group.group_id[..],
                    &group.op_hash[..],
                    group.op,
                    group.signatures
                ],
            )?;
            tx.execute(
                "INSERT INTO devices (group_id, device_id, sign_public_key, added_idx)
                 VALUES (?1, ?2, ?3, 0)",
                params![
                    &group.group_id[..],
                    &group.device_id[..],
                    &group.device_sign_public_key[..]
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// The signing key of an active device, if the group and device exist.
    pub async fn device_key(
        &self,
        group_id: [u8; 16],
        device_id: [u8; 16],
    ) -> Result<Option<[u8; 32]>> {
        self.read(move |conn| {
            let key: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT sign_public_key FROM devices
                     WHERE group_id = ?1 AND device_id = ?2 AND removed_idx IS NULL",
                    params![&group_id[..], &device_id[..]],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(key.and_then(|key| key.try_into().ok()))
        })
        .await
    }

    /// The group's newest sequence number.
    pub async fn high_seq(&self, group_id: [u8; 16]) -> Result<u64> {
        self.read(move |conn| {
            let seq: Option<i64> = conn
                .query_row(
                    "SELECT high_seq FROM groups WHERE id = ?1",
                    [&group_id[..]],
                    |row| row.get(0),
                )
                .optional()?;
            seq.map(to_u64).ok_or(StoreError::NotFound)
        })
        .await
    }

    /// Apply a batch atomically: every `expected_seq` must match the
    /// record's current sequence number (0 for a record that does not
    /// exist), or nothing is stored and the stale records are returned.
    pub async fn commit(
        &self,
        group_id: [u8; 16],
        changes: Vec<PendingChange>,
        max_group_bytes: u64,
        now_ms: i64,
    ) -> Result<CommitOutcome> {
        self.write(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let group: Option<(i64, i64, i64)> = tx
                .query_row(
                    "SELECT epoch, high_seq, stored_bytes FROM groups WHERE id = ?1",
                    [&group_id[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (epoch, high_seq, stored_bytes) = group.ok_or(StoreError::NotFound)?;
            let (epoch, mut seq, stored_bytes) =
                (to_u64(epoch), to_u64(high_seq), to_u64(stored_bytes));

            let mut conflicts = Vec::new();
            let mut freed = 0u64;
            {
                let mut current = tx.prepare_cached(
                    "SELECT seq, size FROM records WHERE group_id = ?1 AND record_id = ?2",
                )?;
                for change in &changes {
                    let row: Option<(i64, i64)> = current
                        .query_row(params![&group_id[..], &change.record_id[..]], |row| {
                            Ok((row.get(0)?, row.get(1)?))
                        })
                        .optional()?;
                    let (current_seq, size) = row.map_or((0, 0), |(s, z)| (to_u64(s), to_u64(z)));
                    if current_seq != change.expected_seq {
                        conflicts.push((change.record_id, current_seq));
                    }
                    freed += size;
                }
            }
            if !conflicts.is_empty() {
                return Ok(CommitOutcome::Conflicts(conflicts));
            }
            if changes
                .iter()
                .filter_map(|change| change.payload.as_ref())
                .any(|payload| payload.epoch != epoch)
            {
                return Err(StoreError::Invalid(
                    "a record was sealed for another key epoch",
                ));
            }
            let added: u64 = changes
                .iter()
                .filter_map(|change| change.payload.as_ref())
                .map(Payload::size)
                .sum();
            let new_bytes = stored_bytes.saturating_sub(freed) + added;
            if new_bytes > max_group_bytes && added > freed {
                return Err(StoreError::QuotaExceeded);
            }

            let mut seqs = Vec::with_capacity(changes.len());
            {
                let mut upsert = tx.prepare_cached(
                    "INSERT INTO records
                       (group_id, record_id, seq, deleted, tag, epoch, nonce, ciphertext, size, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                     ON CONFLICT (group_id, record_id) DO UPDATE SET
                       seq = excluded.seq, deleted = excluded.deleted, tag = excluded.tag,
                       epoch = excluded.epoch, nonce = excluded.nonce,
                       ciphertext = excluded.ciphertext, size = excluded.size,
                       updated_at = excluded.updated_at",
                )?;
                for change in changes {
                    seq += 1;
                    let seq_value = to_i64(seq)?;
                    match &change.payload {
                        Some(payload) => upsert.execute(params![
                            &group_id[..],
                            &change.record_id[..],
                            seq_value,
                            0,
                            payload.tag,
                            to_i64(payload.epoch)?,
                            payload.nonce,
                            payload.ciphertext,
                            to_i64(payload.size())?,
                            now_ms
                        ])?,
                        None => upsert.execute(params![
                            &group_id[..],
                            &change.record_id[..],
                            seq_value,
                            1,
                            None::<Vec<u8>>,
                            None::<i64>,
                            None::<Vec<u8>>,
                            None::<Vec<u8>>,
                            0,
                            now_ms
                        ])?,
                    };
                    seqs.push((change.record_id, seq));
                }
            }
            tx.execute(
                "UPDATE groups SET high_seq = ?2, stored_bytes = ?3 WHERE id = ?1",
                params![&group_id[..], to_i64(seq)?, to_i64(new_bytes)?],
            )?;
            tx.commit()?;
            Ok(CommitOutcome::Applied {
                high_seq: seq,
                seqs,
            })
        })
        .await
    }

    /// Records with `seq > since`, oldest first, read from one snapshot.
    /// `since = 0` reads the whole group and is always allowed; any other
    /// cursor below the tombstone horizon is [`StoreError::Gone`].
    pub async fn changes(&self, group_id: [u8; 16], since: u64, limit: u32) -> Result<ChangesPage> {
        self.read(move |conn| {
            let tx = conn.transaction()?;
            let group: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT high_seq, horizon_seq FROM groups WHERE id = ?1",
                    [&group_id[..]],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (high_seq, horizon) = group.ok_or(StoreError::NotFound)?;
            let (high_seq, horizon) = (to_u64(high_seq), to_u64(horizon));
            if since != 0 && since < horizon {
                return Err(StoreError::Gone);
            }
            let mut records = Vec::new();
            {
                let mut query = tx.prepare_cached(
                    "SELECT record_id, seq, deleted, tag, epoch, nonce, ciphertext
                     FROM records WHERE group_id = ?1 AND seq > ?2
                     ORDER BY seq LIMIT ?3",
                )?;
                let mut rows =
                    query.query(params![&group_id[..], to_i64(since)?, i64::from(limit) + 1])?;
                while let Some(row) = rows.next()? {
                    let deleted: i64 = row.get(2)?;
                    let payload = if deleted == 1 {
                        None
                    } else {
                        Some(Payload {
                            tag: row.get(3)?,
                            epoch: to_u64(row.get(4)?),
                            nonce: row.get(5)?,
                            ciphertext: row.get(6)?,
                        })
                    };
                    records.push(StoredRecord {
                        record_id: row.get(0)?,
                        seq: to_u64(row.get(1)?),
                        payload,
                    });
                }
            }
            tx.finish()?;
            let more = records.len() > limit as usize;
            records.truncate(limit as usize);
            Ok(ChangesPage {
                records,
                high_seq,
                more,
            })
        })
        .await
    }

    /// Drop tombstones last changed before `cutoff_ms`, raising each
    /// affected group's horizon. Returns how many were dropped.
    pub async fn purge_tombstones(&self, cutoff_ms: i64) -> Result<usize> {
        self.write(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE groups SET horizon_seq = max(horizon_seq, purged.max_seq)
                 FROM (SELECT group_id, max(seq) AS max_seq FROM records
                       WHERE deleted = 1 AND updated_at < ?1 GROUP BY group_id) AS purged
                 WHERE groups.id = purged.group_id",
                [cutoff_ms],
            )?;
            let purged = tx.execute(
                "DELETE FROM records WHERE deleted = 1 AND updated_at < ?1",
                [cutoff_ms],
            )?;
            tx.commit()?;
            Ok(purged)
        })
        .await
    }

    /// Write a consistent copy of the database to `destination`, which must
    /// not exist yet. Runs on its own connection: it reads a snapshot, so
    /// writers are not blocked while it copies.
    pub async fn backup(&self, destination: PathBuf) -> Result<()> {
        let source = self.inner.path.clone();
        tokio::task::spawn_blocking(move || {
            let destination = destination
                .to_str()
                .ok_or(StoreError::Invalid("the backup path is not valid UTF-8"))?
                .to_owned();
            let conn = open_connection(&source, false)?;
            conn.execute("VACUUM INTO ?1", [destination])?;
            Ok(())
        })
        .await
        .map_err(|error| StoreError::Task(error.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("sync.db"), 2).unwrap();
        (dir, store)
    }

    fn group(id: u8) -> NewGroup {
        NewGroup {
            group_id: [id; 16],
            op_hash: [0; 32],
            op: vec![1],
            signatures: vec![0; 128],
            recovery_sign_public_key: [3; 32],
            device_id: [4; 16],
            device_sign_public_key: [5; 32],
        }
    }

    fn put(id: u8, expected: u64, size: usize) -> PendingChange {
        PendingChange {
            record_id: [id; 16],
            expected_seq: expected,
            payload: Some(Payload {
                tag: vec![1; 16],
                epoch: 1,
                nonce: vec![2; 24],
                ciphertext: vec![3; size],
            }),
        }
    }

    #[tokio::test]
    async fn migrations_run_once_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.db");
        drop(Store::open(&path, 1).unwrap());
        let store = Store::open(&path, 1).unwrap();
        store.ping().await.unwrap();
    }

    #[tokio::test]
    async fn commits_assign_increasing_seqs_and_detect_stale_writers() {
        let (_dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        let CommitOutcome::Applied { high_seq, seqs } = store
            .commit([1; 16], vec![put(1, 0, 10), put(2, 0, 10)], 1 << 20, 1)
            .await
            .unwrap()
        else {
            panic!("expected the commit to apply");
        };
        assert_eq!(high_seq, 2);
        assert_eq!(seqs, vec![([1; 16], 1), ([2; 16], 2)]);

        // A writer that still believes record 1 is new conflicts, and its
        // other change is not applied either.
        let CommitOutcome::Conflicts(conflicts) = store
            .commit([1; 16], vec![put(3, 0, 10), put(1, 0, 10)], 1 << 20, 2)
            .await
            .unwrap()
        else {
            panic!("expected a conflict");
        };
        assert_eq!(conflicts, vec![([1; 16], 1)]);
        assert_eq!(store.high_seq([1; 16]).await.unwrap(), 2);
        let page = store.changes([1; 16], 0, 100).await.unwrap();
        assert_eq!(page.records.len(), 2, "the batch was all-or-nothing");
    }

    #[tokio::test]
    async fn quota_counts_replaced_and_deleted_records() {
        let (_dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        let quota = 2 * (16 + 24 + 100);
        store
            .commit([1; 16], vec![put(1, 0, 100), put(2, 0, 100)], quota, 1)
            .await
            .unwrap();
        assert!(matches!(
            store.commit([1; 16], vec![put(3, 0, 100)], quota, 2).await,
            Err(StoreError::QuotaExceeded)
        ));
        let delete = PendingChange {
            record_id: [1; 16],
            expected_seq: 1,
            payload: None,
        };
        store.commit([1; 16], vec![delete], quota, 3).await.unwrap();
        assert!(matches!(
            store.commit([1; 16], vec![put(3, 0, 100)], quota, 4).await,
            Ok(CommitOutcome::Applied { .. })
        ));
    }

    #[tokio::test]
    async fn purged_tombstones_raise_the_horizon() {
        let (_dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        store
            .commit([1; 16], vec![put(1, 0, 10), put(2, 0, 10)], 1 << 20, 1)
            .await
            .unwrap();
        let delete = PendingChange {
            record_id: [1; 16],
            expected_seq: 1,
            payload: None,
        };
        store
            .commit([1; 16], vec![delete], 1 << 20, 100)
            .await
            .unwrap();
        assert_eq!(store.purge_tombstones(50).await.unwrap(), 0, "too recent");
        assert_eq!(store.purge_tombstones(200).await.unwrap(), 1);
        assert!(matches!(
            store.changes([1; 16], 2, 100).await,
            Err(StoreError::Gone)
        ));
        assert_eq!(
            store.changes([1; 16], 3, 100).await.unwrap().records.len(),
            0
        );
        let full = store.changes([1; 16], 0, 100).await.unwrap();
        assert_eq!(full.records.len(), 1, "only the live record remains");
    }

    #[tokio::test]
    async fn pages_report_more() {
        let (_dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        let batch = (1..=5).map(|id| put(id, 0, 10)).collect();
        store.commit([1; 16], batch, 1 << 20, 1).await.unwrap();
        let first = store.changes([1; 16], 0, 2).await.unwrap();
        assert_eq!(
            first.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(first.more);
        let last = store.changes([1; 16], 4, 2).await.unwrap();
        assert_eq!(last.records.len(), 1);
        assert!(!last.more);
    }

    #[tokio::test]
    async fn duplicate_groups_are_refused() {
        let (_dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        assert!(matches!(
            store.create_group(group(1), 0).await,
            Err(StoreError::GroupExists)
        ));
    }

    #[tokio::test]
    async fn backups_are_complete_databases() {
        let (dir, store) = store();
        store.create_group(group(1), 0).await.unwrap();
        let copy = dir.path().join("copy.db");
        store.backup(copy.clone()).await.unwrap();
        let restored = Store::open(&copy, 1).unwrap();
        assert_eq!(restored.high_seq([1; 16]).await.unwrap(), 0);
    }
}
