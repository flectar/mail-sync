//! Groups, their signed membership chain, devices and key wraps.
//!
//! Every operation is checked by replaying the stored chain through
//! [`GroupState`], the same state machine devices run. That happens inside
//! the writer's transaction, so two appends can never both extend the same
//! head. The `groups.epoch`, `groups.recovery_sign_public_key` and `devices`
//! columns cache the chain's latest state for logins and commits.

use super::{Result, Store, StoreError, to_i64, to_u64};
use flectar_mail_sync_crypto::{GroupState, Op, OpKind, RECOVERY_ID, op_hash};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::BTreeSet;

/// Largest accepted key wrap. X-Wing wraps are 1170 bytes.
pub const MAX_WRAP_BYTES: usize = 4096;

/// A root key wrapped for one device, or for recovery ([`RECOVERY_ID`]).
#[derive(Clone, Debug)]
pub struct WrapIn {
    pub target: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// A group to create from its genesis operation.
#[derive(Clone, Debug)]
pub struct NewGroup {
    pub op: Vec<u8>,
    pub signatures: Vec<[u8; 64]>,
    pub wraps: Vec<WrapIn>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOp {
    pub index: u64,
    pub op: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

/// The applied operation and the chain's state after it.
#[derive(Debug)]
pub struct AppendOutcome {
    pub op: Op,
    pub state: GroupState,
}

fn invalid(error: flectar_mail_sync_crypto::Error) -> StoreError {
    StoreError::InvalidOp(error.to_string())
}

/// `Ok` for a live group, else why it cannot be used.
fn require_live(conn: &Connection, group_id: &[u8; 16]) -> Result<()> {
    let deleted_at: Option<Option<i64>> = conn
        .query_row(
            "SELECT deleted_at FROM groups WHERE id = ?1",
            [&group_id[..]],
            |row| row.get(0),
        )
        .optional()?;
    match deleted_at {
        None => Err(StoreError::NotFound),
        Some(Some(_)) => Err(StoreError::Deleted),
        Some(None) => Ok(()),
    }
}

/// `Ok` unless a group other than `owner` holds the recovery key `key`.
fn require_recovery_key_free(
    conn: &Connection,
    key: &[u8; 32],
    owner: Option<&[u8; 16]>,
) -> Result<()> {
    let holder: Option<Vec<u8>> = conn
        .query_row(
            "SELECT id FROM groups WHERE recovery_sign_public_key = ?1",
            [&key[..]],
            |row| row.get(0),
        )
        .optional()?;
    match holder {
        Some(holder) if owner.is_none_or(|owner| holder != owner[..]) => {
            Err(StoreError::RecoveryKeyTaken)
        }
        _ => Ok(()),
    }
}

fn load_state(conn: &Connection, group_id: &[u8; 16]) -> Result<GroupState> {
    let mut query = conn.prepare_cached(
        "SELECT op, signatures FROM membership_ops WHERE group_id = ?1 ORDER BY idx",
    )?;
    let rows = query
        .query_map([&group_id[..]], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    GroupState::replay(
        rows.iter()
            .map(|(op, signatures)| (op.as_slice(), signatures.chunks(64).collect())),
    )
    .map_err(|error| StoreError::Task(format!("the stored chain does not verify: {error}")))
}

/// Check that `wraps` is the set the operation requires (SPEC §6.10).
fn check_wraps(kind: &OpKind, state: &GroupState, wraps: &[WrapIn]) -> Result<()> {
    let mut targets = BTreeSet::new();
    for wrap in wraps {
        if wrap.ciphertext.is_empty() || wrap.ciphertext.len() > MAX_WRAP_BYTES {
            return Err(StoreError::Invalid("a wrap is empty or too large"));
        }
        if !targets.insert(wrap.target) {
            return Err(StoreError::Invalid("a wrap target appears twice"));
        }
    }
    let (allowed, required): (BTreeSet<[u8; 16]>, BTreeSet<[u8; 16]>) = match kind {
        OpKind::Genesis(genesis) => (
            [RECOVERY_ID, genesis.device.device_id].into(),
            [RECOVERY_ID].into(),
        ),
        OpKind::AddDevice(add) => ([add.device.device_id].into(), BTreeSet::new()),
        OpKind::Rotate(_) => {
            let everyone: BTreeSet<[u8; 16]> =
                state.devices.keys().copied().chain([RECOVERY_ID]).collect();
            (everyone.clone(), everyone)
        }
        OpKind::ResetRecovery(_) => ([RECOVERY_ID].into(), BTreeSet::new()),
        OpKind::RemoveDevice(_) | OpKind::MoveServer(_) | OpKind::DeleteGroup(_) => {
            (BTreeSet::new(), BTreeSet::new())
        }
    };
    if !targets.is_subset(&allowed) {
        return Err(StoreError::Invalid(
            "a wrap is addressed to a target this operation does not allow",
        ));
    }
    if !required.is_subset(&targets) {
        return Err(StoreError::Invalid(
            "the operation is missing a required wrap",
        ));
    }
    Ok(())
}

fn insert_wraps(
    conn: &Connection,
    group_id: &[u8; 16],
    epoch: u64,
    wraps: &[WrapIn],
) -> Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT OR REPLACE INTO wraps (group_id, epoch, target, ciphertext) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for wrap in wraps {
        insert.execute(params![
            &group_id[..],
            to_i64(epoch)?,
            &wrap.target[..],
            wrap.ciphertext
        ])?;
    }
    Ok(())
}

fn insert_op(
    conn: &Connection,
    group_id: &[u8; 16],
    index: u64,
    op: &[u8],
    signatures: &[[u8; 64]],
) -> Result<()> {
    conn.execute(
        "INSERT INTO membership_ops (group_id, idx, hash, op, signatures) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &group_id[..],
            to_i64(index)?,
            &op_hash(op)[..],
            op,
            signatures.concat()
        ],
    )?;
    Ok(())
}

impl Store {
    /// Create a group from its genesis operation, verified here. The id of a
    /// deleted group stays taken.
    pub async fn create_group(&self, group: NewGroup, now_ms: i64) -> Result<GroupState> {
        self.write(move |conn| {
            let signatures: Vec<&[u8]> = group.signatures.iter().map(|s| s.as_slice()).collect();
            let (state, op) = GroupState::from_genesis(&group.op, &signatures).map_err(invalid)?;
            let OpKind::Genesis(genesis) = &op.kind else {
                unreachable!("from_genesis accepts only a genesis");
            };
            check_wraps(&op.kind, &state, &group.wraps)?;
            let group_id = state.group_id;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            match require_live(&tx, &group_id) {
                Err(StoreError::NotFound) => {}
                Ok(()) | Err(StoreError::Deleted) => return Err(StoreError::GroupExists),
                Err(error) => return Err(error),
            }
            require_recovery_key_free(&tx, &genesis.recovery_sign_public_key, None)?;
            tx.execute(
                "INSERT INTO groups (id, created_at, epoch, high_seq, recovery_sign_public_key)
                 VALUES (?1, ?2, 1, 0, ?3)",
                params![&group_id[..], now_ms, &genesis.recovery_sign_public_key[..]],
            )?;
            insert_op(&tx, &group_id, 0, &group.op, &group.signatures)?;
            tx.execute(
                "INSERT INTO devices (group_id, device_id, sign_public_key) VALUES (?1, ?2, ?3)",
                params![
                    &group_id[..],
                    &genesis.device.device_id[..],
                    &genesis.device.sign_public_key[..]
                ],
            )?;
            insert_wraps(&tx, &group_id, 1, &group.wraps)?;
            tx.commit()?;
            Ok(state)
        })
        .await
    }

    /// Verify and append the next operation of a group's chain, with the
    /// wraps it requires, and apply its effects.
    pub async fn append_op(
        &self,
        group_id: [u8; 16],
        op_bytes: Vec<u8>,
        signatures: Vec<[u8; 64]>,
        wraps: Vec<WrapIn>,
        max_devices: u32,
        now_ms: i64,
    ) -> Result<AppendOutcome> {
        self.write(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_live(&tx, &group_id)?;
            let mut state = load_state(&tx, &group_id)?;
            let decoded = Op::decode(&op_bytes).map_err(invalid)?;
            if decoded.group_id == group_id && decoded.index <= state.head_index {
                return Err(StoreError::ChainMoved);
            }
            let signature_refs: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();
            let op = state.apply(&op_bytes, &signature_refs).map_err(invalid)?;
            check_wraps(&op.kind, &state, &wraps)?;
            if state.devices.len() > max_devices as usize {
                return Err(StoreError::DeviceLimit);
            }
            if let OpKind::ResetRecovery(reset) = &op.kind {
                require_recovery_key_free(&tx, &reset.recovery_sign_public_key, Some(&group_id))?;
            }
            insert_op(&tx, &group_id, op.index, &op_bytes, &signatures)?;
            match &op.kind {
                OpKind::Genesis(_) => unreachable!("apply rejects a second genesis"),
                OpKind::AddDevice(add) => {
                    tx.execute(
                        "INSERT INTO devices (group_id, device_id, sign_public_key) VALUES (?1, ?2, ?3)",
                        params![
                            &group_id[..],
                            &add.device.device_id[..],
                            &add.device.sign_public_key[..]
                        ],
                    )?;
                }
                OpKind::RemoveDevice(remove) => {
                    tx.execute(
                        "DELETE FROM devices WHERE group_id = ?1 AND device_id = ?2",
                        params![&group_id[..], &remove.device_id[..]],
                    )?;
                    tx.execute(
                        "DELETE FROM wraps WHERE group_id = ?1 AND target = ?2",
                        params![&group_id[..], &remove.device_id[..]],
                    )?;
                }
                OpKind::Rotate(rotate) => {
                    let epoch = to_i64(rotate.epoch)?;
                    tx.execute(
                        "UPDATE groups SET epoch = ?2 WHERE id = ?1",
                        params![&group_id[..], epoch],
                    )?;
                    tx.execute(
                        "DELETE FROM wraps WHERE group_id = ?1 AND epoch < ?2",
                        params![&group_id[..], epoch],
                    )?;
                }
                OpKind::ResetRecovery(reset) => {
                    tx.execute(
                        "UPDATE groups SET recovery_sign_public_key = ?2 WHERE id = ?1",
                        params![&group_id[..], &reset.recovery_sign_public_key[..]],
                    )?;
                    tx.execute(
                        "DELETE FROM wraps WHERE group_id = ?1 AND target = ?2",
                        params![&group_id[..], &RECOVERY_ID[..]],
                    )?;
                }
                OpKind::MoveServer(_) => {}
                OpKind::DeleteGroup(_) => {
                    for table in ["records", "wraps", "devices", "membership_ops"] {
                        tx.execute(
                            &format!("DELETE FROM {table} WHERE group_id = ?1"),
                            [&group_id[..]],
                        )?;
                    }
                    tx.execute(
                        "UPDATE groups SET deleted_at = ?2, stored_bytes = 0,
                         recovery_sign_public_key = NULL WHERE id = ?1",
                        params![&group_id[..], now_ms],
                    )?;
                }
            }
            insert_wraps(&tx, &group_id, state.epoch, &wraps)?;
            tx.commit()?;
            Ok(AppendOutcome { op, state })
        })
        .await
    }

    /// Operations with `index >= since`, oldest first.
    pub async fn ops(
        &self,
        group_id: [u8; 16],
        since: u64,
        limit: u32,
    ) -> Result<(Vec<StoredOp>, bool)> {
        self.read(move |conn| {
            let tx = conn.transaction()?;
            require_live(&tx, &group_id)?;
            let mut ops = {
                let mut query = tx.prepare_cached(
                    "SELECT idx, op, signatures FROM membership_ops
                     WHERE group_id = ?1 AND idx >= ?2 ORDER BY idx LIMIT ?3",
                )?;
                query
                    .query_map(
                        params![&group_id[..], to_i64(since)?, i64::from(limit) + 1],
                        |row| {
                            let signatures: Vec<u8> = row.get(2)?;
                            Ok(StoredOp {
                                index: to_u64(row.get(0)?),
                                op: row.get(1)?,
                                signatures: signatures.chunks(64).map(<[u8]>::to_vec).collect(),
                            })
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.finish()?;
            let more = ops.len() > limit as usize;
            ops.truncate(limit as usize);
            Ok((ops, more))
        })
        .await
    }

    /// The current epoch's wrap for `target`, if one is stored.
    pub async fn current_wrap(
        &self,
        group_id: [u8; 16],
        target: [u8; 16],
    ) -> Result<Option<(u64, Vec<u8>)>> {
        self.read(move |conn| {
            let tx = conn.transaction()?;
            require_live(&tx, &group_id)?;
            let wrap: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT wraps.epoch, wraps.ciphertext FROM wraps
                     JOIN groups ON groups.id = wraps.group_id AND groups.epoch = wraps.epoch
                     WHERE wraps.group_id = ?1 AND wraps.target = ?2",
                    params![&group_id[..], &target[..]],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            tx.finish()?;
            Ok(wrap.map(|(epoch, ciphertext)| (to_u64(epoch), ciphertext)))
        })
        .await
    }

    /// The signing key of an active device of a live group.
    pub async fn device_key(
        &self,
        group_id: [u8; 16],
        device_id: [u8; 16],
    ) -> Result<Option<[u8; 32]>> {
        self.read(move |conn| {
            let key: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT devices.sign_public_key FROM devices
                     JOIN groups ON groups.id = devices.group_id AND groups.deleted_at IS NULL
                     WHERE devices.group_id = ?1 AND devices.device_id = ?2",
                    params![&group_id[..], &device_id[..]],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(key.and_then(|key| key.try_into().ok()))
        })
        .await
    }

    /// The live group whose current recovery signing key is `key`.
    pub async fn group_by_recovery_key(&self, key: [u8; 32]) -> Result<Option<[u8; 16]>> {
        self.read(move |conn| {
            let id: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT id FROM groups WHERE recovery_sign_public_key = ?1",
                    [&key[..]],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(id.and_then(|id| id.try_into().ok()))
        })
        .await
    }

    /// The current recovery signing key of a live group.
    pub async fn recovery_key(&self, group_id: [u8; 16]) -> Result<Option<[u8; 32]>> {
        self.read(move |conn| {
            let key: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT recovery_sign_public_key FROM groups WHERE id = ?1 AND deleted_at IS NULL",
                    [&group_id[..]],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(key.and_then(|key| key.try_into().ok()))
        })
        .await
    }
}
