-- A group is one person's devices and their encrypted records. The server
-- stores only ciphertext, opaque tags and public keys.
CREATE TABLE groups (
  id BLOB PRIMARY KEY CHECK (length(id) = 16),
  created_at INTEGER NOT NULL,
  -- Current key epoch; records of other epochs are refused.
  epoch INTEGER NOT NULL CHECK (epoch >= 1),
  -- Newest sequence number handed out in this group.
  high_seq INTEGER NOT NULL CHECK (high_seq >= 0),
  -- Highest sequence number of a purged tombstone. A device whose cursor is
  -- below it may have missed a deletion and must read the group again.
  horizon_seq INTEGER NOT NULL DEFAULT 0 CHECK (horizon_seq >= 0),
  -- Sum of the stored sizes of the group's records, for the quota.
  stored_bytes INTEGER NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0),
  -- Current recovery signing key. A recovery login finds its group by this
  -- key, so each key belongs to one group at most. The chain in
  -- membership_ops is authoritative; this copies its latest value. NULL once
  -- the group is deleted.
  recovery_sign_public_key BLOB UNIQUE CHECK (length(recovery_sign_public_key) = 32),
  -- Set when a delete_group operation emptied the group. The row stays so
  -- the id is never reused and devices learn the group was deleted.
  deleted_at INTEGER,
  CHECK ((deleted_at IS NULL) = (recovery_sign_public_key IS NOT NULL))
) STRICT, WITHOUT ROWID;

-- The signed, hash-chained membership log. Index 0 is the genesis. The
-- server replays it through the same state machine devices use.
CREATE TABLE membership_ops (
  group_id BLOB NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  idx INTEGER NOT NULL CHECK (idx >= 0),
  hash BLOB NOT NULL CHECK (length(hash) = 32),
  op BLOB NOT NULL,
  -- Concatenated 64-byte Ed25519 signatures, in the order the op requires.
  signatures BLOB NOT NULL CHECK (length(signatures) % 64 = 0),
  PRIMARY KEY (group_id, idx)
) STRICT, WITHOUT ROWID;

-- Active devices and their signing keys, for logins: a cache of the
-- chain's latest state. Removed devices are deleted from this table.
CREATE TABLE devices (
  group_id BLOB NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  device_id BLOB NOT NULL CHECK (length(device_id) = 16),
  sign_public_key BLOB NOT NULL CHECK (length(sign_public_key) = 32),
  PRIMARY KEY (group_id, device_id)
) STRICT, WITHOUT ROWID;

-- The latest version of each record. A deleted record is a tombstone with
-- no payload, kept so other devices learn about the deletion.
CREATE TABLE records (
  group_id BLOB NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  record_id BLOB NOT NULL CHECK (length(record_id) = 16),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
  tag BLOB,
  epoch INTEGER,
  nonce BLOB,
  ciphertext BLOB,
  size INTEGER NOT NULL CHECK (size >= 0),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, record_id),
  CHECK ((deleted = 1) = (ciphertext IS NULL)),
  CHECK ((deleted = 1) = (tag IS NULL)),
  CHECK ((deleted = 1) = (nonce IS NULL)),
  CHECK ((deleted = 1) = (epoch IS NULL))
) STRICT, WITHOUT ROWID;

-- Root keys wrapped for devices and the recovery key (target all zeros).
-- Only the current epoch's wraps are kept: older root keys travel sealed in
-- the chain's rotate operations.
CREATE TABLE wraps (
  group_id BLOB NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL CHECK (epoch >= 1),
  target BLOB NOT NULL CHECK (length(target) = 16),
  ciphertext BLOB NOT NULL,
  PRIMARY KEY (group_id, epoch, target)
) STRICT, WITHOUT ROWID;

CREATE INDEX records_by_seq ON records (group_id, seq);
CREATE INDEX tombstones_by_age ON records (updated_at) WHERE deleted = 1;
