# Flectar Mail Sync protocol, version 1

Status: **draft**. Sections marked *(planned)* are not implemented yet and may
change. Everything else is implemented by the crates in this repository and
covered by their tests.

## 1. Overview

Flectar Mail Sync keeps one person's app state the same on all their
devices. That state covers accounts, preferences, signatures, rules and similar
records. Mail, contacts and calendars are not part of it: they sync with
the mail provider as before.

- A **group** is one person's devices and their records.
- A **device** holds the group's keys in its operating system's key store.
- A **record** is an encrypted blob with a random 16-byte id. The server
  stores the newest version of each record. A deleted record leaves a
  **tombstone** without payload.
- Every change gets the next **sequence number** (`seq`) of its group. The
  server assigns it, so no device clock ever orders changes.
- The **epoch** numbers the group's current root key. It starts at 1 and
  increases each time a removed device forces a new key (§5, planned).

The server is blind. It never holds a key that could read a record and it
does not know which kind of state a record carries. Every device keeps the
complete state, so a server can be rebuilt from any device.

## 2. Encoding

- Bodies are UTF-8 JSON with camelCase keys.
- Binary values are unpadded base64url strings (RFC 4648 §5).
- Integers are JSON numbers below 2^53.
- Times are milliseconds since the Unix epoch.
- Unknown JSON fields must be ignored by both sides.

| Value | Bytes |
|---|---|
| group id, device id, record id, challenge id | 16, random |
| collection tag | 16 |
| record nonce | 24 |
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| login nonce | 32 |

## 3. Versioning

`GET /v1/info` returns `protocolMin` and `protocolMax`. A client must not talk
to a server whose range excludes its protocol version. The path prefix `/v1`
changes only with an incompatible protocol version.

## 4. Cryptography

### 4.1 Primitives

| Use | Primitive |
|---|---|
| Signatures | Ed25519 (RFC 8032), strict verification |
| Key derivation | HKDF-SHA256 (RFC 5869) with no salt, 32-byte output |
| Record encryption | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) |
| Collection tags | HMAC-SHA256, first 16 bytes |
| Operation hashes | SHA-256 |
| Wrapping root keys to devices *(planned)* | HPKE (RFC 9180) with a versioned suite id. Target suite: X-Wing hybrid KEM. |

Every secret fed to HKDF is uniformly random, so no password stretching is
used (RFC 5869 §4).

### 4.2 Labels

Each derivation and signature is bound to one purpose by an ASCII label:

| Name | Bytes |
|---|---|
| `RECOVERY_SIGN` | `flectar-mail-sync/v1 recovery-sign` |
| `RECOVERY_KEM` | `flectar-mail-sync/v1 recovery-kem` |
| `RECORD_KEY` | `flectar-mail-sync/v1 record-key` |
| `TAG_KEY` | `flectar-mail-sync/v1 tag-key` |
| `RECORD_AAD` | `flectar-mail-sync/v1 record` |
| `AUTH` | `flectar-mail-sync/v1 auth` |
| `OP_SIGNATURE` | `flectar-mail-sync/v1 op` |
| `OP_HASH` | `flectar-mail-sync/v1 op-hash` |

`||` is concatenation. `u16be` and `u64be` are big-endian unsigned integers.

### 4.3 Recovery code

- The recovery code is 32 random bytes, shown as 24 words of the BIP39 English
  list. The words only encode the 32 bytes and their checksum. BIP39's
  PBKDF2 seed derivation is not used.
- recovery signing key = Ed25519 key whose seed is
  `HKDF(code, RECOVERY_SIGN)`.
- recovery KEM seed = `HKDF(code, RECOVERY_KEM)` *(used when key wrapping
  lands)*.

### 4.4 Root key and epochs

- The root key `K_e` of epoch `e` is 32 random bytes.
- record key = `HKDF(K_e, RECORD_KEY || u64be(e))`
- tag key = `HKDF(K_e, TAG_KEY || u64be(e))`

### 4.5 Records

- **Plaintext:** defined by the client application. It should carry a schema
  number and keep unknown fields when rewriting. The server never sees it.
- **Padding:** append `0x80`, then zeros up to the next multiple of 256 bytes.
  At least one byte is always added.
- **Sealing:** `ciphertext = XChaCha20-Poly1305(record key, nonce, padded, aad)`
  with a random 24-byte nonce, where
  `aad = RECORD_AAD || group_id || record_id || tag || u64be(epoch)`.

The associated data binds a ciphertext to its group, record, collection and
epoch, so a server cannot move it elsewhere.

### 4.6 Collection tags

`tag = HMAC-SHA256(tag key, UTF-8 collection name)[0..16]`. The server sees
only the tag.

### 4.7 Login message

```
AUTH || u16be(len(audience)) || audience || group_id || device_id || nonce
```

`audience` is the server's public URL without a trailing slash, exactly as the
device is configured. A signature for one server cannot log in to another.

## 5. Membership operations

### 5.1 Encoding

Operations are signed and hashed over this canonical binary encoding, never
over JSON:

```
"FMSO" || 0x01 || kind (1 byte) || group_id (16) || u64be(index)
       || prev_hash (32) || u64be(created_at_ms) || body
```

- A variable field is `u16be(length) || bytes`.
- Decoders reject unknown kinds, over-long fields and trailing bytes.

### 5.2 Signatures and the chain

- **Signature:** `Ed25519(key, OP_SIGNATURE || op_bytes)`.
- **Hash:** `SHA-256(OP_HASH || op_bytes)`.
- **Chain:** each operation's `prev_hash` is the previous operation's hash.
  The genesis has index 0 and an all-zero `prev_hash`.
- **Client checks** *(planned)*: clients remember the last hash they
  verified and refuse a chain that forks or drops operations.

### 5.3 Kinds

| Kind | Name | Signed by |
|---|---|---|
| 1 | genesis | recovery key, then the first device |
| 2 | add_device *(planned)* | an existing device or the recovery key |
| 3 | remove_device *(planned)* | a remaining device or the recovery key |
| 4 | rotate *(planned)* | a device or the recovery key |
| 5 | reset_recovery *(planned)* | a device or the recovery key |
| 6 | move_server *(planned)* | a device |
| 7 | delete_group *(planned)* | a device or the recovery key |

The genesis body contains, in order:

- `recovery_sign_public_key` (32)
- variable `recovery_kem_public_key`, at most 4096 bytes
- `device_id` (16)
- `device_sign_public_key` (32)
- variable `device_kem_public_key`, at most 4096 bytes
- variable `device_name`, UTF-8, at most 64 bytes

The server treats KEM keys and names as opaque.

## 6. HTTP API

### 6.1 General

- Servers are reached over HTTPS.
- Authenticated endpoints take `Authorization: Bearer <token>` (§6.4).
- Every error is answered with this body, plus `conflicts` on commit
  conflicts:

```json
{"error": {"code": "conflict", "message": "…"}, "conflicts": [{"recordId": "…", "currentSeq": 5}]}
```

| Status | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed request |
| 401 | `unauthorized` | Missing or invalid session, or a failed login |
| 403 | `forbidden` | The session belongs to another group |
| 404 | `not_found` | Unknown group |
| 409 | `conflict` | Stale `expectedSeq`, or the group already exists |
| 410 | `gone` | `since` is below the tombstone horizon; read again from 0 |
| 413 | `payload_too_large` | Over a size or batch limit |
| 429 | `rate_limited` | Too many requests |
| 507 | `quota_exceeded` | The group would exceed its storage quota |
| 500 | `internal` | Server failure |

### 6.2 `GET /v1/info`

```json
{"server": "flectar-mail-sync", "version": "0.1.0", "protocolMin": 1, "protocolMax": 1,
 "limits": {"maxRecordBytes": 262144, "maxBatchRecords": 1000, "maxRequestBytes": 8388608,
            "maxGroupBytes": 67108864, "maxPageRecords": 1000}}
```

### 6.3 `POST /v1/groups`

Request: `{"op": <genesis op_bytes>, "signatures": [<recovery>, <device>]}`.

The server verifies the encoding and both signatures, then stores the group
with epoch 1 and `high_seq` 0. It answers `201 {"groupId": …, "highSeq": 0}`.
If the group exists, it answers `409`.

### 6.4 Login

1. `POST /v1/auth/challenge` with `{"groupId", "deviceId"}` returns
   `{"challengeId", "nonce", "expiresAt"}`. A challenge lasts 120 s and is
   single-use. It is issued even for unknown groups or devices.
2. `POST /v1/auth/session` with `{"challengeId", "signature"}` takes the
   device's signature over the login message (§4.7). It returns
   `{"token", "expiresAt"}`, and the session lasts one hour.
3. Any failure, including an unknown device, a removed device, a bad
   signature or an expired challenge, is `401`.

### 6.5 `POST /v1/groups/{group}/commit`

`{"items": [item, …]}`, applied atomically: either every item is stored or
none.

- **Put:** `{"recordId", "expectedSeq", "tag", "epoch", "nonce", "ciphertext"}`.
- **Delete:** `{"recordId", "expectedSeq", "deleted": true}`.

Rules:

- `expectedSeq` must equal the record's current `seq`, or 0 if the record
  does not exist (a tombstone counts as existing). Otherwise the answer is
  `409` with every stale record and its `currentSeq`, and nothing is stored.
- A record id appears at most once per commit.
- A deletion needs `expectedSeq > 0`.
- `epoch` must equal the group's current epoch.
- Size, batch and quota limits come from `/v1/info`. A commit that does not
  grow the group is accepted even over quota.

Success returns `{"highSeq", "results": [{"recordId", "seq"}, …]}`. The
results are in item order, with consecutive sequence numbers.

### 6.6 `GET /v1/groups/{group}/changes?since=N&limit=M`

Returns records and tombstones with `seq > N`, oldest first, read from one
snapshot: `{"records": [...], "highSeq", "more"}`. A tombstone carries only
`recordId`, `seq` and `"deleted": true`.

- **Paging:** if `more` is true, ask again with `since` set to the last
  `seq`. `limit` defaults to, and is capped at, `maxPageRecords`.
- **Tombstone horizon:** tombstones are dropped after the server's retention
  period (180 days by default). The group's horizon is the highest dropped
  `seq`.
  - `0 < since < horizon` answers `410`.
  - `since = 0` is always allowed and reads the whole group. A client must
    then delete local records that are not in it.

### 6.7 `GET /v1/groups/{group}/events`

A Server-Sent Events stream with a `seq` event. The current value is sent at
once, and again each time it advances:

```
event: seq
data: {"highSeq":12}
```

The server sends keep-alive comments every 15 s. Clients reconnect with
backoff.

### 6.8 `GET /healthz`

`200 ok` when the database answers.

## 7. Client algorithm (informative)

A device keeps:

- a cursor: the highest `seq` it has applied
- a mirror: for each record, the last server version, used as the merge base
- an outbox: local changes not yet committed

One sync cycle:

1. **Pull:** read `changes` from the cursor until `more` is false. Merge each
   record into local state: decrypt, then merge three ways against the mirror.
   Update the mirror and the cursor.
2. **Push:** commit the outbox with `expectedSeq` taken from the mirror. On a
   `409`, pull again, merge, and retry with backoff.
3. **`410`:** read the whole group from `since=0`, then delete local records
   that are not in it.
4. **Rollback:** a server `highSeq` below the cursor means the server lost
   data, for example after a restore. Read from `since=0`, then commit local
   versions that are newer than the server's, using the server's current
   `seq` values.
5. **When:** sync at start and on foreground, about 2 s after a local
   change, on each `seq` event, and periodically while running.

## 8. Limits

These are the defaults. A server may configure others and reports them in
`/v1/info`.

| Limit | Default |
|---|---|
| Record ciphertext | 256 KiB |
| Records per commit | 1000 |
| Request body | 8 MiB |
| Stored bytes per group | 64 MiB |
| Records per page | 1000 |
| Challenge lifetime | 120 s |
| Session lifetime | 1 h |
| Tombstone retention | 180 days |

## 9. Security considerations

- **What the server learns:**
  - group and device ids and public keys
  - opaque tags
  - padded sizes
  - sequence numbers
  - timing
  - the connecting addresses, which it does not log by default
- **What it cannot do:**
  - read records or learn their kind
  - move a ciphertext to another record
  - log in as a device
  - add a device *(planned, through the verified chain)*
- **Rollback detection:**
  - A server that rolls a group back is detected through `highSeq` (§7).
  - A server that rolls one record back is detected through the hybrid
    logical clock the client keeps inside the record.
- **Login replay:** login signatures are bound to the server URL and to a
  single-use nonce. Session tokens are random and stored only as SHA-256
  hashes.
