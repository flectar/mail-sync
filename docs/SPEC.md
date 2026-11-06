# Flectar Mail Sync protocol, version 1

Status: **draft**. Sections marked *(planned)* are not implemented yet and may
change. Everything else is implemented by the crates in this repository and
covered by their tests.

## 1. Overview

Flectar Mail Sync keeps one person's app state the same on all their
devices. That state covers accounts, preferences, signatures, rules and similar
records. Mail, contacts and calendars are not part of it: they sync with
the mail provider as before.

- **Group:** one person's devices and their records.
- **Device:** holds its own signing key and KEM key in its operating system's
  key store, plus the group's root keys.
- **Record:** an encrypted blob with a random 16-byte id. The server stores
  the newest version of each record. A deleted record leaves a **tombstone**
  without payload.
- **Sequence number (`seq`):** every record change gets the next one in its
  group. The server assigns it, so no device clock ever orders changes.
- **Membership chain:** a hash-chained list of signed operations that says
  which devices belong to the group, which recovery key may act, and which
  root key is current. The server and every device check it with the same
  rules (§5.4).
- **Epoch:** numbers the group's current root key. It starts at 1 and
  increases with each `rotate` operation.

The server is blind. It never holds a key that could read a record, and it
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
| group id, device id, record id, challenge id, pairing slot id | 16, random |
| collection tag | 16 |
| record nonce | 24 |
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| X-Wing public key | 1216 |
| login nonce | 32 |

`RECOVERY_ID` is 16 zero bytes. It stands for the recovery key wherever a
device id is expected: in logins, key wraps and operation authorizers.

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
| Record and key sealing | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) |
| Collection tags | HMAC-SHA256, first 16 bytes |
| Hashes and commitments | SHA-256 |
| Wrapping root keys to devices | HPKE (RFC 9180), base mode, suite 1 (§4.8) |

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
| `ROOT_COMMIT` | `flectar-mail-sync/v1 root-commit` |
| `PREVIOUS_ROOT` | `flectar-mail-sync/v1 previous-root` |
| `WRAP` | `flectar-mail-sync/v1 wrap` |
| `AUTH` | `flectar-mail-sync/v1 auth` |
| `OP_SIGNATURE` | `flectar-mail-sync/v1 op` |
| `OP_HASH` | `flectar-mail-sync/v1 op-hash` |
| `DEVICE_BINDING` | `flectar-mail-sync/v1 device-binding` |
| `RECOVERY_BINDING` | `flectar-mail-sync/v1 recovery-binding` |
| `PAIRING` | `flectar-mail-sync/v1 pairing` |
| `FINGERPRINT` | `flectar-mail-sync/v1 fingerprint` |

`||` is concatenation. `u16be` and `u64be` are big-endian unsigned integers.

### 4.3 Recovery code

- **The code:** 32 random bytes, shown as 24 words of the BIP39 English list.
  The words only encode the 32 bytes and their checksum. BIP39's PBKDF2
  seed derivation is not used.
- **Recovery signing key:** the Ed25519 key whose seed is
  `HKDF(code, RECOVERY_SIGN)`.
- **Recovery KEM key:** HPKE `DeriveKeyPair(HKDF(code, RECOVERY_KEM))` of
  suite 1. Devices hold only its public half, so they can wrap new root keys
  for recovery without knowing the code.
- **Finding the group:** the server finds a group by its current recovery
  signing key (§6.4), so the 24 words and the server's address are enough to
  recover, even after `reset_recovery` replaced the code. A recovery key
  belongs to one group at most.

### 4.4 Root keys and epochs

- The root key `K_e` of epoch `e` is 32 random bytes.
- record key = `HKDF(K_e, RECORD_KEY || u64be(e))`
- tag key = `HKDF(K_e, TAG_KEY || u64be(e))`
- **Commitment:**
  `SHA-256(ROOT_COMMIT || group_id || u64be(e) || K_e)`.
  - The genesis operation (epoch 1) and every `rotate` operation carry it.
  - A device must compare every root key it unwraps with the commitment in
    the verified chain. A wrap does not prove who made it (§4.8); the
    commitment does.
- **Sealed previous root:** a `rotate` to epoch `e` carries
  `nonce (24) || XChaCha20-Poly1305(HKDF(K_e, PREVIOUS_ROOT || u64be(e)), nonce, K_{e-1}, aad)`,
  where `aad = PREVIOUS_ROOT || group_id || u64be(e)`. That is 72 bytes. With
  the current root key a device can walk back to every earlier one, so records
  of older epochs stay readable without being re-encrypted.

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
For a recovery login, `group_id` and `device_id` are both `RECOVERY_ID`,
because recovery learns its group only once logged in, and the recovery
signing key signs.

### 4.8 Key wraps

- **Suite 1:** HPKE base mode with:
  - KEM: X-Wing, the hybrid of X25519 and ML-KEM-768. KEM id `0x647a`, as
    draft-ietf-hpke-pq-03 assigns it.
  - KDF: HKDF-SHA256.
  - AEAD: ChaCha20-Poly1305.

  Wraps are stored on the server, so the hybrid post-quantum KEM keeps them
  safe from "harvest now, decrypt later".
- **Format:** `u16be(1) || enc (1120) || ciphertext (48)`, where `ciphertext`
  seals `K_e`.
  - `info`: `WRAP || group_id || u64be(e) || target`.
  - `aad`: empty.
  - `target`: the device id, or `RECOVERY_ID`.
- **No sender authentication:** X-Wing has no authenticated mode. A device
  must check what it unwraps against the chain's commitment (§4.4).

### 4.9 Pairing

- **Pairing secret:** 32 random bytes. The existing device shows it in a QR
  code.
- **Pairing messages:**
  `nonce (24) || XChaCha20-Poly1305(HKDF(secret, PAIRING), nonce, message, aad)`,
  where:
  - `aad = PAIRING || slot_id || direction`
  - direction 1 is the offer, sent by the new device; direction 2 is the
    answer, sent by the existing device.
- **Approval words**, used when no camera is available:
  1. Compute `SHA-256(FINGERPRINT || group_id || head_hash || device_id || sign_public_key || u64be(len(kem_public_key)) || kem_public_key)`.
  2. Take its first 66 bits.
  3. Read them as six 11-bit indices into the BIP39 English list.

  Both devices show the six words. They differ if a server swapped the new
  device's keys or the group.

## 5. Membership chain

### 5.1 Encoding

Operations are signed and hashed over this canonical binary encoding, never
over JSON:

```
"FMSO" || 0x01 || kind (1 byte) || group_id (16) || u64be(index)
       || prev_hash (32) || u64be(created_at_ms) || body
```

- A variable field (`var`) is `u16be(length) || bytes`.
- **Device keys:** `device_id (16) || sign_public_key (32) || var kem_public_key`.
  The KEM key is at most 4096 bytes.
- **Authorizer:** 17 bytes. It is either `0x01 || device_id`, where the
  device id is not `RECOVERY_ID`, or `0x02 || RECOVERY_ID`.
- Decoders reject unknown kinds, bad authorizers, over-long fields and
  trailing bytes.

### 5.2 Signatures, hashes and bindings

- **Signature:** `Ed25519(key, OP_SIGNATURE || op_bytes)`.
- **Hash:** `SHA-256(OP_HASH || op_bytes)`.
- **Chain:** each operation's `prev_hash` is the previous operation's hash and
  its `index` is one higher. The genesis has index 0 and an all-zero
  `prev_hash`.
- **Device binding:** a device being added signs
  `DEVICE_BINDING || group_id || device keys`, proving it holds its private
  key.
- **Recovery binding:** a new recovery key signs
  `RECOVERY_BINDING || group_id || recovery_sign_public_key || var recovery_kem_public_key`,
  so nobody can reset recovery to a key they do not hold, such as another
  group's.

Operations are plaintext to the server, so they carry only ids, public keys
and commitments. Device names belong in encrypted records.

### 5.3 Kinds

| Kind | Name | Body after the header | Signatures |
|---|---|---|---|
| 1 | genesis | `recovery_sign_public_key (32)`, `var recovery_kem_public_key`, device keys, `root_commitment (32)` | the recovery key's, then the device's |
| 2 | add_device | authorizer, device keys, `binding_signature (64)` | the authorizer's |
| 3 | remove_device | authorizer, `device_id (16)` | the authorizer's |
| 4 | rotate | authorizer, `u64be(epoch)`, `root_commitment (32)`, `var sealed_previous_root`, at most 256 bytes | the authorizer's |
| 5 | reset_recovery | authorizer, `recovery_sign_public_key (32)`, `var recovery_kem_public_key`, `binding_signature (64)` | the authorizer's |
| 6 | move_server | authorizer, `var url` (UTF-8, at most 2048 bytes) | the authorizer's |
| 7 | delete_group | authorizer | the authorizer's |

### 5.4 Rules

A chain is valid when its first operation is a valid genesis and each later
operation passes these checks against the state before it:

1. **Order and authority:**
   - The group is not deleted, the group id matches, and the index and
     `prev_hash` extend the head.
   - The operation is not a genesis and carries exactly one signature.
   - That signature verifies with the authorizer's current key: an active
     device's signing key, or the current recovery signing key.
2. **add_device:**
   - The id is not `RECOVERY_ID`, not active, and was never removed.
   - The binding signature verifies with the new device's key.
3. **remove_device:** the device is active. A device may remove itself.
4. **rotate:** `epoch` is the current epoch plus one, and the sealed previous
   root is not empty.
5. **reset_recovery:** the binding signature verifies with the new recovery
   signing key.
6. **move_server:** the URL starts with `https://` or `http://`.
7. **delete_group:** no operation may follow it.

`GroupState` in `flectar-mail-sync-crypto` implements these rules. The server
and the app both use it.

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
| 400 | `bad_request` | Malformed request, or an operation that breaks §5.4 |
| 401 | `unauthorized` | Missing or invalid session, or a failed login |
| 403 | `forbidden` | The session belongs to another group, or a recovery session asked for something only devices may do |
| 404 | `not_found` | Unknown group, or no wrap for this session |
| 409 | `conflict` | Stale `expectedSeq`, the group id is taken, the recovery key belongs to another group, or the chain moved on |
| 410 | `gone` | `since` is below the tombstone horizon; read again from 0 |
| 410 | `group_deleted` | The group was deleted |
| 413 | `payload_too_large` | Over a size or batch limit |
| 429 | `rate_limited` | Too many requests |
| 507 | `quota_exceeded` | The group would exceed its storage quota or device limit |
| 500 | `internal` | Server failure |

### 6.2 `GET /v1/info`

```json
{"server": "flectar-mail-sync", "version": "0.1.0", "protocolMin": 1, "protocolMax": 1,
 "limits": {"maxRecordBytes": 262144, "maxBatchRecords": 1000, "maxRequestBytes": 8388608,
            "maxGroupBytes": 67108864, "maxPageRecords": 1000, "maxDevices": 25}}
```

### 6.3 `POST /v1/groups`

Request: `{"op": <genesis>, "signatures": [<recovery>, <device>], "wraps": [{"target", "ciphertext"}, …]}`.

- **Wraps:** epoch 1 wraps. The recovery wrap is required; the device's own
  wrap is optional.
- **Success:** `201 {"groupId", "highSeq": 0}`.
- **Taken id or recovery key:** `409`. The id of a deleted group is never used
  again; its recovery key is free again.

### 6.4 Login

1. `POST /v1/auth/challenge` returns `{"challengeId", "nonce", "expiresAt"}`.
   - A device sends `{"groupId", "deviceId"}`. `deviceId` must not be
     `RECOVERY_ID`.
   - Recovery sends only `{"recoveryPublicKey"}`, its current signing key.
     The server finds the group whose current recovery key it is.
   - A challenge lasts 120 s and is single-use. It is issued even for
     unknown groups, devices or keys, so the endpoint does not reveal which
     exist.
2. `POST /v1/auth/session` with `{"challengeId", "signature"}` takes the
   signature over the login message (§4.7). It returns
   `{"token", "expiresAt", "groupId"}`, and the session lasts one hour.
3. Any failure is `401`.

**Recovery sessions:** recovery learns its group from the session response.
It must then check that the chain's current recovery key is its own. A
recovery session may only:
- read the chain (§6.9);
- read the recovery wrap (§6.11);
- append an `add_device` operation (§6.10).

**When sessions end:**
- A removed device's sessions end at once, and so do recovery sessions when
  recovery is reset.
- After a group is deleted, its sessions last until they expire, and every
  request answers `410 group_deleted`. Devices still connected learn of the
  deletion that way.

### 6.5 `POST /v1/groups/{group}/commit`

This endpoint is for device sessions only.

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

This endpoint is for device sessions only.

Returns records and tombstones with `seq > N`, oldest first, read from one
snapshot: `{"records": [...], "highSeq", "more"}`. A tombstone carries only
`recordId`, `seq` and `"deleted": true`.

- **Paging:** if `more` is true, ask again with `since` set to the last
  `seq`. `limit` defaults to, and is capped at, `maxPageRecords`.
- **Tombstone horizon:** tombstones are dropped after the server's retention
  period (180 days by default). The group's horizon is the highest dropped
  `seq`.
  - `0 < since < horizon` answers `410 gone`.
  - `since = 0` is always allowed and reads the whole group. A client must
    then delete local records that are not in it.

### 6.7 `GET /v1/groups/{group}/events`

This endpoint is for device sessions only.

A Server-Sent Events stream with a `seq` event. The current value is sent at
once, and again each time it advances:

```
event: seq
data: {"highSeq":12}
```

- The server sends keep-alive comments every 15 s. Clients reconnect with
  backoff.
- The stream ends when the server shuts down, when a device of the group is
  removed, or when the group is deleted.

### 6.8 `GET /healthz`

`200 ok` when the database answers.

### 6.9 `GET /v1/groups/{group}/ops?since=N`

Returns `{"ops": [{"index", "op", "signatures"}, …], "more"}`: operations
with `index >= N`, oldest first.

A device verifies them with §5.4. It anchors the chain to a head hash it
already trusts: one it verified before, or the one a pairing gave it.

### 6.10 `POST /v1/groups/{group}/ops`

Request: `{"op", "signatures", "wraps"}`.

1. The server replays the stored chain, checks the operation with §5.4, and
   applies it.
2. An operation for an index that already exists answers `409`; the client
   reads the chain again and rebuilds the operation.
3. Success returns `{"headIndex", "epoch"}`.

The wraps must be exactly what the kind allows. They are stored for the epoch
current after the operation.

| Kind | Required wraps | Allowed wraps |
|---|---|---|
| add_device | none | the new device |
| rotate | every remaining device and `RECOVERY_ID` | the same |
| reset_recovery | none | `RECOVERY_ID` (for the new recovery key) |
| remove_device, move_server, delete_group | none | none |

Effects:
- **add_device:** answers `507` when it would exceed `maxDevices`.
- **remove_device:** drops the device's wraps, ends its sessions, and ends the
  group's event streams.
- **rotate:** drops wraps of older epochs.
- **reset_recovery:** drops the old recovery wrap and ends recovery sessions.
  A new key that belongs to another group answers `409`.
- **delete_group:** erases the group's records, wraps, devices, chain and
  recovery key. A marker keeps the id from being used again.

### 6.11 `GET /v1/groups/{group}/wrap`

Returns `{"epoch", "ciphertext"}`: the current epoch's wrap for the session's
device, or for recovery in a recovery session. If there is none, it answers
`404`.

### 6.12 Pairing rendezvous *(planned)*

One-time slots where a new device and an existing one exchange encrypted
pairing messages (§4.9), or public keys plus approval words when no camera is
available.

## 7. Device flows (informative)

- **Create a group:**
  1. Generate a random group id and a recovery code.
  2. Generate the device's keys and the root key `K_1`.
  3. Sign the genesis with both keys.
  4. Wrap `K_1` for recovery and send `POST /v1/groups`.
- **Add a device with a QR code:**
  1. The existing device shows the server URL, the group id, the chain's
     head hash and a pairing secret.
  2. The new device sends its keys and a binding signature in a sealed offer.
  3. The existing device appends `add_device`, with a wrap of the current
     root key for the new device.
  4. The new device logs in, verifies the chain against the head hash from
     the QR code, unwraps its key and checks the commitment.
- **Add a device without a camera:** the same, except that the user compares
  approval words (§4.9) on both screens before the existing device appends.
- **Recover:**
  1. Type the 24 words and the server's address.
  2. Log in with the recovery key. The session response names the group.
  3. Read the chain and check that its recovery key is this code's.
  4. Read the recovery wrap, unwrap it and check the commitment.
  5. Append `add_device` authorized by the recovery key.
  6. Continue as the new device.
- **Remove a device:**
  1. Append `remove_device`, then `rotate` with a new root key wrapped for
     every remaining device and recovery.
  2. Write new records under the new epoch.
- **If the recovery code may have leaked:** generate a new code, then
  `reset_recovery` and `rotate`.
- **Read older records:** open the sealed previous roots back from the
  current key.

## 8. Client sync algorithm (informative)

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
3. **`410 gone`:** read the whole group from `since=0`, then delete local
   records that are not in it.
4. **Rollback:** a server `highSeq` below the cursor means the server lost
   data, for example after a restore. Read from `since=0`, then commit local
   versions that are newer than the server's, using the server's current
   `seq` values.
5. **When:** sync at start and on foreground, about 2 s after a local
   change, on each `seq` event, and periodically while running.

## 9. Limits

These are the defaults. A server may configure others and reports them in
`/v1/info`.

| Limit | Default |
|---|---|
| Record ciphertext | 256 KiB |
| Records per commit | 1000 |
| Request body | 8 MiB |
| Stored bytes per group | 64 MiB |
| Records or operations per page | 1000 |
| Devices per group | 25 |
| Wrap size | 4096 bytes |
| Challenge lifetime | 120 s |
| Session lifetime | 1 h |
| Tombstone retention | 180 days |

## 10. Security considerations

- **What the server learns:**
  - group and device ids and public keys
  - the membership chain
  - opaque tags
  - padded sizes
  - sequence numbers
  - timing
  - the connecting addresses, which it does not log by default
- **What it cannot do:**
  - read records or learn their kind
  - move a ciphertext to another record
  - log in as a device
  - add a device: every operation is signed by a member, and devices verify
    the chain
  - slip a root key of its own to devices: unwrapped keys must match the
    chain's commitment
- **Rollback detection:**
  - A server that rolls a group back is detected through `highSeq` (§8).
  - A server that rolls one record back is detected through the hybrid
    logical clock the client keeps inside the record.
  - A server that rolls the chain back is detected through the head hash each
    device remembers.
- **Logins:** login signatures are bound to the server URL and to a
  single-use nonce. Session tokens are random and stored only as SHA-256
  hashes.
- **Removed devices:** a removed device keeps what it already saw. After
  `rotate`, it cannot read anything new.
