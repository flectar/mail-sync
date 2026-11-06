//! Wire types of the Flectar Mail Sync protocol, version 1.
//!
//! Every request and response body is JSON. Binary values travel as
//! unpadded base64url strings ([`Bytes`]). The server never sees plaintext:
//! record payloads, collection tags and device keys are opaque to it.
//! `docs/SPEC.md` is the normative description; these types follow it.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The protocol version this crate describes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Lengths of the fixed-size identifiers and keys.
pub mod len {
    /// Random group identifier.
    pub const GROUP_ID: usize = 16;
    /// Random device identifier.
    pub const DEVICE_ID: usize = 16;
    /// Random record identifier.
    pub const RECORD_ID: usize = 16;
    /// Opaque collection tag (truncated HMAC).
    pub const TAG: usize = 16;
    /// XChaCha20-Poly1305 nonce.
    pub const NONCE: usize = 24;
    /// Ed25519 public key.
    pub const SIGN_PUBLIC_KEY: usize = 32;
    /// Ed25519 signature.
    pub const SIGNATURE: usize = 64;
    /// Authentication challenge nonce.
    pub const CHALLENGE_NONCE: usize = 32;
    /// Challenge identifier.
    pub const CHALLENGE_ID: usize = 16;
}

/// Binary data carried as an unpadded base64url string.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value as a fixed-size array, if it has exactly `N` bytes.
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        self.0.as_slice().try_into().ok()
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn decode(text: &str) -> Option<Self> {
        URL_SAFE_NO_PAD.decode(text).ok().map(Self)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(value: [u8; N]) -> Self {
        Self(value.to_vec())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", self.encode())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::decode(&text).ok_or_else(|| serde::de::Error::custom("invalid base64url value"))
    }
}

/// `GET /v1/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub server: String,
    pub version: String,
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub limits: Limits,
}

/// Limits a server enforces. Clients size their batches by these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Largest accepted ciphertext of one record, in bytes.
    pub max_record_bytes: u64,
    /// Most records in one commit.
    pub max_batch_records: u32,
    /// Largest accepted request body, in bytes.
    pub max_request_bytes: u64,
    /// Total stored bytes per group.
    pub max_group_bytes: u64,
    /// Most records returned by one `changes` page.
    pub max_page_records: u32,
}

/// `POST /v1/groups`: create a group from its signed genesis operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroup {
    /// Canonical encoding of the genesis operation (SPEC §5).
    pub op: Bytes,
    /// Signatures over the operation: the recovery key's, then the device's.
    pub signatures: Vec<Bytes>,
}

/// Response to [`CreateGroup`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreated {
    pub group_id: Bytes,
    pub high_seq: u64,
}

/// `POST /v1/auth/challenge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    pub group_id: Bytes,
    pub device_id: Bytes,
}

/// A one-time login challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge_id: Bytes,
    pub nonce: Bytes,
    /// Milliseconds since the Unix epoch.
    pub expires_at: i64,
}

/// `POST /v1/auth/session`: answer a challenge with a device signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub challenge_id: Bytes,
    pub signature: Bytes,
}

/// A bearer session for one device of one group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub token: String,
    /// Milliseconds since the Unix epoch.
    pub expires_at: i64,
}

/// One change in a commit: either a new ciphertext for the record or its
/// deletion.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitItem {
    pub record_id: Bytes,
    /// The record's sequence number the writer last saw; 0 if it believes
    /// the record does not exist.
    pub expected_seq: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<Bytes>,
}

/// A validated [`CommitItem`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change<'a> {
    Put {
        tag: &'a [u8],
        epoch: u64,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
    },
    Delete,
}

impl CommitItem {
    /// Check the shape of the item; `max_record_bytes` bounds the ciphertext.
    pub fn change(&self, max_record_bytes: u64) -> Result<Change<'_>, &'static str> {
        if self.record_id.len() != len::RECORD_ID {
            return Err("recordId must be 16 bytes");
        }
        if self.deleted {
            if self.tag.is_some()
                || self.epoch.is_some()
                || self.nonce.is_some()
                || self.ciphertext.is_some()
            {
                return Err("a deletion carries no payload");
            }
            return Ok(Change::Delete);
        }
        let (Some(tag), Some(epoch), Some(nonce), Some(ciphertext)) =
            (&self.tag, self.epoch, &self.nonce, &self.ciphertext)
        else {
            return Err("a record needs tag, epoch, nonce and ciphertext");
        };
        if tag.len() != len::TAG {
            return Err("tag must be 16 bytes");
        }
        if nonce.len() != len::NONCE {
            return Err("nonce must be 24 bytes");
        }
        if ciphertext.is_empty() {
            return Err("ciphertext is empty");
        }
        if ciphertext.len() as u64 > max_record_bytes {
            return Err("ciphertext is larger than the record limit");
        }
        Ok(Change::Put {
            tag: tag.as_slice(),
            epoch,
            nonce: nonce.as_slice(),
            ciphertext: ciphertext.as_slice(),
        })
    }
}

/// `POST /v1/groups/{group}/commit`. Applied atomically: either every item
/// is stored or none is.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitRequest {
    pub items: Vec<CommitItem>,
}

/// The sequence number a committed record received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Committed {
    pub record_id: Bytes,
    pub seq: u64,
}

/// Successful commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitResponse {
    pub high_seq: u64,
    pub results: Vec<Committed>,
}

/// A record whose `expectedSeq` did not match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    pub record_id: Bytes,
    /// 0 if the record does not exist.
    pub current_seq: u64,
}

/// One record in a `changes` page. Deleted records carry no payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub record_id: Bytes,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<Bytes>,
}

/// `GET /v1/groups/{group}/changes?since=N&limit=M`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    /// Records with `seq > since`, oldest first.
    pub records: Vec<Record>,
    /// The group's newest sequence number when the page was read.
    pub high_seq: u64,
    /// More records follow; ask again with `since` = the last `seq`.
    pub more: bool,
}

/// Data of the `seq` server-sent event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeqEvent {
    pub high_seq: u64,
}

/// Machine-readable error category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    /// The requested `since` is older than the group's tombstone horizon:
    /// read the whole group again with `since=0`.
    Gone,
    PayloadTooLarge,
    QuotaExceeded,
    RateLimited,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

/// Body of every error response. `conflicts` is present only for
/// [`ErrorCode::Conflict`] answers to a commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub error: ErrorDetail,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_unpadded_base64url() {
        let value = Bytes(vec![0xfb, 0xff, 0x01]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"-_8B\"");
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), value);
        assert!(serde_json::from_str::<Bytes>("\"+/8B\"").is_err());
        assert!(serde_json::from_str::<Bytes>("\"-_8B==\"").is_err());
    }

    #[test]
    fn commit_items_validate_their_shape() {
        let put = CommitItem {
            record_id: Bytes(vec![1; 16]),
            expected_seq: 0,
            tag: Some(Bytes(vec![2; 16])),
            epoch: Some(1),
            nonce: Some(Bytes(vec![3; 24])),
            ciphertext: Some(Bytes(vec![4; 40])),
            ..Default::default()
        };
        assert!(matches!(put.change(64), Ok(Change::Put { epoch: 1, .. })));
        assert!(put.change(39).is_err(), "over the record limit");

        let delete = CommitItem {
            record_id: Bytes(vec![1; 16]),
            expected_seq: 4,
            deleted: true,
            ..Default::default()
        };
        assert_eq!(delete.change(64), Ok(Change::Delete));

        let mixed = CommitItem {
            ciphertext: Some(Bytes(vec![4; 40])),
            ..delete.clone()
        };
        assert!(mixed.change(64).is_err());
        let short_id = CommitItem {
            record_id: Bytes(vec![1; 15]),
            ..delete
        };
        assert!(short_id.change(64).is_err());
    }

    #[test]
    fn deletions_serialize_without_payload_fields() {
        let delete = CommitItem {
            record_id: Bytes(vec![0; 16]),
            expected_seq: 7,
            deleted: true,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&delete).unwrap(),
            serde_json::json!({"recordId": "AAAAAAAAAAAAAAAAAAAAAA", "expectedSeq": 7, "deleted": true})
        );
    }

    #[test]
    fn error_codes_are_snake_case() {
        let body = ErrorBody {
            error: ErrorDetail {
                code: ErrorCode::QuotaExceeded,
                message: "full".into(),
            },
            conflicts: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            serde_json::json!({"error": {"code": "quota_exceeded", "message": "full"}})
        );
    }
}
