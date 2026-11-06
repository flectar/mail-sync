//! Cryptography of Flectar Mail Sync, shared by the app and the server.
//!
//! The server uses only the parts that verify: the membership chain
//! ([`GroupState`]), login signatures and operation hashes. Everything that
//! encrypts or decrypts runs on devices; key wrapping is behind the `kem`
//! feature, which the server does not enable. `docs/SPEC.md` §4 and §5
//! describe the formats.

mod auth;
mod chain;
#[cfg(feature = "kem")]
mod kem;
mod keys;
mod op;
mod pairing;
mod record;
mod recovery;

pub use auth::{auth_message, sign_auth, verify_auth};
pub use chain::{GroupState, Member};
#[cfg(feature = "kem")]
pub use kem::{
    KEM_PUBLIC_KEY_BYTES, KemSecretKey, WRAP_SUITE_XWING_HKDFSHA256_CHACHA20POLY1305,
    unwrap_root_key, wrap_root_key,
};
pub use keys::{DeviceSigningKey, RootKey, SignPublicKey, hkdf_sha256};
pub use op::{
    AddDevice, Authorizer, DeleteGroup, DeviceKeys, Genesis, MAX_KEM_PUBLIC_KEY_BYTES,
    MAX_SEALED_ROOT_BYTES, MAX_URL_BYTES, MoveServer, Op, OpKind, RECOVERY_ID, RemoveDevice,
    ResetRecovery, Rotate, device_binding_message, op_hash, recovery_binding_message, sign_op,
    verify_op,
};
pub use pairing::{
    INVITE_INDEX, Invite, JOIN_REQUEST_INDEX, JOIN_RESULT_INDEX, JoinRequest, JoinResult,
    PairingSecret, approval_words,
};
pub use record::{collection_tag, open_record, pad, seal_record, unpad};
pub use recovery::RecoveryCode;

/// Domain-separation labels. Each key and signature is bound to exactly one
/// purpose by one of these.
pub mod label {
    pub const RECOVERY_SIGN: &[u8] = b"flectar-mail-sync/v1 recovery-sign";
    pub const RECOVERY_KEM: &[u8] = b"flectar-mail-sync/v1 recovery-kem";
    pub const RECORD_KEY: &[u8] = b"flectar-mail-sync/v1 record-key";
    pub const TAG_KEY: &[u8] = b"flectar-mail-sync/v1 tag-key";
    pub const RECORD_ID: &[u8] = b"flectar-mail-sync/v1 record-id";
    pub const RECORD_AAD: &[u8] = b"flectar-mail-sync/v1 record";
    pub const AUTH: &[u8] = b"flectar-mail-sync/v1 auth";
    pub const OP_SIGNATURE: &[u8] = b"flectar-mail-sync/v1 op";
    pub const OP_HASH: &[u8] = b"flectar-mail-sync/v1 op-hash";
    pub const DEVICE_BINDING: &[u8] = b"flectar-mail-sync/v1 device-binding";
    pub const RECOVERY_BINDING: &[u8] = b"flectar-mail-sync/v1 recovery-binding";
    pub const ROOT_COMMIT: &[u8] = b"flectar-mail-sync/v1 root-commit";
    pub const PREVIOUS_ROOT: &[u8] = b"flectar-mail-sync/v1 previous-root";
    pub const WRAP: &[u8] = b"flectar-mail-sync/v1 wrap";
    pub const PAIRING: &[u8] = b"flectar-mail-sync/v1 pairing";
    pub const FINGERPRINT: &[u8] = b"flectar-mail-sync/v1 fingerprint";
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the recovery code is not valid")]
    InvalidRecoveryCode,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("the operating system random generator failed")]
    Random,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Fill `buf` from the operating system's random generator.
pub fn random_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// `N` random bytes from the operating system's random generator.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    random_fill(&mut bytes)?;
    Ok(bytes)
}
