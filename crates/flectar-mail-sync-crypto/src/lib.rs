//! Cryptography of Flectar Mail Sync, shared by the app and the server.
//!
//! The server uses only the parts that verify: operation signatures, login
//! signatures and operation hashes. Everything that encrypts or decrypts runs
//! on devices. `docs/SPEC.md` §4 describes the key schedule and formats.

mod auth;
mod keys;
mod op;
mod record;
mod recovery;

pub use auth::{auth_message, sign_auth, verify_auth};
pub use keys::{DeviceSigningKey, RootKey, SignPublicKey, hkdf_sha256};
pub use op::{
    DeviceKeys, Genesis, MAX_DEVICE_NAME_BYTES, MAX_KEM_PUBLIC_KEY_BYTES, Op, OpKind, op_hash,
    sign_op, verify_op,
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
    pub const RECORD_AAD: &[u8] = b"flectar-mail-sync/v1 record";
    pub const AUTH: &[u8] = b"flectar-mail-sync/v1 auth";
    pub const OP_SIGNATURE: &[u8] = b"flectar-mail-sync/v1 op";
    pub const OP_HASH: &[u8] = b"flectar-mail-sync/v1 op-hash";
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
