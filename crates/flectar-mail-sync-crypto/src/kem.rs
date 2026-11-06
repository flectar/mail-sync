//! Wrapping root keys to devices (SPEC §4.8): HPKE (RFC 9180) in base mode
//! with the X-Wing hybrid KEM (X25519 + ML-KEM-768), HKDF-SHA256 and
//! ChaCha20-Poly1305. Wraps are stored on the server, so a hybrid
//! post-quantum KEM keeps them safe from "harvest now, decrypt later".
//!
//! X-Wing has no authenticated mode, so a wrap does not prove who made it.
//! Devices check every unwrapped key against the commitment in the signed
//! chain ([`crate::RootKey::commitment`]).

use crate::{Error, Result, RootKey, label, random_bytes};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use zeroize::Zeroize;

/// Ciphersuite number at the start of every wrap.
pub const WRAP_SUITE_XWING_HKDFSHA256_CHACHA20POLY1305: u16 = 1;
/// Length of an X-Wing public key.
pub const KEM_PUBLIC_KEY_BYTES: usize = 1216;
/// Length of an X-Wing encapsulation.
const ENCAPPED_BYTES: usize = 1120;

/// A device's (or the recovery code's) KEM secret key: a 32-byte X-Wing
/// seed.
pub struct KemSecretKey(<XWing as Kem>::PrivateKey);

impl KemSecretKey {
    pub fn generate() -> Result<Self> {
        let mut ikm = random_bytes::<32>()?;
        let key = Self::derive(&ikm);
        ikm.zeroize();
        Ok(key)
    }

    /// Derive a key pair from `ikm` (RFC 9180 DeriveKeyPair); used for the
    /// recovery key, whose `ikm` comes from the recovery code.
    pub fn derive(ikm: &[u8]) -> Self {
        Self(XWing::derive_keypair(ikm).0)
    }

    /// The secret key to store in the OS key store.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        <XWing as Kem>::PrivateKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::Malformed("invalid KEM secret key"))
    }

    pub fn public_key(&self) -> Vec<u8> {
        XWing::sk_to_pk(&self.0).to_bytes().to_vec()
    }
}

impl std::fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemSecretKey(..)")
    }
}

fn wrap_info(group_id: &[u8; 16], epoch: u64, target: &[u8; 16]) -> Vec<u8> {
    let mut info = Vec::with_capacity(label::WRAP.len() + 40);
    info.extend_from_slice(label::WRAP);
    info.extend_from_slice(group_id);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(target);
    info
}

/// Wrap `root` for the holder of `kem_public_key`. `target` is the device id
/// the wrap is for, or [`crate::RECOVERY_ID`].
pub fn wrap_root_key(
    kem_public_key: &[u8],
    group_id: &[u8; 16],
    epoch: u64,
    target: &[u8; 16],
    root: &RootKey,
) -> Result<Vec<u8>> {
    let public_key = <XWing as Kem>::PublicKey::from_bytes(kem_public_key)
        .map_err(|_| Error::InvalidPublicKey)?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &public_key,
        &wrap_info(group_id, epoch, target),
        root.as_bytes(),
        b"",
    )
    .map_err(|_| Error::Random)?;
    let mut out = Vec::with_capacity(2 + ENCAPPED_BYTES + ciphertext.len());
    out.extend_from_slice(&WRAP_SUITE_XWING_HKDFSHA256_CHACHA20POLY1305.to_be_bytes());
    out.extend_from_slice(&encapped.to_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap a root key wrapped by [`wrap_root_key`]. The caller must still
/// compare its [`RootKey::commitment`] with the signed chain.
pub fn unwrap_root_key(
    secret: &KemSecretKey,
    wrapped: &[u8],
    group_id: &[u8; 16],
    epoch: u64,
    target: &[u8; 16],
) -> Result<RootKey> {
    let (suite, rest) = wrapped
        .split_first_chunk::<2>()
        .ok_or(Error::Malformed("wrap is truncated"))?;
    if u16::from_be_bytes(*suite) != WRAP_SUITE_XWING_HKDFSHA256_CHACHA20POLY1305 {
        return Err(Error::Malformed("unsupported wrap suite"));
    }
    if rest.len() <= ENCAPPED_BYTES {
        return Err(Error::Malformed("wrap is truncated"));
    }
    let (encapped, ciphertext) = rest.split_at(ENCAPPED_BYTES);
    let encapped = <XWing as Kem>::EncappedKey::from_bytes(encapped)
        .map_err(|_| Error::Malformed("invalid encapsulation"))?;
    let mut opened = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &secret.0,
        &encapped,
        &wrap_info(group_id, epoch, target),
        ciphertext,
        b"",
    )
    .map_err(|_| Error::Decrypt)?;
    let bytes: std::result::Result<[u8; 32], _> = opened.as_slice().try_into();
    opened.zeroize();
    Ok(RootKey::from_bytes(bytes.map_err(|_| Error::Decrypt)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RECOVERY_ID, RecoveryCode};

    #[test]
    fn wraps_open_only_for_their_holder_and_context() {
        let device = KemSecretKey::generate().unwrap();
        let public_key = device.public_key();
        assert_eq!(public_key.len(), KEM_PUBLIC_KEY_BYTES);
        let root = RootKey::from_bytes([4; 32]);
        let wrapped = wrap_root_key(&public_key, &[1; 16], 3, &[2; 16], &root).unwrap();
        assert_eq!(wrapped.len(), 2 + 1120 + 32 + 16);
        let opened = unwrap_root_key(&device, &wrapped, &[1; 16], 3, &[2; 16]).unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());

        let other = KemSecretKey::generate().unwrap();
        assert_eq!(
            unwrap_root_key(&other, &wrapped, &[1; 16], 3, &[2; 16]).unwrap_err(),
            Error::Decrypt
        );
        for (group, epoch, target) in [
            ([9; 16], 3, [2; 16]),
            ([1; 16], 4, [2; 16]),
            ([1; 16], 3, [9; 16]),
        ] {
            assert_eq!(
                unwrap_root_key(&device, &wrapped, &group, epoch, &target).unwrap_err(),
                Error::Decrypt
            );
        }
    }

    #[test]
    fn secret_keys_survive_storage_and_recovery_keys_are_derived() {
        let device = KemSecretKey::generate().unwrap();
        let restored = KemSecretKey::from_bytes(&device.to_bytes()).unwrap();
        assert_eq!(restored.public_key(), device.public_key());

        let code = RecoveryCode::from_bytes([6; 32]);
        let recovery = KemSecretKey::derive(&code.kem_seed());
        assert_eq!(
            recovery.public_key(),
            KemSecretKey::derive(&RecoveryCode::from_bytes([6; 32]).kem_seed()).public_key()
        );
        let root = RootKey::from_bytes([8; 32]);
        let wrapped =
            wrap_root_key(&recovery.public_key(), &[1; 16], 1, &RECOVERY_ID, &root).unwrap();
        let reopened = unwrap_root_key(&recovery, &wrapped, &[1; 16], 1, &RECOVERY_ID).unwrap();
        assert_eq!(reopened.as_bytes(), root.as_bytes());
    }

    #[test]
    fn malformed_wraps_are_rejected() {
        let device = KemSecretKey::generate().unwrap();
        let mut wrapped = wrap_root_key(
            &device.public_key(),
            &[1; 16],
            1,
            &[2; 16],
            &RootKey::from_bytes([1; 32]),
        )
        .unwrap();
        assert!(unwrap_root_key(&device, &wrapped[..100], &[1; 16], 1, &[2; 16]).is_err());
        wrapped[1] = 9;
        assert!(unwrap_root_key(&device, &wrapped, &[1; 16], 1, &[2; 16]).is_err());
        assert!(
            wrap_root_key(
                &[0; 10],
                &[1; 16],
                1,
                &[2; 16],
                &RootKey::from_bytes([1; 32])
            )
            .is_err()
        );
    }
}
