use crate::{Error, Result, label, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF-SHA256 (RFC 5869) without salt. Every input here is a uniformly
/// random secret, so no stretching is needed: RFC 5869 §4 reserves slow
/// derivation for passwords.
pub fn hkdf_sha256(ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    // 32 bytes is far below HKDF-SHA256's 8160-byte output limit.
    hk.expand_multi_info(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// The group's root key for one epoch. Record and tag keys derive from it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; 32]);

impl RootKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Key for sealing records of `epoch`.
    pub fn record_key(&self, epoch: u64) -> [u8; 32] {
        hkdf_sha256(&self.0, &[label::RECORD_KEY, &epoch.to_be_bytes()])
    }

    /// Key for computing collection tags of `epoch`.
    pub fn tag_key(&self, epoch: u64) -> [u8; 32] {
        hkdf_sha256(&self.0, &[label::TAG_KEY, &epoch.to_be_bytes()])
    }

    /// Key for naming records after items known by name, such as a
    /// preference key. Only epoch 1's root key is used for it, so a name
    /// keeps its record id across key rotations.
    pub fn record_id_key(&self) -> [u8; 32] {
        hkdf_sha256(&self.0, &[label::RECORD_ID])
    }

    /// Public commitment to this key as the root key of `epoch`. Signed
    /// operations carry it, so a device can check that a key it unwraps is
    /// the one a member chose and not one the server substituted.
    pub fn commitment(&self, group_id: &[u8; 16], epoch: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(label::ROOT_COMMIT);
        hasher.update(group_id);
        hasher.update(epoch.to_be_bytes());
        hasher.update(self.0);
        hasher.finalize().into()
    }

    /// Seal `previous` under this key, the root key of `epoch`, for a
    /// `rotate` operation. Output: nonce (24) || ciphertext (48).
    pub fn seal_previous(
        &self,
        previous: &RootKey,
        group_id: &[u8; 16],
        epoch: u64,
    ) -> Result<Vec<u8>> {
        let nonce = random_bytes::<24>()?;
        let mut key = hkdf_sha256(&self.0, &[label::PREVIOUS_ROOT, &epoch.to_be_bytes()]);
        let sealed = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &previous.0,
                    aad: &previous_root_aad(group_id, epoch),
                },
            )
            .map_err(|_| Error::Decrypt);
        key.zeroize();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed?);
        Ok(out)
    }

    /// Open what [`RootKey::seal_previous`] sealed: the root key of
    /// `epoch - 1`.
    pub fn open_previous(&self, sealed: &[u8], group_id: &[u8; 16], epoch: u64) -> Result<RootKey> {
        if sealed.len() != 24 + 32 + 16 {
            return Err(Error::Malformed("sealed root key has the wrong length"));
        }
        let (nonce, ciphertext) = sealed.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| Error::Decrypt)?;
        let mut key = hkdf_sha256(&self.0, &[label::PREVIOUS_ROOT, &epoch.to_be_bytes()]);
        let opened = XChaCha20Poly1305::new(&key.into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &previous_root_aad(group_id, epoch),
                },
            )
            .map_err(|_| Error::Decrypt);
        key.zeroize();
        let mut opened = opened?;
        let bytes: [u8; 32] = opened.as_slice().try_into().map_err(|_| Error::Decrypt)?;
        opened.zeroize();
        Ok(Self(bytes))
    }
}

fn previous_root_aad(group_id: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(label::PREVIOUS_ROOT.len() + 24);
    aad.extend_from_slice(label::PREVIOUS_ROOT);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey(..)")
    }
}

/// An Ed25519 signing key: a device's, or the recovery key.
pub struct DeviceSigningKey(SigningKey);

impl DeviceSigningKey {
    pub fn generate() -> Result<Self> {
        let mut seed = random_bytes::<32>()?;
        let key = Self::from_seed(&seed);
        seed.zeroize();
        Ok(key)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> SignPublicKey {
        SignPublicKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for DeviceSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DeviceSigningKey")
            .field(&self.public_key())
            .finish()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignPublicKey(VerifyingKey);

impl SignPublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Strict verification (RFC 8032 §5.1.7 without malleable encodings).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let signature: [u8; 64] = signature.try_into().map_err(|_| Error::BadSignature)?;
        self.0
            .verify_strict(message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text.split_whitespace().collect::<String>()).unwrap()
    }

    /// RFC 5869 Test Case 1 (with its salt; our derivations pass none).
    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let hk = Hkdf::<Sha256>::new(
            Some(&unhex("000102030405060708090a0b0c")),
            &unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        );
        let mut okm = [0u8; 42];
        hk.expand(&unhex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                 34007208d5b887185865"
            )
        );
    }

    /// RFC 8032 §7.1 TEST 1.
    #[test]
    fn ed25519_matches_rfc8032_test_1() {
        let seed: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let key = DeviceSigningKey::from_seed(&seed);
        assert_eq!(
            key.public_key().to_bytes().to_vec(),
            unhex("d75a980182b10ab7d54bfed3c964073a 0ee172f3daa62325af021a68f707511a")
        );
        let signature = key.sign(b"");
        assert_eq!(
            signature.to_vec(),
            unhex(
                "e5564300c360ac729086e2cc806e828a 84877f1eb8e5d974d873e06522490155
                 5fb8821590a33bacc61e39701cf9b46b d25bf5f0595bbe24655141438e7a100b"
            )
        );
        key.public_key().verify(b"", &signature).unwrap();
        assert_eq!(
            key.public_key().verify(b"x", &signature),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn previous_roots_open_only_under_the_newer_key_and_context() {
        let old = RootKey::from_bytes([1; 32]);
        let new = RootKey::from_bytes([2; 32]);
        let sealed = new.seal_previous(&old, &[5; 16], 2).unwrap();
        assert_eq!(sealed.len(), 72);
        assert_eq!(
            new.open_previous(&sealed, &[5; 16], 2).unwrap().as_bytes(),
            old.as_bytes()
        );
        assert_eq!(
            old.open_previous(&sealed, &[5; 16], 2).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            new.open_previous(&sealed, &[6; 16], 2).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            new.open_previous(&sealed, &[5; 16], 3).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn commitments_bind_key_group_and_epoch() {
        let key = RootKey::from_bytes([1; 32]);
        let commitment = key.commitment(&[5; 16], 1);
        assert_ne!(
            commitment,
            RootKey::from_bytes([2; 32]).commitment(&[5; 16], 1)
        );
        assert_ne!(commitment, key.commitment(&[6; 16], 1));
        assert_ne!(commitment, key.commitment(&[5; 16], 2));
    }

    #[test]
    fn record_and_tag_keys_differ_by_purpose_and_epoch() {
        let root = RootKey::from_bytes([7; 32]);
        assert_ne!(root.record_key(1), root.tag_key(1));
        assert_ne!(root.record_key(1), root.record_key(2));
        assert_eq!(
            root.record_key(1),
            RootKey::from_bytes([7; 32]).record_key(1)
        );
    }
}
