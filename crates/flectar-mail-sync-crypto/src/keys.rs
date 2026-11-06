use crate::{Error, Result, label, random_bytes};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
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
