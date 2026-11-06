use crate::keys::{DeviceSigningKey, hkdf_sha256};
use crate::{Error, Result, label, random_bytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The recovery code: 256 random bits, written as 24 BIP39 English words.
///
/// The word list is only an encoding with a checksum; the 32 bytes are used
/// directly (as Brave does), not through BIP39's PBKDF2 seed derivation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; 32]);

impl RecoveryCode {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse 24 words, ignoring case and extra whitespace.
    pub fn from_words(words: &str) -> Result<Self> {
        let normalized = words
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ");
        let mnemonic = bip39::Mnemonic::parse_normalized(&normalized)
            .map_err(|_| Error::InvalidRecoveryCode)?;
        let mut entropy = mnemonic.to_entropy();
        let bytes: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidRecoveryCode)?;
        entropy.zeroize();
        Ok(Self(bytes))
    }

    /// The 24 words, separated by single spaces.
    pub fn to_words(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.0)
            .expect("32 bytes is a valid BIP39 entropy length")
            .to_string()
    }

    /// The recovery signing key, which signs membership operations when no
    /// device is available.
    pub fn signing_key(&self) -> DeviceSigningKey {
        let mut seed = hkdf_sha256(&self.0, &[label::RECOVERY_SIGN]);
        let key = DeviceSigningKey::from_seed(&seed);
        seed.zeroize();
        key
    }

    /// Seed of the recovery KEM key pair. Devices hold only its public half,
    /// so they can wrap new root keys for recovery without the code.
    pub fn kem_seed(&self) -> [u8; 32] {
        hkdf_sha256(&self.0, &[label::RECOVERY_KEM])
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip() {
        let code = RecoveryCode::generate().unwrap();
        let words = code.to_words();
        assert_eq!(words.split(' ').count(), 24);
        let parsed = RecoveryCode::from_words(&format!("  {}  ", words.to_uppercase())).unwrap();
        assert_eq!(parsed.0, code.0);
    }

    #[test]
    fn known_entropy_encodes_to_bip39_words() {
        // BIP39 reference vector: 32 zero bytes.
        let code = RecoveryCode::from_bytes([0; 32]);
        assert_eq!(
            code.to_words(),
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn bad_checksums_and_lengths_are_rejected() {
        let mut words: Vec<String> = RecoveryCode::from_bytes([0; 32])
            .to_words()
            .split(' ')
            .map(String::from)
            .collect();
        words[23] = "abandon".into();
        assert_eq!(
            RecoveryCode::from_words(&words.join(" ")).unwrap_err(),
            Error::InvalidRecoveryCode
        );
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        assert_eq!(
            RecoveryCode::from_words(twelve).unwrap_err(),
            Error::InvalidRecoveryCode,
            "a valid 12-word phrase is not a recovery code"
        );
    }

    #[test]
    fn derived_keys_are_stable_and_separate() {
        let code = RecoveryCode::from_bytes([9; 32]);
        assert_eq!(
            code.signing_key().public_key(),
            RecoveryCode::from_bytes([9; 32]).signing_key().public_key()
        );
        assert_ne!(code.signing_key().seed(), code.kem_seed());
    }
}
