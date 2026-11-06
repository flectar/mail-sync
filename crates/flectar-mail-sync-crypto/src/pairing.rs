//! Adding a device (SPEC §4.9).
//!
//! With a QR code, the existing device shows a one-time secret. Both sides
//! encrypt their rendezvous messages under it, so the server only relays
//! ciphertext. Without a camera, the user instead compares
//! [`approval_words`] shown on both screens.

use crate::keys::hkdf_sha256;
use crate::op::DeviceKeys;
use crate::{Error, Result, label, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Who wrote a rendezvous message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The new device, sending its public keys.
    Offer = 1,
    /// The existing device, answering with what the new one needs.
    Answer = 2,
}

/// The one-time secret a QR code carries.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; 32]);

impl PairingSecret {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn aad(slot_id: &[u8; 16], direction: Direction) -> Vec<u8> {
        let mut aad = Vec::with_capacity(label::PAIRING.len() + 17);
        aad.extend_from_slice(label::PAIRING);
        aad.extend_from_slice(slot_id);
        aad.push(direction as u8);
        aad
    }

    /// Encrypt a rendezvous message. Output: nonce (24) || ciphertext.
    pub fn seal(
        &self,
        slot_id: &[u8; 16],
        direction: Direction,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = random_bytes::<24>()?;
        let mut key = hkdf_sha256(&self.0, &[label::PAIRING]);
        let sealed = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: message,
                    aad: &Self::aad(slot_id, direction),
                },
            )
            .map_err(|_| Error::Decrypt);
        key.zeroize();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed?);
        Ok(out)
    }

    pub fn open(&self, slot_id: &[u8; 16], direction: Direction, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 24 + 16 {
            return Err(Error::Malformed("pairing message is truncated"));
        }
        let (nonce, ciphertext) = sealed.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| Error::Decrypt)?;
        let mut key = hkdf_sha256(&self.0, &[label::PAIRING]);
        let opened = XChaCha20Poly1305::new(&key.into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &Self::aad(slot_id, direction),
                },
            )
            .map_err(|_| Error::Decrypt);
        key.zeroize();
        opened
    }
}

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(..)")
    }
}

/// Six words both devices show when a device is approved without a QR code.
///
/// They cover the new device's keys and the group's chain head, so a server
/// that swapped either the keys or the group shows different words on one
/// side.
pub fn approval_words(
    group_id: &[u8; 16],
    head_hash: &[u8; 32],
    device: &DeviceKeys,
) -> [&'static str; 6] {
    let mut hasher = Sha256::new();
    hasher.update(label::FINGERPRINT);
    hasher.update(group_id);
    hasher.update(head_hash);
    hasher.update(device.device_id);
    hasher.update(device.sign_public_key);
    hasher.update((device.kem_public_key.len() as u64).to_be_bytes());
    hasher.update(&device.kem_public_key);
    let digest: [u8; 32] = hasher.finalize().into();
    let bits = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
    let list = bip39::Language::English.word_list();
    // 6 words × 11 bits = 66 bits, taken from the top of the digest.
    std::array::from_fn(|i| list[((bits >> (128 - 11 * (i + 1))) & 0x7ff) as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_open_only_with_the_secret_slot_and_direction() {
        let secret = PairingSecret::from_bytes([1; 32]);
        let sealed = secret.seal(&[2; 16], Direction::Offer, b"keys").unwrap();
        assert_eq!(
            secret.open(&[2; 16], Direction::Offer, &sealed).unwrap(),
            b"keys"
        );
        assert!(secret.open(&[2; 16], Direction::Answer, &sealed).is_err());
        assert!(secret.open(&[3; 16], Direction::Offer, &sealed).is_err());
        assert!(
            PairingSecret::from_bytes([9; 32])
                .open(&[2; 16], Direction::Offer, &sealed)
                .is_err()
        );
    }

    #[test]
    fn approval_words_change_with_any_input() {
        let device = DeviceKeys {
            device_id: [1; 16],
            sign_public_key: [2; 32],
            kem_public_key: vec![3; 1216],
        };
        let words = approval_words(&[4; 16], &[5; 32], &device);
        assert_eq!(words, approval_words(&[4; 16], &[5; 32], &device));
        assert_ne!(words, approval_words(&[9; 16], &[5; 32], &device));
        assert_ne!(words, approval_words(&[4; 16], &[9; 32], &device));
        let swapped = DeviceKeys {
            sign_public_key: [9; 32],
            ..device
        };
        assert_ne!(words, approval_words(&[4; 16], &[5; 32], &swapped));
    }
}
