//! Adding a device (SPEC §4.9).
//!
//! The device that shows a QR code or a short code opens a pairing slot on a
//! server. The two devices then exchange three messages through it:
//!
//! 0. [`Invite`], from the existing device: where the group lives and the
//!    head of its chain.
//! 1. [`JoinRequest`], from the new device: its keys, bound to that group.
//! 2. [`JoinResult`], from the existing device, after it added the new one
//!    to the chain or the user declined.
//!
//! With a QR code, every message is sealed under the code's
//! [`PairingSecret`], so the server only relays ciphertext. With a short
//! code, the messages travel in the clear and the user compares
//! [`approval_words`] on both screens before the existing device adds the
//! new one.

use crate::keys::hkdf_sha256;
use crate::op::{DeviceKeys, MAX_URL_BYTES, Reader, put_device, put_var};
use crate::{Error, Result, label, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Slot index of the [`Invite`].
pub const INVITE_INDEX: u8 = 0;
/// Slot index of the [`JoinRequest`].
pub const JOIN_REQUEST_INDEX: u8 = 1;
/// Slot index of the [`JoinResult`].
pub const JOIN_RESULT_INDEX: u8 = 2;

const MESSAGE_VERSION: u8 = 1;

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

    fn aad(slot_id: &[u8; 16], index: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(label::PAIRING.len() + 17);
        aad.extend_from_slice(label::PAIRING);
        aad.extend_from_slice(slot_id);
        aad.push(index);
        aad
    }

    /// Encrypt the message stored at `index` of the slot. Binding the index
    /// keeps a server from replaying one side's message as the other's.
    /// Output: nonce (24) || ciphertext.
    pub fn seal(&self, slot_id: &[u8; 16], index: u8, message: &[u8]) -> Result<Vec<u8>> {
        let nonce = random_bytes::<24>()?;
        let mut key = hkdf_sha256(&self.0, &[label::PAIRING]);
        let sealed = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: message,
                    aad: &Self::aad(slot_id, index),
                },
            )
            .map_err(|_| Error::Decrypt);
        key.zeroize();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed?);
        Ok(out)
    }

    pub fn open(&self, slot_id: &[u8; 16], index: u8, sealed: &[u8]) -> Result<Vec<u8>> {
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
                    aad: &Self::aad(slot_id, index),
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

/// Message 0: the group the new device is invited to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    /// The group's server, which may differ from the one holding the slot.
    pub server_url: String,
    pub group_id: [u8; 16],
    /// The chain head the existing device has verified. The new device
    /// refuses a chain that does not contain it.
    pub head_index: u64,
    pub head_hash: [u8; 32],
}

/// Message 1: the new device's keys, with its signature over
/// [`crate::device_binding_message`] for the invited group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    pub device: DeviceKeys,
    pub binding_signature: [u8; 64],
}

/// Message 2: what the existing device did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinResult {
    /// The `add_device` operation is at `index` of the chain.
    Added {
        index: u64,
    },
    Declined,
}

fn start(bytes: &[u8]) -> Result<Reader<'_>> {
    let mut reader = Reader(bytes);
    if reader.byte()? != MESSAGE_VERSION {
        return Err(Error::Malformed("unsupported pairing message version"));
    }
    Ok(reader)
}

fn finish(reader: &Reader<'_>) -> Result<()> {
    if reader.0.is_empty() {
        Ok(())
    } else {
        Err(Error::Malformed("trailing bytes after pairing message"))
    }
}

impl Invite {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(59 + self.server_url.len());
        out.push(MESSAGE_VERSION);
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.head_index.to_be_bytes());
        out.extend_from_slice(&self.head_hash);
        put_var(&mut out, self.server_url.as_bytes(), MAX_URL_BYTES)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = start(bytes)?;
        let invite = Self {
            group_id: reader.array()?,
            head_index: u64::from_be_bytes(reader.array()?),
            head_hash: reader.array()?,
            server_url: std::str::from_utf8(reader.var(MAX_URL_BYTES)?)
                .map_err(|_| Error::Malformed("server URL is not UTF-8"))?
                .to_owned(),
        };
        finish(&reader)?;
        Ok(invite)
    }
}

impl JoinRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(115 + self.device.kem_public_key.len());
        out.push(MESSAGE_VERSION);
        put_device(&mut out, &self.device)?;
        out.extend_from_slice(&self.binding_signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = start(bytes)?;
        let request = Self {
            device: reader.device()?,
            binding_signature: reader.array()?,
        };
        finish(&reader)?;
        Ok(request)
    }
}

impl JoinResult {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Added { index } => {
                let mut out = vec![MESSAGE_VERSION, 1];
                out.extend_from_slice(&index.to_be_bytes());
                out
            }
            Self::Declined => vec![MESSAGE_VERSION, 2],
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = start(bytes)?;
        let result = match reader.byte()? {
            1 => Self::Added {
                index: u64::from_be_bytes(reader.array()?),
            },
            2 => Self::Declined,
            _ => return Err(Error::Malformed("unknown pairing result")),
        };
        finish(&reader)?;
        Ok(result)
    }
}

/// Six words both devices show when a device is added with a short code
/// instead of a QR code.
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

    fn device() -> DeviceKeys {
        DeviceKeys {
            device_id: [1; 16],
            sign_public_key: [2; 32],
            kem_public_key: vec![3; 1216],
        }
    }

    #[test]
    fn messages_open_only_with_the_secret_slot_and_index() {
        let secret = PairingSecret::from_bytes([1; 32]);
        let sealed = secret.seal(&[2; 16], JOIN_REQUEST_INDEX, b"keys").unwrap();
        assert_eq!(
            secret.open(&[2; 16], JOIN_REQUEST_INDEX, &sealed).unwrap(),
            b"keys"
        );
        assert!(secret.open(&[2; 16], INVITE_INDEX, &sealed).is_err());
        assert!(secret.open(&[3; 16], JOIN_REQUEST_INDEX, &sealed).is_err());
        assert!(
            PairingSecret::from_bytes([9; 32])
                .open(&[2; 16], JOIN_REQUEST_INDEX, &sealed)
                .is_err()
        );
    }

    #[test]
    fn messages_round_trip_and_reject_garbage() {
        let invite = Invite {
            server_url: "https://sync.example.org".into(),
            group_id: [4; 16],
            head_index: 7,
            head_hash: [5; 32],
        };
        assert_eq!(Invite::decode(&invite.encode().unwrap()).unwrap(), invite);
        let request = JoinRequest {
            device: device(),
            binding_signature: [6; 64],
        };
        assert_eq!(
            JoinRequest::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        for result in [JoinResult::Added { index: 8 }, JoinResult::Declined] {
            assert_eq!(JoinResult::decode(&result.encode()).unwrap(), result);
        }

        let mut trailing = invite.encode().unwrap();
        trailing.push(0);
        assert!(Invite::decode(&trailing).is_err());
        let mut future = request.encode().unwrap();
        future[0] = 2;
        assert!(JoinRequest::decode(&future).is_err());
        assert!(JoinResult::decode(&[MESSAGE_VERSION, 9]).is_err());
    }

    #[test]
    fn decoding_damaged_messages_never_panics() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % below as u64) as usize
        };
        let invite = Invite {
            server_url: "https://sync.example.org".into(),
            group_id: [4; 16],
            head_index: 7,
            head_hash: [5; 32],
        }
        .encode()
        .unwrap();
        let request = JoinRequest {
            device: device(),
            binding_signature: [6; 64],
        }
        .encode()
        .unwrap();
        for _ in 0..20_000 {
            let mut bytes = if next(2) == 0 {
                invite.clone()
            } else {
                request.clone()
            };
            match next(3) {
                0 => bytes.truncate(next(bytes.len() + 1)),
                1 => bytes = (0..next(200)).map(|_| next(256) as u8).collect(),
                _ => {
                    let at = next(bytes.len());
                    bytes[at] = next(256) as u8;
                }
            }
            let _ = Invite::decode(&bytes);
            let _ = JoinRequest::decode(&bytes);
            let _ = JoinResult::decode(&bytes);
        }
    }

    #[test]
    fn approval_words_change_with_any_input() {
        let words = approval_words(&[4; 16], &[5; 32], &device());
        assert_eq!(words, approval_words(&[4; 16], &[5; 32], &device()));
        assert_ne!(words, approval_words(&[9; 16], &[5; 32], &device()));
        assert_ne!(words, approval_words(&[4; 16], &[9; 32], &device()));
        let swapped = DeviceKeys {
            sign_public_key: [9; 32],
            ..device()
        };
        assert_ne!(words, approval_words(&[4; 16], &[5; 32], &swapped));
    }
}
