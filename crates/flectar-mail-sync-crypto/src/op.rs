//! Signed membership operations (SPEC §5).
//!
//! Operations are signed over a canonical binary encoding, never over JSON,
//! so every implementation verifies exactly the bytes that were signed. Each
//! operation names the hash of the one before it, forming a chain the server
//! stores and every device verifies.

use crate::keys::{DeviceSigningKey, SignPublicKey};
use crate::{Error, Result, label};
use sha2::{Digest, Sha256};

/// Largest accepted KEM public key. X-Wing public keys are 1216 bytes.
pub const MAX_KEM_PUBLIC_KEY_BYTES: usize = 4096;
/// Largest accepted device name, in UTF-8 bytes.
pub const MAX_DEVICE_NAME_BYTES: usize = 64;

const MAGIC: &[u8; 4] = b"FMSO";
const FORMAT_VERSION: u8 = 1;

/// Operation kinds. The numbers are part of the wire format.
mod kind {
    pub const GENESIS: u8 = 1;
}

/// A device's public keys and display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    pub device_id: [u8; 16],
    pub sign_public_key: [u8; 32],
    /// Opaque to the server; devices wrap root keys to it.
    pub kem_public_key: Vec<u8>,
    pub name: String,
}

/// The first operation of a group: its recovery public keys and first
/// device. Signed by both the recovery key and the device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub recovery_sign_public_key: [u8; 32],
    /// Opaque to the server; devices wrap root keys to it for recovery.
    pub recovery_kem_public_key: Vec<u8>,
    pub device: DeviceKeys,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    Genesis(Genesis),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub group_id: [u8; 16],
    /// Position in the group's chain, starting at 0.
    pub index: u64,
    /// [`op_hash`] of the previous operation; all zeros for the genesis.
    pub prev_hash: [u8; 32],
    /// Milliseconds since the Unix epoch, as claimed by the signer.
    pub created_at_ms: u64,
    pub kind: OpKind,
}

impl Op {
    /// The canonical encoding that signatures and hashes cover.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        match &self.kind {
            OpKind::Genesis(_) => out.push(kind::GENESIS),
        }
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        match &self.kind {
            OpKind::Genesis(genesis) => {
                out.extend_from_slice(&genesis.recovery_sign_public_key);
                put_var(
                    &mut out,
                    &genesis.recovery_kem_public_key,
                    MAX_KEM_PUBLIC_KEY_BYTES,
                )?;
                put_device(&mut out, &genesis.device)?;
            }
        }
        Ok(out)
    }

    /// Parse a canonical encoding. Rejects unknown kinds and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        if reader.take(4)? != MAGIC {
            return Err(Error::Malformed("not a membership operation"));
        }
        if reader.byte()? != FORMAT_VERSION {
            return Err(Error::Malformed("unsupported operation format"));
        }
        let kind_code = reader.byte()?;
        let group_id = reader.array::<16>()?;
        let index = u64::from_be_bytes(reader.array()?);
        let prev_hash = reader.array::<32>()?;
        let created_at_ms = u64::from_be_bytes(reader.array()?);
        let kind = match kind_code {
            kind::GENESIS => OpKind::Genesis(Genesis {
                recovery_sign_public_key: reader.array()?,
                recovery_kem_public_key: reader.var(MAX_KEM_PUBLIC_KEY_BYTES)?.to_vec(),
                device: reader.device()?,
            }),
            _ => return Err(Error::Malformed("unknown operation kind")),
        };
        if !reader.0.is_empty() {
            return Err(Error::Malformed("trailing bytes after operation"));
        }
        Ok(Self {
            group_id,
            index,
            prev_hash,
            created_at_ms,
            kind,
        })
    }

    /// Decode a genesis operation and check both of its signatures: the
    /// recovery key's first, then the device's. Returns the operation.
    pub fn verify_genesis(bytes: &[u8], signatures: &[&[u8]]) -> Result<Self> {
        let op = Self::decode(bytes)?;
        let OpKind::Genesis(genesis) = &op.kind;
        if op.index != 0 || op.prev_hash != [0; 32] {
            return Err(Error::Malformed("a genesis operation starts the chain"));
        }
        let [recovery_signature, device_signature] = signatures else {
            return Err(Error::Malformed(
                "a genesis operation carries two signatures",
            ));
        };
        verify_op(
            bytes,
            &SignPublicKey::from_bytes(&genesis.recovery_sign_public_key)?,
            recovery_signature,
        )?;
        verify_op(
            bytes,
            &SignPublicKey::from_bytes(&genesis.device.sign_public_key)?,
            device_signature,
        )?;
        Ok(op)
    }
}

/// SHA-256 of an operation's canonical encoding, domain-separated.
pub fn op_hash(op_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label::OP_HASH);
    hasher.update(op_bytes);
    hasher.finalize().into()
}

/// Sign an operation's canonical encoding.
pub fn sign_op(key: &DeviceSigningKey, op_bytes: &[u8]) -> [u8; 64] {
    key.sign(&signed_bytes(op_bytes))
}

/// Verify one signature over an operation's canonical encoding.
pub fn verify_op(op_bytes: &[u8], key: &SignPublicKey, signature: &[u8]) -> Result<()> {
    key.verify(&signed_bytes(op_bytes), signature)
}

fn signed_bytes(op_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(label::OP_SIGNATURE.len() + op_bytes.len());
    message.extend_from_slice(label::OP_SIGNATURE);
    message.extend_from_slice(op_bytes);
    message
}

fn put_var(out: &mut Vec<u8>, value: &[u8], max: usize) -> Result<()> {
    if value.len() > max {
        return Err(Error::Malformed("field is longer than allowed"));
    }
    let len = u16::try_from(value.len()).map_err(|_| Error::Malformed("field is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn put_device(out: &mut Vec<u8>, device: &DeviceKeys) -> Result<()> {
    out.extend_from_slice(&device.device_id);
    out.extend_from_slice(&device.sign_public_key);
    put_var(out, &device.kem_public_key, MAX_KEM_PUBLIC_KEY_BYTES)?;
    put_var(out, device.name.as_bytes(), MAX_DEVICE_NAME_BYTES)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("operation is truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    fn var(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        if len > max {
            return Err(Error::Malformed("field is longer than allowed"));
        }
        self.take(len)
    }

    fn device(&mut self) -> Result<DeviceKeys> {
        let device_id = self.array()?;
        let sign_public_key = self.array()?;
        let kem_public_key = self.var(MAX_KEM_PUBLIC_KEY_BYTES)?.to_vec();
        let name = std::str::from_utf8(self.var(MAX_DEVICE_NAME_BYTES)?)
            .map_err(|_| Error::Malformed("device name is not UTF-8"))?
            .to_owned();
        Ok(DeviceKeys {
            device_id,
            sign_public_key,
            kem_public_key,
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecoveryCode;

    fn genesis(recovery: &DeviceSigningKey, device: &DeviceSigningKey) -> Op {
        Op {
            group_id: [1; 16],
            index: 0,
            prev_hash: [0; 32],
            created_at_ms: 1_762_400_000_000,
            kind: OpKind::Genesis(Genesis {
                recovery_sign_public_key: recovery.public_key().to_bytes(),
                recovery_kem_public_key: vec![7; 1216],
                device: DeviceKeys {
                    device_id: [2; 16],
                    sign_public_key: device.public_key().to_bytes(),
                    kem_public_key: vec![8; 1216],
                    name: "Laptop".into(),
                },
            }),
        }
    }

    #[test]
    fn genesis_round_trips_and_verifies() {
        let recovery = RecoveryCode::from_bytes([4; 32]).signing_key();
        let device = DeviceSigningKey::from_seed(&[5; 32]);
        let op = genesis(&recovery, &device);
        let bytes = op.encode().unwrap();
        assert_eq!(Op::decode(&bytes).unwrap(), op);
        let signatures = [sign_op(&recovery, &bytes), sign_op(&device, &bytes)];
        let verified = Op::verify_genesis(&bytes, &[&signatures[0], &signatures[1]]).unwrap();
        assert_eq!(verified, op);
    }

    #[test]
    fn genesis_needs_both_signatures_in_order() {
        let recovery = RecoveryCode::from_bytes([4; 32]).signing_key();
        let device = DeviceSigningKey::from_seed(&[5; 32]);
        let bytes = genesis(&recovery, &device).encode().unwrap();
        let by_recovery = sign_op(&recovery, &bytes);
        let by_device = sign_op(&device, &bytes);
        assert!(Op::verify_genesis(&bytes, &[&by_device, &by_recovery]).is_err());
        assert!(Op::verify_genesis(&bytes, &[&by_recovery]).is_err());
        assert!(Op::verify_genesis(&bytes, &[&by_recovery, &by_recovery]).is_err());
    }

    #[test]
    fn any_change_to_the_bytes_breaks_signatures_and_hash() {
        let recovery = RecoveryCode::from_bytes([4; 32]).signing_key();
        let device = DeviceSigningKey::from_seed(&[5; 32]);
        let bytes = genesis(&recovery, &device).encode().unwrap();
        let signature = sign_op(&device, &bytes);
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_op(&tampered, &device.public_key(), &signature).is_err());
        assert_ne!(op_hash(&bytes), op_hash(&tampered));
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let recovery = RecoveryCode::from_bytes([4; 32]).signing_key();
        let device = DeviceSigningKey::from_seed(&[5; 32]);
        let bytes = genesis(&recovery, &device).encode().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Op::decode(&trailing).is_err());
        assert!(Op::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut unknown = bytes.clone();
        unknown[5] = 99;
        assert!(Op::decode(&unknown).is_err());
        let mut long_name = genesis(&recovery, &device);
        let OpKind::Genesis(g) = &mut long_name.kind;
        g.device.name = "x".repeat(MAX_DEVICE_NAME_BYTES + 1);
        assert!(long_name.encode().is_err());
    }
}
