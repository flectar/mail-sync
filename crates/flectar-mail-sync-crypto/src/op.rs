//! Signed membership operations (SPEC §5).
//!
//! Operations are signed over a canonical binary encoding, never over JSON,
//! so every implementation verifies exactly the bytes that were signed. Each
//! operation names the hash of the one before it, forming a chain the server
//! stores and every device verifies with [`crate::GroupState`].
//!
//! Operations are plaintext to the server, so they carry only identifiers,
//! public keys and commitments. Device names live in encrypted records.

use crate::keys::{DeviceSigningKey, SignPublicKey};
use crate::{Error, Result, label};
use sha2::{Digest, Sha256};

/// Largest accepted KEM public key. X-Wing public keys are 1216 bytes.
pub const MAX_KEM_PUBLIC_KEY_BYTES: usize = 4096;
/// Largest accepted server URL in a `move_server` operation.
pub const MAX_URL_BYTES: usize = 2048;
/// Largest accepted sealed previous root key.
pub const MAX_SEALED_ROOT_BYTES: usize = 256;
/// The identifier that stands for the recovery key wherever a device id is
/// expected: in logins, key wraps and authorizers.
pub const RECOVERY_ID: [u8; 16] = [0; 16];

const MAGIC: &[u8; 4] = b"FMSO";
const FORMAT_VERSION: u8 = 1;

/// Operation kinds. The numbers are part of the wire format.
mod kind {
    pub const GENESIS: u8 = 1;
    pub const ADD_DEVICE: u8 = 2;
    pub const REMOVE_DEVICE: u8 = 3;
    pub const ROTATE: u8 = 4;
    pub const RESET_RECOVERY: u8 = 5;
    pub const MOVE_SERVER: u8 = 6;
    pub const DELETE_GROUP: u8 = 7;
}

/// Who signed an operation other than the genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Authorizer {
    Device([u8; 16]),
    Recovery,
}

/// A device's public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    pub device_id: [u8; 16],
    pub sign_public_key: [u8; 32],
    /// Devices wrap root keys to it.
    pub kem_public_key: Vec<u8>,
}

/// The first operation of a group: its recovery public keys, first device
/// and first root key's commitment. Signed by the recovery key and the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub recovery_sign_public_key: [u8; 32],
    pub recovery_kem_public_key: Vec<u8>,
    pub device: DeviceKeys,
    /// [`crate::RootKey::commitment`] of epoch 1.
    pub root_commitment: [u8; 32],
}

/// Add a device. `binding_signature` is the new device's signature over
/// [`device_binding_message`], proving it holds its private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddDevice {
    pub authorizer: Authorizer,
    pub device: DeviceKeys,
    pub binding_signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveDevice {
    pub authorizer: Authorizer,
    pub device_id: [u8; 16],
}

/// Start epoch `epoch` with a new root key. The previous root key travels
/// sealed under the new one, so any current device can still read records
/// of older epochs without re-encrypting them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotate {
    pub authorizer: Authorizer,
    pub epoch: u64,
    pub root_commitment: [u8; 32],
    pub sealed_previous_root: Vec<u8>,
}

/// Replace the recovery keys with those of a new recovery code.
/// `binding_signature` is the new recovery key's signature over
/// [`recovery_binding_message`], so no device can point recovery at a key it
/// does not hold, such as another group's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetRecovery {
    pub authorizer: Authorizer,
    pub recovery_sign_public_key: [u8; 32],
    pub recovery_kem_public_key: Vec<u8>,
    pub binding_signature: [u8; 64],
}

/// The group moves to the server at `url`; devices follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveServer {
    pub authorizer: Authorizer,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteGroup {
    pub authorizer: Authorizer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    Genesis(Genesis),
    AddDevice(AddDevice),
    RemoveDevice(RemoveDevice),
    Rotate(Rotate),
    ResetRecovery(ResetRecovery),
    MoveServer(MoveServer),
    DeleteGroup(DeleteGroup),
}

impl OpKind {
    fn code(&self) -> u8 {
        match self {
            Self::Genesis(_) => kind::GENESIS,
            Self::AddDevice(_) => kind::ADD_DEVICE,
            Self::RemoveDevice(_) => kind::REMOVE_DEVICE,
            Self::Rotate(_) => kind::ROTATE,
            Self::ResetRecovery(_) => kind::RESET_RECOVERY,
            Self::MoveServer(_) => kind::MOVE_SERVER,
            Self::DeleteGroup(_) => kind::DELETE_GROUP,
        }
    }

    /// The signer of any operation but the genesis.
    pub fn authorizer(&self) -> Option<Authorizer> {
        match self {
            Self::Genesis(_) => None,
            Self::AddDevice(op) => Some(op.authorizer),
            Self::RemoveDevice(op) => Some(op.authorizer),
            Self::Rotate(op) => Some(op.authorizer),
            Self::ResetRecovery(op) => Some(op.authorizer),
            Self::MoveServer(op) => Some(op.authorizer),
            Self::DeleteGroup(op) => Some(op.authorizer),
        }
    }
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
        out.push(self.kind.code());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        match &self.kind {
            OpKind::Genesis(op) => {
                out.extend_from_slice(&op.recovery_sign_public_key);
                put_var(
                    &mut out,
                    &op.recovery_kem_public_key,
                    MAX_KEM_PUBLIC_KEY_BYTES,
                )?;
                put_device(&mut out, &op.device)?;
                out.extend_from_slice(&op.root_commitment);
            }
            OpKind::AddDevice(op) => {
                put_authorizer(&mut out, op.authorizer);
                put_device(&mut out, &op.device)?;
                out.extend_from_slice(&op.binding_signature);
            }
            OpKind::RemoveDevice(op) => {
                put_authorizer(&mut out, op.authorizer);
                out.extend_from_slice(&op.device_id);
            }
            OpKind::Rotate(op) => {
                put_authorizer(&mut out, op.authorizer);
                out.extend_from_slice(&op.epoch.to_be_bytes());
                out.extend_from_slice(&op.root_commitment);
                put_var(&mut out, &op.sealed_previous_root, MAX_SEALED_ROOT_BYTES)?;
            }
            OpKind::ResetRecovery(op) => {
                put_authorizer(&mut out, op.authorizer);
                out.extend_from_slice(&op.recovery_sign_public_key);
                put_var(
                    &mut out,
                    &op.recovery_kem_public_key,
                    MAX_KEM_PUBLIC_KEY_BYTES,
                )?;
                out.extend_from_slice(&op.binding_signature);
            }
            OpKind::MoveServer(op) => {
                put_authorizer(&mut out, op.authorizer);
                put_var(&mut out, op.url.as_bytes(), MAX_URL_BYTES)?;
            }
            OpKind::DeleteGroup(op) => put_authorizer(&mut out, op.authorizer),
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
                root_commitment: reader.array()?,
            }),
            kind::ADD_DEVICE => OpKind::AddDevice(AddDevice {
                authorizer: reader.authorizer()?,
                device: reader.device()?,
                binding_signature: reader.array()?,
            }),
            kind::REMOVE_DEVICE => OpKind::RemoveDevice(RemoveDevice {
                authorizer: reader.authorizer()?,
                device_id: reader.array()?,
            }),
            kind::ROTATE => OpKind::Rotate(Rotate {
                authorizer: reader.authorizer()?,
                epoch: u64::from_be_bytes(reader.array()?),
                root_commitment: reader.array()?,
                sealed_previous_root: reader.var(MAX_SEALED_ROOT_BYTES)?.to_vec(),
            }),
            kind::RESET_RECOVERY => OpKind::ResetRecovery(ResetRecovery {
                authorizer: reader.authorizer()?,
                recovery_sign_public_key: reader.array()?,
                recovery_kem_public_key: reader.var(MAX_KEM_PUBLIC_KEY_BYTES)?.to_vec(),
                binding_signature: reader.array()?,
            }),
            kind::MOVE_SERVER => OpKind::MoveServer(MoveServer {
                authorizer: reader.authorizer()?,
                url: std::str::from_utf8(reader.var(MAX_URL_BYTES)?)
                    .map_err(|_| Error::Malformed("server URL is not UTF-8"))?
                    .to_owned(),
            }),
            kind::DELETE_GROUP => OpKind::DeleteGroup(DeleteGroup {
                authorizer: reader.authorizer()?,
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

/// The statement a new device signs to prove it holds the keys an
/// `add_device` operation names.
pub fn device_binding_message(group_id: &[u8; 16], device: &DeviceKeys) -> Result<Vec<u8>> {
    let mut message =
        Vec::with_capacity(label::DEVICE_BINDING.len() + 66 + device.kem_public_key.len());
    message.extend_from_slice(label::DEVICE_BINDING);
    message.extend_from_slice(group_id);
    put_device(&mut message, device)?;
    Ok(message)
}

/// The statement a new recovery key signs to prove it is held by whoever
/// resets recovery to it.
pub fn recovery_binding_message(
    group_id: &[u8; 16],
    recovery_sign_public_key: &[u8; 32],
    recovery_kem_public_key: &[u8],
) -> Result<Vec<u8>> {
    let mut message =
        Vec::with_capacity(label::RECOVERY_BINDING.len() + 50 + recovery_kem_public_key.len());
    message.extend_from_slice(label::RECOVERY_BINDING);
    message.extend_from_slice(group_id);
    message.extend_from_slice(recovery_sign_public_key);
    put_var(
        &mut message,
        recovery_kem_public_key,
        MAX_KEM_PUBLIC_KEY_BYTES,
    )?;
    Ok(message)
}

pub(crate) fn put_var(out: &mut Vec<u8>, value: &[u8], max: usize) -> Result<()> {
    if value.len() > max {
        return Err(Error::Malformed("field is longer than allowed"));
    }
    let len = u16::try_from(value.len()).map_err(|_| Error::Malformed("field is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

pub(crate) fn put_device(out: &mut Vec<u8>, device: &DeviceKeys) -> Result<()> {
    out.extend_from_slice(&device.device_id);
    out.extend_from_slice(&device.sign_public_key);
    put_var(out, &device.kem_public_key, MAX_KEM_PUBLIC_KEY_BYTES)
}

fn put_authorizer(out: &mut Vec<u8>, authorizer: Authorizer) {
    match authorizer {
        Authorizer::Device(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        Authorizer::Recovery => {
            out.push(2);
            out.extend_from_slice(&RECOVERY_ID);
        }
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub(crate) fn var(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        if len > max {
            return Err(Error::Malformed("field is longer than allowed"));
        }
        self.take(len)
    }

    pub(crate) fn device(&mut self) -> Result<DeviceKeys> {
        Ok(DeviceKeys {
            device_id: self.array()?,
            sign_public_key: self.array()?,
            kem_public_key: self.var(MAX_KEM_PUBLIC_KEY_BYTES)?.to_vec(),
        })
    }

    fn authorizer(&mut self) -> Result<Authorizer> {
        let tag = self.byte()?;
        let id = self.array::<16>()?;
        match (tag, id) {
            (1, id) if id != RECOVERY_ID => Ok(Authorizer::Device(id)),
            (2, RECOVERY_ID) => Ok(Authorizer::Recovery),
            _ => Err(Error::Malformed("invalid authorizer")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_keys(id: u8) -> DeviceKeys {
        DeviceKeys {
            device_id: [id; 16],
            sign_public_key: [id; 32],
            kem_public_key: vec![id; 1216],
        }
    }

    fn header(kind: OpKind) -> Op {
        Op {
            group_id: [1; 16],
            index: 3,
            prev_hash: [9; 32],
            created_at_ms: 1_762_400_000_000,
            kind,
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let kinds = [
            OpKind::Genesis(Genesis {
                recovery_sign_public_key: [2; 32],
                recovery_kem_public_key: vec![3; 1216],
                device: device_keys(4),
                root_commitment: [5; 32],
            }),
            OpKind::AddDevice(AddDevice {
                authorizer: Authorizer::Device([4; 16]),
                device: device_keys(6),
                binding_signature: [7; 64],
            }),
            OpKind::RemoveDevice(RemoveDevice {
                authorizer: Authorizer::Recovery,
                device_id: [6; 16],
            }),
            OpKind::Rotate(Rotate {
                authorizer: Authorizer::Device([4; 16]),
                epoch: 2,
                root_commitment: [8; 32],
                sealed_previous_root: vec![9; 72],
            }),
            OpKind::ResetRecovery(ResetRecovery {
                authorizer: Authorizer::Device([4; 16]),
                recovery_sign_public_key: [10; 32],
                recovery_kem_public_key: vec![11; 1216],
                binding_signature: [12; 64],
            }),
            OpKind::MoveServer(MoveServer {
                authorizer: Authorizer::Device([4; 16]),
                url: "https://sync.example.org".into(),
            }),
            OpKind::DeleteGroup(DeleteGroup {
                authorizer: Authorizer::Recovery,
            }),
        ];
        for kind in kinds {
            let op = header(kind);
            assert_eq!(Op::decode(&op.encode().unwrap()).unwrap(), op);
        }
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let op = header(OpKind::RemoveDevice(RemoveDevice {
            authorizer: Authorizer::Device([4; 16]),
            device_id: [6; 16],
        }));
        let bytes = op.encode().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Op::decode(&trailing).is_err());
        assert!(Op::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut unknown = bytes.clone();
        unknown[5] = 99;
        assert!(Op::decode(&unknown).is_err());
        // An authorizer naming the recovery id as a device is invalid.
        let mut bad_authorizer = bytes.clone();
        let at = 4 + 1 + 1 + 16 + 8 + 32 + 8;
        bad_authorizer[at + 1..at + 17].copy_from_slice(&RECOVERY_ID);
        assert!(Op::decode(&bad_authorizer).is_err());
        let long_url = header(OpKind::MoveServer(MoveServer {
            authorizer: Authorizer::Recovery,
            url: "x".repeat(MAX_URL_BYTES + 1),
        }));
        assert!(long_url.encode().is_err());
    }

    /// Decoding untrusted bytes returns an error, never panics: random
    /// bytes, and valid encodings with bytes changed, cut or added.
    #[test]
    fn decoding_damaged_input_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % below as u64) as usize
        };
        let valid: Vec<Vec<u8>> = [
            OpKind::Genesis(Genesis {
                recovery_sign_public_key: [2; 32],
                recovery_kem_public_key: vec![3; 40],
                device: device_keys(4),
                root_commitment: [5; 32],
            }),
            OpKind::ResetRecovery(ResetRecovery {
                authorizer: Authorizer::Recovery,
                recovery_sign_public_key: [10; 32],
                recovery_kem_public_key: vec![11; 40],
                binding_signature: [12; 64],
            }),
            OpKind::MoveServer(MoveServer {
                authorizer: Authorizer::Device([4; 16]),
                url: "https://sync.example.org".into(),
            }),
        ]
        .into_iter()
        .map(|kind| header(kind).encode().unwrap())
        .collect();
        for _ in 0..20_000 {
            let mut bytes = valid[next(valid.len())].clone();
            match next(4) {
                0 => bytes = (0..next(300)).map(|_| next(256) as u8).collect(),
                1 => bytes.truncate(next(bytes.len() + 1)),
                2 => bytes.extend((0..next(8)).map(|_| next(256) as u8)),
                _ => {
                    for _ in 0..1 + next(4) {
                        let at = next(bytes.len());
                        bytes[at] = next(256) as u8;
                    }
                }
            }
            let _ = Op::decode(&bytes);
        }
    }

    #[test]
    fn signatures_and_hashes_cover_every_byte() {
        let key = DeviceSigningKey::from_seed(&[5; 32]);
        let bytes = header(OpKind::DeleteGroup(DeleteGroup {
            authorizer: Authorizer::Device([4; 16]),
        }))
        .encode()
        .unwrap();
        let signature = sign_op(&key, &bytes);
        verify_op(&bytes, &key.public_key(), &signature).unwrap();
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_op(&tampered, &key.public_key(), &signature).is_err());
        assert_ne!(op_hash(&bytes), op_hash(&tampered));
    }
}
