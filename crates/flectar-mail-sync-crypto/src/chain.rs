//! The membership state machine (SPEC §5.4). The server and every device
//! replay a group's signed operations through the same rules, so they agree
//! on which keys may act for the group.

use crate::keys::SignPublicKey;
use crate::op::{
    Authorizer, OpKind, RECOVERY_ID, device_binding_message, op_hash, recovery_binding_message,
    verify_op,
};
use crate::{Error, Op, Result};
use std::collections::{BTreeMap, BTreeSet};

/// A device that currently belongs to the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub sign_public_key: [u8; 32],
    pub kem_public_key: Vec<u8>,
}

/// Everything the chain decides, after its last verified operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupState {
    pub group_id: [u8; 16],
    /// Index and hash of the last applied operation.
    pub head_index: u64,
    pub head_hash: [u8; 32],
    pub devices: BTreeMap<[u8; 16], Member>,
    /// Devices once in the group. Their ids are never accepted again.
    pub removed: BTreeSet<[u8; 16]>,
    pub recovery_sign_public_key: [u8; 32],
    pub recovery_kem_public_key: Vec<u8>,
    pub epoch: u64,
    /// Commitment to the current epoch's root key.
    pub root_commitment: [u8; 32],
    /// Sealed previous root key of each epoch above 1, by epoch.
    pub sealed_previous_roots: BTreeMap<u64, Vec<u8>>,
    /// Set by a `move_server` operation.
    pub server_url: Option<String>,
    /// A device was removed or recovery was reset since the last rotation,
    /// so a member should rotate the root key. Any device that sees this
    /// does; the chain's compare-and-set lets only one succeed.
    pub rotation_due: bool,
    pub deleted: bool,
}

impl GroupState {
    /// Start a chain from its genesis operation, checking both signatures:
    /// the recovery key's first, then the device's.
    pub fn from_genesis(op_bytes: &[u8], signatures: &[&[u8]]) -> Result<(Self, Op)> {
        let op = Op::decode(op_bytes)?;
        let OpKind::Genesis(genesis) = &op.kind else {
            return Err(Error::Malformed("the chain does not start with a genesis"));
        };
        if op.index != 0 || op.prev_hash != [0; 32] {
            return Err(Error::Malformed("a genesis operation starts the chain"));
        }
        if genesis.device.device_id == RECOVERY_ID {
            return Err(Error::Malformed("the device id is reserved for recovery"));
        }
        let [recovery_signature, device_signature] = signatures else {
            return Err(Error::Malformed(
                "a genesis operation carries two signatures",
            ));
        };
        verify_op(
            op_bytes,
            &SignPublicKey::from_bytes(&genesis.recovery_sign_public_key)?,
            recovery_signature,
        )?;
        verify_op(
            op_bytes,
            &SignPublicKey::from_bytes(&genesis.device.sign_public_key)?,
            device_signature,
        )?;
        let mut devices = BTreeMap::new();
        devices.insert(
            genesis.device.device_id,
            Member {
                sign_public_key: genesis.device.sign_public_key,
                kem_public_key: genesis.device.kem_public_key.clone(),
            },
        );
        let state = Self {
            group_id: op.group_id,
            head_index: 0,
            head_hash: op_hash(op_bytes),
            devices,
            removed: BTreeSet::new(),
            recovery_sign_public_key: genesis.recovery_sign_public_key,
            recovery_kem_public_key: genesis.recovery_kem_public_key.clone(),
            epoch: 1,
            root_commitment: genesis.root_commitment,
            sealed_previous_roots: BTreeMap::new(),
            server_url: None,
            rotation_due: false,
            deleted: false,
        };
        Ok((state, op))
    }

    /// Replay a whole chain, oldest operation first.
    pub fn replay<'a>(chain: impl IntoIterator<Item = (&'a [u8], Vec<&'a [u8]>)>) -> Result<Self> {
        let mut chain = chain.into_iter();
        let (genesis, signatures) = chain.next().ok_or(Error::Malformed("the chain is empty"))?;
        let (mut state, _) = Self::from_genesis(genesis, &signatures)?;
        for (op, signatures) in chain {
            state.apply(op, &signatures)?;
        }
        Ok(state)
    }

    /// The public key that signs for `authorizer`, if it may act now.
    pub fn authorizer_key(&self, authorizer: Authorizer) -> Result<SignPublicKey> {
        let key = match authorizer {
            Authorizer::Recovery => self.recovery_sign_public_key,
            Authorizer::Device(id) => {
                self.devices
                    .get(&id)
                    .ok_or(Error::Malformed("the signer is not a device of the group"))?
                    .sign_public_key
            }
        };
        SignPublicKey::from_bytes(&key)
    }

    /// Verify the next operation and apply it. On error the state is
    /// unchanged.
    pub fn apply(&mut self, op_bytes: &[u8], signatures: &[&[u8]]) -> Result<Op> {
        if self.deleted {
            return Err(Error::Malformed("the group was deleted"));
        }
        let op = Op::decode(op_bytes)?;
        if op.group_id != self.group_id {
            return Err(Error::Malformed("the operation belongs to another group"));
        }
        if op.index != self.head_index + 1 || op.prev_hash != self.head_hash {
            return Err(Error::Malformed("the operation does not extend the chain"));
        }
        let authorizer = op
            .kind
            .authorizer()
            .ok_or(Error::Malformed("a chain has only one genesis"))?;
        let [signature] = signatures else {
            return Err(Error::Malformed("the operation carries one signature"));
        };
        verify_op(op_bytes, &self.authorizer_key(authorizer)?, signature)?;

        let mut next = self.clone();
        match &op.kind {
            OpKind::Genesis(_) => unreachable!("rejected above: no authorizer"),
            OpKind::AddDevice(add) => {
                let id = add.device.device_id;
                if id == RECOVERY_ID || next.devices.contains_key(&id) || next.removed.contains(&id)
                {
                    return Err(Error::Malformed("the device id is taken"));
                }
                SignPublicKey::from_bytes(&add.device.sign_public_key)?.verify(
                    &device_binding_message(&self.group_id, &add.device)?,
                    &add.binding_signature,
                )?;
                next.devices.insert(
                    id,
                    Member {
                        sign_public_key: add.device.sign_public_key,
                        kem_public_key: add.device.kem_public_key.clone(),
                    },
                );
            }
            OpKind::RemoveDevice(remove) => {
                if next.devices.remove(&remove.device_id).is_none() {
                    return Err(Error::Malformed("the device is not in the group"));
                }
                next.removed.insert(remove.device_id);
                next.rotation_due = true;
            }
            OpKind::Rotate(rotate) => {
                if rotate.epoch != next.epoch + 1 {
                    return Err(Error::Malformed("a rotation starts the next epoch"));
                }
                if rotate.sealed_previous_root.is_empty() {
                    return Err(Error::Malformed("a rotation carries the previous root key"));
                }
                next.epoch = rotate.epoch;
                next.root_commitment = rotate.root_commitment;
                next.sealed_previous_roots
                    .insert(rotate.epoch, rotate.sealed_previous_root.clone());
                next.rotation_due = false;
            }
            OpKind::ResetRecovery(reset) => {
                SignPublicKey::from_bytes(&reset.recovery_sign_public_key)?.verify(
                    &recovery_binding_message(
                        &self.group_id,
                        &reset.recovery_sign_public_key,
                        &reset.recovery_kem_public_key,
                    )?,
                    &reset.binding_signature,
                )?;
                next.recovery_sign_public_key = reset.recovery_sign_public_key;
                next.recovery_kem_public_key = reset.recovery_kem_public_key.clone();
                next.rotation_due = true;
            }
            OpKind::MoveServer(moved) => {
                let url = moved.url.as_str();
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(Error::Malformed("the server URL must be http(s)"));
                }
                next.server_url = Some(moved.url.clone());
            }
            OpKind::DeleteGroup(_) => next.deleted = true,
        }
        next.head_index = op.index;
        next.head_hash = op_hash(op_bytes);
        *self = next;
        Ok(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::{
        AddDevice, DeleteGroup, DeviceKeys, Genesis, MoveServer, RemoveDevice, ResetRecovery,
        Rotate,
    };
    use crate::{DeviceSigningKey, RecoveryCode, sign_op};

    struct Chain {
        state: GroupState,
        ops: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    }

    fn device(id: u8) -> (DeviceSigningKey, DeviceKeys) {
        let key = DeviceSigningKey::from_seed(&[id; 32]);
        let keys = DeviceKeys {
            device_id: [id; 16],
            sign_public_key: key.public_key().to_bytes(),
            kem_public_key: vec![id; 32],
        };
        (key, keys)
    }

    fn start(
        recovery: &DeviceSigningKey,
        first: &DeviceSigningKey,
        first_keys: DeviceKeys,
    ) -> Chain {
        let op = Op {
            group_id: [1; 16],
            index: 0,
            prev_hash: [0; 32],
            created_at_ms: 0,
            kind: OpKind::Genesis(Genesis {
                recovery_sign_public_key: recovery.public_key().to_bytes(),
                recovery_kem_public_key: vec![0; 32],
                device: first_keys,
                root_commitment: [7; 32],
            }),
        };
        let bytes = op.encode().unwrap();
        let signatures = vec![
            sign_op(recovery, &bytes).to_vec(),
            sign_op(first, &bytes).to_vec(),
        ];
        let refs: Vec<&[u8]> = signatures.iter().map(Vec::as_slice).collect();
        let (state, _) = GroupState::from_genesis(&bytes, &refs).unwrap();
        Chain {
            state,
            ops: vec![(bytes, signatures)],
        }
    }

    impl Chain {
        fn next(&self, kind: OpKind) -> Op {
            Op {
                group_id: self.state.group_id,
                index: self.state.head_index + 1,
                prev_hash: self.state.head_hash,
                created_at_ms: 0,
                kind,
            }
        }

        fn push(&mut self, signer: &DeviceSigningKey, kind: OpKind) -> Result<()> {
            let bytes = self.next(kind).encode()?;
            let signature = sign_op(signer, &bytes);
            self.state.apply(&bytes, &[&signature])?;
            self.ops.push((bytes, vec![signature.to_vec()]));
            Ok(())
        }
    }

    fn add(
        chain: &Chain,
        authorizer: Authorizer,
        key: &DeviceSigningKey,
        keys: DeviceKeys,
    ) -> OpKind {
        let binding = key.sign(&device_binding_message(&chain.state.group_id, &keys).unwrap());
        OpKind::AddDevice(AddDevice {
            authorizer,
            device: keys,
            binding_signature: binding,
        })
    }

    fn reset(chain: &Chain, authorizer: Authorizer, new: &DeviceSigningKey) -> OpKind {
        let sign_public_key = new.public_key().to_bytes();
        let kem_public_key = vec![2; 32];
        let binding = new.sign(
            &recovery_binding_message(&chain.state.group_id, &sign_public_key, &kem_public_key)
                .unwrap(),
        );
        OpKind::ResetRecovery(ResetRecovery {
            authorizer,
            recovery_sign_public_key: sign_public_key,
            recovery_kem_public_key: kem_public_key,
            binding_signature: binding,
        })
    }

    #[test]
    fn a_full_lifecycle_replays_to_the_same_state() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let (phone, phone_keys) = device(20);
        let mut chain = start(&recovery, &laptop, laptop_keys);

        let kind = add(&chain, Authorizer::Device([10; 16]), &phone, phone_keys);
        chain.push(&laptop, kind).unwrap();
        assert_eq!(chain.state.devices.len(), 2);
        assert!(!chain.state.rotation_due);

        chain
            .push(
                &phone,
                OpKind::RemoveDevice(RemoveDevice {
                    authorizer: Authorizer::Device([20; 16]),
                    device_id: [10; 16],
                }),
            )
            .unwrap();
        assert!(chain.state.rotation_due, "a removal calls for a new key");
        chain
            .push(
                &phone,
                OpKind::Rotate(Rotate {
                    authorizer: Authorizer::Device([20; 16]),
                    epoch: 2,
                    root_commitment: [8; 32],
                    sealed_previous_root: vec![1; 72],
                }),
            )
            .unwrap();
        assert!(!chain.state.rotation_due);
        let new_recovery = RecoveryCode::from_bytes([4; 32]).signing_key();
        let kind = reset(&chain, Authorizer::Device([20; 16]), &new_recovery);
        chain.push(&phone, kind).unwrap();
        assert!(chain.state.rotation_due, "so does a new recovery code");
        chain
            .push(
                &new_recovery,
                OpKind::MoveServer(MoveServer {
                    authorizer: Authorizer::Recovery,
                    url: "https://sync.example.org".into(),
                }),
            )
            .unwrap();

        let state = &chain.state;
        assert_eq!(state.devices.keys().collect::<Vec<_>>(), vec![&[20; 16]]);
        assert!(state.removed.contains(&[10; 16]));
        assert_eq!(state.epoch, 2);
        assert_eq!(state.root_commitment, [8; 32]);
        assert_eq!(state.sealed_previous_roots.get(&2), Some(&vec![1; 72]));
        assert_eq!(
            state.recovery_sign_public_key,
            new_recovery.public_key().to_bytes()
        );
        assert_eq!(
            state.server_url.as_deref(),
            Some("https://sync.example.org")
        );
        assert_eq!(state.head_index, 5);

        let replayed = GroupState::replay(chain.ops.iter().map(|(op, signatures)| {
            (
                op.as_slice(),
                signatures.iter().map(Vec::as_slice).collect(),
            )
        }))
        .unwrap();
        assert_eq!(&replayed, state);

        chain
            .push(
                &phone,
                OpKind::DeleteGroup(DeleteGroup {
                    authorizer: Authorizer::Device([20; 16]),
                }),
            )
            .unwrap();
        assert!(chain.state.deleted);
        assert!(
            chain
                .push(
                    &phone,
                    OpKind::DeleteGroup(DeleteGroup {
                        authorizer: Authorizer::Device([20; 16]),
                    }),
                )
                .is_err(),
            "nothing follows a deletion"
        );
    }

    #[test]
    fn only_current_members_and_recovery_may_sign() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let (phone, phone_keys) = device(20);
        let mut chain = start(&recovery, &laptop, laptop_keys);
        let before = chain.state.clone();

        // A stranger claiming to be the laptop.
        let stranger = DeviceSigningKey::from_seed(&[99; 32]);
        let kind = add(
            &chain,
            Authorizer::Device([10; 16]),
            &phone,
            phone_keys.clone(),
        );
        assert!(chain.push(&stranger, kind.clone()).is_err());
        // An unknown device id as authorizer.
        let unknown = add(
            &chain,
            Authorizer::Device([77; 16]),
            &phone,
            phone_keys.clone(),
        );
        assert!(chain.push(&phone, unknown).is_err());
        assert_eq!(
            chain.state, before,
            "failed operations leave the state alone"
        );

        // The recovery key may add a device.
        let by_recovery = add(&chain, Authorizer::Recovery, &phone, phone_keys);
        chain.push(&recovery, by_recovery).unwrap();

        // A removed device can no longer sign.
        chain
            .push(
                &laptop,
                OpKind::RemoveDevice(RemoveDevice {
                    authorizer: Authorizer::Device([10; 16]),
                    device_id: [10; 16],
                }),
            )
            .unwrap();
        assert!(
            chain
                .push(
                    &laptop,
                    OpKind::MoveServer(MoveServer {
                        authorizer: Authorizer::Device([10; 16]),
                        url: "https://evil.example".into(),
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn added_devices_must_prove_their_keys_and_ids_are_never_reused() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let (phone, phone_keys) = device(20);
        let mut chain = start(&recovery, &laptop, laptop_keys);

        // Binding signed by someone else.
        let impostor = DeviceSigningKey::from_seed(&[55; 32]);
        let forged = add(
            &chain,
            Authorizer::Device([10; 16]),
            &impostor,
            phone_keys.clone(),
        );
        assert!(chain.push(&laptop, forged).is_err());

        let kind = add(
            &chain,
            Authorizer::Device([10; 16]),
            &phone,
            phone_keys.clone(),
        );
        chain.push(&laptop, kind).unwrap();
        let again = add(
            &chain,
            Authorizer::Device([10; 16]),
            &phone,
            phone_keys.clone(),
        );
        assert!(chain.push(&laptop, again).is_err(), "already a member");
        chain
            .push(
                &laptop,
                OpKind::RemoveDevice(RemoveDevice {
                    authorizer: Authorizer::Device([10; 16]),
                    device_id: [20; 16],
                }),
            )
            .unwrap();
        let back = add(&chain, Authorizer::Device([10; 16]), &phone, phone_keys);
        assert!(
            chain.push(&laptop, back).is_err(),
            "removed ids stay removed"
        );
    }

    #[test]
    fn a_new_recovery_key_must_prove_it_is_held() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let mut chain = start(&recovery, &laptop, laptop_keys);
        let wanted = RecoveryCode::from_bytes([4; 32]).signing_key();

        // A binding signed by another key than the one being installed.
        let OpKind::ResetRecovery(mut forged) =
            reset(&chain, Authorizer::Device([10; 16]), &wanted)
        else {
            unreachable!()
        };
        forged.recovery_sign_public_key = recovery.public_key().to_bytes();
        assert!(chain.push(&laptop, OpKind::ResetRecovery(forged)).is_err());

        let kind = reset(&chain, Authorizer::Device([10; 16]), &wanted);
        chain.push(&laptop, kind).unwrap();
        assert_eq!(
            chain.state.recovery_sign_public_key,
            wanted.public_key().to_bytes()
        );
        // The old recovery key no longer authorizes anything.
        assert!(
            chain
                .push(
                    &recovery,
                    OpKind::DeleteGroup(DeleteGroup {
                        authorizer: Authorizer::Recovery,
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn operations_must_extend_the_chain_in_order() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let mut chain = start(&recovery, &laptop, laptop_keys);
        let kind = OpKind::Rotate(Rotate {
            authorizer: Authorizer::Device([10; 16]),
            epoch: 2,
            root_commitment: [8; 32],
            sealed_previous_root: vec![1; 72],
        });

        let mut skipped = chain.next(kind.clone());
        skipped.index += 1;
        let bytes = skipped.encode().unwrap();
        assert!(
            chain
                .state
                .apply(&bytes, &[&sign_op(&laptop, &bytes)])
                .is_err()
        );

        let mut forked = chain.next(kind.clone());
        forked.prev_hash = [0; 32];
        let bytes = forked.encode().unwrap();
        assert!(
            chain
                .state
                .apply(&bytes, &[&sign_op(&laptop, &bytes)])
                .is_err()
        );

        let skip_epoch = OpKind::Rotate(Rotate {
            authorizer: Authorizer::Device([10; 16]),
            epoch: 3,
            root_commitment: [8; 32],
            sealed_previous_root: vec![1; 72],
        });
        assert!(chain.push(&laptop, skip_epoch).is_err());
        chain.push(&laptop, kind).unwrap();
    }

    #[test]
    fn genesis_signatures_are_checked_in_order() {
        let recovery = RecoveryCode::from_bytes([3; 32]).signing_key();
        let (laptop, laptop_keys) = device(10);
        let chain = start(&recovery, &laptop, laptop_keys);
        let (genesis, signatures) = &chain.ops[0];
        let swapped: Vec<&[u8]> = vec![&signatures[1], &signatures[0]];
        assert!(GroupState::from_genesis(genesis, &swapped).is_err());
        assert!(GroupState::from_genesis(genesis, &[&signatures[0]]).is_err());
    }
}
