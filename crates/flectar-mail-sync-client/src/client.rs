//! A device's connection to its group (SPEC §5, §6): sessions, the verified
//! chain, root keys, and the operations that change membership.

use crate::clock::{Clock, Stamp};
use crate::error::{Error, Result};
use crate::http::Http;
use crate::identity::{ChainOp, DeviceIdentity};
use flectar_mail_sync_crypto::{
    AddDevice, Authorizer, DeleteGroup, DeviceSigningKey, Genesis, GroupState, KemSecretKey, Op,
    OpKind, RECOVERY_ID, RecoveryCode, RemoveDevice, ResetRecovery, RootKey, Rotate,
    device_binding_message, op_hash, random_bytes, recovery_binding_message, sign_auth, sign_op,
    unwrap_root_key, wrap_root_key,
};
use flectar_mail_sync_proto::Limits;
use flectar_mail_sync_proto::{
    AppendOp, Bytes, ChallengeRequest, CreateGroup, ErrorCode, Session, SessionRequest, Wrap,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

/// How often an operation is rebuilt when other devices keep moving the
/// chain.
const APPEND_ATTEMPTS: usize = 5;
/// Sessions are renewed this long before they expire.
const SESSION_MARGIN_MS: i64 = 60_000;
const SECRETS_VERSION: u8 = 1;

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// A device's secrets: its identity and the root keys it has unwrapped.
/// Store [`Secrets::to_bytes`] in the OS key store.
#[derive(Clone)]
pub struct Secrets {
    pub identity: DeviceIdentity,
    pub roots: BTreeMap<u64, RootKey>,
}

impl Secrets {
    /// `version || u16be(len) || identity || (u64be(epoch) || root)*`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let identity = self.identity.to_bytes();
        let mut out = Zeroizing::new(Vec::with_capacity(
            3 + identity.len() + 40 * self.roots.len(),
        ));
        out.push(SECRETS_VERSION);
        out.extend_from_slice(
            &u16::try_from(identity.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&identity);
        for (epoch, root) in &self.roots {
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(root.as_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || Error::Malformed("stored sync secrets are invalid".into());
        let (&version, rest) = bytes.split_first().ok_or_else(malformed)?;
        if version != SECRETS_VERSION || rest.len() < 2 {
            return Err(malformed());
        }
        let (len, rest) = rest.split_at(2);
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if rest.len() < len || (rest.len() - len) % 40 != 0 {
            return Err(malformed());
        }
        let (identity, roots) = rest.split_at(len);
        let (entries, _) = roots.as_chunks::<40>();
        Ok(Self {
            identity: DeviceIdentity::from_bytes(identity)?,
            roots: entries
                .iter()
                .map(|entry| {
                    let (epoch, root) = entry.split_first_chunk::<8>().expect("40 > 8");
                    let root: [u8; 32] = root.try_into().expect("40 - 8 = 32");
                    (u64::from_be_bytes(*epoch), RootKey::from_bytes(root))
                })
                .collect(),
        })
    }
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("identity", &self.identity)
            .field("epochs", &self.roots.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The chain as this device verified it.
#[derive(Clone)]
pub(crate) struct Verified {
    pub(crate) ops: Vec<ChainOp>,
    pub(crate) hashes: Vec<[u8; 32]>,
    pub(crate) state: GroupState,
    pub(crate) roots: BTreeMap<u64, RootKey>,
}

fn signature_refs(op: &ChainOp) -> Vec<&[u8]> {
    op.signatures.iter().map(Vec::as_slice).collect()
}

impl Verified {
    fn replay(ops: Vec<ChainOp>, roots: BTreeMap<u64, RootKey>) -> Result<Self> {
        let first = ops
            .first()
            .ok_or_else(|| Error::Malformed("the chain is empty".into()))?;
        let (mut state, _) = GroupState::from_genesis(&first.op, &signature_refs(first))?;
        let mut hashes = vec![op_hash(&first.op)];
        for op in &ops[1..] {
            state.apply(&op.op, &signature_refs(op))?;
            hashes.push(op_hash(&op.op));
        }
        Ok(Self {
            ops,
            hashes,
            state,
            roots,
        })
    }

    fn push(&mut self, op: ChainOp) -> Result<()> {
        self.state
            .apply(&op.op, &signature_refs(&op))
            .map_err(|_| Error::Untrusted("the chain contains an invalid operation"))?;
        self.hashes.push(op_hash(&op.op));
        self.ops.push(op);
        Ok(())
    }

    /// The root key of `epoch`: stored, or opened from the sealed previous
    /// roots back from a newer one.
    pub(crate) fn root(&mut self, group_id: &[u8; 16], epoch: u64) -> Result<RootKey> {
        if let Some(root) = self.roots.get(&epoch) {
            return Ok(root.clone());
        }
        let newer = self
            .roots
            .range(epoch + 1..)
            .next()
            .map(|(epoch, root)| (*epoch, root.clone()))
            .ok_or(Error::Untrusted("no key for this epoch"))?;
        let (mut at, mut root) = newer;
        while at > epoch {
            let sealed = self
                .state
                .sealed_previous_roots
                .get(&at)
                .ok_or(Error::Untrusted("the chain lacks a sealed previous root"))?;
            root = root.open_previous(sealed, group_id, at)?;
            at -= 1;
            self.roots.insert(at, root.clone());
        }
        Ok(root)
    }

    /// The group state after the operation at `index`.
    fn state_at(&self, index: usize) -> Result<GroupState> {
        Ok(Self::replay(self.ops[..=index].to_vec(), BTreeMap::new())?.state)
    }
}

/// Log in as `identity`'s device.
async fn device_login(
    http: &Http,
    identity: &DeviceIdentity,
    signing: &DeviceSigningKey,
) -> Result<Session> {
    let group_id = identity.group_id();
    let device_id = identity.device_id();
    let challenge = http
        .challenge(&ChallengeRequest {
            group_id: Some(Bytes::from(group_id)),
            device_id: Some(Bytes::from(device_id)),
            recovery_public_key: None,
        })
        .await?;
    let nonce = challenge
        .nonce
        .to_array()
        .ok_or_else(|| Error::Malformed("challenge nonce".into()))?;
    let signature = sign_auth(signing, http.server_url(), &group_id, &device_id, &nonce)?;
    match http
        .session(&SessionRequest {
            challenge_id: challenge.challenge_id,
            signature: Bytes::from(signature),
        })
        .await
    {
        Err(error) if error.status() == Some(401) => Err(Error::LoginRefused),
        other => other,
    }
}

/// The whole chain, page by page.
async fn fetch_chain(http: &Http, token: &str, group_id: &[u8; 16]) -> Result<Vec<ChainOp>> {
    let mut ops = Vec::new();
    loop {
        let page = http.ops(token, group_id, ops.len() as u64).await?;
        ops.extend(page.ops.into_iter().map(|op| {
            ChainOp {
                op: op.op.0,
                signatures: op
                    .signatures
                    .into_iter()
                    .map(|signature| signature.0)
                    .collect(),
            }
        }));
        if !page.more {
            return Ok(ops);
        }
    }
}

/// A device's connection to its group.
pub struct SyncClient {
    pub(crate) http: Http,
    pub(crate) identity: DeviceIdentity,
    signing: DeviceSigningKey,
    kem: KemSecretKey,
    pub(crate) clock: Arc<Clock>,
    session: Mutex<Option<Session>>,
    pub(crate) chain: Mutex<Verified>,
    /// The server's limits, read once.
    pub(crate) limits: OnceCell<Limits>,
    /// Chain length and root key epochs the app last stored.
    pub(crate) persisted: Mutex<(usize, Vec<u64>)>,
}

impl std::fmt::Debug for SyncClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

enum Append {
    Done,
    /// The chain moved on; rebuild the operation.
    Moved,
}

impl SyncClient {
    /// Resume a device from what the app stored: its secrets and the chain
    /// it verified. The chain is verified again here, without the network.
    /// `clock_floor` is the latest stamp the app stored.
    pub fn new(
        http: reqwest::Client,
        secrets: Secrets,
        chain: Vec<ChainOp>,
        clock_floor: Option<Stamp>,
    ) -> Result<Self> {
        let Secrets { identity, roots } = secrets;
        let verified = Verified::replay(chain, roots)?;
        if verified.state.group_id != identity.group_id() {
            return Err(Error::Malformed(
                "the chain belongs to another group".into(),
            ));
        }
        let persisted = (verified.ops.len(), verified.roots.keys().copied().collect());
        Ok(Self {
            limits: OnceCell::new(),
            persisted: Mutex::new(persisted),
            http: Http::new(http, identity.server_url()),
            signing: identity.signing_key(),
            kem: identity.kem_key()?,
            clock: Arc::new(Clock::new(identity.device_id(), clock_floor)),
            session: Mutex::new(None),
            chain: Mutex::new(verified),
            identity,
        })
    }

    /// A client the app has stored nothing of yet: its first sync stores
    /// the chain and secrets.
    fn unpersisted(mut self) -> Self {
        *self.persisted.get_mut() = (0, Vec::new());
        self
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// The clock to stamp local changes with.
    pub fn clock(&self) -> &Arc<Clock> {
        &self.clock
    }

    /// What to store in the OS key store.
    pub async fn secrets(&self) -> Secrets {
        Secrets {
            identity: self.identity.clone(),
            roots: self.chain.lock().await.roots.clone(),
        }
    }

    /// The verified chain, for the app to store.
    pub async fn chain(&self) -> Vec<ChainOp> {
        self.chain.lock().await.ops.clone()
    }

    /// The group as last verified.
    pub async fn state(&self) -> GroupState {
        self.chain.lock().await.state.clone()
    }

    async fn login(&self) -> Result<Session> {
        device_login(&self.http, &self.identity, &self.signing).await
    }

    async fn token(&self) -> Result<String> {
        let mut session = self.session.lock().await;
        if let Some(current) = session.as_ref()
            && current.expires_at - SESSION_MARGIN_MS > now_ms()
        {
            return Ok(current.token.clone());
        }
        let fresh = self.login().await?;
        let token = fresh.token.clone();
        *session = Some(fresh);
        Ok(token)
    }

    /// Run `call` with a session, logging in again once if the session was
    /// refused.
    pub(crate) async fn authed<T>(&self, call: impl AsyncFn(&str) -> Result<T>) -> Result<T> {
        let token = self.token().await?;
        let result = match call(&token).await {
            Err(error) if error.status() == Some(401) => {
                *self.session.lock().await = None;
                let token = self.token().await?;
                call(&token).await
            }
            other => other,
        };
        result.map_err(|error| match error.code() {
            Some(ErrorCode::GroupDeleted) => Error::GroupDeleted,
            _ => error,
        })
    }

    /// Fetch and verify new operations. If the server lost operations this
    /// device verified, append them again; if it lost the whole group,
    /// create it again from the genesis. Fails if this device was removed
    /// or the group deleted.
    pub async fn refresh(&self) -> Result<GroupState> {
        let mut chain = self.chain.lock().await;
        self.pull_chain(&mut chain).await?;
        let state = chain.state.clone();
        drop(chain);
        if state.deleted {
            return Err(Error::GroupDeleted);
        }
        if !state.devices.contains_key(&self.identity.device_id()) {
            return Err(Error::Removed);
        }
        Ok(state)
    }

    async fn pull_chain(&self, chain: &mut Verified) -> Result<()> {
        let group_id = self.identity.group_id();
        // Read from our last operation, which the server must still hold.
        let mut since = chain.ops.len() as u64 - 1;
        loop {
            let page = match self
                .authed(async |token| self.http.ops(token, &group_id, since).await)
                .await
            {
                Err(Error::LoginRefused) => {
                    // Our device is unknown: the server may have lost the
                    // group. Creating it again fails if it exists.
                    self.restore_group(chain).await?;
                    return self.restore_ops(chain).await;
                }
                other => other?,
            };
            let mut ops = page.ops.into_iter().peekable();
            if since + 1 == chain.ops.len() as u64 {
                match ops.next() {
                    Some(op)
                        if op.index == since
                            && op_hash(op.op.as_slice()) == chain.hashes[since as usize] => {}
                    Some(op) if op.index == since => {
                        return Err(Error::Untrusted(
                            "the server's chain forked from the one this device verified",
                        ));
                    }
                    // The server's chain is shorter than ours.
                    _ => return self.restore_ops(chain).await,
                }
            }
            for op in ops {
                if op.index != chain.ops.len() as u64 {
                    return Err(Error::Malformed("operations out of order".into()));
                }
                chain.push(ChainOp {
                    op: op.op.0,
                    signatures: op
                        .signatures
                        .into_iter()
                        .map(|signature| signature.0)
                        .collect(),
                })?;
            }
            if !page.more {
                return Ok(());
            }
            since = chain.ops.len() as u64;
        }
    }

    /// The wraps that let devices read the epoch an operation leaves, for
    /// appending it again.
    fn wraps_for(&self, chain: &mut Verified, index: usize) -> Result<Vec<Wrap>> {
        let group_id = self.identity.group_id();
        let op = Op::decode(&chain.ops[index].op)?;
        let after = chain.state_at(index)?;
        let root = chain.root(&group_id, after.epoch)?;
        let targets: Vec<([u8; 16], Vec<u8>)> = match &op.kind {
            OpKind::Genesis(genesis) => vec![
                (RECOVERY_ID, genesis.recovery_kem_public_key.clone()),
                (
                    genesis.device.device_id,
                    genesis.device.kem_public_key.clone(),
                ),
            ],
            OpKind::AddDevice(add) => {
                vec![(add.device.device_id, add.device.kem_public_key.clone())]
            }
            OpKind::Rotate(_) => after
                .devices
                .iter()
                .map(|(id, member)| (*id, member.kem_public_key.clone()))
                .chain([(RECOVERY_ID, after.recovery_kem_public_key.clone())])
                .collect(),
            OpKind::ResetRecovery(reset) => {
                vec![(RECOVERY_ID, reset.recovery_kem_public_key.clone())]
            }
            OpKind::RemoveDevice(_) | OpKind::MoveServer(_) | OpKind::DeleteGroup(_) => vec![],
        };
        targets
            .into_iter()
            .map(|(target, kem_public_key)| {
                Ok(Wrap {
                    target: Bytes::from(target),
                    ciphertext: Bytes(wrap_root_key(
                        &kem_public_key,
                        &group_id,
                        after.epoch,
                        &target,
                        &root,
                    )?),
                })
            })
            .collect()
    }

    /// Create the group again from our genesis, if the server lost it.
    async fn restore_group(&self, chain: &mut Verified) -> Result<()> {
        let genesis = &chain.ops[0];
        let request = CreateGroup {
            op: Bytes(genesis.op.clone()),
            signatures: genesis.signatures.iter().cloned().map(Bytes).collect(),
            wraps: self.wraps_for(chain, 0)?,
        };
        match self.http.create_group(&request).await {
            Ok(_) => {
                tracing::warn!("the sync server had lost the group; created it again");
                Ok(())
            }
            // It exists, so this device is no longer in it.
            Err(error) if error.status() == Some(409) => Err(Error::LoginRefused),
            Err(error) => Err(error),
        }
    }

    /// Append again the operations the server lost.
    async fn restore_ops(&self, chain: &mut Verified) -> Result<()> {
        let group_id = self.identity.group_id();
        let server = self
            .authed(async |token| self.http.ops(token, &group_id, 0).await)
            .await?;
        if server.more {
            return Err(Error::Untrusted("the server's chain does not match"));
        }
        for (index, op) in server.ops.iter().enumerate() {
            if op.index != index as u64
                || chain.hashes.get(index) != Some(&op_hash(op.op.as_slice()))
            {
                return Err(Error::Untrusted(
                    "the server's chain forked from the one this device verified",
                ));
            }
        }
        tracing::warn!(
            lost = chain.ops.len() - server.ops.len(),
            "the sync server had lost chain operations; appending them again"
        );
        for index in server.ops.len()..chain.ops.len() {
            let request = AppendOp {
                op: Bytes(chain.ops[index].op.clone()),
                signatures: chain.ops[index]
                    .signatures
                    .iter()
                    .cloned()
                    .map(Bytes)
                    .collect(),
                wraps: self.wraps_for(chain, index)?,
            };
            self.authed(async |token| self.http.append_op(token, &group_id, &request).await)
                .await?;
        }
        Ok(())
    }

    /// The root key of `epoch`, unwrapping the current one from the server
    /// when needed. Every unwrapped key is checked against the chain.
    pub(crate) async fn root_key(&self, epoch: u64) -> Result<RootKey> {
        let group_id = self.identity.group_id();
        let mut chain = self.chain.lock().await;
        if epoch > chain.state.epoch {
            return Err(Error::Untrusted(
                "a record claims an epoch the chain has not reached",
            ));
        }
        if !chain.roots.contains_key(&chain.state.epoch) {
            let wrap = self
                .authed(async |token| self.http.wrap(token, &group_id).await)
                .await?;
            if wrap.epoch != chain.state.epoch {
                // The chain moved since we read it; the caller refreshes.
                return Err(Error::Server {
                    status: 409,
                    code: ErrorCode::StaleEpoch,
                    message: "the key epoch changed".into(),
                    retry_after: None,
                });
            }
            let root = unwrap_root_key(
                &self.kem,
                wrap.ciphertext.as_slice(),
                &group_id,
                wrap.epoch,
                &self.identity.device_id(),
            )?;
            if root.commitment(&group_id, wrap.epoch) != chain.state.root_commitment {
                return Err(Error::Untrusted(
                    "the root key does not match the chain's commitment",
                ));
            }
            let epoch = chain.state.epoch;
            chain.roots.insert(epoch, root);
        }
        chain.root(&group_id, epoch)
    }

    /// The record id of an item known by name, such as a preference key:
    /// the same on every device of the group, and meaningless to the server
    /// (SPEC §4.6).
    pub async fn named_record_id(&self, name: &str) -> Result<[u8; 16]> {
        let first = self.root_key(1).await?;
        Ok(flectar_mail_sync_crypto::collection_tag(
            &first.record_id_key(),
            name,
        ))
    }

    /// The current epoch and its root key.
    pub(crate) async fn current_root(&self) -> Result<(u64, RootKey)> {
        let epoch = self.chain.lock().await.state.epoch;
        Ok((epoch, self.root_key(epoch).await?))
    }

    async fn try_append(
        &self,
        state: &GroupState,
        kind: OpKind,
        wraps: Vec<Wrap>,
    ) -> Result<Append> {
        let group_id = self.identity.group_id();
        let op = Op {
            group_id,
            index: state.head_index + 1,
            prev_hash: state.head_hash,
            created_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            kind,
        }
        .encode()?;
        let request = AppendOp {
            signatures: vec![Bytes::from(sign_op(&self.signing, &op))],
            op: Bytes(op),
            wraps,
        };
        match self
            .authed(async |token| self.http.append_op(token, &group_id, &request).await)
            .await
        {
            Ok(_) => Ok(Append::Done),
            Err(error) if error.code() == Some(ErrorCode::Conflict) => Ok(Append::Moved),
            Err(error) => Err(error),
        }
    }

    /// Append the operation `build` makes from the current state, rebuilding
    /// it while other devices move the chain. `build` returns `None` when
    /// the operation is no longer needed.
    async fn append(
        &self,
        build: impl AsyncFn(&GroupState) -> Result<Option<(OpKind, Vec<Wrap>)>>,
    ) -> Result<GroupState> {
        for _ in 0..APPEND_ATTEMPTS {
            let state = self.refresh().await?;
            let Some((kind, wraps)) = build(&state).await? else {
                return Ok(state);
            };
            if let Append::Done = self.try_append(&state, kind, wraps).await? {
                return self.refresh_lenient().await;
            }
        }
        Err(Error::Server {
            status: 409,
            code: ErrorCode::Conflict,
            message: "the chain kept changing; try again".into(),
            retry_after: None,
        })
    }

    /// Like [`SyncClient::refresh`], but also after this device removed
    /// itself or deleted the group.
    async fn refresh_lenient(&self) -> Result<GroupState> {
        match self.refresh().await {
            Err(Error::Removed | Error::GroupDeleted | Error::LoginRefused) => {
                Ok(self.chain.lock().await.state.clone())
            }
            other => other,
        }
    }

    fn wrap_for(
        &self,
        kem_public_key: &[u8],
        epoch: u64,
        target: [u8; 16],
        root: &RootKey,
    ) -> Result<Wrap> {
        Ok(Wrap {
            target: Bytes::from(target),
            ciphertext: Bytes(wrap_root_key(
                kem_public_key,
                &self.identity.group_id(),
                epoch,
                &target,
                root,
            )?),
        })
    }

    /// Add the device that sent `device` and its binding signature. Returns
    /// the index of the `add_device` operation.
    pub(crate) async fn add_device(
        &self,
        device: &flectar_mail_sync_crypto::DeviceKeys,
        binding_signature: [u8; 64],
    ) -> Result<u64> {
        let authorizer = Authorizer::Device(self.identity.device_id());
        let state = self
            .append(async |state: &GroupState| {
                let (epoch, root) = self.current_root().await?;
                if epoch != state.epoch {
                    return Err(Error::Untrusted("the key epoch changed while adding"));
                }
                Ok(Some((
                    OpKind::AddDevice(AddDevice {
                        authorizer,
                        device: device.clone(),
                        binding_signature,
                    }),
                    vec![self.wrap_for(&device.kem_public_key, epoch, device.device_id, &root)?],
                )))
            })
            .await?;
        Ok(state.head_index)
    }

    /// Remove a device, then move everyone else to a new root key.
    pub async fn remove_device(&self, device_id: [u8; 16]) -> Result<()> {
        let authorizer = Authorizer::Device(self.identity.device_id());
        self.append(async |state: &GroupState| {
            Ok(state.devices.contains_key(&device_id).then(|| {
                (
                    OpKind::RemoveDevice(RemoveDevice {
                        authorizer,
                        device_id,
                    }),
                    vec![],
                )
            }))
        })
        .await?;
        if device_id == self.identity.device_id() {
            return Ok(());
        }
        self.rotate_now(true).await
    }

    /// Start a new epoch with a new root key, wrapped for every device and
    /// for recovery.
    pub async fn rotate(&self) -> Result<()> {
        self.rotate_now(false).await
    }

    /// Rotate; with `if_due`, only while the chain says a rotation is due,
    /// so devices racing to finish a removal rotate once between them.
    async fn rotate_now(&self, if_due: bool) -> Result<()> {
        let authorizer = Authorizer::Device(self.identity.device_id());
        let group_id = self.identity.group_id();
        let fresh = RootKey::generate()?;
        self.append(async |state: &GroupState| {
            if if_due && !state.rotation_due {
                return Ok(None);
            }
            let (epoch, current) = self.current_root().await?;
            if epoch != state.epoch {
                return Err(Error::Untrusted("the key epoch changed while rotating"));
            }
            let next = epoch + 1;
            let mut wraps = state
                .devices
                .iter()
                .map(|(id, member)| self.wrap_for(&member.kem_public_key, next, *id, &fresh))
                .collect::<Result<Vec<_>>>()?;
            wraps.push(self.wrap_for(&state.recovery_kem_public_key, next, RECOVERY_ID, &fresh)?);
            Ok(Some((
                OpKind::Rotate(Rotate {
                    authorizer,
                    epoch: next,
                    root_commitment: fresh.commitment(&group_id, next),
                    sealed_previous_root: fresh.seal_previous(&current, &group_id, next)?,
                }),
                wraps,
            )))
        })
        .await?;
        let mut chain = self.chain.lock().await;
        if chain.state.root_commitment == fresh.commitment(&group_id, chain.state.epoch) {
            let epoch = chain.state.epoch;
            chain.roots.insert(epoch, fresh);
        }
        Ok(())
    }

    /// Rotate if a removal or a recovery reset left a rotation due. Another
    /// device may get there first, which is fine.
    pub(crate) async fn rotate_if_due(&self) -> Result<()> {
        if self.chain.lock().await.state.rotation_due {
            self.rotate_now(true).await?;
        }
        Ok(())
    }

    /// Replace the recovery code: the old one stops working at once. Show
    /// the returned code to the user.
    pub async fn reset_recovery(&self) -> Result<RecoveryCode> {
        let authorizer = Authorizer::Device(self.identity.device_id());
        let group_id = self.identity.group_id();
        let code = RecoveryCode::generate()?;
        let signing = code.signing_key();
        let kem_public_key = KemSecretKey::derive(&code.kem_seed()).public_key();
        let sign_public_key = signing.public_key().to_bytes();
        let binding = signing.sign(&recovery_binding_message(
            &group_id,
            &sign_public_key,
            &kem_public_key,
        )?);
        self.append(async |state: &GroupState| {
            let (epoch, root) = self.current_root().await?;
            if epoch != state.epoch {
                return Err(Error::Untrusted("the key epoch changed while resetting"));
            }
            Ok(Some((
                OpKind::ResetRecovery(ResetRecovery {
                    authorizer,
                    recovery_sign_public_key: sign_public_key,
                    recovery_kem_public_key: kem_public_key.clone(),
                    binding_signature: binding,
                }),
                vec![self.wrap_for(&kem_public_key, epoch, RECOVERY_ID, &root)?],
            )))
        })
        .await?;
        // The old code may have read the current key; move on from it.
        self.rotate_now(true).await?;
        Ok(code)
    }

    /// Delete the group and everything the server holds for it.
    pub async fn delete_group(&self) -> Result<()> {
        let authorizer = Authorizer::Device(self.identity.device_id());
        self.append(async |_: &GroupState| {
            Ok(Some((
                OpKind::DeleteGroup(DeleteGroup { authorizer }),
                vec![],
            )))
        })
        .await?;
        Ok(())
    }

    /// Start a group with this device as its first member. Returns the
    /// client and the recovery code to show the user once.
    pub async fn create_group(
        http: reqwest::Client,
        server_url: &str,
    ) -> Result<(Self, RecoveryCode)> {
        let code = RecoveryCode::generate()?;
        let recovery = code.signing_key();
        let recovery_kem = KemSecretKey::derive(&code.kem_seed());
        let identity = DeviceIdentity::generate(server_url, random_bytes()?)?;
        let group_id = identity.group_id();
        let root = RootKey::generate()?;
        let op = Op {
            group_id,
            index: 0,
            prev_hash: [0; 32],
            created_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            kind: OpKind::Genesis(Genesis {
                recovery_sign_public_key: recovery.public_key().to_bytes(),
                recovery_kem_public_key: recovery_kem.public_key(),
                device: identity.keys()?,
                root_commitment: root.commitment(&group_id, 1),
            }),
        }
        .encode()?;
        let signatures = vec![
            sign_op(&recovery, &op).to_vec(),
            sign_op(&identity.signing_key(), &op).to_vec(),
        ];
        let device_kem = identity.kem_key()?.public_key();
        let device_id = identity.device_id();
        let wrap = |kem_public_key: &[u8], target: [u8; 16]| -> Result<Wrap> {
            Ok(Wrap {
                target: Bytes::from(target),
                ciphertext: Bytes(wrap_root_key(kem_public_key, &group_id, 1, &target, &root)?),
            })
        };
        let request = CreateGroup {
            op: Bytes(op.clone()),
            signatures: signatures.iter().cloned().map(Bytes).collect(),
            wraps: vec![
                wrap(&recovery_kem.public_key(), RECOVERY_ID)?,
                wrap(&device_kem, device_id)?,
            ],
        };
        Http::new(http.clone(), server_url)
            .create_group(&request)
            .await?;
        let client = Self::new(
            http,
            Secrets {
                identity,
                roots: BTreeMap::from([(1, root)]),
            },
            vec![ChainOp { op, signatures }],
            None,
        )?
        .unpersisted();
        Ok((client, code))
    }

    /// Finish joining once an existing device added `identity`: log in,
    /// check that the chain contains the head the invite named and, after
    /// it, this device's addition, then unwrap the root key.
    pub(crate) async fn join(
        http: reqwest::Client,
        identity: DeviceIdentity,
        invite: &flectar_mail_sync_crypto::Invite,
    ) -> Result<Self> {
        let api = Http::new(http.clone(), identity.server_url());
        let group_id = identity.group_id();
        let session = device_login(&api, &identity, &identity.signing_key()).await?;
        let ops = fetch_chain(&api, &session.token, &group_id).await?;
        let verified = Verified::replay(ops, BTreeMap::new())
            .map_err(|_| Error::Untrusted("the chain does not verify"))?;
        let at_invite = usize::try_from(invite.head_index).unwrap_or(usize::MAX);
        if verified.hashes.get(at_invite) != Some(&invite.head_hash) {
            return Err(Error::Untrusted(
                "the chain does not contain the head the other device saw",
            ));
        }
        let added_after_invite = verified.ops[at_invite + 1..].iter().any(|op| {
            Op::decode(&op.op).is_ok_and(|op| {
                matches!(&op.kind, OpKind::AddDevice(add) if add.device.device_id == identity.device_id())
            })
        });
        if !added_after_invite || !verified.state.devices.contains_key(&identity.device_id()) {
            return Err(Error::Untrusted("the chain lacks this device's addition"));
        }
        let state = verified.state.clone();
        let wrap = api.wrap(&session.token, &group_id).await?;
        let root = unwrap_root_key(
            &identity.kem_key()?,
            wrap.ciphertext.as_slice(),
            &group_id,
            wrap.epoch,
            &identity.device_id(),
        )?;
        if wrap.epoch != state.epoch
            || root.commitment(&group_id, wrap.epoch) != state.root_commitment
        {
            return Err(Error::Untrusted(
                "the root key does not match the chain's commitment",
            ));
        }
        let Verified { ops, .. } = verified;
        Ok(Self::new(
            http,
            Secrets {
                identity,
                roots: BTreeMap::from([(state.epoch, root)]),
            },
            ops,
            None,
        )?
        .unpersisted())
    }

    /// Join the group of a recovery code as a new device, when no other
    /// device is at hand.
    pub async fn recover(http: reqwest::Client, server_url: &str, words: &str) -> Result<Self> {
        let code = RecoveryCode::from_words(words)?;
        let recovery = code.signing_key();
        let recovery_kem = KemSecretKey::derive(&code.kem_seed());
        let api = Http::new(http.clone(), server_url);

        let challenge = api
            .challenge(&ChallengeRequest {
                group_id: None,
                device_id: None,
                recovery_public_key: Some(Bytes::from(recovery.public_key().to_bytes())),
            })
            .await?;
        let nonce = challenge
            .nonce
            .to_array()
            .ok_or_else(|| Error::Malformed("challenge nonce".into()))?;
        let signature = sign_auth(
            &recovery,
            api.server_url(),
            &RECOVERY_ID,
            &RECOVERY_ID,
            &nonce,
        )?;
        let session = match api
            .session(&SessionRequest {
                challenge_id: challenge.challenge_id,
                signature: Bytes::from(signature),
            })
            .await
        {
            Err(error) if error.status() == Some(401) => return Err(Error::UnknownRecoveryCode),
            other => other?,
        };
        let group_id: [u8; 16] = session
            .group_id
            .to_array()
            .ok_or_else(|| Error::Malformed("group id".into()))?;
        let identity = DeviceIdentity::generate(server_url, group_id)?;
        let keys = identity.keys()?;
        let binding = identity
            .signing_key()
            .sign(&device_binding_message(&group_id, &keys)?);

        for _ in 0..APPEND_ATTEMPTS {
            let ops = fetch_chain(&api, &session.token, &group_id).await?;
            let mut verified = Verified::replay(ops, BTreeMap::new())
                .map_err(|_| Error::Untrusted("the chain does not verify"))?;
            let state = verified.state.clone();
            if state.recovery_sign_public_key != recovery.public_key().to_bytes() {
                return Err(Error::Untrusted(
                    "the group's recovery key is not this code's",
                ));
            }
            let wrap = api.wrap(&session.token, &group_id).await?;
            let root = unwrap_root_key(
                &recovery_kem,
                wrap.ciphertext.as_slice(),
                &group_id,
                wrap.epoch,
                &RECOVERY_ID,
            )?;
            if wrap.epoch != state.epoch
                || root.commitment(&group_id, wrap.epoch) != state.root_commitment
            {
                return Err(Error::Untrusted(
                    "the root key does not match the chain's commitment",
                ));
            }
            let op = Op {
                group_id,
                index: state.head_index + 1,
                prev_hash: state.head_hash,
                created_at_ms: u64::try_from(now_ms()).unwrap_or(0),
                kind: OpKind::AddDevice(AddDevice {
                    authorizer: Authorizer::Recovery,
                    device: keys.clone(),
                    binding_signature: binding,
                }),
            }
            .encode()?;
            let signature = sign_op(&recovery, &op);
            let request = AppendOp {
                op: Bytes(op.clone()),
                signatures: vec![Bytes::from(signature)],
                wraps: vec![Wrap {
                    target: Bytes::from(identity.device_id()),
                    ciphertext: Bytes(wrap_root_key(
                        &keys.kem_public_key,
                        &group_id,
                        state.epoch,
                        &identity.device_id(),
                        &root,
                    )?),
                }],
            };
            match api.append_op(&session.token, &group_id, &request).await {
                Ok(_) => {
                    verified.push(ChainOp {
                        op,
                        signatures: vec![signature.to_vec()],
                    })?;
                    verified.roots.insert(state.epoch, root);
                    let Verified { ops, roots, .. } = verified;
                    return Ok(
                        Self::new(http, Secrets { identity, roots }, ops, None)?.unpersisted()
                    );
                }
                Err(error) if error.code() == Some(ErrorCode::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(Error::Server {
            status: 409,
            code: ErrorCode::Conflict,
            message: "the chain kept changing; try again".into(),
            retry_after: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_secrets_are_refused_without_panicking() {
        let secrets = Secrets {
            identity: DeviceIdentity::generate("https://sync.test", [3; 16]).unwrap(),
            roots: BTreeMap::from([(1, RootKey::from_bytes([1; 32]))]),
        };
        let bytes = secrets.to_bytes();
        let mut state = 0x853c_49e6_748f_ea9bu64;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % below as u64) as usize
        };
        // Fewer rounds than the other decoders: a parse that gets far
        // expands an X-Wing key, which is slow in debug builds.
        for _ in 0..2_000 {
            let mut damaged = bytes.to_vec();
            if next(2) == 0 {
                damaged.truncate(next(damaged.len() + 1));
            } else {
                let at = next(damaged.len());
                damaged[at] = next(256) as u8;
            }
            let _ = Secrets::from_bytes(&damaged);
        }
    }

    #[test]
    fn secrets_round_trip() {
        let secrets = Secrets {
            identity: DeviceIdentity::generate("https://sync.test", [3; 16]).unwrap(),
            roots: BTreeMap::from([
                (1, RootKey::from_bytes([1; 32])),
                (2, RootKey::from_bytes([2; 32])),
            ]),
        };
        let restored = Secrets::from_bytes(&secrets.to_bytes()).unwrap();
        assert_eq!(*restored.to_bytes(), *secrets.to_bytes());
        assert_eq!(restored.roots[&2].as_bytes(), &[2; 32]);
        let bytes = secrets.to_bytes();
        assert!(Secrets::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
