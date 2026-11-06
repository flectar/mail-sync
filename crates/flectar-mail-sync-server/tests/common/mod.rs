//! A test harness that acts as devices: it creates groups from signed
//! genesis operations, logs in, wraps and unwraps root keys, and appends
//! operations to the chain the same way the app will.
#![allow(dead_code, clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use flectar_mail_sync_crypto::{
    AddDevice, Authorizer, DeviceKeys, DeviceSigningKey, Genesis, GroupState, KemSecretKey, Op,
    OpKind, RECOVERY_ID, RecoveryCode, ResetRecovery, RootKey, collection_tag,
    device_binding_message, random_bytes, recovery_binding_message, seal_record, sign_auth,
    sign_op, unwrap_root_key, wrap_root_key,
};
use flectar_mail_sync_proto::Bytes;
use flectar_mail_sync_server::{AppState, Config, State, Store, app};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

pub const AUDIENCE: &str = "https://sync.test";

pub struct Harness {
    _dir: tempfile::TempDir,
    pub state: AppState,
    pub router: Router,
}

impl Harness {
    pub fn new() -> Self {
        Self::with_config(|_| {})
    }

    pub fn with_config(adjust: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("sync.db"), 2).unwrap();
        let mut config = Config::new(AUDIENCE);
        adjust(&mut config);
        let state = State::new(config, store);
        let router = app(state.clone());
        Self {
            _dir: dir,
            state,
            router,
        }
    }

    pub async fn call(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => request.body(Body::empty()).unwrap(),
        };
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
        };
        (status, value)
    }
}

/// One device of a group, with its keys and the root key it holds.
pub struct Device {
    pub group_id: [u8; 16],
    pub device_id: [u8; 16],
    pub key: DeviceSigningKey,
    pub kem: KemSecretKey,
    pub root: RootKey,
    pub epoch: u64,
}

impl Device {
    pub fn new(group_id: [u8; 16], root: RootKey, epoch: u64) -> Self {
        Self {
            group_id,
            device_id: flectar_mail_sync_crypto::random_bytes().unwrap(),
            key: DeviceSigningKey::generate().unwrap(),
            kem: KemSecretKey::generate().unwrap(),
            root,
            epoch,
        }
    }

    pub fn group(&self) -> String {
        Bytes::from(self.group_id).encode()
    }

    pub fn keys(&self) -> DeviceKeys {
        DeviceKeys {
            device_id: self.device_id,
            sign_public_key: self.key.public_key().to_bytes(),
            kem_public_key: self.kem.public_key(),
        }
    }

    pub fn authorizer(&self) -> Authorizer {
        Authorizer::Device(self.device_id)
    }
}

/// The recovery key pair a recovery code derives.
pub struct Recovery {
    pub code: RecoveryCode,
    pub key: DeviceSigningKey,
    pub kem: KemSecretKey,
}

impl Recovery {
    pub fn new() -> Self {
        let code = RecoveryCode::generate().unwrap();
        Self {
            key: code.signing_key(),
            kem: KemSecretKey::derive(&code.kem_seed()),
            code,
        }
    }
}

pub fn wrap(
    kem_public_key: &[u8],
    group_id: [u8; 16],
    epoch: u64,
    target: [u8; 16],
    root: &RootKey,
) -> Value {
    json!({
        "target": Bytes::from(target).encode(),
        "ciphertext": Bytes(wrap_root_key(kem_public_key, &group_id, epoch, &target, root).unwrap()).encode(),
    })
}

pub fn genesis_request(device: &Device, recovery: &Recovery) -> Value {
    let op = Op {
        group_id: device.group_id,
        index: 0,
        prev_hash: [0; 32],
        created_at_ms: 1_762_400_000_000,
        kind: OpKind::Genesis(Genesis {
            recovery_sign_public_key: recovery.key.public_key().to_bytes(),
            recovery_kem_public_key: recovery.kem.public_key(),
            device: device.keys(),
            root_commitment: device.root.commitment(&device.group_id, 1),
        }),
    };
    let bytes = op.encode().unwrap();
    json!({
        "op": Bytes(bytes.clone()).encode(),
        "signatures": [
            Bytes::from(sign_op(&recovery.key, &bytes)).encode(),
            Bytes::from(sign_op(&device.key, &bytes)).encode(),
        ],
        "wraps": [wrap(&recovery.kem.public_key(), device.group_id, 1, RECOVERY_ID, &device.root)],
    })
}

/// Create a group with a random id, as the app does.
pub async fn create_group(h: &Harness) -> (Device, Recovery) {
    let recovery = Recovery::new();
    let device = Device::new(random_bytes().unwrap(), RootKey::generate().unwrap(), 1);
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/groups",
            None,
            Some(genesis_request(&device, &recovery)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (device, recovery)
}

/// Ask for a challenge with `request`, sign its nonce with `sign`, and
/// return the session body if the server accepts the signature.
async fn answer_challenge(
    h: &Harness,
    request: Value,
    sign: impl FnOnce(&[u8; 32]) -> [u8; 64],
) -> Option<Value> {
    let (status, challenge) = h
        .call(Method::POST, "/v1/auth/challenge", None, Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let nonce: [u8; 32] = Bytes::decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    let (status, session) = h
        .call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(json!({
                "challengeId": challenge["challengeId"],
                "signature": Bytes::from(sign(&nonce)).encode(),
            })),
        )
        .await;
    (status == StatusCode::OK).then_some(session)
}

pub async fn login_as(
    h: &Harness,
    group_id: [u8; 16],
    device_id: [u8; 16],
    key: &DeviceSigningKey,
) -> Option<String> {
    let request = json!({
        "groupId": Bytes::from(group_id).encode(),
        "deviceId": Bytes::from(device_id).encode(),
    });
    let session = answer_challenge(h, request, |nonce| {
        sign_auth(key, AUDIENCE, &group_id, &device_id, nonce).unwrap()
    })
    .await?;
    assert_eq!(session["groupId"], Bytes::from(group_id).encode());
    Some(session["token"].as_str().unwrap().to_owned())
}

/// Log in with nothing but a recovery key, as a device that only has the 24
/// words does. Returns the session and the group the server found.
pub async fn login_recovery(h: &Harness, key: &DeviceSigningKey) -> Option<(String, [u8; 16])> {
    let request = json!({"recoveryPublicKey": Bytes::from(key.public_key().to_bytes()).encode()});
    let session = answer_challenge(h, request, |nonce| {
        sign_auth(key, AUDIENCE, &RECOVERY_ID, &RECOVERY_ID, nonce).unwrap()
    })
    .await?;
    let group_id = Bytes::decode(session["groupId"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    Some((session["token"].as_str().unwrap().to_owned(), group_id))
}

pub async fn login(h: &Harness, device: &Device) -> String {
    login_as(h, device.group_id, device.device_id, &device.key)
        .await
        .expect("the device logs in")
}

/// The group's chain, fetched and verified like a device would.
pub async fn chain(h: &Harness, token: &str, group: &str) -> GroupState {
    let (status, page) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{group}/ops?since=0"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let ops: Vec<(Vec<u8>, Vec<Vec<u8>>)> = page["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            (
                Bytes::decode(op["op"].as_str().unwrap()).unwrap().0,
                op["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| Bytes::decode(s.as_str().unwrap()).unwrap().0)
                    .collect(),
            )
        })
        .collect();
    GroupState::replay(ops.iter().map(|(op, signatures)| {
        (
            op.as_slice(),
            signatures.iter().map(Vec::as_slice).collect(),
        )
    }))
    .unwrap()
}

/// Sign `kind` as the next operation after `state` and append it.
pub async fn append(
    h: &Harness,
    token: &str,
    state: &GroupState,
    signer: &DeviceSigningKey,
    kind: OpKind,
    wraps: Vec<Value>,
) -> (StatusCode, Value) {
    let op = Op {
        group_id: state.group_id,
        index: state.head_index + 1,
        prev_hash: state.head_hash,
        created_at_ms: 1_762_400_000_000,
        kind,
    }
    .encode()
    .unwrap();
    h.call(
        Method::POST,
        &format!("/v1/groups/{}/ops", Bytes::from(state.group_id).encode()),
        Some(token),
        Some(json!({
            "op": Bytes(op.clone()).encode(),
            "signatures": [Bytes::from(sign_op(signer, &op)).encode()],
            "wraps": wraps,
        })),
    )
    .await
}

/// An `add_device` operation for `new`, authorized by `authorizer`.
pub fn add_device(authorizer: Authorizer, new: &Device) -> OpKind {
    let keys = new.keys();
    let binding = new
        .key
        .sign(&device_binding_message(&new.group_id, &keys).unwrap());
    OpKind::AddDevice(AddDevice {
        authorizer,
        device: keys,
        binding_signature: binding,
    })
}

/// A `reset_recovery` operation to the keys of `fresh`, with the binding
/// signature that proves `fresh` holds them.
pub fn reset_recovery(group_id: [u8; 16], authorizer: Authorizer, fresh: &Recovery) -> OpKind {
    let sign_public_key = fresh.key.public_key().to_bytes();
    let kem_public_key = fresh.kem.public_key();
    let binding = fresh
        .key
        .sign(&recovery_binding_message(&group_id, &sign_public_key, &kem_public_key).unwrap());
    OpKind::ResetRecovery(ResetRecovery {
        authorizer,
        recovery_sign_public_key: sign_public_key,
        recovery_kem_public_key: kem_public_key,
        binding_signature: binding,
    })
}

/// Fetch and unwrap the current root key, and check it against the chain's
/// commitment as a device must.
pub async fn fetch_root(
    h: &Harness,
    token: &str,
    group_id: [u8; 16],
    target: [u8; 16],
    kem: &KemSecretKey,
) -> (u64, RootKey) {
    let group = Bytes::from(group_id).encode();
    let (status, body) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{group}/wrap"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let epoch = body["epoch"].as_u64().unwrap();
    let wrapped = Bytes::decode(body["ciphertext"].as_str().unwrap()).unwrap();
    let root = unwrap_root_key(kem, wrapped.as_slice(), &group_id, epoch, &target).unwrap();
    let state = chain(h, token, &group).await;
    assert_eq!(state.epoch, epoch);
    assert_eq!(
        root.commitment(&group_id, epoch),
        state.root_commitment,
        "the unwrapped key is the one the chain committed to"
    );
    (epoch, root)
}

/// A sealed `put` commit item for `record_id`.
pub fn put(device: &Device, record_id: [u8; 16], expected_seq: u64, body: &[u8]) -> Value {
    let tag = collection_tag(&device.root.tag_key(device.epoch), "pref");
    let (nonce, ciphertext) = seal_record(
        &device.root.record_key(device.epoch),
        &device.group_id,
        &record_id,
        &tag,
        device.epoch,
        body,
    )
    .unwrap();
    json!({
        "recordId": Bytes::from(record_id).encode(),
        "expectedSeq": expected_seq,
        "tag": Bytes::from(tag).encode(),
        "epoch": device.epoch,
        "nonce": Bytes::from(nonce).encode(),
        "ciphertext": Bytes(ciphertext).encode(),
    })
}

pub fn delete(record_id: [u8; 16], expected_seq: u64) -> Value {
    json!({"recordId": Bytes::from(record_id).encode(), "expectedSeq": expected_seq, "deleted": true})
}
