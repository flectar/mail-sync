#![allow(clippy::unwrap_used)]

//! End-to-end tests of the HTTP API, acting as a device would: build and
//! sign a genesis operation, log in by challenge, seal records, commit and
//! read them back.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use flectar_mail_sync_crypto::{
    DeviceKeys, DeviceSigningKey, Genesis, Op, OpKind, RecoveryCode, RootKey, collection_tag,
    open_record, seal_record, sign_auth, sign_op,
};
use flectar_mail_sync_proto::Bytes;
use flectar_mail_sync_server::{AppState, Config, State, Store, app};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

const AUDIENCE: &str = "https://sync.test";

struct Harness {
    _dir: tempfile::TempDir,
    state: AppState,
    router: Router,
}

impl Harness {
    fn new() -> Self {
        Self::with_config(|_| {})
    }

    fn with_config(adjust: impl FnOnce(&mut Config)) -> Self {
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

    async fn call(
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

struct Device {
    group_id: [u8; 16],
    device_id: [u8; 16],
    key: DeviceSigningKey,
    root: RootKey,
}

impl Device {
    fn group(&self) -> String {
        Bytes::from(self.group_id).encode()
    }
}

fn genesis_request(
    group_id: [u8; 16],
    device_id: [u8; 16],
    device: &DeviceSigningKey,
    recovery: &RecoveryCode,
) -> Value {
    let recovery_key = recovery.signing_key();
    let op = Op {
        group_id,
        index: 0,
        prev_hash: [0; 32],
        created_at_ms: 1_762_400_000_000,
        kind: OpKind::Genesis(Genesis {
            recovery_sign_public_key: recovery_key.public_key().to_bytes(),
            recovery_kem_public_key: vec![1; 32],
            device: DeviceKeys {
                device_id,
                sign_public_key: device.public_key().to_bytes(),
                kem_public_key: vec![2; 32],
                name: "Test laptop".into(),
            },
        }),
    };
    let bytes = op.encode().unwrap();
    json!({
        "op": Bytes(bytes.clone()).encode(),
        "signatures": [
            Bytes::from(sign_op(&recovery_key, &bytes)).encode(),
            Bytes::from(sign_op(device, &bytes)).encode(),
        ],
    })
}

async fn create_group(h: &Harness) -> Device {
    let group_id = flectar_mail_sync_crypto::random_bytes().unwrap();
    let device_id = flectar_mail_sync_crypto::random_bytes().unwrap();
    let key = DeviceSigningKey::generate().unwrap();
    let recovery = RecoveryCode::generate().unwrap();
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/groups",
            None,
            Some(genesis_request(group_id, device_id, &key, &recovery)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["groupId"], Bytes::from(group_id).encode());
    Device {
        group_id,
        device_id,
        key,
        root: RootKey::generate().unwrap(),
    }
}

async fn login(h: &Harness, device: &Device) -> String {
    let (status, challenge) = h
        .call(
            Method::POST,
            "/v1/auth/challenge",
            None,
            Some(json!({
                "groupId": Bytes::from(device.group_id).encode(),
                "deviceId": Bytes::from(device.device_id).encode(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let nonce: [u8; 32] = Bytes::decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    let signature = sign_auth(
        &device.key,
        AUDIENCE,
        &device.group_id,
        &device.device_id,
        &nonce,
    )
    .unwrap();
    let (status, session) = h
        .call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(json!({
                "challengeId": challenge["challengeId"],
                "signature": Bytes::from(signature).encode(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    session["token"].as_str().unwrap().to_owned()
}

/// A sealed `put` commit item for `record_id`.
fn put(device: &Device, record_id: [u8; 16], expected_seq: u64, body: &[u8]) -> Value {
    let tag = collection_tag(&device.root.tag_key(1), "pref");
    let (nonce, ciphertext) = seal_record(
        &device.root.record_key(1),
        &device.group_id,
        &record_id,
        &tag,
        1,
        body,
    )
    .unwrap();
    json!({
        "recordId": Bytes::from(record_id).encode(),
        "expectedSeq": expected_seq,
        "tag": Bytes::from(tag).encode(),
        "epoch": 1,
        "nonce": Bytes::from(nonce).encode(),
        "ciphertext": Bytes(ciphertext).encode(),
    })
}

fn delete(record_id: [u8; 16], expected_seq: u64) -> Value {
    json!({"recordId": Bytes::from(record_id).encode(), "expectedSeq": expected_seq, "deleted": true})
}

#[tokio::test]
async fn info_reports_protocol_and_limits() {
    let h = Harness::new();
    let (status, info) = h.call(Method::GET, "/v1/info", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["protocolMin"], 1);
    assert_eq!(info["limits"]["maxRecordBytes"], 256 * 1024);
    let (status, _) = h.call(Method::GET, "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_device_seals_commits_and_reads_back_its_records() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/commit", device.group());
    let (status, committed) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&device, [1; 16], 0, b"{\"theme\":\"dark\"}"), put(&device, [2; 16], 0, b"{}")]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{committed}");
    assert_eq!(committed["highSeq"], 2);

    let (status, page) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes?since=0", device.group()),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["highSeq"], 2);
    assert_eq!(page["more"], false);
    let first = &page["records"][0];
    let record_id: [u8; 16] = Bytes::decode(first["recordId"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    let opened = open_record(
        &device.root.record_key(1),
        &device.group_id,
        &record_id,
        &Bytes::decode(first["tag"].as_str().unwrap())
            .unwrap()
            .to_array()
            .unwrap(),
        1,
        &Bytes::decode(first["nonce"].as_str().unwrap())
            .unwrap()
            .to_array()
            .unwrap(),
        Bytes::decode(first["ciphertext"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(opened, b"{\"theme\":\"dark\"}");
}

#[tokio::test]
async fn stale_writers_get_conflicts_and_nothing_is_applied() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/commit", device.group());
    h.call(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({"items": [put(&device, [1; 16], 0, b"a")]})),
    )
    .await;
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(
                json!({"items": [put(&device, [3; 16], 0, b"c"), put(&device, [1; 16], 0, b"b")]}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "conflict");
    assert_eq!(
        body["conflicts"],
        json!([{"recordId": Bytes::from([1u8; 16]).encode(), "currentSeq": 1}])
    );
    let (_, page) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes", device.group()),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn deletions_leave_tombstones_and_records_can_return() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/commit", device.group());
    h.call(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({"items": [put(&device, [1; 16], 0, b"a")]})),
    )
    .await;
    let (status, _) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [delete([1; 16], 1)]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, page) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes?since=1", device.group()),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(
        page["records"],
        json!([{"recordId": Bytes::from([1u8; 16]).encode(), "seq": 2, "deleted": true}])
    );
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&device, [1; 16], 2, b"b")]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn cursors_behind_purged_tombstones_must_read_again() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/commit", device.group());
    h.call(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({"items": [put(&device, [1; 16], 0, b"a"), put(&device, [2; 16], 0, b"b")]})),
    )
    .await;
    h.call(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({"items": [delete([1; 16], 1)]})),
    )
    .await;
    h.state.store.purge_tombstones(i64::MAX).await.unwrap();
    let changes = |since: u64| format!("/v1/groups/{}/changes?since={since}", device.group());
    let (status, body) = h.call(Method::GET, &changes(2), Some(&token), None).await;
    assert_eq!(status, StatusCode::GONE, "{body}");
    assert_eq!(body["error"]["code"], "gone");
    let (status, page) = h.call(Method::GET, &changes(0), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sessions_are_required_and_scoped_to_their_group() {
    let h = Harness::new();
    let alice = create_group(&h).await;
    let bob = create_group(&h).await;
    let alice_token = login(&h, &alice).await;
    let commit = json!({"items": [put(&bob, [1; 16], 0, b"x")]});
    let (status, _) = h
        .call(
            Method::POST,
            &format!("/v1/groups/{}/commit", bob.group()),
            None,
            Some(commit.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h
        .call(
            Method::POST,
            &format!("/v1/groups/{}/commit", bob.group()),
            Some(&alice_token),
            Some(commit),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes", bob.group()),
            Some("forged"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logins_need_the_device_key_and_a_fresh_challenge() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let request = json!({
        "groupId": Bytes::from(device.group_id).encode(),
        "deviceId": Bytes::from(device.device_id).encode(),
    });
    let (_, challenge) = h
        .call(
            Method::POST,
            "/v1/auth/challenge",
            None,
            Some(request.clone()),
        )
        .await;
    let nonce: [u8; 32] = Bytes::decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    let impostor = DeviceSigningKey::generate().unwrap();
    let forged = sign_auth(
        &impostor,
        AUDIENCE,
        &device.group_id,
        &device.device_id,
        &nonce,
    )
    .unwrap();
    let (status, _) = h
        .call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(json!({"challengeId": challenge["challengeId"], "signature": Bytes::from(forged).encode()})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The failed attempt consumed the challenge.
    let genuine = sign_auth(
        &device.key,
        AUDIENCE,
        &device.group_id,
        &device.device_id,
        &nonce,
    )
    .unwrap();
    let (status, _) = h
        .call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(json!({"challengeId": challenge["challengeId"], "signature": Bytes::from(genuine).encode()})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A signature for another server does not log in here.
    let (_, challenge) = h
        .call(Method::POST, "/v1/auth/challenge", None, Some(request))
        .await;
    let nonce: [u8; 32] = Bytes::decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    let elsewhere = sign_auth(
        &device.key,
        "https://other.test",
        &device.group_id,
        &device.device_id,
        &nonce,
    )
    .unwrap();
    let (status, _) = h
        .call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(json!({"challengeId": challenge["challengeId"], "signature": Bytes::from(elsewhere).encode()})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn genesis_operations_are_verified() {
    let h = Harness::new();
    let key = DeviceSigningKey::generate().unwrap();
    let recovery = RecoveryCode::generate().unwrap();
    let mut request = genesis_request([5; 16], [6; 16], &key, &recovery);
    request["signatures"] = json!([request["signatures"][1], request["signatures"][0]]);
    let (status, body) = h
        .call(Method::POST, "/v1/groups", None, Some(request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let request = genesis_request([5; 16], [6; 16], &key, &recovery);
    let (status, _) = h
        .call(Method::POST, "/v1/groups", None, Some(request.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = h
        .call(Method::POST, "/v1/groups", None, Some(request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn limits_are_enforced() {
    let h = Harness::with_config(|config| {
        config.limits.max_record_bytes = 300;
        config.limits.max_group_bytes = 700;
        config.limits.max_batch_records = 2;
    });
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/commit", device.group());
    let big = vec![0u8; 400];
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&device, [1; 16], 0, &big)]})),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    let three = json!({"items": [put(&device, [1; 16], 0, b"a"), put(&device, [2; 16], 0, b"b"), put(&device, [3; 16], 0, b"c")]});
    let (status, _) = h.call(Method::POST, &uri, Some(&token), Some(three)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(
                json!({"items": [put(&device, [1; 16], 0, b"a"), put(&device, [2; 16], 0, b"b")]}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&device, [3; 16], 0, b"c")]})),
        )
        .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
    assert_eq!(body["error"]["code"], "quota_exceeded");
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(
                json!({"items": [put(&device, [4; 16], 0, b"d"), put(&device, [4; 16], 0, b"d")]}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn event_streams_announce_new_sequence_numbers() {
    let h = Harness::new();
    let device = create_group(&h).await;
    let token = login(&h, &device).await;
    let request = Request::builder()
        .uri(format!("/v1/groups/{}/events", device.group()))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    let mut body = response.into_body();
    let mut next_event = async || {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("an event arrives")
            .unwrap()
            .unwrap();
        String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap()
    };
    assert_eq!(next_event().await, "event: seq\ndata: {\"highSeq\":0}\n\n");
    h.call(
        Method::POST,
        &format!("/v1/groups/{}/commit", device.group()),
        Some(&token),
        Some(json!({"items": [put(&device, [1; 16], 0, b"a")]})),
    )
    .await;
    assert_eq!(next_event().await, "event: seq\ndata: {\"highSeq\":1}\n\n");
}
