#![allow(clippy::unwrap_used)]

//! End-to-end tests of records: sealing, committing and reading back,
//! conflicts, deletions, limits, logins and live events.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{
    AUDIENCE, Device, Harness, Recovery, create_group, delete, genesis_request, login, put,
};
use flectar_mail_sync_crypto::{DeviceSigningKey, RootKey, open_record, sign_auth};
use flectar_mail_sync_proto::Bytes;
use flectar_mail_sync_server::serve;
use http_body_util::BodyExt;
use serde_json::json;
use std::time::Duration;
use tower::ServiceExt;

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
    let (device, _) = create_group(&h).await;
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
    let (device, _) = create_group(&h).await;
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
    let (device, _) = create_group(&h).await;
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
    let (device, _) = create_group(&h).await;
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
    let (alice, _) = create_group(&h).await;
    let (bob, _) = create_group(&h).await;
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
    let (device, _) = create_group(&h).await;
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
    let recovery = Recovery::new();
    let device = Device::new(
        flectar_mail_sync_crypto::random_bytes().unwrap(),
        RootKey::generate().unwrap(),
        1,
    );

    let mut swapped = genesis_request(&device, &recovery);
    swapped["signatures"] = json!([swapped["signatures"][1], swapped["signatures"][0]]);
    let (status, body) = h
        .call(Method::POST, "/v1/groups", None, Some(swapped))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let mut unwrapped = genesis_request(&device, &recovery);
    unwrapped["wraps"] = json!([]);
    let (status, body) = h
        .call(Method::POST, "/v1/groups", None, Some(unwrapped))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the recovery wrap is required: {body}"
    );

    let request = genesis_request(&device, &recovery);
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
    let (device, _) = create_group(&h).await;
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
    let (device, _) = create_group(&h).await;
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
    assert_eq!(response.headers()["x-accel-buffering"], "no");
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

#[tokio::test]
async fn shutdown_finishes_while_event_streams_are_open() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = Harness::new();
    let (device, _) = create_group(&h).await;
    let token = login(&h, &device).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, h.state.clone(), async {
        let _ = stopped.await;
    }));

    // A device listening for events, over a real connection.
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET /v1/groups/{}/events HTTP/1.1\r\nHost: sync.test\r\nAuthorization: Bearer {token}\r\n\r\n",
        device.group()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    let mut buffer = [0u8; 1024];
    while !String::from_utf8_lossy(&received).contains("event: seq") {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("the stream opens")
            .unwrap();
        assert!(read > 0, "the server closed the stream early");
        received.extend_from_slice(&buffer[..read]);
    }

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("shutdown does not wait for open event streams")
        .unwrap()
        .unwrap();
}
