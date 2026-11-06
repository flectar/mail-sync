#![allow(clippy::unwrap_used)]

//! End-to-end tests of pairing: a new device joins a group through a slot,
//! with a QR code shown by either device, or with a short code and approval
//! words.

mod common;

use axum::http::{Method, StatusCode};
use common::{AUDIENCE, Device, Harness, append, chain, create_group, fetch_root, login, ops};
use flectar_mail_sync_crypto::{
    AddDevice, INVITE_INDEX, Invite, JOIN_REQUEST_INDEX, JOIN_RESULT_INDEX, JoinRequest,
    JoinResult, OpKind, PairingSecret, RootKey, approval_words, device_binding_message, op_hash,
};
use flectar_mail_sync_proto::Bytes;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// How messages travel through the slot.
enum Channel {
    /// Sealed under the secret a QR code carries.
    Sealed(PairingSecret),
    /// In the clear; the user compares approval words instead.
    Clear,
}

impl Channel {
    fn seal(&self, slot_id: &[u8; 16], index: u8, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sealed(secret) => secret.seal(slot_id, index, message).unwrap(),
            Self::Clear => message.to_vec(),
        }
    }

    fn open(&self, slot_id: &[u8; 16], index: u8, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sealed(secret) => secret.open(slot_id, index, message).unwrap(),
            Self::Clear => message.to_vec(),
        }
    }
}

async fn open_slot(h: &Harness, code: bool) -> ([u8; 16], Option<String>) {
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/pairing",
            None,
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let slot_id = Bytes::decode(body["slotId"].as_str().unwrap())
        .unwrap()
        .to_array()
        .unwrap();
    (slot_id, body["code"].as_str().map(str::to_owned))
}

fn slot_uri(slot_id: &[u8; 16]) -> String {
    format!("/v1/pairing/{}", Bytes::from(*slot_id).encode())
}

async fn put(h: &Harness, slot_id: &[u8; 16], index: u8, message: &[u8]) -> (StatusCode, Value) {
    h.call(
        Method::PUT,
        &format!("{}/messages/{index}", slot_uri(slot_id)),
        None,
        Some(json!({"message": Bytes(message.to_vec()).encode()})),
    )
    .await
}

/// Message `index`, waiting for it to arrive.
async fn take(h: &Harness, slot_id: &[u8; 16], index: u8) -> Vec<u8> {
    let (status, body) = h
        .call(
            Method::GET,
            &format!("{}/messages?from={index}&wait=5", slot_uri(slot_id)),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = &body["messages"][0];
    assert_eq!(message["index"], u64::from(index));
    Bytes::decode(message["message"].as_str().unwrap())
        .unwrap()
        .0
}

/// Run the three-message exchange between `laptop`, already in the group,
/// and a new phone, then check that the phone holds the group's root key.
/// With a clear channel, both sides' approval words must match before the
/// laptop adds the phone.
async fn pair(h: &Harness, laptop: &Device, slot_id: [u8; 16], channel: &Channel) {
    let token = login(h, laptop).await;
    let state = chain(h, &token, &laptop.group()).await;

    // 0. The laptop invites.
    let invite = Invite {
        server_url: AUDIENCE.into(),
        group_id: laptop.group_id,
        head_index: state.head_index,
        head_hash: state.head_hash,
    };
    let sealed = channel.seal(&slot_id, INVITE_INDEX, &invite.encode().unwrap());
    assert_eq!(
        put(h, &slot_id, INVITE_INDEX, &sealed).await.0,
        StatusCode::CREATED
    );

    // 1. The phone reads the invite and asks to join that group.
    let received = Invite::decode(&channel.open(
        &slot_id,
        INVITE_INDEX,
        &take(h, &slot_id, INVITE_INDEX).await,
    ))
    .unwrap();
    assert_eq!(received, invite);
    let mut phone = Device::new(received.group_id, RootKey::from_bytes([0; 32]), 1);
    let request = JoinRequest {
        device: phone.keys(),
        binding_signature: phone
            .key
            .sign(&device_binding_message(&received.group_id, &phone.keys()).unwrap()),
    };
    let sealed = channel.seal(&slot_id, JOIN_REQUEST_INDEX, &request.encode().unwrap());
    put(h, &slot_id, JOIN_REQUEST_INDEX, &sealed).await;

    // 2. The laptop adds the phone, with the root key wrapped for it.
    let request = JoinRequest::decode(&channel.open(
        &slot_id,
        JOIN_REQUEST_INDEX,
        &take(h, &slot_id, JOIN_REQUEST_INDEX).await,
    ))
    .unwrap();
    if matches!(channel, Channel::Clear) {
        assert_eq!(
            approval_words(&laptop.group_id, &state.head_hash, &request.device),
            approval_words(&received.group_id, &received.head_hash, &phone.keys()),
            "both screens show the same words"
        );
    }
    let (status, body) = append(
        h,
        &token,
        &state,
        &laptop.key,
        OpKind::AddDevice(AddDevice {
            authorizer: laptop.authorizer(),
            device: request.device.clone(),
            binding_signature: request.binding_signature,
        }),
        vec![common::wrap(
            &request.device.kem_public_key,
            laptop.group_id,
            laptop.epoch,
            request.device.device_id,
            &laptop.root,
        )],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let added = JoinResult::Added {
        index: body["headIndex"].as_u64().unwrap(),
    };
    put(
        h,
        &slot_id,
        JOIN_RESULT_INDEX,
        &channel.seal(&slot_id, JOIN_RESULT_INDEX, &added.encode()),
    )
    .await;

    // The phone learns it was added, logs in, and checks the chain contains
    // the head it was invited at before trusting the key it unwraps.
    let result = JoinResult::decode(&channel.open(
        &slot_id,
        JOIN_RESULT_INDEX,
        &take(h, &slot_id, JOIN_RESULT_INDEX).await,
    ))
    .unwrap();
    assert_eq!(result, added);
    let phone_token = login(h, &phone).await;
    let chain_ops = ops(h, &phone_token, &phone.group()).await;
    let at_invite = usize::try_from(received.head_index).unwrap();
    assert_eq!(op_hash(&chain_ops[at_invite].0), received.head_hash);
    let (_, root) = fetch_root(h, &phone_token, phone.group_id, phone.device_id, &phone.kem).await;
    assert_eq!(root.as_bytes(), laptop.root.as_bytes());
    phone.root = root;

    let (status, _) = h
        .call(Method::DELETE, &slot_uri(&slot_id), None, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h
        .call(
            Method::GET,
            &format!("{}/messages", slot_uri(&slot_id)),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn devices_pair_through_a_qr_code() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    // Either device may open the slot and show the QR code; the server
    // cannot tell which did, and the messages are the same.
    let (slot_id, code) = open_slot(&h, false).await;
    assert!(code.is_none());
    pair(
        &h,
        &laptop,
        slot_id,
        &Channel::Sealed(PairingSecret::generate().unwrap()),
    )
    .await;
}

#[tokio::test]
async fn devices_without_cameras_pair_with_a_code_and_approval_words() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    let (slot_id, code) = open_slot(&h, true).await;
    let code = code.unwrap();
    assert_eq!(code.len(), 8);
    // The user types the code on the new device.
    let (status, body) = h
        .call(
            Method::GET,
            &format!("/v1/pairing/codes/{code}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["slotId"], Bytes::from(slot_id).encode());
    let (status, _) = h
        .call(
            Method::GET,
            &format!("/v1/pairing/codes/{code}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a code works once");
    pair(&h, &laptop, slot_id, &Channel::Clear).await;
}

#[tokio::test]
async fn slots_keep_messages_in_order() {
    let h = Harness::new();
    let (slot_id, _) = open_slot(&h, false).await;
    let (status, body) = put(&h, &slot_id, 1, b"early").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(put(&h, &slot_id, 0, b"a").await.0, StatusCode::CREATED);
    assert_eq!(
        put(&h, &slot_id, 0, b"a").await.0,
        StatusCode::OK,
        "a retried write"
    );
    assert_eq!(put(&h, &slot_id, 0, b"b").await.0, StatusCode::CONFLICT);
    let (status, _) = put(&h, &slot_id, 1, &[0; 4097]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    for index in 1..4 {
        assert_eq!(put(&h, &slot_id, index, b"x").await.0, StatusCode::CREATED);
    }
    assert_eq!(
        put(&h, &slot_id, 4, b"x").await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let (status, _) = put(&h, &[7; 16], 0, b"a").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reads_wait_for_the_next_message() {
    let h = Harness::new();
    let (slot_id, _) = open_slot(&h, false).await;
    let started = Instant::now();
    let (status, body) = h
        .call(
            Method::GET,
            &format!("{}/messages?from=0&wait=1", slot_uri(&slot_id)),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["messages"], json!([]));
    assert!(started.elapsed() >= Duration::from_secs(1));

    let reader = {
        let router = h.router.clone();
        let uri = format!("{}/messages?from=0&wait=10", slot_uri(&slot_id));
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tower::ServiceExt;
            let request = axum::http::Request::get(uri)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    put(&h, &slot_id, 0, b"hello").await;
    let body = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("the waiting read returns once the message arrives")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        body["messages"][0]["message"],
        Bytes(b"hello".to_vec()).encode()
    );
}
