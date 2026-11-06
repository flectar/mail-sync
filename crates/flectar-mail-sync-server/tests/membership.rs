#![allow(clippy::unwrap_used)]

//! End-to-end tests of the membership chain: adding and removing devices,
//! rotating root keys, recovery logins and deleting a group.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{
    Device, Harness, add_device, append, chain, create_group, delete, fetch_root, genesis_request,
    login, login_as, login_recovery, put, reset_recovery, wrap,
};
use flectar_mail_sync_crypto::{
    Authorizer, DeleteGroup, MoveServer, OpKind, RECOVERY_ID, RemoveDevice, RootKey, Rotate,
    random_bytes,
};
use flectar_mail_sync_proto::Bytes;
use http_body_util::BodyExt;
use serde_json::json;
use std::time::Duration;
use tower::ServiceExt;

#[tokio::test]
async fn a_device_added_through_the_chain_gets_the_committed_root_key() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let state = chain(&h, &token, &laptop.group()).await;
    assert_eq!(state.devices.len(), 1);

    let mut phone = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &phone),
        vec![wrap(
            &phone.kem.public_key(),
            laptop.group_id,
            1,
            phone.device_id,
            &laptop.root,
        )],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"headIndex": 1, "epoch": 1}));

    let phone_token = login(&h, &phone).await;
    let (epoch, root) = fetch_root(
        &h,
        &phone_token,
        phone.group_id,
        phone.device_id,
        &phone.kem,
    )
    .await;
    assert_eq!(epoch, 1);
    assert_eq!(root.as_bytes(), laptop.root.as_bytes());
    phone.root = root;

    // The phone can now read what the laptop writes.
    let uri = format!("/v1/groups/{}/commit", laptop.group());
    let (status, _) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&laptop, [1; 16], 0, b"x")]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, page) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes", phone.group()),
            Some(&phone_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn removing_a_device_locks_it_out_and_rotation_moves_everyone_to_a_new_key() {
    let h = Harness::new();
    let (mut laptop, recovery) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let phone = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let state = chain(&h, &token, &laptop.group()).await;
    append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &phone),
        vec![],
    )
    .await;
    let phone_token = login(&h, &phone).await;

    let state = chain(&h, &token, &laptop.group()).await;
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        OpKind::RemoveDevice(RemoveDevice {
            authorizer: laptop.authorizer(),
            device_id: phone.device_id,
        }),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The removed device's session and logins stop working at once.
    let (status, _) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{}/changes", phone.group()),
            Some(&phone_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        login_as(&h, phone.group_id, phone.device_id, &phone.key)
            .await
            .is_none()
    );

    // A rotation must wrap the new key for every remaining device and for
    // recovery.
    let new_root = RootKey::generate().unwrap();
    let state = chain(&h, &token, &laptop.group()).await;
    let rotate = OpKind::Rotate(Rotate {
        authorizer: laptop.authorizer(),
        epoch: 2,
        root_commitment: new_root.commitment(&laptop.group_id, 2),
        sealed_previous_root: new_root
            .seal_previous(&laptop.root, &laptop.group_id, 2)
            .unwrap(),
    });
    let laptop_wrap = wrap(
        &laptop.kem.public_key(),
        laptop.group_id,
        2,
        laptop.device_id,
        &new_root,
    );
    let recovery_wrap = wrap(
        &recovery.kem.public_key(),
        laptop.group_id,
        2,
        RECOVERY_ID,
        &new_root,
    );
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        rotate.clone(),
        vec![laptop_wrap.clone()],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the recovery wrap is missing: {body}"
    );
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        rotate,
        vec![laptop_wrap, recovery_wrap],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (epoch, root) =
        fetch_root(&h, &token, laptop.group_id, laptop.device_id, &laptop.kem).await;
    assert_eq!((epoch, root.as_bytes()), (2, new_root.as_bytes()));
    // The old key travels sealed in the chain, so older records stay readable.
    let state = chain(&h, &token, &laptop.group()).await;
    let previous = root
        .open_previous(
            state.sealed_previous_roots.get(&2).unwrap(),
            &laptop.group_id,
            2,
        )
        .unwrap();
    assert_eq!(previous.as_bytes(), laptop.root.as_bytes());

    // Writes sealed for the old epoch are refused.
    let uri = format!("/v1/groups/{}/commit", laptop.group());
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&laptop, [1; 16], 0, b"x")]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    laptop.root = root;
    laptop.epoch = 2;
    let (status, _) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [put(&laptop, [1; 16], 0, b"x")]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_recovery_code_alone_brings_a_new_device_in() {
    let h = Harness::new();
    let (laptop, recovery) = create_group(&h).await;
    // Every device is lost; the user types the 24 words on a new one. The
    // server finds the group by the recovery key.
    let (recovery_token, group_id) = login_recovery(&h, &recovery.key)
        .await
        .expect("the recovery key logs in");
    assert_eq!(group_id, laptop.group_id);
    let group = Bytes::from(group_id).encode();

    // A recovery session cannot touch records.
    let (status, body) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{group}/changes"),
            Some(&recovery_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The device checks that the chain is the one its code governs, then
    // unwraps the root key.
    let state = chain(&h, &recovery_token, &group).await;
    assert_eq!(
        state.recovery_sign_public_key,
        recovery.key.public_key().to_bytes()
    );
    let (epoch, root) = fetch_root(&h, &recovery_token, group_id, RECOVERY_ID, &recovery.kem).await;
    assert_eq!((epoch, root.as_bytes()), (1, laptop.root.as_bytes()));

    let replacement = Device::new(group_id, RootKey::from_bytes([0; 32]), 1);
    // Only adding a device is allowed with a recovery session.
    let (status, _) = append(
        &h,
        &recovery_token,
        &state,
        &recovery.key,
        OpKind::MoveServer(MoveServer {
            authorizer: Authorizer::Recovery,
            url: "https://elsewhere.test".into(),
        }),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = append(
        &h,
        &recovery_token,
        &state,
        &recovery.key,
        add_device(Authorizer::Recovery, &replacement),
        vec![wrap(
            &replacement.kem.public_key(),
            group_id,
            1,
            replacement.device_id,
            &root,
        )],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = login(&h, &replacement).await;
    let (_, unwrapped) = fetch_root(
        &h,
        &token,
        group_id,
        replacement.device_id,
        &replacement.kem,
    )
    .await;
    assert_eq!(unwrapped.as_bytes(), laptop.root.as_bytes());

    // A new recovery code replaces the old one at once.
    let fresh = common::Recovery::new();
    let state = chain(&h, &token, &group).await;
    let (status, body) = append(
        &h,
        &token,
        &state,
        &replacement.key,
        reset_recovery(group_id, replacement.authorizer(), &fresh),
        vec![wrap(
            &fresh.kem.public_key(),
            group_id,
            1,
            RECOVERY_ID,
            &root,
        )],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h
        .call(
            Method::GET,
            &format!("/v1/groups/{group}/wrap"),
            Some(&recovery_token),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old recovery sessions end"
    );
    assert!(login_recovery(&h, &recovery.key).await.is_none());
    // The new words find the same group.
    let (fresh_token, found) = login_recovery(&h, &fresh.key).await.unwrap();
    assert_eq!(found, group_id);
    fetch_root(&h, &fresh_token, group_id, RECOVERY_ID, &fresh.kem).await;
}

#[tokio::test]
async fn recovery_keys_belong_to_one_group() {
    let h = Harness::new();
    let (_, recovery) = create_group(&h).await;
    // A second group cannot start with the same recovery key...
    let other = Device::new(random_bytes().unwrap(), RootKey::generate().unwrap(), 1);
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/groups",
            None,
            Some(genesis_request(&other, &recovery)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // ...nor reset to it later, even with a valid binding signature.
    let (second, _) = create_group(&h).await;
    let token = login(&h, &second).await;
    let state = chain(&h, &token, &second.group()).await;
    let (status, body) = append(
        &h,
        &token,
        &state,
        &second.key,
        reset_recovery(second.group_id, second.authorizer(), &recovery),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["error"]["message"],
        "the recovery key belongs to another group"
    );
}

#[tokio::test]
async fn challenges_take_one_login_form() {
    let h = Harness::new();
    let (laptop, recovery) = create_group(&h).await;
    let recovery_key = Bytes::from(recovery.key.public_key().to_bytes()).encode();
    for request in [
        // A device login cannot claim the recovery id...
        json!({"groupId": laptop.group(), "deviceId": Bytes::from(RECOVERY_ID).encode()}),
        // ...nor mix in a recovery key.
        json!({"groupId": laptop.group(), "recoveryPublicKey": recovery_key}),
        json!({"groupId": laptop.group()}),
        json!({}),
    ] {
        let (status, body) = h
            .call(Method::POST, "/v1/auth/challenge", None, Some(request))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // An unknown recovery key still gets a challenge, which no signature
    // can answer.
    let stranger = common::Recovery::new();
    assert!(login_recovery(&h, &stranger.key).await.is_none());
}

#[tokio::test]
async fn concurrent_appends_cannot_both_extend_the_same_head() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let state = chain(&h, &token, &laptop.group()).await;
    let first = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let second = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let (status, _) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &first),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &second),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let state = chain(&h, &token, &laptop.group()).await;
    assert_eq!(state.devices.len(), 2);
}

#[tokio::test]
async fn forged_operations_and_wrong_wraps_are_refused() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let state = chain(&h, &token, &laptop.group()).await;
    let phone = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);

    // Signed by a key the chain does not know.
    let (status, body) = append(
        &h,
        &token,
        &state,
        &phone.key,
        add_device(laptop.authorizer(), &phone),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // A wrap for a device the operation does not add.
    let stray = wrap(
        &laptop.kem.public_key(),
        laptop.group_id,
        1,
        laptop.device_id,
        &laptop.root,
    );
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &phone),
        vec![stray],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // Skipping an epoch.
    let new_root = RootKey::generate().unwrap();
    let (status, _) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        OpKind::Rotate(Rotate {
            authorizer: laptop.authorizer(),
            epoch: 3,
            root_commitment: new_root.commitment(&laptop.group_id, 3),
            sealed_previous_root: new_root
                .seal_previous(&laptop.root, &laptop.group_id, 3)
                .unwrap(),
        }),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn groups_hold_a_limited_number_of_devices() {
    let h = Harness::with_config(|config| config.limits.max_devices = 1);
    let (laptop, _) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let state = chain(&h, &token, &laptop.group()).await;
    let phone = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &phone),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
    assert_eq!(
        body["error"]["message"],
        "the group has reached its device limit"
    );
}

#[tokio::test]
async fn deleting_a_group_erases_it_and_retires_its_id() {
    let h = Harness::new();
    let (laptop, recovery) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let uri = format!("/v1/groups/{}/commit", laptop.group());
    h.call(
        Method::POST,
        &uri,
        Some(&token),
        Some(json!({"items": [put(&laptop, [1; 16], 0, b"x")]})),
    )
    .await;
    let state = chain(&h, &token, &laptop.group()).await;
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        OpKind::DeleteGroup(DeleteGroup {
            authorizer: laptop.authorizer(),
        }),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Devices still connected learn of the deletion; nobody logs in again.
    let (status, body) = h
        .call(
            Method::POST,
            &uri,
            Some(&token),
            Some(json!({"items": [delete([1; 16], 1)]})),
        )
        .await;
    assert_eq!(status, StatusCode::GONE, "{body}");
    assert_eq!(body["error"]["code"], "group_deleted");
    assert!(
        login_as(&h, laptop.group_id, laptop.device_id, &laptop.key)
            .await
            .is_none()
    );
    assert!(login_recovery(&h, &recovery.key).await.is_none());

    // The id is never used again, but the recovery key is free.
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/groups",
            None,
            Some(genesis_request(&laptop, &recovery)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let fresh = Device::new(random_bytes().unwrap(), RootKey::generate().unwrap(), 1);
    let (status, body) = h
        .call(
            Method::POST,
            "/v1/groups",
            None,
            Some(genesis_request(&fresh, &recovery)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn removing_a_device_ends_the_groups_event_streams() {
    let h = Harness::new();
    let (laptop, _) = create_group(&h).await;
    let token = login(&h, &laptop).await;
    let phone = Device::new(laptop.group_id, RootKey::from_bytes([0; 32]), 1);
    let state = chain(&h, &token, &laptop.group()).await;
    append(
        &h,
        &token,
        &state,
        &laptop.key,
        add_device(laptop.authorizer(), &phone),
        vec![],
    )
    .await;
    let phone_token = login(&h, &phone).await;
    let request = Request::builder()
        .uri(format!("/v1/groups/{}/events", phone.group()))
        .header(header::AUTHORIZATION, format!("Bearer {phone_token}"))
        .body(Body::empty())
        .unwrap();
    let mut events = h.router.clone().oneshot(request).await.unwrap().into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), events.frame())
        .await
        .expect("the current seq arrives");
    assert!(first.is_some());

    let state = chain(&h, &token, &laptop.group()).await;
    let (status, body) = append(
        &h,
        &token,
        &state,
        &laptop.key,
        OpKind::RemoveDevice(RemoveDevice {
            authorizer: laptop.authorizer(),
            device_id: phone.device_id,
        }),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let end = tokio::time::timeout(Duration::from_secs(5), events.frame())
        .await
        .expect("the stream ends");
    assert!(end.is_none());
}
