#![allow(clippy::unwrap_used)]

//! Devices converging through a real server: pairing, edits, conflicts,
//! deletions, removal with key rotation, recovery, and servers that lose
//! data.

mod common;

use common::{Device, Server, http};
use flectar_mail_sync_client::{Error, Event, Joining, SyncClient};
use futures_util::StreamExt;
use std::time::Duration;

/// A new device joins `existing` through a QR code the existing one shows.
async fn join_by_qr(existing: &Device) -> Device {
    let invitation = existing.client.invite_with_qr().await.unwrap();
    let qr_code = invitation.qr_code().unwrap();
    let mut joining = Joining::scanned(http(), &qr_code).unwrap();
    let (words, attempt) = tokio::join!(joining.request(), invitation.wait_for_request());
    let attempt = attempt.unwrap();
    assert_eq!(words.unwrap(), attempt.approval_words());
    let (accepted, joined) = tokio::join!(
        existing.client.accept(&invitation, &attempt),
        joining.finish()
    );
    accepted.unwrap();
    Device::new(joined.unwrap())
}

async fn start_group(server: &Server) -> (Device, String) {
    let (client, code) = SyncClient::create_group(http(), &server.url).await.unwrap();
    (Device::new(client), code.to_words())
}

#[tokio::test]
async fn devices_pair_and_converge() {
    let server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    laptop.set(1, "dark");
    laptop.sync().await;
    assert!(
        laptop.store.secrets.is_some(),
        "the first sync stores the secrets"
    );
    assert_eq!(laptop.store.chain.len(), 1);

    let mut phone = join_by_qr(&laptop).await;

    // A desktop without a camera joins with a short code; both screens
    // show the same words.
    let invitation = laptop.client.invite_with_code().await.unwrap();
    let code = invitation.short_code().unwrap().to_owned();
    let mut joining = Joining::with_code(http(), &server.url, &code)
        .await
        .unwrap();
    let (words, attempt) = tokio::join!(joining.request(), invitation.wait_for_request());
    let attempt = attempt.unwrap();
    assert_eq!(words.unwrap(), attempt.approval_words());
    let (accepted, joined) = tokio::join!(
        laptop.client.accept(&invitation, &attempt),
        joining.finish()
    );
    accepted.unwrap();
    let mut desktop = Device::new(joined.unwrap());

    for device in [&mut phone, &mut desktop] {
        device.sync().await;
        assert_eq!(device.value(1).as_deref(), Some("dark"));
    }

    // Concurrent edits of one record: the newer one wins everywhere.
    phone.set(1, "light");
    tokio::time::sleep(Duration::from_millis(5)).await;
    desktop.set(1, "sepia");
    desktop.set(2, "compact");
    phone.sync().await;
    desktop.sync().await;
    laptop.remove(2);
    laptop.sync().await;
    for device in [&mut laptop, &mut phone, &mut desktop] {
        device.sync().await;
    }
    for device in [&laptop, &phone, &desktop] {
        assert_eq!(device.value(1).as_deref(), Some("sepia"));
        assert_eq!(device.value(2), None);
    }
    assert_eq!(laptop.client.state().await.devices.len(), 3);
}

#[tokio::test]
async fn a_declined_device_does_not_join() {
    let server = Server::start().await;
    let (laptop, _) = start_group(&server).await;
    let (mut joining, qr_code) = Joining::show_qr_code(http(), &server.url).await.unwrap();
    let invitation = laptop.client.invite_scanned(&qr_code).await.unwrap();
    let (_, attempt) = tokio::join!(joining.request(), invitation.wait_for_request());
    attempt.unwrap();
    let (declined, joined) = tokio::join!(laptop.client.decline(&invitation), joining.finish());
    declined.unwrap();
    assert!(matches!(joined, Err(Error::Declined)));
    assert_eq!(laptop.client.state().await.devices.len(), 1);
}

#[tokio::test]
async fn removed_devices_are_locked_out_and_the_key_moves_on() {
    let server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    laptop.set(1, "before");
    laptop.sync().await;
    let mut phone = join_by_qr(&laptop).await;
    let tablet = join_by_qr(&laptop).await;
    phone.sync().await;

    laptop
        .client
        .remove_device(tablet.client.identity().device_id())
        .await
        .unwrap();
    let state = laptop.client.state().await;
    assert_eq!(state.epoch, 2);
    assert!(!state.rotation_due);
    assert!(matches!(
        tablet.client.refresh().await,
        Err(Error::LoginRefused | Error::Removed)
    ));

    // The phone follows to the new key, and new writes use it.
    phone.set(2, "after");
    phone.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.value(2).as_deref(), Some("after"));
    // A device added after the rotation still reads records of the first
    // epoch, through the sealed previous root.
    let mut late = join_by_qr(&laptop).await;
    late.sync().await;
    assert_eq!(late.value(1).as_deref(), Some("before"));
    assert_eq!(late.value(2).as_deref(), Some("after"));
}

#[tokio::test]
async fn a_device_that_leaves_has_the_others_rotate_once() {
    let server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    let mut phone = join_by_qr(&laptop).await;
    let tablet = join_by_qr(&laptop).await;
    // The tablet leaves. It cannot rotate for the others, so the chain
    // marks a rotation as due.
    tablet
        .client
        .remove_device(tablet.client.identity().device_id())
        .await
        .unwrap();
    let state = laptop.client.refresh().await.unwrap();
    assert!(state.rotation_due);
    assert_eq!(state.epoch, 1);

    // The next device to sync rotates; the other finds nothing left to do.
    phone.sync().await;
    laptop.sync().await;
    for device in [&laptop, &phone] {
        let state = device.client.state().await;
        assert_eq!(state.epoch, 2);
        assert!(!state.rotation_due);
    }
    assert!(matches!(
        tablet.client.refresh().await,
        Err(Error::LoginRefused | Error::Removed)
    ));
}

#[tokio::test]
async fn the_recovery_code_restores_a_lost_device() {
    let server = Server::start().await;
    let (mut laptop, words) = start_group(&server).await;
    laptop.set(1, "kept");
    laptop.sync().await;

    let mut replacement = Device::new(
        SyncClient::recover(http(), &server.url, &words)
            .await
            .unwrap(),
    );
    replacement.sync().await;
    assert_eq!(replacement.value(1).as_deref(), Some("kept"));

    // A new code replaces the old one at once.
    let fresh = replacement.client.reset_recovery().await.unwrap();
    assert!(matches!(
        SyncClient::recover(http(), &server.url, &words).await,
        Err(Error::UnknownRecoveryCode)
    ));
    let mut again = Device::new(
        SyncClient::recover(http(), &server.url, &fresh.to_words())
            .await
            .unwrap(),
    );
    again.sync().await;
    assert_eq!(again.value(1).as_deref(), Some("kept"));
    assert_eq!(
        replacement.client.state().await.epoch,
        2,
        "a new code also moves to a new key"
    );
}

#[tokio::test]
async fn devices_repair_a_server_restored_from_an_old_backup() {
    let mut server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    laptop.set(1, "one");
    laptop.sync().await;
    let backup = server.backup().await;

    // After the backup: a new device, an edit and a new record.
    let mut phone = join_by_qr(&laptop).await;
    laptop.set(1, "two");
    laptop.set(2, "new");
    laptop.sync().await;
    phone.sync().await;

    server.restart(Some(&backup)).await;
    // The laptop puts back the lost operation and records.
    let report = laptop.sync().await;
    assert!(report.restored);
    assert_eq!(laptop.client.state().await.devices.len(), 2);
    // The phone was in the lost part of the chain; it is back, with the
    // newest values.
    phone.sync().await;
    assert_eq!(phone.value(1).as_deref(), Some("two"));
    assert_eq!(phone.value(2).as_deref(), Some("new"));
}

#[tokio::test]
async fn devices_rebuild_a_server_that_lost_everything() {
    let mut server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    let mut phone = join_by_qr(&laptop).await;
    laptop.set(1, "one");
    laptop.sync().await;
    phone.sync().await;

    server.restart(None).await;
    // The laptop creates the group again from its chain and uploads its
    // records; the phone then logs in as before.
    let report = laptop.sync().await;
    assert!(report.restored);
    phone.set(2, "two");
    phone.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.value(2).as_deref(), Some("two"));
    assert_eq!(phone.value(1).as_deref(), Some("one"));
}

#[tokio::test]
async fn a_cursor_behind_expired_tombstones_reads_everything_again() {
    let server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    laptop.set(1, "doomed");
    laptop.set(2, "kept");
    laptop.sync().await;
    let mut phone = join_by_qr(&laptop).await;
    phone.sync().await;
    assert_eq!(phone.value(1).as_deref(), Some("doomed"));

    laptop.remove(1);
    laptop.set(3, "later");
    laptop.sync().await;
    let purged = server
        .state()
        .store
        .purge_tombstones(i64::MAX)
        .await
        .unwrap();
    assert_eq!(purged, 1);

    phone.sync().await;
    assert_eq!(phone.value(1), None, "the deletion is not missed");
    assert_eq!(phone.value(2).as_deref(), Some("kept"));
    assert_eq!(phone.value(3).as_deref(), Some("later"));
}

#[tokio::test]
async fn events_announce_other_devices_changes() {
    let server = Server::start().await;
    let (laptop, _) = start_group(&server).await;
    let mut phone = join_by_qr(&laptop).await;
    let mut events = Box::pin(laptop.client.events().await.unwrap());
    let first = events.next().await.unwrap().unwrap();
    assert!(matches!(first, Event::Seq(_)));
    phone.set(1, "x");
    phone.sync().await;
    let next = tokio::time::timeout(Duration::from_secs(5), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(next, Event::Seq(seq) if seq >= 1), "{next:?}");
}

#[tokio::test]
async fn a_tampered_qr_code_is_rejected() {
    for qr_code in [
        "https://example.org",
        "flectar-mail-sync:pair?v=2&server=x&slot=AAAAAAAAAAAAAAAAAAAAAA&secret=x",
        "flectar-mail-sync:pair?v=1&server=http://x&slot=short&secret=x",
    ] {
        assert!(matches!(
            Joining::scanned(http(), qr_code),
            Err(Error::NotAPairingCode)
        ));
    }
}

/// A session for `device`, logged in by hand, to write what a correct
/// client never would.
async fn raw_session(server: &Server, device: &Device) -> String {
    use flectar_mail_sync_client::Http;
    use flectar_mail_sync_proto::{Bytes, ChallengeRequest, SessionRequest};
    let api = Http::new(http(), &server.url);
    let identity = device.client.identity();
    let challenge = api
        .challenge(&ChallengeRequest {
            group_id: Some(Bytes::from(identity.group_id())),
            device_id: Some(Bytes::from(identity.device_id())),
            recovery_public_key: None,
        })
        .await
        .unwrap();
    let signature = flectar_mail_sync_crypto::sign_auth(
        &identity.signing_key(),
        &server.url,
        &identity.group_id(),
        &identity.device_id(),
        &challenge.nonce.to_array().unwrap(),
    )
    .unwrap();
    api.session(&SessionRequest {
        challenge_id: challenge.challenge_id,
        signature: Bytes::from(signature),
    })
    .await
    .unwrap()
    .token
}

#[tokio::test]
async fn one_unreadable_record_does_not_stop_sync() {
    use flectar_mail_sync_client::Http;
    use flectar_mail_sync_proto::{Bytes, CommitItem, CommitRequest};
    let server = Server::start().await;
    let (mut laptop, _) = start_group(&server).await;
    let mut phone = join_by_qr(&laptop).await;
    let token = raw_session(&server, &laptop).await;
    Http::new(http(), &server.url)
        .commit(
            &token,
            &laptop.client.identity().group_id(),
            &CommitRequest {
                items: vec![CommitItem {
                    record_id: Bytes::from([9; 16]),
                    expected_seq: 0,
                    deleted: false,
                    tag: Some(Bytes::from([1; 16])),
                    epoch: Some(1),
                    nonce: Some(Bytes::from([2; 24])),
                    ciphertext: Some(Bytes(vec![3; 64])),
                }],
            },
        )
        .await
        .unwrap();
    laptop.set(1, "fine");
    laptop.sync().await;

    let report = phone.sync().await;
    assert_eq!(report.unreadable, 1);
    assert_eq!(phone.value(1).as_deref(), Some("fine"));
    assert_eq!(
        phone.store.cursor, report.high_seq,
        "the cursor moved past it"
    );
}

#[tokio::test]
async fn a_lost_answer_does_not_strand_a_joining_device() {
    use flectar_mail_sync_client::Http;
    use flectar_mail_sync_proto::Bytes;
    let server = Server::start().await;
    let (laptop, _) = start_group(&server).await;
    let invitation = laptop.client.invite_with_qr().await.unwrap();
    let qr_code = invitation.qr_code().unwrap();
    let mut joining = Joining::scanned(http(), &qr_code).unwrap();
    let (_, attempt) = tokio::join!(joining.request(), invitation.wait_for_request());
    laptop
        .client
        .accept(&invitation, &attempt.unwrap())
        .await
        .unwrap();
    // The slot vanishes before the new device reads the answer.
    let slot = url::Url::parse(&qr_code)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "slot")
        .map(|(_, value)| Bytes::decode(&value).unwrap().to_array().unwrap())
        .unwrap();
    Http::new(http(), &server.url)
        .delete_slot(&slot)
        .await
        .unwrap();

    let mut phone = Device::new(joining.finish().await.unwrap());
    phone.sync().await;
    assert_eq!(phone.client.state().await.devices.len(), 2);
}

/// A small deterministic generator, so failures replay.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self, below: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % below
    }
}

#[tokio::test]
async fn random_edits_on_three_devices_converge() {
    for seed in [1, 7, 42, 1234, 99_991] {
        let server = Server::start().await;
        let (laptop, _) = start_group(&server).await;
        let phone = join_by_qr(&laptop).await;
        let desktop = join_by_qr(&laptop).await;
        let mut devices = [laptop, phone, desktop];
        let mut random = Xorshift(seed);
        for step in 0..150 {
            let device = &mut devices[random.next(3) as usize];
            let record = random.next(6) as u8;
            match random.next(10) {
                0..=4 => device.set(record, &format!("{seed}-{step}")),
                5..=6 => device.remove(record),
                _ => {
                    device.sync().await;
                }
            }
        }
        // Everyone syncs twice: the first round uploads, the second reads.
        for _ in 0..2 {
            for device in &mut devices {
                device.sync().await;
            }
        }
        let [first, rest @ ..] = &devices;
        for device in rest {
            assert_eq!(device.store.entries, first.store.entries, "seed {seed}");
        }
        for device in &devices {
            assert!(device.store.outbox.is_empty(), "seed {seed}");
        }
    }
}

#[tokio::test]
async fn named_records_get_the_same_id_on_every_device_and_after_rotation() {
    let server = Server::start().await;
    let (laptop, _) = start_group(&server).await;
    let phone = join_by_qr(&laptop).await;
    let id = laptop.client.named_record_id("pref:theme").await.unwrap();
    assert_eq!(
        id,
        phone.client.named_record_id("pref:theme").await.unwrap()
    );
    assert_ne!(
        id,
        laptop
            .client
            .named_record_id("pref:language")
            .await
            .unwrap()
    );
    laptop.client.rotate().await.unwrap();
    assert_eq!(
        id,
        laptop.client.named_record_id("pref:theme").await.unwrap()
    );
    // A device that joins after the rotation derives the same id.
    let tablet = join_by_qr(&laptop).await;
    assert_eq!(
        id,
        tablet.client.named_record_id("pref:theme").await.unwrap()
    );
}
