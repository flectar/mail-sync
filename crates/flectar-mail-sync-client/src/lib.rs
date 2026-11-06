//! Client of Flectar Mail Sync.
//!
//! - [`SyncClient`]: a device's connection to its group. It verifies the
//!   group's chain, holds the root keys, changes membership, and syncs
//!   records with a [`Store`] the app implements.
//! - [`SyncClient::create_group`] and [`SyncClient::recover`] start a device
//!   without another one; [`Joining`] and [`Invitation`] pair a new device
//!   with an existing one.
//!
//! The app persists three things: [`Secrets`] in the OS key store, and the
//! chain and its [`Store`] state in its database. [`SyncClient::sync`] saves
//! them through the store when they change.
//!
//! `docs/SPEC.md` describes the protocol.

mod client;
mod clock;
mod engine;
mod error;
mod http;
mod identity;
mod memory;
mod pairing;
mod sse;

pub use client::{Secrets, SyncClient};
pub use clock::{Clock, Stamp};
pub use engine::{Entry, Mirrored, Pending, Remote, Store, SyncReport};
pub use error::{Error, Result, StoreError};
pub use flectar_mail_sync_crypto::{GroupState, RecoveryCode};
pub use flectar_mail_sync_proto::ErrorCode;
pub use http::Http;
pub use identity::{ChainOp, DeviceIdentity};
pub use memory::MemoryStore;
pub use pairing::{Invitation, JoinAttempt, Joining};
pub use sse::Event;

/// Apps run these futures on multi-threaded runtimes, so each must be
/// `Send`. This only has to compile.
#[cfg(test)]
#[allow(dead_code, clippy::unwrap_used)]
fn futures_are_send(
    client: &SyncClient,
    store: &mut MemoryStore,
    invitation: &Invitation,
    attempt: &JoinAttempt,
    joining: Joining,
) {
    fn send<T: Send>(_: T) {}
    send(client.sync(store));
    send(client.refresh());
    send(client.events());
    send(client.rotate());
    send(client.remove_device([0; 16]));
    send(client.reset_recovery());
    send(client.delete_group());
    send(client.named_record_id("pref:theme"));
    send(client.invite_with_qr());
    send(client.invite_with_code());
    send(client.invite_scanned(""));
    send(client.accept(invitation, attempt));
    send(client.decline(invitation));
    send(invitation.wait_for_request());
    send(SyncClient::create_group(reqwest::Client::new(), ""));
    send(SyncClient::recover(reqwest::Client::new(), "", ""));
    send(Joining::show_qr_code(reqwest::Client::new(), ""));
    send(Joining::with_code(reqwest::Client::new(), "", ""));
    let mut joining = joining;
    send(joining.request());
    send(joining.finish());
}
