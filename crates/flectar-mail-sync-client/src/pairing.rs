//! Adding a device (SPEC §4.9, §6.12).
//!
//! The existing device runs an [`Invitation`]; the new one a [`Joining`].
//! Either device may open the slot and show the QR code: a phone usually
//! scans a computer's screen, whichever of the two is new. Without a camera,
//! the existing device shows a short code instead, and the user compares
//! approval words on both screens.

use crate::client::SyncClient;
use crate::error::{Error, Result};
use crate::http::Http;
use crate::identity::DeviceIdentity;
use flectar_mail_sync_crypto::{
    INVITE_INDEX, Invite, JOIN_REQUEST_INDEX, JOIN_RESULT_INDEX, JoinRequest, JoinResult,
    PairingSecret, approval_words, device_binding_message,
};
use flectar_mail_sync_proto::Bytes;
use std::time::Duration;
use url::Url;

const QR_SCHEME: &str = "flectar-mail-sync";
/// One read waits this long for the other device, then asks again.
const POLL: Duration = Duration::from_secs(25);

/// How the two devices protect their messages.
#[derive(Clone, Debug)]
enum Channel {
    /// Sealed under the secret the QR code carries.
    Sealed(PairingSecret),
    /// In the clear; the user compares approval words.
    Clear,
}

impl Channel {
    fn seal(&self, slot_id: &[u8; 16], index: u8, message: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Sealed(secret) => secret.seal(slot_id, index, message)?,
            Self::Clear => message.to_vec(),
        })
    }

    fn open(&self, slot_id: &[u8; 16], index: u8, message: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Sealed(secret) => secret.open(slot_id, index, message)?,
            Self::Clear => message.to_vec(),
        })
    }
}

/// A pairing slot as one device sees it.
#[derive(Clone, Debug)]
struct Slot {
    /// The server holding the slot.
    http: Http,
    slot_id: [u8; 16],
    channel: Channel,
}

impl Slot {
    async fn put(&self, index: u8, message: &[u8]) -> Result<()> {
        let sealed = self.channel.seal(&self.slot_id, index, message)?;
        self.http.put_message(&self.slot_id, index, sealed).await
    }

    /// The message at `index`, waiting for the other device. Fails with
    /// [`Error::PairingExpired`] once the slot is gone.
    async fn take(&self, index: u8) -> Result<Vec<u8>> {
        loop {
            match self.http.messages(&self.slot_id, index, POLL).await {
                Ok(page) => {
                    if let Some(message) = page
                        .messages
                        .into_iter()
                        .find(|message| message.index == u32::from(index))
                    {
                        return self
                            .channel
                            .open(&self.slot_id, index, message.message.as_slice());
                    }
                }
                Err(error) if error.status() == Some(404) => return Err(Error::PairingExpired),
                Err(error) => return Err(error),
            }
        }
    }

    async fn close(&self) {
        if let Err(error) = self.http.delete_slot(&self.slot_id).await {
            tracing::debug!(%error, "could not delete the pairing slot");
        }
    }

    /// The QR code content for this slot.
    fn uri(&self) -> String {
        let secret = match &self.channel {
            Channel::Sealed(secret) => Bytes::from(*secret.as_bytes()).encode(),
            Channel::Clear => String::new(),
        };
        let mut uri = Url::parse(&format!("{QR_SCHEME}:pair")).expect("a valid URI");
        uri.query_pairs_mut()
            .append_pair("v", "1")
            .append_pair("server", self.http.server_url())
            .append_pair("slot", &Bytes::from(self.slot_id).encode())
            .append_pair("secret", &secret);
        uri.into()
    }

    fn from_uri(client: &reqwest::Client, uri: &str) -> Result<Self> {
        let uri = Url::parse(uri.trim()).map_err(|_| Error::NotAPairingCode)?;
        if uri.scheme() != QR_SCHEME || uri.path() != "pair" {
            return Err(Error::NotAPairingCode);
        }
        let field = |name: &str| {
            uri.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .ok_or(Error::NotAPairingCode)
        };
        if field("v")? != "1" {
            return Err(Error::NotAPairingCode);
        }
        let bytes = |name: &str| Bytes::decode(&field(name)?).ok_or(Error::NotAPairingCode);
        Ok(Self {
            http: Http::new(client.clone(), &field("server")?),
            slot_id: bytes("slot")?.to_array().ok_or(Error::NotAPairingCode)?,
            channel: Channel::Sealed(PairingSecret::from_bytes(
                bytes("secret")?.to_array().ok_or(Error::NotAPairingCode)?,
            )),
        })
    }
}

/// The existing device's side of a pairing.
#[derive(Debug)]
pub struct Invitation {
    slot: Slot,
    code: Option<String>,
    invite: Invite,
}

/// A new device asking to join, waiting for the user's decision.
#[derive(Clone, Debug)]
pub struct JoinAttempt {
    request: JoinRequest,
    words: [&'static str; 6],
}

impl JoinAttempt {
    /// The words to compare with the new device's screen. They matter when
    /// pairing with a short code; with a QR code the channel is already
    /// authenticated.
    pub fn approval_words(&self) -> [&'static str; 6] {
        self.words
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.request.device.device_id
    }
}

impl Invitation {
    /// The QR code to show, when the invitation has one.
    pub fn qr_code(&self) -> Option<String> {
        matches!(self.slot.channel, Channel::Sealed(_)).then(|| self.slot.uri())
    }

    /// The eight digits to show, when the invitation has them.
    pub fn short_code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// Wait for the new device's request.
    pub async fn wait_for_request(&self) -> Result<JoinAttempt> {
        let request = JoinRequest::decode(&self.slot.take(JOIN_REQUEST_INDEX).await?)?;
        flectar_mail_sync_crypto::SignPublicKey::from_bytes(&request.device.sign_public_key)?
            .verify(
                &device_binding_message(&self.invite.group_id, &request.device)?,
                &request.binding_signature,
            )?;
        Ok(JoinAttempt {
            words: approval_words(
                &self.invite.group_id,
                &self.invite.head_hash,
                &request.device,
            ),
            request,
        })
    }
}

impl SyncClient {
    async fn invite_into(&self, slot: Slot, code: Option<String>) -> Result<Invitation> {
        let state = self.refresh().await?;
        let invite = Invite {
            server_url: self.identity.server_url().to_owned(),
            group_id: self.identity.group_id(),
            head_index: state.head_index,
            head_hash: state.head_hash,
        };
        slot.put(INVITE_INDEX, &invite.encode()?).await?;
        Ok(Invitation { slot, code, invite })
    }

    /// Invite a device by showing a QR code.
    pub async fn invite_with_qr(&self) -> Result<Invitation> {
        let created = self.http.open_slot(false).await?;
        let slot = Slot {
            http: self.http.clone(),
            slot_id: created
                .slot_id
                .to_array()
                .ok_or_else(|| Error::Malformed("slot id".into()))?,
            channel: Channel::Sealed(PairingSecret::generate()?),
        };
        self.invite_into(slot, None).await
    }

    /// Invite a device that has no camera: show the returned short code and
    /// compare approval words before accepting.
    pub async fn invite_with_code(&self) -> Result<Invitation> {
        let created = self.http.open_slot(true).await?;
        let slot = Slot {
            http: self.http.clone(),
            slot_id: created
                .slot_id
                .to_array()
                .ok_or_else(|| Error::Malformed("slot id".into()))?,
            channel: Channel::Clear,
        };
        self.invite_into(slot, created.code).await
    }

    /// Answer the QR code a new device shows.
    pub async fn invite_scanned(&self, qr_code: &str) -> Result<Invitation> {
        self.invite_into(Slot::from_uri(self.http.client(), qr_code)?, None)
            .await
    }

    /// Add the device and tell it so.
    pub async fn accept(&self, invitation: &Invitation, attempt: &JoinAttempt) -> Result<()> {
        let index = self
            .add_device(&attempt.request.device, attempt.request.binding_signature)
            .await?;
        invitation
            .slot
            .put(JOIN_RESULT_INDEX, &JoinResult::Added { index }.encode())
            .await?;
        Ok(())
    }

    pub async fn decline(&self, invitation: &Invitation) -> Result<()> {
        invitation
            .slot
            .put(JOIN_RESULT_INDEX, &JoinResult::Declined.encode())
            .await?;
        invitation.slot.close().await;
        Ok(())
    }
}

/// The new device's side of a pairing.
#[derive(Debug)]
pub struct Joining {
    http: reqwest::Client,
    slot: Slot,
    invite: Option<Invite>,
    identity: Option<DeviceIdentity>,
}

impl Joining {
    /// Show a QR code for an existing device to scan. `server_url` holds
    /// the slot; the group may live elsewhere.
    pub async fn show_qr_code(http: reqwest::Client, server_url: &str) -> Result<(Self, String)> {
        let api = Http::new(http.clone(), server_url);
        let created = api.open_slot(false).await?;
        let slot = Slot {
            http: api,
            slot_id: created
                .slot_id
                .to_array()
                .ok_or_else(|| Error::Malformed("slot id".into()))?,
            channel: Channel::Sealed(PairingSecret::generate()?),
        };
        let uri = slot.uri();
        Ok((
            Self {
                http,
                slot,
                invite: None,
                identity: None,
            },
            uri,
        ))
    }

    /// The QR code of an existing device was scanned.
    pub fn scanned(http: reqwest::Client, qr_code: &str) -> Result<Self> {
        Ok(Self {
            slot: Slot::from_uri(&http, qr_code)?,
            http,
            invite: None,
            identity: None,
        })
    }

    /// The user typed the short code an existing device shows.
    pub async fn with_code(http: reqwest::Client, server_url: &str, code: &str) -> Result<Self> {
        let digits: String = code.chars().filter(char::is_ascii_digit).collect();
        let api = Http::new(http.clone(), server_url);
        let slot = match api.resolve_code(&digits).await {
            Ok(slot) => slot,
            Err(error) if error.status() == Some(404) => return Err(Error::PairingExpired),
            Err(error) => return Err(error),
        };
        Ok(Self {
            slot: Slot {
                http: api,
                slot_id: slot
                    .slot_id
                    .to_array()
                    .ok_or_else(|| Error::Malformed("slot id".into()))?,
                channel: Channel::Clear,
            },
            http,
            invite: None,
            identity: None,
        })
    }

    /// Wait for the invitation, then ask to join with fresh keys. Returns the
    /// approval words to show while the user compares them.
    pub async fn request(&mut self) -> Result<[&'static str; 6]> {
        let invite = Invite::decode(&self.slot.take(INVITE_INDEX).await?)?;
        let identity = DeviceIdentity::generate(&invite.server_url, invite.group_id)?;
        let keys = identity.keys()?;
        let request = JoinRequest {
            binding_signature: identity
                .signing_key()
                .sign(&device_binding_message(&invite.group_id, &keys)?),
            device: keys,
        };
        self.slot
            .put(JOIN_REQUEST_INDEX, &request.encode()?)
            .await?;
        let words = approval_words(&invite.group_id, &invite.head_hash, &request.device);
        self.invite = Some(invite);
        self.identity = Some(identity);
        Ok(words)
    }

    /// Wait for the existing device's answer. Once added, this device logs
    /// in, checks that the chain contains the head it was invited at, and
    /// unwraps the group's root key.
    pub async fn finish(self) -> Result<SyncClient> {
        let (Some(invite), Some(identity)) = (self.invite, self.identity) else {
            return Err(Error::Malformed("finish needs request first".into()));
        };
        match self.slot.take(JOIN_RESULT_INDEX).await {
            Ok(result) => {
                self.slot.close().await;
                if JoinResult::decode(&result)? == JoinResult::Declined {
                    return Err(Error::Declined);
                }
            }
            // The answer may have been lost after the other device added
            // this one: logging in tells.
            Err(Error::PairingExpired) => {}
            Err(error) => return Err(error),
        }
        match SyncClient::join(self.http, identity, &invite).await {
            Err(Error::LoginRefused) => Err(Error::PairingExpired),
            other => other,
        }
    }
}
