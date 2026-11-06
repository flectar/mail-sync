//! Typed calls to the HTTP API (SPEC §6). Every method is one request; the
//! session handling and retries live in [`crate::SyncClient`].

use crate::error::{Error, Result};
use crate::sse::{Event, SseParser};
use flectar_mail_sync_proto::{
    AppendOp, Appended, Bytes, Challenge, ChallengeRequest, Changes, CommitRequest, CommitResponse,
    Conflict, CreateGroup, CreatePairing, CurrentWrap, ErrorBody, ErrorCode, GroupCreated, Info,
    OpsPage, PairingCreated, PairingMessages, PairingSlot, PutPairingMessage, Session,
    SessionRequest,
};
use futures_util::{Stream, StreamExt};
use reqwest::header::RETRY_AFTER;
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::time::Duration;

/// What a commit did.
#[derive(Debug)]
pub enum CommitOutcome {
    Committed(CommitResponse),
    /// Nothing was stored: these records changed since the writer read them.
    Conflicts(Vec<Conflict>),
}

/// The HTTP API of one server.
#[derive(Clone, Debug)]
pub struct Http {
    client: reqwest::Client,
    base: String,
}

fn group_path(group_id: &[u8; 16]) -> String {
    format!("/v1/groups/{}", Bytes::from(*group_id).encode())
}

fn slot_path(slot_id: &[u8; 16]) -> String {
    format!("/v1/pairing/{}", Bytes::from(*slot_id).encode())
}

impl Http {
    /// `client` carries the app's TLS and trust settings. `server_url` is
    /// the server's public URL; logins are bound to it.
    pub fn new(client: reqwest::Client, server_url: &str) -> Self {
        Self {
            client,
            base: server_url.trim_end_matches('/').to_owned(),
        }
    }

    pub fn server_url(&self) -> &str {
        &self.base
    }

    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn get(&self, path: &str) -> RequestBuilder {
        self.client.get(format!("{}{path}", self.base))
    }

    fn post(&self, path: &str) -> RequestBuilder {
        self.client.post(format!("{}{path}", self.base))
    }

    async fn error(response: Response) -> Error {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok())
            .map(Duration::from_secs);
        match response.json::<ErrorBody>().await {
            Ok(body) => Error::Server {
                status,
                code: body.error.code,
                message: body.error.message,
                retry_after,
            },
            // A proxy in front of the server may answer without our body.
            Err(_) => Error::Server {
                status,
                code: ErrorCode::Unknown,
                message: format!("HTTP {status}"),
                retry_after,
            },
        }
    }

    async fn send(request: RequestBuilder) -> Result<Response> {
        let response = request.send().await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Self::error(response).await)
        }
    }

    async fn json<T: DeserializeOwned>(request: RequestBuilder) -> Result<T> {
        Ok(Self::send(request).await?.json().await?)
    }

    pub async fn info(&self) -> Result<Info> {
        Self::json(self.get("/v1/info")).await
    }

    pub async fn create_group(&self, request: &CreateGroup) -> Result<GroupCreated> {
        Self::json(self.post("/v1/groups").json(request)).await
    }

    pub async fn challenge(&self, request: &ChallengeRequest) -> Result<Challenge> {
        Self::json(self.post("/v1/auth/challenge").json(request)).await
    }

    pub async fn session(&self, request: &SessionRequest) -> Result<Session> {
        Self::json(self.post("/v1/auth/session").json(request)).await
    }

    pub async fn commit(
        &self,
        token: &str,
        group_id: &[u8; 16],
        request: &CommitRequest,
    ) -> Result<CommitOutcome> {
        let response = self
            .post(&format!("{}/commit", group_path(group_id)))
            .bearer_auth(token)
            .json(request)
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT {
            let body: ErrorBody = response.json().await?;
            if body.error.code == ErrorCode::Conflict {
                return Ok(CommitOutcome::Conflicts(body.conflicts));
            }
            return Err(Error::Server {
                status: StatusCode::CONFLICT.as_u16(),
                code: body.error.code,
                message: body.error.message,
                retry_after: None,
            });
        }
        if !response.status().is_success() {
            return Err(Self::error(response).await);
        }
        Ok(CommitOutcome::Committed(response.json().await?))
    }

    pub async fn changes(
        &self,
        token: &str,
        group_id: &[u8; 16],
        since: u64,
        limit: Option<u32>,
    ) -> Result<Changes> {
        let limit = limit.map_or(String::new(), |limit| format!("&limit={limit}"));
        Self::json(
            self.get(&format!(
                "{}/changes?since={since}{limit}",
                group_path(group_id)
            ))
            .bearer_auth(token),
        )
        .await
    }

    pub async fn ops(&self, token: &str, group_id: &[u8; 16], since: u64) -> Result<OpsPage> {
        Self::json(
            self.get(&format!("{}/ops?since={since}", group_path(group_id)))
                .bearer_auth(token),
        )
        .await
    }

    pub async fn append_op(
        &self,
        token: &str,
        group_id: &[u8; 16],
        request: &AppendOp,
    ) -> Result<Appended> {
        Self::json(
            self.post(&format!("{}/ops", group_path(group_id)))
                .bearer_auth(token)
                .json(request),
        )
        .await
    }

    pub async fn wrap(&self, token: &str, group_id: &[u8; 16]) -> Result<CurrentWrap> {
        Self::json(
            self.get(&format!("{}/wrap", group_path(group_id)))
                .bearer_auth(token),
        )
        .await
    }

    /// The group's event stream. It ends when the server closes it; callers
    /// reconnect with backoff.
    pub async fn events(
        &self,
        token: &str,
        group_id: &[u8; 16],
    ) -> Result<impl Stream<Item = Result<Event>> + Send + use<>> {
        let response = Self::send(
            self.get(&format!("{}/events", group_path(group_id)))
                .bearer_auth(token)
                .header(reqwest::header::ACCEPT, "text/event-stream"),
        )
        .await?;
        let mut parser = SseParser::default();
        Ok(response
            .bytes_stream()
            .map(move |chunk| match chunk {
                Ok(chunk) => Ok(parser.push(&chunk)),
                Err(error) => Err(Error::from(error)),
            })
            .flat_map(|events| {
                futures_util::stream::iter(match events {
                    Ok(events) => events.into_iter().map(Ok).collect(),
                    Err(error) => vec![Err(error)],
                })
            }))
    }

    pub async fn open_slot(&self, code: bool) -> Result<PairingCreated> {
        Self::json(self.post("/v1/pairing").json(&CreatePairing { code })).await
    }

    pub async fn resolve_code(&self, code: &str) -> Result<PairingSlot> {
        Self::json(self.get(&format!("/v1/pairing/codes/{code}"))).await
    }

    pub async fn put_message(&self, slot_id: &[u8; 16], index: u8, message: Vec<u8>) -> Result<()> {
        Self::send(
            self.client
                .put(format!(
                    "{}{}/messages/{index}",
                    self.base,
                    slot_path(slot_id)
                ))
                .json(&PutPairingMessage {
                    message: Bytes(message),
                }),
        )
        .await?;
        Ok(())
    }

    /// Messages from index `from`, waiting up to `wait` for one to arrive.
    pub async fn messages(
        &self,
        slot_id: &[u8; 16],
        from: u8,
        wait: Duration,
    ) -> Result<PairingMessages> {
        Self::json(self.get(&format!(
            "{}/messages?from={from}&wait={}",
            slot_path(slot_id),
            wait.as_secs()
        )))
        .await
    }

    pub async fn delete_slot(&self, slot_id: &[u8; 16]) -> Result<()> {
        Self::send(
            self.client
                .delete(format!("{}{}", self.base, slot_path(slot_id))),
        )
        .await?;
        Ok(())
    }
}
