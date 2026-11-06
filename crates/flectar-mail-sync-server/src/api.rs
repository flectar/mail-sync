//! HTTP handlers (SPEC §6).

use crate::error::ApiError;
use crate::sessions::{Principal, SessionError};
use crate::store::{CommitOutcome, NewGroup, Payload, PendingChange};
use crate::{AppState, now_ms};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use flectar_mail_sync_crypto::{Op, OpKind, SignPublicKey, op_hash, verify_auth};
use flectar_mail_sync_proto::{
    Bytes, Challenge, ChallengeRequest, Change, Changes, CommitRequest, CommitResponse, Committed,
    CreateGroup, GroupCreated, Info, ItemError, PROTOCOL_VERSION, Record, SeqEvent, Session,
    SessionRequest, len,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

/// Map a JSON body rejection to our error body.
fn body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    match payload {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(
            ApiError::PayloadTooLarge("the request body is larger than the server accepts".into()),
        ),
        Err(rejection) => Err(ApiError::bad_request(rejection.body_text())),
    }
}

fn fixed<const N: usize>(value: &Bytes, field: &str) -> Result<[u8; N], ApiError> {
    value
        .to_array()
        .ok_or_else(|| ApiError::bad_request(format!("{field} must be {N} bytes")))
}

fn group_from_path(group: &str) -> Result<[u8; 16], ApiError> {
    Bytes::decode(group)
        .and_then(|bytes| bytes.to_array())
        .ok_or_else(|| ApiError::bad_request("the group id in the path is not valid"))
}

/// A request authenticated by a bearer session.
#[derive(Clone, Copy, Debug)]
pub struct Authed(pub Principal);

impl FromRequestParts<AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        // RFC 6750 §2.1 with RFC 9110 §11.1: the scheme is case-insensitive.
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token)
            .ok_or(ApiError::Unauthorized)?;
        state
            .sessions
            .authenticate(token.trim(), now_ms())
            .map(Authed)
            .ok_or(ApiError::Unauthorized)
    }
}

impl Authed {
    /// The session's group, if it is the one named in the path.
    fn group(&self, path_group: &str) -> Result<[u8; 16], ApiError> {
        let group_id = group_from_path(path_group)?;
        if group_id != self.0.group_id {
            return Err(ApiError::Forbidden);
        }
        Ok(group_id)
    }
}

pub async fn info(State(state): State<AppState>) -> Json<Info> {
    Json(Info {
        server: "flectar-mail-sync".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol_min: PROTOCOL_VERSION,
        protocol_max: PROTOCOL_VERSION,
        limits: state.config.limits.clone(),
    })
}

pub async fn healthz(State(state): State<AppState>) -> Response {
    match state.store.ping().await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(error) => {
            tracing::error!(%error, "health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response()
        }
    }
}

pub async fn create_group(
    State(state): State<AppState>,
    payload: Result<Json<CreateGroup>, JsonRejection>,
) -> Result<(StatusCode, Json<GroupCreated>), ApiError> {
    let request = body(payload)?;
    let signatures: Vec<&[u8]> = request.signatures.iter().map(Bytes::as_slice).collect();
    let op = Op::verify_genesis(request.op.as_slice(), &signatures)
        .map_err(|error| ApiError::bad_request(format!("invalid genesis operation: {error}")))?;
    let OpKind::Genesis(genesis) = &op.kind;
    state
        .store
        .create_group(
            NewGroup {
                group_id: op.group_id,
                op_hash: op_hash(request.op.as_slice()),
                op: request.op.0.clone(),
                signatures: signatures.concat(),
                recovery_sign_public_key: genesis.recovery_sign_public_key,
                device_id: genesis.device.device_id,
                device_sign_public_key: genesis.device.sign_public_key,
            },
            now_ms(),
        )
        .await?;
    tracing::info!("group created");
    Ok((
        StatusCode::CREATED,
        Json(GroupCreated {
            group_id: Bytes::from(op.group_id),
            high_seq: 0,
        }),
    ))
}

pub async fn challenge(
    State(state): State<AppState>,
    payload: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Result<Json<Challenge>, ApiError> {
    let request = body(payload)?;
    let principal = Principal {
        group_id: fixed::<{ len::GROUP_ID }>(&request.group_id, "groupId")?,
        device_id: fixed::<{ len::DEVICE_ID }>(&request.device_id, "deviceId")?,
    };
    let (id, pending) = state
        .sessions
        .issue_challenge(principal, now_ms())
        .map_err(|error| match error {
            SessionError::Busy => ApiError::RateLimited,
            SessionError::Random => ApiError::Internal,
        })?;
    Ok(Json(Challenge {
        challenge_id: Bytes::from(id),
        nonce: Bytes::from(pending.nonce),
        expires_at: pending.expires_at,
    }))
}

pub async fn session(
    State(state): State<AppState>,
    payload: Result<Json<SessionRequest>, JsonRejection>,
) -> Result<Json<Session>, ApiError> {
    let request = body(payload)?;
    let id = fixed::<{ len::CHALLENGE_ID }>(&request.challenge_id, "challengeId")?;
    let now = now_ms();
    let pending = state
        .sessions
        .take_challenge(&id, now)
        .ok_or(ApiError::Unauthorized)?;
    let principal = pending.principal;
    let key = state
        .store
        .device_key(principal.group_id, principal.device_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let key = SignPublicKey::from_bytes(&key).map_err(|_| ApiError::Internal)?;
    verify_auth(
        &key,
        &state.config.public_url,
        &principal.group_id,
        &principal.device_id,
        &pending.nonce,
        request.signature.as_slice(),
    )
    .map_err(|_| ApiError::Unauthorized)?;
    let (token, expires_at) = state
        .sessions
        .create_session(principal, now)
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(Session { token, expires_at }))
}

pub async fn commit(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
    payload: Result<Json<CommitRequest>, JsonRejection>,
) -> Result<Json<CommitResponse>, ApiError> {
    let group_id = auth.group(&group)?;
    let request = body(payload)?;
    let limits = &state.config.limits;
    if request.items.is_empty() {
        return Err(ApiError::bad_request("a commit needs at least one item"));
    }
    if request.items.len() > limits.max_batch_records as usize {
        return Err(ApiError::PayloadTooLarge(format!(
            "a commit carries at most {} records",
            limits.max_batch_records
        )));
    }
    let mut seen = HashSet::with_capacity(request.items.len());
    let mut changes = Vec::with_capacity(request.items.len());
    for item in &request.items {
        let change = item
            .change(limits.max_record_bytes)
            .map_err(|error| match error {
                ItemError::TooLarge => ApiError::PayloadTooLarge(error.to_string()),
                ItemError::Invalid(message) => ApiError::bad_request(message),
            })?;
        let record_id = fixed::<{ len::RECORD_ID }>(&item.record_id, "recordId")?;
        if !seen.insert(record_id) {
            return Err(ApiError::bad_request(
                "a record appears twice in one commit",
            ));
        }
        let payload = match change {
            Change::Put {
                tag,
                epoch,
                nonce,
                ciphertext,
            } => Some(Payload {
                tag: tag.to_vec(),
                epoch,
                nonce: nonce.to_vec(),
                ciphertext: ciphertext.to_vec(),
            }),
            Change::Delete if item.expected_seq == 0 => {
                return Err(ApiError::bad_request(
                    "a record that does not exist cannot be deleted",
                ));
            }
            Change::Delete => None,
        };
        changes.push(PendingChange {
            record_id,
            expected_seq: item.expected_seq,
            payload,
        });
    }
    match state
        .store
        .commit(group_id, changes, limits.max_group_bytes, now_ms())
        .await?
    {
        CommitOutcome::Applied { high_seq, seqs } => {
            state.events.publish(group_id, high_seq);
            Ok(Json(CommitResponse {
                high_seq,
                results: seqs
                    .into_iter()
                    .map(|(record_id, seq)| Committed {
                        record_id: Bytes::from(record_id),
                        seq,
                    })
                    .collect(),
            }))
        }
        CommitOutcome::Conflicts(stale) => Err(ApiError::Conflicts(stale)),
    }
}

#[derive(Debug, Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    since: u64,
    limit: Option<u32>,
}

pub async fn changes(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<Changes>, ApiError> {
    let group_id = auth.group(&group)?;
    let max = state.config.limits.max_page_records;
    let limit = query.limit.unwrap_or(max).clamp(1, max);
    let page = state.store.changes(group_id, query.since, limit).await?;
    Ok(Json(Changes {
        records: page
            .records
            .into_iter()
            .map(|record| match record.payload {
                Some(payload) => Record {
                    record_id: Bytes(record.record_id),
                    seq: record.seq,
                    deleted: false,
                    tag: Some(Bytes(payload.tag)),
                    epoch: Some(payload.epoch),
                    nonce: Some(Bytes(payload.nonce)),
                    ciphertext: Some(Bytes(payload.ciphertext)),
                },
                None => Record {
                    record_id: Bytes(record.record_id),
                    seq: record.seq,
                    deleted: true,
                    tag: None,
                    epoch: None,
                    nonce: None,
                    ciphertext: None,
                },
            })
            .collect(),
        high_seq: page.high_seq,
        more: page.more,
    }))
}

fn seq_event(high_seq: u64) -> Event {
    Event::default()
        .event("seq")
        .json_data(SeqEvent { high_seq })
        .unwrap_or_default()
}

/// Server-Sent Events: the current `high_seq` first, then every advance.
pub async fn events(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let group_id = auth.group(&group)?;
    // Subscribe before reading, so no advance between the two is missed.
    let updates = state.events.subscribe(group_id);
    let current = state.store.high_seq(group_id).await?;
    let first = tokio_stream::once(Ok(seq_event(current)));
    let rest = BroadcastStream::new(updates).filter_map(|update| match update {
        Ok(high_seq) => Some(Ok(seq_event(high_seq))),
        // A lagging listener skipped values; the next one carries the newest.
        Err(_) => None,
    });
    Ok(Sse::new(first.chain(rest)).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
