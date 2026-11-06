//! HTTP handlers (SPEC §6).

pub mod pairing;

use crate::error::ApiError;
use crate::limits::{bucket, client_address};
use crate::sessions::{Principal, SessionError};
use crate::store::{CommitOutcome, NewGroup, Payload, PendingChange, WrapIn};
use crate::{AppState, now_ms};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use flectar_mail_sync_crypto::{Op, OpKind, RECOVERY_ID, SignPublicKey, random_bytes, verify_auth};
use flectar_mail_sync_proto::{
    AppendOp, Appended, Bytes, Challenge, ChallengeRequest, Change, Changes, CommitRequest,
    CommitResponse, Committed, CreateGroup, CurrentWrap, GroupCreated, Info, ItemError, OpsPage,
    PROTOCOL_VERSION, Record, SeqEvent, Session, SessionRequest, SignedOp, Wrap, len,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

/// Map a JSON body rejection to our error body.
pub(crate) fn body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
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
        let principal = state
            .sessions
            .authenticate(token.trim(), now_ms())
            .ok_or(ApiError::Unauthorized)?;
        state
            .rate_limits
            .group
            .check(principal.group_id, Instant::now())
            .map_err(ApiError::RateLimited)?;
        Ok(Authed(principal))
    }
}

/// Which per-address limit a route counts against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    CreateGroup,
    Login,
    Pairing,
    PairingCode,
}

/// Middleware: refuse requests over the client address's rate limit. The
/// app must be served with connection info, as [`crate::serve`] does.
pub async fn limit_by_address(
    State((state, limit)): State<(AppState, Limit)>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let address = bucket(client_address(
        peer,
        request.headers(),
        &state.config.trusted_proxies,
    ));
    let limiter = match limit {
        Limit::CreateGroup => &state.rate_limits.create_group,
        Limit::Login => &state.rate_limits.login,
        Limit::Pairing => &state.rate_limits.pairing,
        Limit::PairingCode => &state.rate_limits.pairing_code,
    };
    match limiter.check(address, Instant::now()) {
        Ok(()) => next.run(request).await,
        Err(wait) => ApiError::RateLimited(wait).into_response(),
    }
}

const RECOVERY_ONLY: &str =
    "a recovery session may only read the chain and its wrap, and add a device";

impl Authed {
    /// The session's group, if it is the one named in the path. Recovery
    /// sessions may use it too.
    fn group(&self, path_group: &str) -> Result<[u8; 16], ApiError> {
        let group_id = group_from_path(path_group)?;
        if group_id != self.0.group_id {
            return Err(ApiError::Forbidden("the session belongs to another group"));
        }
        Ok(group_id)
    }

    /// Like [`Authed::group`], but only for a device session: recovery
    /// sessions may read the chain and the recovery wrap, and add a device,
    /// nothing else.
    fn device_group(&self, path_group: &str) -> Result<[u8; 16], ApiError> {
        if self.0.is_recovery() {
            return Err(ApiError::Forbidden(RECOVERY_ONLY));
        }
        self.group(path_group)
    }
}

fn signatures(values: &[Bytes]) -> Result<Vec<[u8; 64]>, ApiError> {
    values
        .iter()
        .map(|signature| fixed::<{ len::SIGNATURE }>(signature, "signature"))
        .collect()
}

fn wraps(values: Vec<Wrap>) -> Result<Vec<WrapIn>, ApiError> {
    values
        .into_iter()
        .map(|wrap| {
            Ok(WrapIn {
                target: fixed::<16>(&wrap.target, "wrap target")?,
                ciphertext: wrap.ciphertext.0,
            })
        })
        .collect()
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
    let group = state
        .store
        .create_group(
            NewGroup {
                signatures: signatures(&request.signatures)?,
                wraps: wraps(request.wraps)?,
                op: request.op.0,
            },
            now_ms(),
        )
        .await?;
    tracing::info!("group created");
    Ok((
        StatusCode::CREATED,
        Json(GroupCreated {
            group_id: Bytes::from(group.group_id),
            high_seq: 0,
        }),
    ))
}

pub async fn challenge(
    State(state): State<AppState>,
    payload: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Result<Json<Challenge>, ApiError> {
    let request = body(payload)?;
    let principal = match (
        &request.group_id,
        &request.device_id,
        &request.recovery_public_key,
    ) {
        (Some(group_id), Some(device_id), None) => {
            let device_id = fixed::<{ len::DEVICE_ID }>(device_id, "deviceId")?;
            if device_id == RECOVERY_ID {
                return Err(ApiError::bad_request(
                    "this device id is reserved; recovery logs in with recoveryPublicKey",
                ));
            }
            Principal {
                group_id: fixed::<{ len::GROUP_ID }>(group_id, "groupId")?,
                device_id,
            }
        }
        (None, None, Some(key)) => {
            let key = fixed::<{ len::SIGN_PUBLIC_KEY }>(key, "recoveryPublicKey")?;
            // An unknown key gets a challenge for a group that does not
            // exist, which no signature can answer, so the endpoint does not
            // reveal which keys are in use.
            let group_id = match state.store.group_by_recovery_key(key).await? {
                Some(group_id) => group_id,
                None => random_bytes().map_err(|_| ApiError::Internal)?,
            };
            Principal {
                group_id,
                device_id: RECOVERY_ID,
            }
        }
        _ => {
            return Err(ApiError::bad_request(
                "send groupId and deviceId, or only recoveryPublicKey",
            ));
        }
    };
    let (id, pending) = state
        .sessions
        .issue_challenge(principal, now_ms())
        .map_err(|error| match error {
            SessionError::Busy => ApiError::RateLimited(Duration::from_secs(10)),
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
    // Recovery does not know its group before logging in, so its login
    // message names RECOVERY_ID as the group too (SPEC §4.7).
    let (key, signed_group) = if principal.is_recovery() {
        (
            state.store.recovery_key(principal.group_id).await?,
            RECOVERY_ID,
        )
    } else {
        (
            state
                .store
                .device_key(principal.group_id, principal.device_id)
                .await?,
            principal.group_id,
        )
    };
    let key = SignPublicKey::from_bytes(&key.ok_or(ApiError::Unauthorized)?)
        .map_err(|_| ApiError::Internal)?;
    verify_auth(
        &key,
        &state.config.public_url,
        &signed_group,
        &principal.device_id,
        &pending.nonce,
        request.signature.as_slice(),
    )
    .map_err(|_| ApiError::Unauthorized)?;
    let (token, expires_at) = state
        .sessions
        .create_session(principal, now)
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(Session {
        token,
        expires_at,
        group_id: Bytes::from(principal.group_id),
    }))
}

pub async fn commit(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
    payload: Result<Json<CommitRequest>, JsonRejection>,
) -> Result<Json<CommitResponse>, ApiError> {
    let group_id = auth.device_group(&group)?;
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
    let group_id = auth.device_group(&group)?;
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
    let group_id = auth.device_group(&group)?;
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

#[derive(Debug, Deserialize)]
pub struct OpsQuery {
    #[serde(default)]
    since: u64,
}

/// The group's chain from `since` (SPEC §6.9).
pub async fn ops(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
    Query(query): Query<OpsQuery>,
) -> Result<Json<OpsPage>, ApiError> {
    let group_id = auth.group(&group)?;
    let (ops, more) = state
        .store
        .ops(group_id, query.since, state.config.limits.max_page_records)
        .await?;
    Ok(Json(OpsPage {
        ops: ops
            .into_iter()
            .map(|op| SignedOp {
                index: op.index,
                op: Bytes(op.op),
                signatures: op.signatures.into_iter().map(Bytes).collect(),
            })
            .collect(),
        more,
    }))
}

/// Append the next operation (SPEC §6.10).
pub async fn append_op(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
    payload: Result<Json<AppendOp>, JsonRejection>,
) -> Result<Json<Appended>, ApiError> {
    let group_id = auth.group(&group)?;
    let request = body(payload)?;
    // A recovery session exists to add a new device; once that device is
    // in, it does everything else with its own session.
    if auth.0.is_recovery()
        && !Op::decode(request.op.as_slice())
            .is_ok_and(|op| matches!(op.kind, OpKind::AddDevice(_)))
    {
        return Err(ApiError::Forbidden(RECOVERY_ONLY));
    }
    let outcome = state
        .store
        .append_op(
            group_id,
            request.op.0,
            signatures(&request.signatures)?,
            wraps(request.wraps)?,
            state.config.limits.max_devices,
            now_ms(),
        )
        .await?;
    match &outcome.op.kind {
        OpKind::RemoveDevice(remove) => {
            state.sessions.revoke_device(Principal {
                group_id,
                device_id: remove.device_id,
            });
            // The removed device may be listening. Streams are per group, so
            // end them all; the remaining devices reconnect.
            state.events.close_group(group_id);
        }
        OpKind::ResetRecovery(_) => state.sessions.revoke_device(Principal {
            group_id,
            device_id: RECOVERY_ID,
        }),
        // Sessions stay valid until they expire, so connected devices learn
        // of the deletion: every request now answers 410 group_deleted.
        OpKind::DeleteGroup(_) => state.events.close_group(group_id),
        _ => {}
    }
    Ok(Json(Appended {
        head_index: outcome.state.head_index,
        epoch: outcome.state.epoch,
    }))
}

/// The current epoch's wrap for the session's device, or for recovery.
pub async fn wrap(
    State(state): State<AppState>,
    auth: Authed,
    Path(group): Path<String>,
) -> Result<Json<CurrentWrap>, ApiError> {
    let group_id = auth.group(&group)?;
    let (epoch, ciphertext) = state
        .store
        .current_wrap(group_id, auth.0.device_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(CurrentWrap {
        epoch,
        ciphertext: Bytes(ciphertext),
    }))
}
