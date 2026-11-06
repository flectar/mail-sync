//! Pairing slot handlers (SPEC §6.12). None needs a session: the new device
//! has none yet. The slot id, from the QR code or a short code, is the only
//! way in, and every message is end-to-end encrypted or checked with
//! approval words.

use super::body;
use crate::error::ApiError;
use crate::pairing::{PairingError, Stored, format_code, parse_code};
use crate::{AppState, now_ms};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use flectar_mail_sync_proto::{
    Bytes, CreatePairing, PairingCreated, PairingMessage, PairingMessages, PairingSlot,
    PutPairingMessage,
};
use serde::Deserialize;
use std::time::Duration;

/// Longest a read waits for a new message. Below the server's 30 s request
/// timeout, and below common proxy timeouts.
const MAX_WAIT: Duration = Duration::from_secs(25);

impl From<PairingError> for ApiError {
    fn from(error: PairingError) -> Self {
        match error {
            PairingError::NotFound => Self::NotFound,
            PairingError::Busy => Self::RateLimited(Duration::from_secs(30)),
            PairingError::OutOfOrder { .. } | PairingError::Conflict => {
                Self::PairingConflict(error.to_string())
            }
            PairingError::SlotFull { .. } | PairingError::TooLarge { .. } => {
                Self::PayloadTooLarge(error.to_string())
            }
            PairingError::Random => Self::Internal,
        }
    }
}

fn slot_from_path(slot: &str) -> Result<[u8; 16], ApiError> {
    Bytes::decode(slot)
        .and_then(|bytes| bytes.to_array())
        .ok_or_else(|| ApiError::bad_request("the slot id in the path is not valid"))
}

pub async fn create(
    State(state): State<AppState>,
    payload: Result<Json<CreatePairing>, JsonRejection>,
) -> Result<(StatusCode, Json<PairingCreated>), ApiError> {
    let request = body(payload)?;
    let created = state.pairing.create(request.code, now_ms())?;
    Ok((
        StatusCode::CREATED,
        Json(PairingCreated {
            slot_id: Bytes::from(created.slot_id),
            code: created.code.map(format_code),
            expires_at: created.expires_at,
        }),
    ))
}

pub async fn resolve_code(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<PairingSlot>, ApiError> {
    let code = parse_code(&code).ok_or(ApiError::NotFound)?;
    let slot_id = state
        .pairing
        .resolve(code, now_ms())
        .ok_or(ApiError::NotFound)?;
    Ok(Json(PairingSlot {
        slot_id: Bytes::from(slot_id),
    }))
}

pub async fn put_message(
    State(state): State<AppState>,
    Path((slot, index)): Path<(String, u32)>,
    payload: Result<Json<PutPairingMessage>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let slot_id = slot_from_path(&slot)?;
    let request = body(payload)?;
    match state
        .pairing
        .put(&slot_id, index as usize, request.message.0, now_ms())?
    {
        Stored::New => Ok(StatusCode::CREATED),
        Stored::Repeated => Ok(StatusCode::OK),
    }
}

#[derive(Debug, Deserialize)]
pub struct MessagesQuery {
    #[serde(default)]
    from: u32,
    /// Seconds to wait for message `from` if it is not there yet.
    #[serde(default)]
    wait: u64,
}

pub async fn messages(
    State(state): State<AppState>,
    Path(slot): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<PairingMessages>, ApiError> {
    let slot_id = slot_from_path(&slot)?;
    let from = query.from as usize;
    let mut read = state.pairing.read(&slot_id, from, now_ms())?;
    if read.messages.is_empty() && query.wait > 0 {
        let wait = Duration::from_secs(query.wait).min(MAX_WAIT);
        let arrived = tokio::time::timeout(wait, read.changes.wait_for(|count| *count > from))
            .await
            .map(|changed| changed.is_ok());
        match arrived {
            Ok(true) => read = state.pairing.read(&slot_id, from, now_ms())?,
            // The slot ended while we waited.
            Ok(false) => return Err(ApiError::NotFound),
            Err(_timeout) => {}
        }
    }
    Ok(Json(PairingMessages {
        messages: (from..)
            .zip(read.messages)
            .map(|(index, message)| PairingMessage {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                message: Bytes(message),
            })
            .collect(),
        expires_at: read.expires_at,
    }))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(slot): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.pairing.delete(&slot_from_path(&slot)?);
    Ok(StatusCode::NO_CONTENT)
}
