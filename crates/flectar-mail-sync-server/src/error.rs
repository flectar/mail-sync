use crate::store::StoreError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use flectar_mail_sync_proto::{Bytes, Conflict, ErrorBody, ErrorCode, ErrorDetail};

/// Every error a handler can answer with. The response body is always an
/// [`ErrorBody`].
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(&'static str),
    NotFound,
    GroupDeleted,
    GroupExists,
    RecoveryKeyTaken,
    ChainMoved,
    Conflicts(Vec<([u8; 16], u64)>),
    Gone,
    PayloadTooLarge(String),
    QuotaExceeded,
    DeviceLimit,
    RateLimited,
    Internal,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::Deleted => Self::GroupDeleted,
            StoreError::GroupExists => Self::GroupExists,
            StoreError::ChainMoved => Self::ChainMoved,
            StoreError::InvalidOp(message) => Self::BadRequest(message),
            StoreError::Gone => Self::Gone,
            StoreError::QuotaExceeded => Self::QuotaExceeded,
            StoreError::DeviceLimit => Self::DeviceLimit,
            StoreError::RecoveryKeyTaken => Self::RecoveryKeyTaken,
            StoreError::Invalid(message) => Self::BadRequest(message.into()),
            StoreError::Sqlite(_) | StoreError::Task(_) => {
                tracing::error!(%error, "storage failure");
                Self::Internal
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, conflicts) = match self {
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::BadRequest,
                message,
                vec![],
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "a valid session is required".into(),
                vec![],
            ),
            Self::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                message.into(),
                vec![],
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "not found".into(),
                vec![],
            ),
            Self::GroupDeleted => (
                StatusCode::GONE,
                ErrorCode::GroupDeleted,
                "the group was deleted".into(),
                vec![],
            ),
            Self::ChainMoved => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "the chain has a newer head; read it again and rebuild the operation".into(),
                vec![],
            ),
            Self::GroupExists => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "the group already exists".into(),
                vec![],
            ),
            Self::RecoveryKeyTaken => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "the recovery key belongs to another group".into(),
                vec![],
            ),
            Self::Conflicts(stale) => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "some records changed since the writer read them".into(),
                stale
                    .into_iter()
                    .map(|(record_id, current_seq)| Conflict {
                        record_id: Bytes::from(record_id),
                        current_seq,
                    })
                    .collect(),
            ),
            Self::Gone => (
                StatusCode::GONE,
                ErrorCode::Gone,
                "the cursor is older than the tombstone horizon; read again from 0".into(),
                vec![],
            ),
            Self::PayloadTooLarge(message) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::PayloadTooLarge,
                message,
                vec![],
            ),
            Self::QuotaExceeded => (
                StatusCode::INSUFFICIENT_STORAGE,
                ErrorCode::QuotaExceeded,
                "the group would exceed its storage quota".into(),
                vec![],
            ),
            Self::DeviceLimit => (
                StatusCode::INSUFFICIENT_STORAGE,
                ErrorCode::QuotaExceeded,
                "the group has reached its device limit".into(),
                vec![],
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::RateLimited,
                "too many requests; try again later".into(),
                vec![],
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                "internal server error".into(),
                vec![],
            ),
        };
        (
            status,
            Json(ErrorBody {
                error: ErrorDetail { code, message },
                conflicts,
            }),
        )
            .into_response()
    }
}
