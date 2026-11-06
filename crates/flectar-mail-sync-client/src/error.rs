use flectar_mail_sync_proto::ErrorCode;
use std::time::Duration;

/// An error a [`crate::Store`] reports.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not reach the sync server: {0}")]
    Network(#[source] reqwest::Error),
    #[error("the sync server answered {status}: {message}")]
    Server {
        status: u16,
        code: ErrorCode,
        message: String,
        /// From `Retry-After`, when the server sent one.
        retry_after: Option<Duration>,
    },
    #[error("the sync server sent something malformed: {0}")]
    Malformed(String),
    /// The server contradicted what this device verified before: a forked
    /// or rolled-back chain, or a key that does not match its commitment.
    #[error("the sync server cannot be trusted: {0}")]
    Untrusted(&'static str),
    /// The server refused this device's login: it was removed from the
    /// group, the group was deleted, or the server lost the group.
    #[error("the sync server no longer accepts this device")]
    LoginRefused,
    #[error("this device was removed from the sync group")]
    Removed,
    #[error("the sync group was deleted")]
    GroupDeleted,
    #[error("no sync group on this server uses that recovery code")]
    UnknownRecoveryCode,
    #[error("the other device declined")]
    Declined,
    #[error("the pairing expired")]
    PairingExpired,
    #[error("this is not a Flectar Sync pairing code")]
    NotAPairingCode,
    #[error(transparent)]
    Crypto(#[from] flectar_mail_sync_crypto::Error),
    #[error("could not store sync state: {0}")]
    Store(#[source] StoreError),
}

impl Error {
    /// The server's error code, when the server answered with one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub(crate) fn status(&self) -> Option<u16> {
        match self {
            Self::Server { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether trying again later may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::Server { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        if error.is_decode() {
            Self::Malformed(error.to_string())
        } else {
            Self::Network(error)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
