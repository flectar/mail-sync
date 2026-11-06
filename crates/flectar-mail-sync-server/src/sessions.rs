//! Login challenges and bearer sessions.
//!
//! Both live in memory: a restart only makes devices log in again, which
//! costs one round trip. Tokens are stored as SHA-256 hashes, so a memory
//! dump does not reveal usable tokens.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use flectar_mail_sync_crypto::random_bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Pending challenges kept at most; beyond this, new logins are refused
/// until old challenges expire.
const MAX_PENDING_CHALLENGES: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal {
    pub group_id: [u8; 16],
    pub device_id: [u8; 16],
}

#[derive(Clone, Copy, Debug)]
pub struct PendingChallenge {
    pub principal: Principal,
    pub nonce: [u8; 32],
    pub expires_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("too many pending logins")]
    Busy,
    #[error("the random generator failed")]
    Random,
}

#[derive(Debug)]
pub struct Sessions {
    challenge_ttl_ms: i64,
    session_ttl_ms: i64,
    challenges: Mutex<HashMap<[u8; 16], PendingChallenge>>,
    sessions: Mutex<HashMap<[u8; 32], (Principal, i64)>>,
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl Sessions {
    pub fn new(challenge_ttl_ms: i64, session_ttl_ms: i64) -> Self {
        Self {
            challenge_ttl_ms,
            session_ttl_ms,
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// A new single-use challenge. Issued even for unknown groups and
    /// devices, so the endpoint does not reveal which ones exist.
    pub fn issue_challenge(
        &self,
        principal: Principal,
        now_ms: i64,
    ) -> Result<([u8; 16], PendingChallenge), SessionError> {
        let id = random_bytes::<16>().map_err(|_| SessionError::Random)?;
        let challenge = PendingChallenge {
            principal,
            nonce: random_bytes().map_err(|_| SessionError::Random)?,
            expires_at: now_ms + self.challenge_ttl_ms,
        };
        let mut challenges = self
            .challenges
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            challenges.retain(|_, pending| pending.expires_at > now_ms);
            if challenges.len() >= MAX_PENDING_CHALLENGES {
                return Err(SessionError::Busy);
            }
        }
        challenges.insert(id, challenge);
        Ok((id, challenge))
    }

    /// Remove and return a challenge if it has not expired.
    pub fn take_challenge(&self, id: &[u8; 16], now_ms: i64) -> Option<PendingChallenge> {
        self.challenges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)
            .filter(|challenge| challenge.expires_at > now_ms)
    }

    /// Start a session; returns the bearer token and its expiry.
    pub fn create_session(
        &self,
        principal: Principal,
        now_ms: i64,
    ) -> Result<(String, i64), SessionError> {
        let token = URL_SAFE_NO_PAD.encode(random_bytes::<32>().map_err(|_| SessionError::Random)?);
        let expires_at = now_ms + self.session_ttl_ms;
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(token_hash(&token), (principal, expires_at));
        Ok((token, expires_at))
    }

    pub fn authenticate(&self, token: &str, now_ms: i64) -> Option<Principal> {
        let sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        sessions
            .get(&token_hash(token))
            .filter(|(_, expires_at)| *expires_at > now_ms)
            .map(|(principal, _)| *principal)
    }

    /// End every session of one device, e.g. after it is removed.
    pub fn revoke_device(&self, principal: Principal) {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (owner, _)| *owner != principal);
    }

    /// Drop expired challenges and sessions.
    pub fn prune(&self, now_ms: i64) {
        self.challenges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, challenge| challenge.expires_at > now_ms);
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (_, expires_at)| *expires_at > now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: Principal = Principal {
        group_id: [1; 16],
        device_id: [2; 16],
    };

    #[test]
    fn challenges_are_single_use_and_expire() {
        let sessions = Sessions::new(1_000, 60_000);
        let (id, _) = sessions.issue_challenge(ALICE, 0).unwrap();
        assert!(sessions.take_challenge(&id, 10).is_some());
        assert!(sessions.take_challenge(&id, 10).is_none(), "single use");
        let (late, _) = sessions.issue_challenge(ALICE, 0).unwrap();
        assert!(sessions.take_challenge(&late, 1_000).is_none(), "expired");
    }

    #[test]
    fn sessions_authenticate_until_expiry_or_revocation() {
        let sessions = Sessions::new(1_000, 60_000);
        let (token, expires_at) = sessions.create_session(ALICE, 0).unwrap();
        assert_eq!(expires_at, 60_000);
        assert_eq!(sessions.authenticate(&token, 59_999), Some(ALICE));
        assert_eq!(sessions.authenticate(&token, 60_000), None);
        assert_eq!(sessions.authenticate("not-a-token", 0), None);
        let (token, _) = sessions.create_session(ALICE, 0).unwrap();
        sessions.revoke_device(ALICE);
        assert_eq!(sessions.authenticate(&token, 1), None);
    }
}
