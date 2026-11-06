//! Pairing slots (SPEC §6.12): short-lived mailboxes in which a new device
//! and an existing one exchange the few messages that add the new device.
//!
//! Slots live in memory. A restart only means scanning the code again, and
//! nothing in a slot is useful once it expires.

use flectar_mail_sync_crypto::random_bytes;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use tokio::sync::watch;

/// Short codes have this many decimal digits.
pub const CODE_DIGITS: usize = 8;
const CODE_SPACE: u32 = 100_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingLimits {
    /// Open slots at most. New pairings wait for older ones to end.
    pub max_slots: usize,
    pub max_messages: usize,
    pub max_message_bytes: usize,
    /// Lifetime of a slot, in milliseconds.
    pub ttl_ms: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("no such pairing slot")]
    NotFound,
    #[error("too many pairings are in progress; try again shortly")]
    Busy,
    #[error("message {next} comes next")]
    OutOfOrder { next: usize },
    #[error("a different message is stored at this index")]
    Conflict,
    #[error("a pairing slot holds at most {max} messages")]
    SlotFull { max: usize },
    #[error("a pairing message holds at most {max} bytes")]
    TooLarge { max: usize },
    #[error("the random generator failed")]
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Created {
    pub slot_id: [u8; 16],
    pub code: Option<u32>,
    pub expires_at: i64,
}

/// What a write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    New,
    /// The same message was already stored at this index: a retried write.
    Repeated,
}

/// Messages from index `from` on, and a receiver that changes when more
/// arrive and closes when the slot ends.
#[derive(Debug)]
pub struct Read {
    pub from: usize,
    pub messages: Vec<Vec<u8>>,
    pub expires_at: i64,
    pub changes: watch::Receiver<usize>,
}

struct Slot {
    expires_at: i64,
    code: Option<u32>,
    messages: Vec<Vec<u8>>,
    /// The number of messages, for waiting readers.
    count: watch::Sender<usize>,
}

#[derive(Default)]
struct Slots {
    by_id: HashMap<[u8; 16], Slot>,
    by_code: HashMap<u32, [u8; 16]>,
}

impl Slots {
    fn remove(&mut self, slot_id: &[u8; 16]) {
        if let Some(slot) = self.by_id.remove(slot_id)
            && let Some(code) = slot.code
        {
            self.by_code.remove(&code);
        }
    }

    fn prune(&mut self, now_ms: i64) {
        let expired: Vec<[u8; 16]> = self
            .by_id
            .iter()
            .filter(|(_, slot)| slot.expires_at <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.remove(&id);
        }
    }

    /// The slot, unless it is unknown or expired.
    fn live(&mut self, slot_id: &[u8; 16], now_ms: i64) -> Result<&mut Slot, PairingError> {
        if self
            .by_id
            .get(slot_id)
            .is_some_and(|slot| slot.expires_at <= now_ms)
        {
            self.remove(slot_id);
        }
        self.by_id.get_mut(slot_id).ok_or(PairingError::NotFound)
    }
}

pub struct Pairing {
    limits: PairingLimits,
    slots: Mutex<Slots>,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("Pairing")
            .field("limits", &self.limits)
            .field("slots", &slots.by_id.len())
            .finish()
    }
}

/// A uniformly random code below [`CODE_SPACE`].
fn random_code() -> Result<u32, PairingError> {
    // The largest multiple of CODE_SPACE that fits in a u32; values above
    // it would make low codes likelier.
    const LIMIT: u32 = (u32::MAX / CODE_SPACE) * CODE_SPACE;
    loop {
        let value = u32::from_be_bytes(random_bytes().map_err(|_| PairingError::Random)?);
        if value < LIMIT {
            return Ok(value % CODE_SPACE);
        }
    }
}

/// `code` as the eight digits users type.
pub fn format_code(code: u32) -> String {
    format!("{code:0width$}", width = CODE_DIGITS)
}

/// Eight ASCII digits as a code.
pub fn parse_code(text: &str) -> Option<u32> {
    (text.len() == CODE_DIGITS && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

impl Pairing {
    pub fn new(limits: PairingLimits) -> Self {
        Self {
            limits,
            slots: Mutex::new(Slots::default()),
        }
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Open a slot, with a short code that finds it if `with_code`.
    pub fn create(&self, with_code: bool, now_ms: i64) -> Result<Created, PairingError> {
        let slot_id = random_bytes::<16>().map_err(|_| PairingError::Random)?;
        let mut slots = self.slots();
        if slots.by_id.len() >= self.limits.max_slots {
            slots.prune(now_ms);
            if slots.by_id.len() >= self.limits.max_slots {
                return Err(PairingError::Busy);
            }
        }
        let code = if with_code {
            // At most max_slots of the 10^8 codes are taken, so a free one
            // turns up at once.
            let mut code = random_code()?;
            while slots.by_code.contains_key(&code) {
                code = random_code()?;
            }
            slots.by_code.insert(code, slot_id);
            Some(code)
        } else {
            None
        };
        let expires_at = now_ms + self.limits.ttl_ms;
        slots.by_id.insert(
            slot_id,
            Slot {
                expires_at,
                code,
                messages: Vec::new(),
                count: watch::Sender::new(0),
            },
        );
        Ok(Created {
            slot_id,
            code,
            expires_at,
        })
    }

    /// The slot a code points to. A code works once, so whoever guesses
    /// codes can find a slot only before its owner does.
    pub fn resolve(&self, code: u32, now_ms: i64) -> Option<[u8; 16]> {
        let mut slots = self.slots();
        let slot_id = slots.by_code.remove(&code)?;
        let slot = slots.live(&slot_id, now_ms).ok()?;
        slot.code = None;
        Some(slot_id)
    }

    /// Store `message` at `index`, which must be the next free one. Writing
    /// the same message again is accepted, so writers can retry.
    pub fn put(
        &self,
        slot_id: &[u8; 16],
        index: usize,
        message: Vec<u8>,
        now_ms: i64,
    ) -> Result<Stored, PairingError> {
        if message.len() > self.limits.max_message_bytes {
            return Err(PairingError::TooLarge {
                max: self.limits.max_message_bytes,
            });
        }
        if index >= self.limits.max_messages {
            return Err(PairingError::SlotFull {
                max: self.limits.max_messages,
            });
        }
        let mut slots = self.slots();
        let slot = slots.live(slot_id, now_ms)?;
        match slot.messages.get(index) {
            Some(stored) if *stored == message => Ok(Stored::Repeated),
            Some(_) => Err(PairingError::Conflict),
            None if index == slot.messages.len() => {
                slot.messages.push(message);
                slot.count.send_replace(slot.messages.len());
                Ok(Stored::New)
            }
            None => Err(PairingError::OutOfOrder {
                next: slot.messages.len(),
            }),
        }
    }

    pub fn read(&self, slot_id: &[u8; 16], from: usize, now_ms: i64) -> Result<Read, PairingError> {
        let mut slots = self.slots();
        let slot = slots.live(slot_id, now_ms)?;
        Ok(Read {
            from,
            messages: slot.messages.get(from..).unwrap_or_default().to_vec(),
            expires_at: slot.expires_at,
            changes: slot.count.subscribe(),
        })
    }

    /// End a slot. Waiting readers wake up and find it gone.
    pub fn delete(&self, slot_id: &[u8; 16]) {
        self.slots().remove(slot_id);
    }

    /// Drop expired slots.
    pub fn prune(&self, now_ms: i64) {
        self.slots().prune(now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairing() -> Pairing {
        Pairing::new(PairingLimits {
            max_slots: 2,
            max_messages: 3,
            max_message_bytes: 8,
            ttl_ms: 1_000,
        })
    }

    #[test]
    fn messages_are_appended_in_order_and_retries_are_harmless() {
        let pairing = pairing();
        let slot = pairing.create(false, 0).unwrap().slot_id;
        assert_eq!(
            pairing.put(&slot, 1, b"b".to_vec(), 0),
            Err(PairingError::OutOfOrder { next: 0 })
        );
        assert_eq!(pairing.put(&slot, 0, b"a".to_vec(), 0), Ok(Stored::New));
        assert_eq!(
            pairing.put(&slot, 0, b"a".to_vec(), 0),
            Ok(Stored::Repeated)
        );
        assert_eq!(
            pairing.put(&slot, 0, b"x".to_vec(), 0),
            Err(PairingError::Conflict)
        );
        assert_eq!(
            pairing.put(&slot, 1, vec![0; 9], 0),
            Err(PairingError::TooLarge { max: 8 })
        );
        assert_eq!(
            pairing.put(&slot, 3, b"d".to_vec(), 0),
            Err(PairingError::SlotFull { max: 3 })
        );
        pairing.put(&slot, 1, b"b".to_vec(), 0).unwrap();
        let read = pairing.read(&slot, 1, 0).unwrap();
        assert_eq!(read.messages, vec![b"b".to_vec()]);
        assert_eq!(*read.changes.borrow(), 2);
        assert!(pairing.read(&slot, 5, 0).unwrap().messages.is_empty());
    }

    #[test]
    fn slots_expire_and_are_capped() {
        let pairing = pairing();
        let first = pairing.create(false, 0).unwrap();
        assert_eq!(first.expires_at, 1_000);
        pairing.create(false, 0).unwrap();
        assert_eq!(pairing.create(false, 999), Err(PairingError::Busy));
        // Expired slots make room and are gone.
        pairing.create(false, 1_000).unwrap();
        assert_eq!(
            pairing.read(&first.slot_id, 0, 1_000).unwrap_err(),
            PairingError::NotFound
        );
    }

    #[test]
    fn codes_find_their_slot_once() {
        let pairing = pairing();
        let created = pairing.create(true, 0).unwrap();
        let code = created.code.unwrap();
        assert!(code < CODE_SPACE);
        assert_eq!(parse_code(&format_code(code)), Some(code));
        assert_eq!(pairing.resolve(code, 0), Some(created.slot_id));
        assert_eq!(pairing.resolve(code, 0), None, "a code works once");
        // A deleted or expired slot's code finds nothing.
        let deleted = pairing.create(true, 0).unwrap();
        pairing.delete(&deleted.slot_id);
        assert_eq!(pairing.resolve(deleted.code.unwrap(), 0), None);
        let expired = pairing.create(true, 0).unwrap();
        assert_eq!(pairing.resolve(expired.code.unwrap(), 1_000), None);
    }

    #[test]
    fn codes_are_eight_digits() {
        assert_eq!(format_code(42), "00000042");
        assert_eq!(parse_code("00000042"), Some(42));
        for bad in ["0000042", "000000042", "0000004a", "+0000042", ""] {
            assert_eq!(parse_code(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn readers_wake_on_new_messages_and_on_deletion() {
        let pairing = pairing();
        let slot = pairing.create(false, 0).unwrap().slot_id;
        let mut changes = pairing.read(&slot, 0, 0).unwrap().changes;
        pairing.put(&slot, 0, b"a".to_vec(), 0).unwrap();
        assert_eq!(*changes.wait_for(|count| *count > 0).await.unwrap(), 1);
        pairing.delete(&slot);
        assert!(changes.wait_for(|count| *count > 1).await.is_err());
    }
}
