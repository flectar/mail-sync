//! Hybrid logical clocks (Kulkarni et al., 2014): wall-clock time that never
//! runs backwards and always moves past every stamp a device has seen, so
//! stamps order changes across devices even when their clocks disagree.

use serde::{Deserialize, Serialize};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// When and by whom a record version was written. Stamps compare by time,
/// then counter, then device, so any two differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stamp {
    /// Milliseconds since the Unix epoch, or later.
    pub ms: u64,
    /// Orders stamps within one millisecond.
    pub counter: u32,
    pub device: [u8; 16],
}

/// A device's clock. Stamp local changes with [`Clock::now`].
#[derive(Debug)]
pub struct Clock {
    device: [u8; 16],
    /// The largest (ms, counter) issued or observed.
    last: Mutex<(u64, u32)>,
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl Clock {
    /// `floor` is the latest stamp the device stored, so stamps stay
    /// increasing across restarts even if the wall clock was set back.
    pub fn new(device: [u8; 16], floor: Option<Stamp>) -> Self {
        Self {
            device,
            last: Mutex::new(floor.map_or((0, 0), |stamp| (stamp.ms, stamp.counter))),
        }
    }

    pub fn now(&self) -> Stamp {
        self.now_at(wall_ms())
    }

    fn now_at(&self, wall: u64) -> Stamp {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let (ms, counter) = *last;
        *last = if wall > ms {
            (wall, 0)
        } else {
            match counter.checked_add(1) {
                Some(counter) => (ms, counter),
                None => (ms.saturating_add(1), 0),
            }
        };
        Stamp {
            ms: last.0,
            counter: last.1,
            device: self.device,
        }
    }

    /// The latest stamp issued or seen, to store as the next start's floor.
    pub fn floor(&self) -> Stamp {
        let (ms, counter) = *self.last.lock().unwrap_or_else(PoisonError::into_inner);
        Stamp {
            ms,
            counter,
            device: self.device,
        }
    }

    /// Move past a stamp seen in a received record.
    pub fn observe(&self, stamp: &Stamp) {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        *last = (*last).max((stamp.ms, stamp.counter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_always_increase() {
        let clock = Clock::new([1; 16], None);
        let first = clock.now_at(1_000);
        let same_ms = clock.now_at(1_000);
        let earlier_wall = clock.now_at(500);
        assert!(first < same_ms && same_ms < earlier_wall);
        assert_eq!((earlier_wall.ms, earlier_wall.counter), (1_000, 2));
        assert_eq!(clock.now_at(2_000).counter, 0);
    }

    #[test]
    fn observed_stamps_are_overtaken() {
        let clock = Clock::new([1; 16], None);
        let remote = Stamp {
            ms: 9_000,
            counter: 4,
            device: [2; 16],
        };
        clock.observe(&remote);
        let next = clock.now_at(1_000);
        assert!(next > remote);
        assert_eq!((next.ms, next.counter), (9_000, 5));
    }

    #[test]
    fn the_floor_is_the_latest_stamp() {
        let clock = Clock::new([1; 16], None);
        let stamp = clock.now_at(7_000);
        assert_eq!(clock.floor(), stamp);
        let restarted = Clock::new([1; 16], Some(clock.floor()));
        assert!(restarted.now_at(1) > stamp);
    }

    #[test]
    fn a_floor_survives_restarts() {
        let floor = Stamp {
            ms: 5_000,
            counter: 1,
            device: [1; 16],
        };
        let clock = Clock::new([1; 16], Some(floor));
        assert!(clock.now_at(10) > floor);
    }
}
