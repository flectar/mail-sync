//! Rate limits (SPEC §6.13).
//!
//! Unauthenticated endpoints are limited per client address, and IPv6
//! addresses per /64 network, since one host usually holds a whole /64.
//! Authenticated endpoints are limited per group, so one runaway device
//! cannot exhaust the server. Each limit is a GCRA: a burst of requests,
//! refilled at a steady rate.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Keys a limiter tracks at most. Past this, new keys are refused until old
/// ones refill, so an attacker with many addresses cannot exhaust memory.
const MAX_KEYS: usize = 100_000;

/// A burst of `burst` requests, refilled at one request per `every`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub burst: u32,
    pub every: Duration,
}

/// A GCRA limiter per key. It stores one instant per key: the theoretical
/// arrival time of the key's next request.
#[derive(Debug)]
pub struct Limiter<K> {
    interval: Duration,
    tolerance: Duration,
    arrivals: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash + Copy> Limiter<K> {
    pub fn new(rate: Rate) -> Self {
        Self {
            interval: rate.every,
            tolerance: rate.every * rate.burst.saturating_sub(1),
            arrivals: Mutex::new(HashMap::new()),
        }
    }

    /// Count one request of `key`. `Err` holds how long until one would be
    /// allowed.
    pub fn check(&self, key: K, now: Instant) -> Result<(), Duration> {
        let mut arrivals = self.arrivals.lock().unwrap_or_else(PoisonError::into_inner);
        if arrivals.len() >= MAX_KEYS && !arrivals.contains_key(&key) {
            arrivals.retain(|_, arrival| *arrival > now);
            if arrivals.len() >= MAX_KEYS {
                return Err(self.interval);
            }
        }
        let arrival = arrivals
            .get(&key)
            .copied()
            .filter(|arrival| *arrival > now)
            .unwrap_or(now);
        let ahead = arrival.duration_since(now);
        if ahead > self.tolerance {
            return Err(ahead - self.tolerance);
        }
        arrivals.insert(key, arrival + self.interval);
        Ok(())
    }

    /// Forget keys that have refilled completely; they behave as new keys.
    pub fn prune(&self, now: Instant) {
        self.arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, arrival| *arrival > now);
    }
}

/// The address a request came from: the connecting peer, or, when the peer
/// is a trusted proxy, the nearest address in `X-Forwarded-For` that is not
/// a trusted proxy. Entries further left are written by the client and may
/// be forged, so they are never used.
pub fn client_address(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |address: &IpAddr| trusted.iter().any(|net| net.contains(address));
    let mut address = peer.ip().to_canonical();
    if !is_trusted(&address) {
        return address;
    }
    let entries = headers
        .get_all("x-forwarded-for")
        .iter()
        .rev()
        .flat_map(|value| value.to_str().unwrap_or("").rsplit(','));
    for entry in entries {
        let entry = entry.trim();
        let Some(hop) = entry
            .parse::<IpAddr>()
            .or_else(|_| entry.parse::<SocketAddr>().map(|socket| socket.ip()))
            .ok()
            .map(|hop| hop.to_canonical())
        else {
            // An entry no proxy of ours wrote: stop at the last trusted hop.
            break;
        };
        address = hop;
        if !is_trusted(&hop) {
            break;
        }
    }
    address
}

/// The key a client address is limited by: IPv4 addresses as they are,
/// IPv6 addresses by their /64 network.
pub fn bucket(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let network = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(network))
        }
        v4 => v4,
    }
}

/// The server's limiters.
#[derive(Debug)]
pub struct RateLimits {
    pub create_group: Limiter<IpAddr>,
    pub login: Limiter<IpAddr>,
    pub pairing: Limiter<IpAddr>,
    pub pairing_code: Limiter<IpAddr>,
    pub group: Limiter<[u8; 16]>,
}

/// Rates of [`RateLimits`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rates {
    /// Creating groups, per client address.
    pub create_group: Rate,
    /// Login challenges and sessions, per client address.
    pub login: Rate,
    /// Pairing slots and their messages, per client address.
    pub pairing: Rate,
    /// Looking up short pairing codes, per client address. Kept low, since
    /// it is what someone guessing codes would use.
    pub pairing_code: Rate,
    /// Authenticated requests, per group.
    pub group: Rate,
}

impl Default for Rates {
    fn default() -> Self {
        let rate = |burst, every_ms| Rate {
            burst,
            every: Duration::from_millis(every_ms),
        };
        Self {
            create_group: rate(5, 6 * 60 * 1000),
            login: rate(40, 5_000),
            pairing: rate(60, 2_000),
            pairing_code: rate(5, 30_000),
            group: rate(300, 100),
        }
    }
}

impl RateLimits {
    pub fn new(rates: &Rates) -> Self {
        Self {
            create_group: Limiter::new(rates.create_group),
            login: Limiter::new(rates.login),
            pairing: Limiter::new(rates.pairing),
            pairing_code: Limiter::new(rates.pairing_code),
            group: Limiter::new(rates.group),
        }
    }

    pub fn prune(&self, now: Instant) {
        self.create_group.prune(now);
        self.login.prune(now);
        self.pairing.prune(now);
        self.pairing_code.prune(now);
        self.group.prune(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn limiter(burst: u32, every_ms: u64) -> Limiter<u8> {
        Limiter::new(Rate {
            burst,
            every: Duration::from_millis(every_ms),
        })
    }

    #[test]
    fn a_burst_is_allowed_then_one_request_per_interval() {
        let limiter = limiter(3, 1_000);
        let start = Instant::now();
        for _ in 0..3 {
            limiter.check(1, start).unwrap();
        }
        assert_eq!(limiter.check(1, start), Err(Duration::from_millis(1_000)));
        assert_eq!(
            limiter.check(1, start + Duration::from_millis(400)),
            Err(Duration::from_millis(600))
        );
        limiter
            .check(1, start + Duration::from_millis(1_000))
            .unwrap();
        // Other keys have their own burst.
        limiter.check(2, start).unwrap();
    }

    #[test]
    fn refilled_keys_are_forgotten() {
        let limiter = limiter(2, 1_000);
        let start = Instant::now();
        limiter.check(1, start).unwrap();
        limiter.prune(start + Duration::from_millis(999));
        assert_eq!(limiter.arrivals.lock().unwrap().len(), 1);
        limiter.prune(start + Duration::from_millis(1_000));
        assert!(limiter.arrivals.lock().unwrap().is_empty());
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn forwarded_addresses_count_only_behind_trusted_proxies() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()];
        let proxy: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let stranger: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let client = |peer, values: &[&str]| client_address(peer, &headers(values), &trusted);

        // A client connecting directly cannot claim another address.
        assert_eq!(client(stranger, &["203.0.113.1"]), stranger.ip());
        // Behind the proxy, the rightmost untrusted entry wins; what the
        // client wrote to the left of it is ignored.
        assert_eq!(
            client(proxy, &["192.0.2.66, 203.0.113.1"]),
            "203.0.113.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client(proxy, &["192.0.2.66", "203.0.113.1, 10.0.0.3"]),
            "203.0.113.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client(proxy, &["[2001:db8::1]:1234"]),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        // Without a usable entry, the proxy itself is the client.
        assert_eq!(client(proxy, &[]), proxy.ip());
        assert_eq!(client(proxy, &["unknown"]), proxy.ip());
        assert_eq!(
            client(proxy, &["10.0.0.9"]),
            "10.0.0.9".parse::<IpAddr>().unwrap()
        );
        // IPv4 addresses mapped into IPv6 count as IPv4.
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:1".parse().unwrap();
        assert_eq!(client(mapped, &[]), stranger.ip());
    }

    #[test]
    fn ipv6_clients_share_their_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(bucket(a), bucket(b));
        assert_ne!(bucket(a), bucket(other));
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(bucket(v4), v4);
    }
}
