use crate::limits::Rates;
use crate::pairing::PairingLimits;
use flectar_mail_sync_proto::Limits;
use ipnet::IpNet;
use std::time::Duration;

/// Server settings. `main` fills them from flags and environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// The URL devices use to reach this server. Login signatures are bound
    /// to it, so it must match what devices are configured with.
    pub public_url: String,
    pub limits: Limits,
    pub challenge_ttl: Duration,
    pub session_ttl: Duration,
    /// How long deletions stay visible before their tombstones are dropped.
    pub tombstone_retention: Duration,
    pub rates: Rates,
    /// Reverse proxies whose `X-Forwarded-For` entries are believed.
    pub trusted_proxies: Vec<IpNet>,
    pub pairing: PairingLimits,
}

impl Config {
    pub fn new(public_url: impl Into<String>) -> Self {
        Self {
            public_url: public_url.into().trim_end_matches('/').to_owned(),
            limits: Limits {
                max_record_bytes: 256 * 1024,
                max_batch_records: 1000,
                max_request_bytes: 8 * 1024 * 1024,
                max_group_bytes: 64 * 1024 * 1024,
                max_page_records: 1000,
                max_devices: 25,
            },
            challenge_ttl: Duration::from_secs(120),
            session_ttl: Duration::from_secs(3600),
            tombstone_retention: Duration::from_secs(180 * 24 * 3600),
            rates: Rates::default(),
            trusted_proxies: Vec::new(),
            pairing: PairingLimits {
                max_slots: 1024,
                max_messages: 4,
                max_message_bytes: 4096,
                ttl_ms: 10 * 60 * 1000,
            },
        }
    }
}
