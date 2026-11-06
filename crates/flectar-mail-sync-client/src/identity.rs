//! What a device keeps between runs: its identity (secret, for the OS key
//! store) and the group's signed chain (public, for the app's database).

use crate::error::{Error, Result};
use flectar_mail_sync_crypto::{DeviceKeys, DeviceSigningKey, KemSecretKey, random_bytes};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const IDENTITY_VERSION: u8 = 1;
const MAX_URL_BYTES: usize = 2048;

/// A device's membership in a group. It holds the device's secret keys:
/// store [`DeviceIdentity::to_bytes`] in the OS key store, never in a file.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceIdentity {
    #[zeroize(skip)]
    server_url: String,
    #[zeroize(skip)]
    group_id: [u8; 16],
    #[zeroize(skip)]
    device_id: [u8; 16],
    sign_seed: [u8; 32],
    kem_seed: [u8; 32],
}

impl DeviceIdentity {
    /// A new device for `group_id`, with fresh keys.
    pub fn generate(server_url: &str, group_id: [u8; 16]) -> Result<Self> {
        Ok(Self {
            server_url: server_url.trim_end_matches('/').to_owned(),
            group_id,
            device_id: random_bytes()?,
            sign_seed: DeviceSigningKey::generate()?.seed(),
            kem_seed: KemSecretKey::generate()?.to_bytes(),
        })
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn group_id(&self) -> [u8; 16] {
        self.group_id
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    pub fn signing_key(&self) -> DeviceSigningKey {
        DeviceSigningKey::from_seed(&self.sign_seed)
    }

    pub fn kem_key(&self) -> Result<KemSecretKey> {
        Ok(KemSecretKey::from_bytes(&self.kem_seed)?)
    }

    /// The public keys an `add_device` operation names.
    pub fn keys(&self) -> Result<DeviceKeys> {
        Ok(DeviceKeys {
            device_id: self.device_id,
            sign_public_key: self.signing_key().public_key().to_bytes(),
            kem_public_key: self.kem_key()?.public_key(),
        })
    }

    /// `version || group_id || device_id || sign_seed || kem_seed || u16be(len) || server_url`.
    /// Wiped from memory when dropped.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(99 + self.server_url.len()));
        out.push(IDENTITY_VERSION);
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.sign_seed);
        out.extend_from_slice(&self.kem_seed);
        let len = u16::try_from(self.server_url.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.server_url.as_bytes()[..usize::from(len)]);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || Error::Malformed("stored device identity is invalid".into());
        let (&version, rest) = bytes.split_first().ok_or_else(malformed)?;
        if version != IDENTITY_VERSION || rest.len() < 98 {
            return Err(malformed());
        }
        let (group_id, rest) = rest.split_at(16);
        let (device_id, rest) = rest.split_at(16);
        let (sign_seed, rest) = rest.split_at(32);
        let (kem_seed, rest) = rest.split_at(32);
        let (len, url) = rest.split_at(2);
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if url.len() != len || len > MAX_URL_BYTES {
            return Err(malformed());
        }
        let identity = Self {
            server_url: std::str::from_utf8(url)
                .map_err(|_| malformed())?
                .to_owned(),
            group_id: group_id.try_into().map_err(|_| malformed())?,
            device_id: device_id.try_into().map_err(|_| malformed())?,
            sign_seed: sign_seed.try_into().map_err(|_| malformed())?,
            kem_seed: kem_seed.try_into().map_err(|_| malformed())?,
        };
        identity.kem_key()?;
        Ok(identity)
    }
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("server_url", &self.server_url)
            .field(
                "device_id",
                &flectar_mail_sync_proto::Bytes::from(self.device_id),
            )
            .finish_non_exhaustive()
    }
}

/// One signed operation of the group's chain, as the app persists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainOp {
    pub op: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_round_trip_and_reject_damage() {
        let identity = DeviceIdentity::generate("https://sync.example.org/", [7; 16]).unwrap();
        assert_eq!(identity.server_url(), "https://sync.example.org");
        let bytes = identity.to_bytes();
        let restored = DeviceIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
        assert_eq!(restored.keys().unwrap(), identity.keys().unwrap());
        assert!(DeviceIdentity::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut future = bytes.clone();
        future[0] = 2;
        assert!(DeviceIdentity::from_bytes(&future).is_err());
    }
}
