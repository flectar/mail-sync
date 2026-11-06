use crate::keys::{DeviceSigningKey, SignPublicKey};
use crate::{Error, Result, label};

/// The bytes a device signs to answer a login challenge. Binding the
/// server's public URL (`audience`) keeps a signature for one server from
/// being replayed against another. A recovery login passes
/// [`crate::RECOVERY_ID`] as both ids: it learns its group only once logged
/// in.
pub fn auth_message(
    audience: &str,
    group_id: &[u8; 16],
    device_id: &[u8; 16],
    nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    let audience_len: u16 = audience
        .len()
        .try_into()
        .map_err(|_| Error::Malformed("audience is longer than 65535 bytes"))?;
    let mut message = Vec::with_capacity(label::AUTH.len() + 2 + audience.len() + 64);
    message.extend_from_slice(label::AUTH);
    message.extend_from_slice(&audience_len.to_be_bytes());
    message.extend_from_slice(audience.as_bytes());
    message.extend_from_slice(group_id);
    message.extend_from_slice(device_id);
    message.extend_from_slice(nonce);
    Ok(message)
}

pub fn sign_auth(
    key: &DeviceSigningKey,
    audience: &str,
    group_id: &[u8; 16],
    device_id: &[u8; 16],
    nonce: &[u8; 32],
) -> Result<[u8; 64]> {
    Ok(key.sign(&auth_message(audience, group_id, device_id, nonce)?))
}

pub fn verify_auth(
    key: &SignPublicKey,
    audience: &str,
    group_id: &[u8; 16],
    device_id: &[u8; 16],
    nonce: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    key.verify(
        &auth_message(audience, group_id, device_id, nonce)?,
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_bound_to_server_group_device_and_nonce() {
        let key = DeviceSigningKey::from_seed(&[5; 32]);
        let public = key.public_key();
        let (group, device, nonce) = ([1u8; 16], [2u8; 16], [3u8; 32]);
        let signature = sign_auth(&key, "https://sync.example", &group, &device, &nonce).unwrap();
        verify_auth(
            &public,
            "https://sync.example",
            &group,
            &device,
            &nonce,
            &signature,
        )
        .unwrap();
        for (audience, g, d, n) in [
            ("https://other.example", group, device, nonce),
            ("https://sync.example", [9u8; 16], device, nonce),
            ("https://sync.example", group, [9u8; 16], nonce),
            ("https://sync.example", group, device, [9u8; 32]),
        ] {
            assert_eq!(
                verify_auth(&public, audience, &g, &d, &n, &signature),
                Err(Error::BadSignature)
            );
        }
    }
}
