use crate::{Error, Result, label, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Plaintexts are padded to a multiple of this many bytes, so the server
/// learns only a coarse size.
pub const PAD_BLOCK: usize = 256;

/// Pad with 0x80 followed by zeros (ISO/IEC 7816-4) up to a multiple of
/// [`PAD_BLOCK`]. Always adds at least one byte.
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let padded_len = (plaintext.len() / PAD_BLOCK + 1) * PAD_BLOCK;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded_len, 0);
    out
}

/// Remove [`pad`]'s padding.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.is_empty() || !padded.len().is_multiple_of(PAD_BLOCK) {
        return Err(Error::Malformed("padded plaintext has the wrong length"));
    }
    let end = padded
        .iter()
        .rposition(|&byte| byte != 0)
        .ok_or(Error::Malformed("padding marker missing"))?;
    if padded[end] != 0x80 {
        return Err(Error::Malformed("padding marker missing"));
    }
    Ok(&padded[..end])
}

fn record_aad(group_id: &[u8; 16], record_id: &[u8; 16], tag: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(label::RECORD_AAD.len() + 56);
    aad.extend_from_slice(label::RECORD_AAD);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(record_id);
    aad.extend_from_slice(tag);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seal a record body with XChaCha20-Poly1305 under `record_key` (from
/// [`crate::RootKey::record_key`]). The associated data binds the
/// ciphertext to its group, record, collection tag and epoch, so the server
/// cannot move it to another record. Returns `(nonce, ciphertext)`.
pub fn seal_record(
    record_key: &[u8; 32],
    group_id: &[u8; 16],
    record_id: &[u8; 16],
    tag: &[u8; 16],
    epoch: u64,
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>)> {
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new(record_key.into());
    let aad = record_aad(group_id, record_id, tag, epoch);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &pad(plaintext),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok((nonce, ciphertext))
}

/// Open a record sealed by [`seal_record`].
pub fn open_record(
    record_key: &[u8; 32],
    group_id: &[u8; 16],
    record_id: &[u8; 16],
    tag: &[u8; 16],
    epoch: u64,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(record_key.into());
    let aad = record_aad(group_id, record_id, tag, epoch);
    let padded = cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(unpad(&padded)?.to_vec())
}

/// The opaque tag the server sees for a collection name, under `tag_key`
/// (from [`crate::RootKey::tag_key`]): HMAC-SHA256 truncated to 16 bytes.
pub fn collection_tag(tag_key: &[u8; 32], collection: &str) -> [u8; 16] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(tag_key).expect("HMAC accepts any key length");
    mac.update(collection.as_bytes());
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text.split_whitespace().collect::<String>()).unwrap()
    }

    /// draft-irtf-cfrg-xchacha-03 §A.3.1.
    #[test]
    fn xchacha20poly1305_matches_the_draft_test_vector() {
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let plaintext = unhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
             637265656e20776f756c642062652069742e",
        );
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let sealed = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                &XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let expected = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e
             c0875924c1c7987947deafd8780acf49",
        );
        assert_eq!(sealed, expected);
    }

    #[test]
    fn padding_hides_lengths_within_a_block() {
        assert_eq!(pad(b"").len(), 256);
        assert_eq!(pad(&[1; 255]).len(), 256);
        assert_eq!(pad(&[1; 256]).len(), 512);
        for len in [0, 1, 100, 255, 256, 1000] {
            let data = vec![0u8; len];
            assert_eq!(unpad(&pad(&data)).unwrap(), data.as_slice());
        }
        assert!(unpad(&[0; 256]).is_err());
        assert!(unpad(&[1; 100]).is_err());
    }

    #[test]
    fn records_open_only_in_their_context() {
        let key = [3u8; 32];
        let (group, record, tag) = ([1u8; 16], [2u8; 16], [4u8; 16]);
        let (nonce, sealed) =
            seal_record(&key, &group, &record, &tag, 1, b"{\"theme\":\"dark\"}").unwrap();
        assert_eq!(
            open_record(&key, &group, &record, &tag, 1, &nonce, &sealed).unwrap(),
            b"{\"theme\":\"dark\"}"
        );
        assert_eq!(sealed.len(), 256 + 16, "padded block plus the Poly1305 tag");
        for (g, r, t, e) in [
            ([9u8; 16], record, tag, 1),
            (group, [9u8; 16], tag, 1),
            (group, record, [9u8; 16], 1),
            (group, record, tag, 2),
        ] {
            assert_eq!(
                open_record(&key, &g, &r, &t, e, &nonce, &sealed),
                Err(Error::Decrypt),
                "a moved or relabelled ciphertext must not open"
            );
        }
    }

    #[test]
    fn collection_tags_are_keyed() {
        let a = collection_tag(&[1; 32], "account");
        assert_eq!(a, collection_tag(&[1; 32], "account"));
        assert_ne!(a, collection_tag(&[2; 32], "account"));
        assert_ne!(a, collection_tag(&[1; 32], "pref"));
    }
}
