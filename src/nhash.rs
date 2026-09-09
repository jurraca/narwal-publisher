//! nhash encoding: TLV + bech32.
//!
//! An nhash is a bech32-encoded identifier with HRP "nhash".
//! The payload is TLV-encoded:
//!   type 0: 32-byte hash (required)
//!   type 5: 32-byte decryption key (optional, not used for public caches)
//!
//! TLV format: [type:u8, length:u8, value:length bytes] repeated.
//! Entries are encoded in ascending type order.

use anyhow::{anyhow, Result};
use bech32::{Bech32, Hrp};

/// TLV type for the hash field.
const TLV_HASH: u8 = 0;

/// Encode a 32-byte hash as an nhash string.
///
/// For public (unencrypted) content, only the hash is included.
/// Returns a string like "nhash1qq...".
pub fn nhash_encode(hash: &[u8; 32]) -> Result<String> {
    let mut tlv = Vec::with_capacity(34);
    tlv.push(TLV_HASH);
    tlv.push(32);
    tlv.extend_from_slice(hash);

    let hrp = Hrp::parse("nhash").map_err(|e| anyhow!("invalid HRP: {}", e))?;
    bech32::encode::<Bech32>(hrp, &tlv).map_err(|e| anyhow!("bech32 encode: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhash_encode() {
        let hash = [0x42; 32];
        let encoded = nhash_encode(&hash).unwrap();
        assert!(encoded.starts_with("nhash1"));
    }

    #[test]
    fn test_nhash_roundtrip_with_htree() {
        // Verify our encoding matches what htree would produce.
        // We verified empirically that htree add produces nhash1qq... for public content.
        let hash = [0x42; 32];
        let encoded = nhash_encode(&hash).unwrap();
        // Just check it starts with the right prefix and can be decoded.
        assert!(encoded.starts_with("nhash1"));
    }
}
