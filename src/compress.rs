//! NAR compression + FileHash computation.
//!
//! Compresses NAR bytes with xz (matching Nix's default binary-cache
//! compression) and computes the FileHash — the SHA-256 of the compressed
//! bytes, which doubles as the Blossom blob address and the narinfo URL
//! component (`nar/<nixbase32(filehash)>.nar.xz`).

use anyhow::Result;
use sha2::{Digest, Sha256};
use xz2::write::XzEncoder;

/// Xz compression level used by `nix copy --to` (Nix's default).
const XZ_LEVEL: u32 = 6;

/// A compressed NAR ready for upload.
pub struct CompressedNar {
    /// xz-compressed NAR bytes
    pub bytes: Vec<u8>,
    /// SHA-256 of the compressed bytes (= Blossom blob address)
    pub file_hash: [u8; 32],
    /// Byte length of compressed NAR
    pub file_size: u64,
}

/// Compress NAR bytes with xz and compute the FileHash.
pub fn compress_xz(nar_bytes: &[u8]) -> Result<CompressedNar> {
    let mut encoder = XzEncoder::new(Vec::new(), XZ_LEVEL);
    std::io::Write::write_all(&mut encoder, nar_bytes)?;
    let compressed = encoder.finish()?;

    let file_hash = sha256(&compressed);
    let file_size = compressed.len() as u64;

    Ok(CompressedNar {
        bytes: compressed,
        file_hash,
        file_size,
    })
}

/// Build the narinfo URL field for a given file hash.
///
/// Returns `nar/<nixbase32(filehash)>.nar.xz`.
pub fn nar_url(file_hash: &[u8; 32]) -> String {
    let encoded = nix_derivation::nixbase32::encode(file_hash);
    format!("nar/{}.nar.xz", encoded)
}

/// Compute SHA-256 of arbitrary bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_and_hash_roundtrip() {
        let nar_bytes = b"nix-archive-test-nar-content-1234567890";
        let compressed = compress_xz(nar_bytes).unwrap();

        // FileHash should be SHA-256 of the compressed bytes
        let expected_hash = sha256(&compressed.bytes);
        assert_eq!(compressed.file_hash, expected_hash);
        assert_eq!(compressed.file_size, compressed.bytes.len() as u64);
    }

    #[test]
    fn compressed_bytes_are_valid_xz() {
        let nar_bytes = b"some nix archive content for xz testing";
        let compressed = compress_xz(nar_bytes).unwrap();

        // Decompress to verify it's valid xz
        let mut decoder = xz2::read::XzDecoder::new(compressed.bytes.as_slice());
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
        assert_eq!(decompressed, nar_bytes);
    }

    #[test]
    fn nar_url_uses_nixbase32() {
        let hash = [0x42; 32];
        let url = nar_url(&hash);
        assert!(url.starts_with("nar/"));
        assert!(url.ends_with(".nar.xz"));

        // The hashpart should be 52 chars (nix base32 of 32 bytes)
        let middle = &url[4..url.len() - 7]; // strip "nar/" and ".nar.xz"
        assert_eq!(middle.len(), 52);
    }

    #[test]
    fn empty_input_compresses() {
        let compressed = compress_xz(b"").unwrap();
        assert!(compressed.file_size > 0); // xz stream has overhead even for empty input
        assert_eq!(compressed.file_hash, sha256(&compressed.bytes));
    }
}
