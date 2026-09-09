//! NAR encoding from store paths using the nix-archive crate.
//!
//! `encode_store_path` serializes a store path's filesystem tree as a NAR
//! and computes its SHA-256 hash, matching `nix-store --dump` byte-for-byte.
//!
//! This module is the first step in replacing the staging-directory flow:
//! instead of `nix copy --to file:///staging` producing pre-built .nar files,
//! we encode NARs directly from /nix/store paths.

use anyhow::Result;
use nix_archive::nar::{hash_path, CaseHack, NarHash};
use std::path::Path;

/// A NAR archive with its hash and size.
pub struct NarOutput {
    /// Uncompressed NAR bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the NAR bytes (what Nix calls NarHash).
    pub nar_hash: [u8; 32],
    /// Byte length of the NAR.
    pub nar_size: u64,
}

/// Encode a store path as a NAR archive and compute its hash.
///
/// This buffers the full NAR in memory. For large store paths, a streaming
/// variant should be used (see Stage 9 of INTEGRATION_PLAN.md).
///
/// `hash_path` computes the hash without materializing the NAR, then
/// `encode_path` produces the actual bytes. Both use the same encoding, so
/// the hash is guaranteed to match the bytes.
pub fn encode_store_path(path: &Path) -> Result<NarOutput> {
    let NarHash {
        size: nar_size,
        sha256: nar_hash,
    } = hash_path(path, CaseHack::native())?;

    let mut bytes = Vec::new();
    nix_archive::nar::encode_path(&mut bytes, path, CaseHack::native())?;

    debug_assert_eq!(bytes.len() as u64, nar_size);

    Ok(NarOutput {
        bytes,
        nar_hash,
        nar_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn encode_hash_matches_bytes() {
        // Encoding a simple file and hashing the bytes should match hash_path.
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("hello");
        std::fs::write(&file, b"hello world\n").unwrap();

        let nar = encode_store_path(&file).unwrap();

        // The hash from hash_path must match a direct SHA-256 of the bytes.
        let mut hasher = sha2::Sha256::new();
        hasher.update(&nar.bytes);
        let direct_hash: [u8; 32] = hasher.finalize().into();

        assert_eq!(nar.nar_hash, direct_hash);
        assert_eq!(nar.nar_size, nar.bytes.len() as u64);
    }
}
