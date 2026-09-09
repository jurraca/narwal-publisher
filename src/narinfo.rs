//! Narinfo construction via nix-narinfo's builder API.
//!
//! Assembles canonical narinfo text from computed fields (NAR hash, size,
//! references, compression, file hash/size) with correct Nix field order
//! and canonical hash encodings — no hand-rolled format strings.

use anyhow::{anyhow, Result};
use nix_derivation::{NixHash, StoreDir, StorePath};
use nix_narinfo::{Compression, NarInfoBuilder, NarInfoSignature};

/// A complete narinfo ready for signing and upload.
pub struct NarInfoOutput {
    /// Canonical narinfo text bytes (unsigned)
    pub bytes: Vec<u8>,
    /// The fingerprint string that gets signed
    pub fingerprint: String,
}

/// Build a narinfo record from computed fields.
///
/// # Arguments
/// * `store_dir` - Logical store directory (usually `/nix/store`)
/// * `store_path` - Parsed store path (hashpart + name)
/// * `url` - Relative URL to the NAR blob (e.g. `nar/<nixbase32>.nar.xz`)
/// * `nar_hash` - SHA-256 of uncompressed NAR bytes
/// * `nar_size` - Byte length of uncompressed NAR
/// * `compression` - Compression format (Xz, Zstd, etc.)
/// * `file_hash` - SHA-256 of compressed bytes
/// * `file_size` - Byte length of compressed NAR
/// * `references` - Store path hashparts referenced by this path
/// * `signatures` - Pre-computed signatures to attach
pub fn build_narinfo(
    store_dir: &StoreDir,
    store_path: &StorePath,
    url: &str,
    nar_hash: [u8; 32],
    nar_size: u64,
    compression: Compression,
    file_hash: [u8; 32],
    file_size: u64,
    references: &[StorePath],
    signatures: &[NarInfoSignature],
) -> Result<NarInfoOutput> {
    let mut builder = NarInfoBuilder::new_in(
        store_dir.clone(),
        store_path.clone(),
        url.to_string(),
        NixHash::Sha256(nar_hash),
        nar_size,
    )
    .compression(compression)
    .file_hash(Some(NixHash::Sha256(file_hash)))
    .file_size(Some(file_size));

    if !references.is_empty() {
        builder = builder.references(references.to_vec());
    }

    for sig in signatures {
        builder = builder.signature(sig.clone());
    }

    let info = builder
        .build()
        .map_err(|e| anyhow!("narinfo build error: {}", e))?;

    let fingerprint = info.fingerprint(store_dir);
    let bytes = info.to_canonical_bytes();

    Ok(NarInfoOutput { bytes, fingerprint })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_narinfo::NarInfo;

    #[test]
    fn build_minimal_narinfo() {
        let store_dir = StoreDir::default();
        let store_path =
            StorePath::from_basename(b"00000000000000000000000000000000-example").unwrap();

        let output = build_narinfo(
            &store_dir,
            &store_path,
            "nar/example.nar.xz",
            [0x42; 32],
            1024,
            Compression::Xz,
            [0x43; 32],
            512,
            &[],
            &[],
        )
        .unwrap();

        // Canonical bytes should contain the store path
        let text = std::str::from_utf8(&output.bytes).unwrap();
        assert!(text.contains("StorePath: /nix/store/00000000000000000000000000000000-example"));
        assert!(text.contains("URL: nar/example.nar.xz"));
        assert!(text.contains("NarSize: 1024"));
        assert!(text.contains("FileSize: 512"));
        assert!(text.contains("Compression: xz"));

        // Fingerprint starts with "1;" + store path
        assert!(output.fingerprint.starts_with("1;/nix/store/00000000000000000000000000000000-example"));
    }

    #[test]
    fn roundtrip_parse_built_narinfo() {
        let store_dir = StoreDir::default();
        let store_path =
            StorePath::from_basename(b"00000000000000000000000000000000-test").unwrap();

        let output = build_narinfo(
            &store_dir,
            &store_path,
            "nar/test.nar.xz",
            [0xAA; 32],
            4096,
            Compression::Xz,
            [0xBB; 32],
            2048,
            &[],
            &[],
        )
        .unwrap();

        // Parse it back
        let parsed = NarInfo::parse_in(&store_dir, &output.bytes).unwrap();
        assert_eq!(parsed.url(), "nar/test.nar.xz");
        assert_eq!(parsed.nar_size(), 4096);
        assert_eq!(parsed.compression(), &Compression::Xz);
    }
}
