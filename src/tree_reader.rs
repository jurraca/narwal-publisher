//! Hashtree reader — decode and flatten existing tree nodes from Blossom.
//!
//! Walks a content-addressed tree starting from a root hash, decoding
//! each msgpack node and collecting all leaf entries (narinfo name →
//! {hash, size}). This is the inverse of `manifest::build_directory_tree`.

use anyhow::{anyhow, Result};
use crate::manifest::{DirEntry, WireTreeNode};

/// Flatten a tree starting from the root hash.
///
/// Fetches nodes from Blossom as needed, decoding each Dir node and
/// recursing into children. Leaf entries (t=0/Blob) are collected into
/// a flat list; intermediate Dir links (t=2) are followed.
///
/// Returns the full entry list (all narinfo entries in the tree).
pub async fn flatten_tree(
    root_hash: &[u8; 32],
    fetcher: &crate::blossom_fetch::BlossomFetcher,
) -> Result<Vec<DirEntry>> {
    let root_hex = hex::encode(root_hash);
    flatten_node(&root_hex, fetcher).await
}

/// Recursively flatten a node: if it's a Dir with Blob children, collect
/// them; if it has Dir children, recurse.
async fn flatten_node(
    node_hash_hex: &str,
    fetcher: &crate::blossom_fetch::BlossomFetcher,
) -> Result<Vec<DirEntry>> {
    let bytes = fetcher.fetch(node_hash_hex).await?;
    let node: WireTreeNode = rmp_serde::from_slice(&bytes)
        .map_err(|e| anyhow!("failed to decode tree node {}: {}", &node_hash_hex[..12], e))?;

    let mut entries = Vec::new();

    for link in &node.l {
        match link.t {
            0 => {
                // Blob (leaf) — this is a narinfo entry
                let name = link.n.clone().unwrap_or_default();
                let hash: [u8; 32] = link
                    .h
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("invalid hash length in tree node for {}", name))?;
                entries.push(DirEntry {
                    name,
                    hash,
                    size: link.s,
                });
            }
            2 => {
                // Dir (intermediate) — recurse
                let child_hex = hex::encode(&link.h);
                let child_entries = Box::pin(flatten_node(&child_hex, fetcher)).await?;
                entries.extend(child_entries);
            }
            other => {
                tracing::warn!("unknown link type {} in tree node, skipping", other);
            }
        }
    }

    Ok(entries)
}

/// Parse an nhash URI to extract the raw 32-byte root hash.
///
/// "htree://nhash1qq..." → decode bech32 → extract TLV type 0 → 32 bytes.
pub fn parse_nhash_uri(uri: &str) -> Result<[u8; 32]> {
    let nhash = uri
        .strip_prefix("htree://")
        .ok_or_else(|| anyhow!("not an htree URI: {}", uri))?;

    let (hrp, data) = bech32::decode(nhash)
        .map_err(|e| anyhow!("invalid nhash bech32: {}", e))?;

    if hrp.as_str() != "nhash" {
        return Err(anyhow!("expected HRP 'nhash', got '{}'", hrp));
    }

    // TLV format: [type:u8, length:u8, value:length bytes] repeated
    // We want type 0 (hash), which should be 32 bytes.
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return Err(anyhow!("truncated TLV in nhash"));
        }
        let tlv_type = data[i];
        let tlv_len = data[i + 1] as usize;
        i += 2;

        if i + tlv_len > data.len() {
            return Err(anyhow!("truncated TLV value in nhash"));
        }

        if tlv_type == 0 && tlv_len == 32 {
            let hash: [u8; 32] = data[i..i + 32]
                .try_into()
                .map_err(|_| anyhow!("invalid hash in nhash"))?;
            return Ok(hash);
        }

        i += tlv_len;
    }

    Err(anyhow!("nhash URI contains no 32-byte hash (type 0)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nhash_roundtrip() {
        // Encode a known hash
        let hash = [0x42; 32];
        let nhash = crate::nhash::nhash_encode(&hash).unwrap();
        let uri = format!("htree://{}", nhash);

        let parsed = parse_nhash_uri(&uri).unwrap();
        assert_eq!(parsed, hash);
    }

    #[test]
    fn parse_nhash_rejects_bad_prefix() {
        assert!(parse_nhash_uri("https://example.com/foo").is_err());
    }

    #[test]
    fn parse_nhash_rejects_bad_hrp() {
        // Encode with wrong HRP using bech32 directly
        use bech32::{Bech32, Hrp};
        let hash = [0x42u8; 32];
        let mut tlv = vec![0u8, 32];
        tlv.extend_from_slice(&hash);
        let wrong_hrp = Hrp::parse("bc").unwrap();
        let encoded = bech32::encode::<Bech32>(wrong_hrp, &tlv).unwrap();

        // Should have HRP "bc", not "nhash"
        let (hrp, _) = bech32::decode(&encoded).unwrap();
        assert_ne!(hrp.as_str(), "nhash");

        // Our parser should reject it
        let uri = format!("htree://{}", encoded);
        assert!(parse_nhash_uri(&uri).is_err());
    }
}
