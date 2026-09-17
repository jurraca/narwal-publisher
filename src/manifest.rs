//! BUD-16 directory manifest encoding.
//!
//! A tree node is a MessagePack map with two fields:
//!   "l" (array): links to child objects
//!   "t" (u8):    node type (2 = Dir)
//!
//! Each link is a map with compact keys:
//!   "h" (bytes):  32-byte SHA256 hash (required)
//!   "n" (string): entry name (optional, for directories)
//!   "s" (u64):    child byte size (required)
//!   "t" (u8):     link type (0 = Blob, default)
//!
//! Directory links MUST be sorted by entry-name UTF-8 bytes before encoding.
//! Encoding uses rmp_serde::to_vec_named (map with string keys, not array).
//!
//! Large directories are chunked into sub-directories (max 174 links per node),
//! with all intermediate nodes also using t=2 (Dir) for Hashtree compatibility.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum links per directory node (BUD-17 fanout default).
const MAX_LINKS: usize = 174;

/// Wire format for a single directory link.
#[derive(Serialize, Deserialize, Clone)]
pub struct WireLink {
    #[serde(with = "serde_bytes")]
    pub h: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    pub s: u64,
    #[serde(default)]
    pub t: u8,
}

/// Wire format for a tree node.
#[derive(Serialize, Deserialize)]
pub struct WireTreeNode {
    pub l: Vec<WireLink>,
    pub t: u8,
}

/// A directory entry: name + SHA256 of the child blob + byte size.
#[derive(Clone)]
pub struct DirEntry {
    pub name: String,
    pub hash: [u8; 32],
    pub size: u64,
}

/// Intermediate built node with its total subtree size.
#[derive(Clone)]
struct BuiltNode {
    bytes: Vec<u8>,
    hash: [u8; 32],
    size: u64,
}

/// Build a chunked directory tree from entries.
///
/// Sorts entries by name (UTF-8 byte order), encodes as MessagePack.
/// If entries <= MAX_LINKS, returns a single node.
/// If entries > MAX_LINKS, creates sub-directory nodes (t=2) and parent
/// directory nodes (t=2) linking to them, recursively until the root
/// has <= MAX_LINKS links.
///
/// Returns (all_nodes, root_hash) where all_nodes is a list of every
/// node that must be uploaded (leaves first, then parents). Each node
/// is (encoded_bytes, hash) where hash = SHA256(encoded_bytes).
pub fn build_directory_tree(entries: Vec<DirEntry>) -> (Vec<(Vec<u8>, [u8; 32])>, [u8; 32]) {
    let mut sorted = entries;
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    // Build leaf directory nodes (each <= MAX_LINKS entries)
    let mut current_level: Vec<BuiltNode> = Vec::new();
    for chunk in sorted.chunks(MAX_LINKS) {
        let total_size = chunk.iter().map(|e| e.size).sum();
        let wire = WireTreeNode {
            t: 2, // Dir
            l: chunk
                .iter()
                .map(|e| WireLink {
                    h: e.hash.to_vec(),
                    n: Some(e.name.clone()),
                    s: e.size,
                    t: 0, // Blob
                })
                .collect(),
        };
        let bytes = rmp_serde::to_vec_named(&wire).expect("directory node encoding must not fail");
        let hash = sha256(&bytes);
        current_level.push(BuiltNode {
            bytes,
            hash,
            size: total_size,
        });
    }

    // Empty directory: create a single node with 0 links
    if current_level.is_empty() {
        let wire = WireTreeNode {
            t: 2, // Dir
            l: Vec::new(),
        };
        let bytes = rmp_serde::to_vec_named(&wire).expect("directory node encoding must not fail");
        let hash = sha256(&bytes);
        return (vec![(bytes, hash)], hash);
    }

    let mut all_nodes = current_level.clone();

    // Build parent directory levels until one root remains
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(MAX_LINKS) {
            let total_size = chunk.iter().map(|n| n.size).sum();
            let wire = WireTreeNode {
                t: 2, // Dir
                l: chunk
                    .iter()
                    .map(|n| WireLink {
                        h: n.hash.to_vec(),
                        n: None,
                        s: n.size,
                        t: 2, // Dir
                    })
                    .collect(),
            };
            let bytes =
                rmp_serde::to_vec_named(&wire).expect("directory node encoding must not fail");
            let hash = sha256(&bytes);
            next_level.push(BuiltNode {
                bytes,
                hash,
                size: total_size,
            });
        }
        all_nodes.extend(next_level.clone());
        current_level = next_level;
    }

    let root = current_level.into_iter().next().expect("tree must have at least one node");
    (
        all_nodes.into_iter().map(|n| (n.bytes, n.hash)).collect(),
        root.hash,
    )
}

/// Build a single BUD-16 directory node from entries (no chunking).
///
/// Used for small directories and as a building block.
pub fn build_directory_node(entries: Vec<DirEntry>) -> (Vec<u8>, [u8; 32]) {
    let mut sorted = entries;
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let wire = WireTreeNode {
        t: 2, // Dir
        l: sorted
            .into_iter()
            .map(|e| WireLink {
                h: e.hash.to_vec(),
                n: Some(e.name),
                s: e.size,
                t: 0, // Blob
            })
            .collect(),
    };

    let bytes = rmp_serde::to_vec_named(&wire).expect("directory node encoding must not fail");
    let hash = sha256(&bytes);
    (bytes, hash)
}

/// Compute SHA256 of input bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, hash_byte: u8, size: u64) -> DirEntry {
        DirEntry {
            name: name.into(),
            hash: [hash_byte; 32],
            size,
        }
    }

    fn make_entries(count: usize) -> Vec<DirEntry> {
        (0..count)
            .map(|i| make_entry(&format!("{:08x}.narinfo", i), (i % 256) as u8, 100 + i as u64))
            .collect()
    }

    #[test]
    fn test_empty_directory() {
        let (nodes, root_hash) = build_directory_tree(vec![]);
        assert_eq!(nodes.len(), 1);
        assert!(!nodes[0].0.is_empty());
        assert_eq!(root_hash.len(), 32);
        assert_eq!(root_hash, sha256(&nodes[0].0));
    }

    #[test]
    fn test_single_entry() {
        let entries = vec![make_entry("test.narinfo", 0xab, 42)];
        let (nodes, root_hash) = build_directory_tree(entries);
        assert_eq!(nodes.len(), 1);
        assert!(!nodes[0].0.is_empty());
        assert_eq!(root_hash, sha256(&nodes[0].0));
    }

    #[test]
    fn test_small_directory_no_chunking() {
        let entries = make_entries(10);
        let (nodes, root_hash) = build_directory_tree(entries);
        assert_eq!(nodes.len(), 1);
        assert_eq!(root_hash, sha256(&nodes[0].0));
    }

    #[test]
    fn test_exactly_max_links() {
        let entries = make_entries(MAX_LINKS);
        let (nodes, root_hash) = build_directory_tree(entries);
        assert_eq!(nodes.len(), 1);
        assert_eq!(root_hash, sha256(&nodes[0].0));
    }

    #[test]
    fn test_one_over_max_links() {
        let entries = make_entries(MAX_LINKS + 1);
        let (nodes, root_hash) = build_directory_tree(entries);
        // 2 leaf nodes (174 + 1) + 1 parent node = 3 total
        assert_eq!(nodes.len(), 3);

        // Decode root and verify it has 2 links (both t=2 Dir)
        let root_bytes = &nodes.last().unwrap().0;
        let root_node: WireTreeNode = rmp_serde::from_slice(root_bytes).unwrap();
        assert_eq!(root_node.t, 2);
        assert_eq!(root_node.l.len(), 2);
        assert!(root_node.l.iter().all(|link| link.t == 2));

        assert_eq!(root_hash, sha256(root_bytes));
    }

    #[test]
    fn test_two_level_chunking() {
        // 174 * 174 = 30276 entries -> fits in one level of leaves + root
        let entries = make_entries(MAX_LINKS * MAX_LINKS);
        let (nodes, root_hash) = build_directory_tree(entries);
        // Leaves: 174, Root: 1 = 175 total
        assert_eq!(nodes.len(), 175);
        assert_eq!(root_hash, sha256(&nodes.last().unwrap().0));
    }

    #[test]
    fn test_three_level_chunking() {
        // 174 * 174 + 1 = 30277 entries -> root needs 175 links, which exceeds MAX_LINKS
        // So we need another level: 174 leaf nodes + 1 parent (174 links) + 1 root (1 link)
        // Wait, 30277 / 174 = 174.01 -> 175 leaf nodes
        // Parent of 175 leaf nodes: ceil(175/174) = 2 parent nodes
        // Root of 2 parent nodes: 1 root
        // Total: 175 + 2 + 1 = 178
        let entries = make_entries(MAX_LINKS * MAX_LINKS + 1);
        let (nodes, root_hash) = build_directory_tree(entries);
        assert_eq!(nodes.len(), 178);
        assert_eq!(root_hash, sha256(&nodes.last().unwrap().0));
    }

    #[test]
    fn test_sorting_is_deterministic() {
        let entries_a = vec![
            make_entry("b.narinfo", 1, 1),
            make_entry("a.narinfo", 2, 2),
        ];
        let entries_b = vec![
            make_entry("a.narinfo", 2, 2),
            make_entry("b.narinfo", 1, 1),
        ];
        let (_, hash_a) = build_directory_tree(entries_a);
        let (_, hash_b) = build_directory_tree(entries_b);
        assert_eq!(hash_a, hash_b, "sorting must produce identical hashes");
    }

    #[test]
    fn test_all_nodes_uploadable() {
        let entries = make_entries(MAX_LINKS + 5);
        let (nodes, root_hash) = build_directory_tree(entries);
        // Every node should hash to its own bytes
        for (bytes, hash) in &nodes {
            assert_eq!(*hash, sha256(bytes), "node hash must match its bytes");
        }
        // Root should be the last node
        assert_eq!(root_hash, nodes.last().unwrap().1);
    }

    #[test]
    fn test_build_directory_node_matches_tree_for_small() {
        let entries = make_entries(10);
        let (tree_nodes, tree_root) = build_directory_tree(entries.clone());
        let (node_bytes, node_hash) = build_directory_node(entries);
        assert_eq!(tree_nodes.len(), 1);
        assert_eq!(tree_root, node_hash);
        assert_eq!(tree_nodes[0].0, node_bytes);
    }
}
