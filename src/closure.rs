//! Self-contained closure resolution via reference scanning.
//!
//! Given input store paths, produce the full ordered list of paths to
//! publish (dependencies first) — without shelling out to `nix-store`.
//!
//! A store path's references are other store-path hashparts that appear
//! literally in its NAR byte stream. nix-archive's `ReferencePattern`
//! scans for exactly these. We discover the full closure by scanning
//! references recursively, starting from the input paths.
//!
//! The candidate set is all paths in `/nix/store` (obtained via readdir).
//! This is cheap because the scanner does O(1) HashMap lookups per byte
//! position with an alphabet pre-check.

use anyhow::{anyhow, Result};
use nix_archive::nar::{CaseHack, ReferencePattern};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A resolved store path in the closure with its NAR metadata and references.
pub struct ClosureEntry {
    /// Full store path, e.g. `/nix/store/0abc...-hello-1.0`
    pub path: PathBuf,
    /// SHA-256 of the NAR bytes
    pub nar_hash: [u8; 32],
    /// NAR byte length
    pub nar_size: u64,
    /// References: hashparts of other store paths (32-char nix32 strings)
    pub references: Vec<String>,
}

/// A candidate entry from readdir(/nix/store), mapping hashpart → full path.
#[derive(Clone)]
struct Candidate {
    hashpart: String,
    path: PathBuf,
}

/// Read all entries from `/nix/store` and extract their hashparts.
///
/// Returns a list of (hashpart, full_path) candidates. Each entry's name
/// is expected to be `<32-char-hash>-<name>`.
fn read_store_candidates(store_dir: &Path) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(store_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let hashpart = match name.find('-') {
            Some(idx) => &name[..idx],
            None => continue, // skip entries without a dash (not store paths)
        };
        if hashpart.len() != 32 {
            continue; // not a standard store path hash
        }
        candidates.push(Candidate {
            hashpart: hashpart.to_string(),
            path: entry.path(),
        });
    }
    Ok(candidates)
}

/// Resolve the full closure of a set of input store paths.
///
/// Returns paths in topological order (dependencies first).
///
/// # Arguments
/// * `input_paths` - Store paths to resolve (e.g. `["/nix/store/0abc...-hello"]`)
/// * `store_dir` - The Nix store directory (default: `/nix/store`)
pub fn resolve(input_paths: &[PathBuf], store_dir: &Path) -> Result<Vec<ClosureEntry>> {
    if input_paths.is_empty() {
        return Ok(Vec::new());
    }

    // 1. readdir /nix/store → all hashparts as candidates
    tracing::info!("reading store candidates from {}", store_dir.display());
    let candidates = read_store_candidates(store_dir)?;
    tracing::info!("found {} store paths as reference candidates", candidates.len());

    // Build hashpart → candidate index map for quick lookup
    let hashpart_to_idx: HashMap<&str, usize> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| (c.hashpart.as_str(), i))
        .collect();

    // Build the candidate hashpart vec for ReferencePattern
    let candidate_hashparts: Vec<String> =
        candidates.iter().map(|c| c.hashpart.clone()).collect();

    // 2. Build the reference pattern (reused for all scans)
    let pattern = ReferencePattern::new(candidate_hashparts.iter().map(|s| s.as_str()))
        .map_err(|e| anyhow!("reference pattern error: {}", e))?;

    // Map input paths to candidate indices
    let input_hashparts: Vec<String> = input_paths
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .ok_or_else(|| anyhow!("invalid path: {}", p.display()))?
                .to_string_lossy()
                .to_string();
            let hp = name.split('-').next().unwrap_or(&name);
            Ok(hp.to_string())
        })
        .collect::<Result<Vec<_>>>()?;

    // Validate input paths exist in the store
    for (i, hp) in input_hashparts.iter().enumerate() {
        if !hashpart_to_idx.contains_key(hp.as_str()) {
            return Err(anyhow!(
                "input path {} not found in store (hashpart: {})",
                input_paths[i].display(),
                hp
            ));
        }
    }

    // 3. BFS closure resolution
    let mut closure: HashMap<String, ClosureEntry> = HashMap::new();
    let mut worklist: Vec<String> = input_hashparts.clone();
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(hashpart) = worklist.pop() {
        if visited.contains(&hashpart) {
            continue;
        }
        visited.insert(hashpart.clone());

        let idx = hashpart_to_idx[&hashpart.as_str()];
        let path = candidates[idx].path.clone();

        tracing::debug!("scanning {}", path.display());

        // Single pass: NAR hash + size + reference matches
        let scan = pattern
            .scan_path(&path, CaseHack::native())
            .map_err(|e| anyhow!("reference scan error for {}: {}", path.display(), e))?;

        // Map matched candidate indices back to hashparts
        let references: Vec<String> = scan
            .matches
            .iter()
            .map(|&i| candidates[i].hashpart.clone())
            .filter(|hp| hp != &hashpart) // exclude self-references
            .collect();

        // Add new references to worklist
        for ref_hp in &references {
            if !visited.contains(ref_hp) {
                worklist.push(ref_hp.clone());
            }
        }

        closure.insert(
            hashpart.clone(),
            ClosureEntry {
                path,
                nar_hash: scan.nar_sha256,
                nar_size: scan.nar_size,
                references,
            },
        );
    }

    // 4. Topological sort (dependencies first)
    let ordered = topo_sort(&closure, &input_hashparts)?;

    tracing::info!("closure resolved: {} paths", ordered.len());
    Ok(ordered)
}

/// Topological sort of the closure graph (dependencies before dependents).
fn topo_sort(
    closure: &HashMap<String, ClosureEntry>,
    roots: &[String],
) -> Result<Vec<ClosureEntry>> {
    // Build adjacency: for each hashpart, its dependency hashparts
    // We want dependencies first, so we do a post-order DFS.
    let mut visited: HashSet<String> = HashSet::new();
    let mut result: Vec<ClosureEntry> = Vec::new();

    fn dfs(
        hp: &str,
        closure: &HashMap<String, ClosureEntry>,
        visited: &mut HashSet<String>,
        result: &mut Vec<ClosureEntry>,
    ) -> Result<()> {
        if visited.contains(hp) {
            return Ok(());
        }
        visited.insert(hp.to_string());

        if let Some(entry) = closure.get(hp) {
            // Visit dependencies first
            for ref_hp in &entry.references {
                dfs(ref_hp, closure, visited, result)?;
            }
            result.push(ClosureEntry {
                path: entry.path.clone(),
                nar_hash: entry.nar_hash,
                nar_size: entry.nar_size,
                references: entry.references.clone(),
            });
        }

        Ok(())
    }

    for root in roots {
        dfs(root, closure, &mut visited, &mut result)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Create a fake store dir with a minimal path that has no references.
    /// We can't create real Nix store paths, but we can verify the candidate
    /// reader and topo sort logic.
    #[test]
    fn read_store_candidates_extracts_hashparts() {
        let tmp = tempdir().unwrap();
        let store = tmp.path();

        // Create fake store path entries
        fs::create_dir(store.join("00000000000000000000000000000000-foo-1.0")).unwrap();
        fs::create_dir(store.join("0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3-bar-2.0")).unwrap();
        fs::create_dir(store.join("invalid-entry")).unwrap();
        fs::create_dir(store.join("short-hash-x")).unwrap();
        fs::write(store.join("random-file"), b"hello").unwrap();

        let candidates = read_store_candidates(store).unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().any(|c| c.hashpart == "00000000000000000000000000000000"));
        assert!(candidates.iter().any(|c| c.hashpart == "0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3"));
    }

    #[test]
    fn topo_sort_orders_dependencies_first() {
        // Build a simple graph: A depends on B, B depends on C
        // Closure: { A: refs [B], B: refs [C], C: refs [] }
        let mut closure: HashMap<String, ClosureEntry> = HashMap::new();
        closure.insert("aaa".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/aaa-A"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec!["bbb".to_string()],
        });
        closure.insert("bbb".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/bbb-B"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec!["ccc".to_string()],
        });
        closure.insert("ccc".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/ccc-C"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec![],
        });

        let result = topo_sort(&closure, &["aaa".to_string()]).unwrap();

        assert_eq!(result.len(), 3);
        // C must come before B, B must come before A
        assert_eq!(result[0].path, PathBuf::from("/nix/store/ccc-C"));
        assert_eq!(result[1].path, PathBuf::from("/nix/store/bbb-B"));
        assert_eq!(result[2].path, PathBuf::from("/nix/store/aaa-A"));
    }

    #[test]
    fn topo_sort_handles_diamond() {
        // Diamond: A → B, A → C, B → D, C → D
        // D should appear once, before both B and C
        let mut closure: HashMap<String, ClosureEntry> = HashMap::new();
        closure.insert("aaa".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/aaa-A"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec!["bbb".to_string(), "ccc".to_string()],
        });
        closure.insert("bbb".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/bbb-B"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec!["ddd".to_string()],
        });
        closure.insert("ccc".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/ccc-C"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec!["ddd".to_string()],
        });
        closure.insert("ddd".to_string(), ClosureEntry {
            path: PathBuf::from("/nix/store/ddd-D"),
            nar_hash: [0; 32],
            nar_size: 100,
            references: vec![],
        });

        let result = topo_sort(&closure, &["aaa".to_string()]).unwrap();

        assert_eq!(result.len(), 4);
        // D must appear before B and C, which must appear before A
        let positions: HashMap<&str, usize> = result
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let hp = e.path.file_name().unwrap().to_str().unwrap();
                (hp, i)
            })
            .collect();
        assert!(positions["ddd-D"] < positions["bbb-B"]);
        assert!(positions["ddd-D"] < positions["ccc-C"]);
        assert!(positions["bbb-B"] < positions["aaa-A"]);
        assert!(positions["ccc-C"] < positions["aaa-A"]);
    }
}
