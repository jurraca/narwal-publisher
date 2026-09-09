//! Reference scanning via nix-archive's `ReferencePattern`.
//!
//! A store path's references are other store-path hashparts that appear
//! literally in its NAR byte stream. nix-archive scans for these in a
//! single pass that also yields the NAR hash and size.
//!
//! This module wraps `ReferencePattern` to provide a convenient API for
//! scanning a single path against a known candidate set.

use anyhow::Result;
use nix_archive::nar::{CaseHack, ReferencePattern, ReferenceScan};
use std::path::Path;

/// Build a `ReferencePattern` from candidate hashparts (32-char nix32 strings).
pub fn build_pattern(candidates: &[String]) -> Result<ReferencePattern> {
    ReferencePattern::new(candidates.iter().map(|s| s.as_str()))
        .map_err(|e| anyhow::anyhow!("reference pattern error: {}", e))
}

/// Scan a store path for references, returning NAR hash + size + matched
/// candidate indices in one pass.
pub fn scan_path(
    pattern: &ReferencePattern,
    path: &Path,
) -> Result<ReferenceScan> {
    pattern
        .scan_path(path, CaseHack::native())
        .map_err(|e| anyhow::anyhow!("reference scan error for {}: {}", path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pattern_is_valid() {
        let pattern = build_pattern(&[]).unwrap();
        assert!(pattern.is_empty());
    }

    #[test]
    fn pattern_len_counts_candidates() {
        let candidates = vec![
            "00000000000000000000000000000000".to_string(),
            "11111111111111111111111111111111".to_string(),
        ];
        let pattern = build_pattern(&candidates).unwrap();
        assert_eq!(pattern.len(), 2);
    }
}
