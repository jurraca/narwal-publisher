//! Scan a Nix binary cache staging directory.
//!
//! Expects the layout produced by `nix copy --to file:///staging`:
//!   nix-cache-info
//!   *.narinfo
//!   nar/*.nar.xz

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A scanned staging directory.
pub struct StagingDir {
    /// Path to nix-cache-info file.
    pub cache_info: PathBuf,
    /// All .narinfo files (path on disk).
    pub narinfos: Vec<PathBuf>,
    /// All NAR files (path on disk), typically nar/*.nar.xz.
    pub nars: Vec<PathBuf>,
}

/// Scan a staging directory.
pub fn scan(path: &Path) -> Result<StagingDir> {
    let cache_info = path.join("nix-cache-info");
    if !cache_info.exists() {
        return Err(anyhow!(
            "nix-cache-info not found in {}",
            path.display()
        ));
    }

    let mut narinfos = Vec::new();
    let mut nars = Vec::new();

    for entry in WalkDir::new(path).min_depth(1).max_depth(2) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "narinfo" {
                    narinfos.push(path.to_path_buf());
                } else if ext == "xz" || ext == "nar" {
                    nars.push(path.to_path_buf());
                }
            }
        }
    }

    narinfos.sort();
    nars.sort();

    tracing::info!(
        "scanned {}: {} narinfos, {} NARs",
        path.display(),
        narinfos.len(),
        nars.len()
    );

    Ok(StagingDir {
        cache_info,
        narinfos,
        nars,
    })
}

/// Read file bytes.
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    Ok(std::fs::read(path)?)
}
