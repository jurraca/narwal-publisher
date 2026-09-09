//! Nix store path handling via nix-derivation types.
//!
//! Wraps `StoreDir` and `StorePath` from the nix-derivation crate to
//! provide ergonomic helpers for parsing store path basenames and
//! rendering full paths — replacing the hand-rolled nix32 logic that
//! the old publisher never had (it relied on `nix copy --to` for this).

use anyhow::{anyhow, Result};
use nix_derivation::{StoreDir, StorePath};

/// The default Nix store directory (`/nix/store`).
pub fn default_store_dir() -> StoreDir {
    StoreDir::default()
}

/// Parse a store path basename (e.g. `0abc...-hello-1.0`) into a `StorePath`.
pub fn parse_basename(basename: &str) -> Result<StorePath> {
    StorePath::from_basename(basename.as_bytes())
        .map_err(|e| anyhow!("invalid store path basename '{}': {}", basename, e))
}

/// Parse a full absolute store path (e.g. `/nix/store/0abc...-hello-1.0`).
pub fn parse_path(store_dir: &StoreDir, path: &str) -> Result<StorePath> {
    store_dir
        .parse_path(path.as_bytes())
        .map_err(|e| anyhow!("invalid store path '{}': {}", path, e))
}

/// Render a `StorePath` as a full absolute path string.
pub fn render_path(store_dir: &StoreDir, path: &StorePath) -> String {
    store_dir.render_path(path)
}

/// Extract the hash part (32-char nix-base32 prefix) from a store path name.
///
/// E.g. `0abc1def...-hello-1.0` → `0abc1def...` (everything before first `-`).
pub fn hash_part(name: &str) -> &str {
    match name.find('-') {
        Some(idx) => &name[..idx],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_render_roundtrip() {
        let dir = default_store_dir();
        let basename = "0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3-hello-2.12.1";
        let sp = parse_basename(basename).unwrap();
        let rendered = render_path(&dir, &sp);
        assert_eq!(rendered, format!("/nix/store/{}", basename));
    }

    #[test]
    fn parse_full_path() {
        let dir = default_store_dir();
        let path = "/nix/store/0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3-hello-2.12.1";
        let sp = parse_path(&dir, path).unwrap();
        let rendered = render_path(&dir, &sp);
        assert_eq!(rendered, path);
    }

    #[test]
    fn extract_hash_part() {
        let name = "0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3-hello-2.12.1";
        assert_eq!(
            hash_part(name),
            "0c2a5hhq7q6wq0qry4l7g55dmvx7v8i3"
        );
    }

    #[test]
    fn hash_part_no_dash() {
        assert_eq!(hash_part("nodash"), "nodash");
    }
}
