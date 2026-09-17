//! Secret key file loading with permission hygiene.
//!
//! Both publisher secrets — the Nostr identity and the Nix cache signing
//! key — are file-only by design. Command-line arguments leak through the
//! process table (`ps`), shell history, and CI logs; files do not (when
//! their permissions are right, which this module enforces).

use anyhow::{anyhow, Result};
use std::path::Path;

/// Read a secret file, refusing group/world-accessible permissions.
///
/// Returns the trimmed file contents. `what` names the secret for error
/// messages (e.g. "Nostr identity", "Nix cache signing key").
pub fn read_secret_file(path: &Path, what: &str) -> Result<String> {
    deny_weak_permissions(path, what)?;
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read {} file {}: {}", what, path.display(), e))?;
    Ok(content.trim().to_string())
}

/// Refuse to load a secret from a group- or world-accessible file.
///
/// SSH-style hard error: `mode & 0o077` must be zero. On non-Unix
/// platforms there is nothing to check, so this is a no-op.
pub fn deny_weak_permissions(path: &Path, what: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| anyhow!("failed to stat {} file {}: {}", what, path.display(), e))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "refusing to load {} from {}: permissions {:o} are group/world-accessible; run `chmod 600 {}`",
                what,
                path.display(),
                mode & 0o777,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (path, what);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn accepts_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "nsec1testpayload").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret_file(&path, "test secret").unwrap(), "nsec1testpayload");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "nsec1testpayload").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = read_secret_file(&path, "test secret").err().expect("weak perms must be refused");
        assert!(err.to_string().contains("group/world-accessible"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "nsec1testpayload").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = deny_weak_permissions(&path, "test secret").err().expect("weak perms must be refused");
        assert!(err.to_string().contains("chmod 600"), "unexpected: {err}");
    }

    #[test]
    fn missing_file_errors() {
        // Missing files fail at stat time, before any read is attempted.
        let err = read_secret_file(Path::new("/nonexistent-dir-xyz/secret"), "test secret").err().expect("missing file must error");
        assert!(err.to_string().contains("failed to stat"), "unexpected: {err}");
    }
}
