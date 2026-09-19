//! Persisted NIP-46 pairing state.
//!
//! A pairing is the durable result of the QR ceremony: the client app key,
//! the remote signer pubkey, the user pubkey, and the relays the signer is
//! reachable on. It lives at `~/.local/share/narwal-cli/pairing.json`
//! (0600) and lets later runs skip the scan.
//!
//! This module is deliberately dependency-free with respect to the transport
//! (`signer`) and the ceremony (`pair`): both depend on it, so it must not
//! depend on either.

use crate::secrets;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Persisted pairing: stable app identity + who it paired with.
#[derive(Debug, Clone)]
pub struct Pairing {
    /// App secret key, hex. Local bearer credential, not the identity key.
    pub app_secret_hex: String,
    /// Signer (bunker) pubkey, hex.
    pub bunker_pubkey_hex: String,
    /// User pubkey, hex. Re-checked on reuse; mismatch warns. May be empty
    /// if the signer accepted the connection but was not yet serving
    /// `get_public_key` when pairing finished — it is then resolved lazily
    /// on first use and cached in-process.
    pub user_pubkey_hex: String,
    /// Relays the signer is reachable on, learned during pairing from the
    /// handshake relays plus any `switch_relays` answer. Persisted so reuse
    /// talks to the *same* relays the signer is listening on instead of
    /// falling back to CLI defaults (which the signer may never see).
    /// Empty for pairing files written before this field existed.
    pub relays: Vec<String>,
}

/// Default pairing file location.
pub fn default_pairing_file() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| anyhow!("HOME is not set; pass --pairing-file explicitly"))?;
    Ok(PathBuf::from(home).join(".local/share/narwal-cli/pairing.json"))
}

/// Load a stored pairing, if present.
pub fn load_pairing(path: &Path) -> Result<Option<Pairing>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = secrets::read_secret_file(path, "bunker pairing")?;
    parse_pairing(&raw)
}

fn parse_pairing(raw: &str) -> Result<Option<Pairing>> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| anyhow!("pairing file is not valid JSON: {e}"))?;
    let get = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("pairing file missing {k:?}"))
    };
    // Relays are optional: older files predate the field, and an empty list
    // simply falls back to the caller's relays.
    let relays = v
        .get("relays")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Pairing {
        app_secret_hex: get("app_secret_hex")?,
        bunker_pubkey_hex: get("bunker_pubkey_hex")?,
        user_pubkey_hex: get("user_pubkey_hex")?,
        relays,
    }))
}

/// Save a pairing with owner-only permissions.
pub fn save_pairing(path: &Path, pairing: &Pairing) -> Result<()> {
    let value = serde_json::json!({
        "app_secret_hex": pairing.app_secret_hex,
        "bunker_pubkey_hex": pairing.bunker_pubkey_hex,
        "user_pubkey_hex": pairing.user_pubkey_hex,
        "relays": pairing.relays,
    });
    let raw = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).map_err(|e| anyhow!("failed to encode pairing: {e}"))?
    );
    secrets::write_secret_file(path, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_file_round_trip_locks_down() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("pairing.json");
        let pairing = Pairing {
            app_secret_hex: "11".repeat(32),
            bunker_pubkey_hex: "22".repeat(32),
            user_pubkey_hex: "33".repeat(32),
            relays: vec![
                "wss://relay.nsec.app".to_string(),
                "wss://nos.lol".to_string(),
            ],
        };
        save_pairing(&path, &pairing).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "pairing file must be owner-only");
        }
        let loaded = load_pairing(&path).unwrap().expect("must load");
        assert_eq!(loaded.app_secret_hex, pairing.app_secret_hex);
        assert_eq!(loaded.bunker_pubkey_hex, pairing.bunker_pubkey_hex);
        assert_eq!(loaded.user_pubkey_hex, pairing.user_pubkey_hex);
        assert_eq!(loaded.relays, pairing.relays);
    }

    /// Pairing files written before the `relays` field existed must still
    /// load (relays default to empty, so the caller falls back).
    #[test]
    fn parse_legacy_pairing_without_relays() {
        let legacy = r#"{"app_secret_hex":"aa","bunker_pubkey_hex":"bb","user_pubkey_hex":"cc"}"#;
        let p = parse_pairing(legacy).unwrap().expect("must parse");
        assert!(p.relays.is_empty());
        assert_eq!(p.user_pubkey_hex, "cc");
    }

    #[test]
    fn load_missing_pairing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_pairing(&dir.path().join("nope.json")).unwrap().is_none());
    }

    #[test]
    fn load_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pairing.json");
        crate::secrets::write_secret_file(&path, "{not json").unwrap();
        assert!(load_pairing(&path).is_err());
    }

    #[test]
    fn default_pairing_file_shape() {
        // Without HOME this errors; with HOME it ends in the right name.
        // Only assert when HOME is set (sandbox-safe either way).
        if std::env::var("HOME").is_ok() {
            let p = default_pairing_file().unwrap();
            assert_eq!(p.file_name().unwrap(), "pairing.json");
        }
    }
}
