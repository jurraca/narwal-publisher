//! Ed25519 signing for narinfo fingerprints.
//!
//! Nix's `require-sigs` is `true` by default and global — unsigned caches
//! serving input-addressed paths are rejected by stock Nix clients. This
//! module signs the nix-narinfo fingerprint (computed correctly by the
//! crate, tested against Nix 2.34–2.36) with Ed25519 via ed25519-dalek.
//!
//! Nix key format: `keyname:base64(64_bytes = 32_seed + 32_public)`

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use nix_narinfo::NarInfoSignature;
use std::path::Path;

/// A Nix cache signing key, loaded from a `nix keygen-secret` file.
pub struct SigningKeyPair {
    pub keyname: String,
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

impl SigningKeyPair {
    /// Load a Nix secret key file.
    ///
    /// Format: `keyname:base64(64_bytes)` where the 64 bytes are the
    /// 32-byte Ed25519 seed followed by the 32-byte public key.
    /// Refuses group/world-accessible files (see `crate::secrets`).
    pub fn from_secret_file(path: &Path) -> Result<Self> {
        crate::secrets::deny_weak_permissions(path, "Nix cache signing key")?;
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read secret key file {}: {}", path.display(), e))?;
        Self::from_secret_str(content.trim())
    }

    /// Parse a Nix secret key string (`keyname:base64`).
    pub fn from_secret_str(s: &str) -> Result<Self> {
        let (keyname, b64) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid key format: expected 'name:base64'"))?;

        let raw = BASE64
            .decode(b64.trim())
            .map_err(|e| anyhow!("invalid base64 in secret key: {}", e))?;

        if raw.len() != 64 {
            return Err(anyhow!(
                "invalid secret key length: expected 64 bytes, got {}",
                raw.len()
            ));
        }

        // First 32 bytes are the seed
        let secret = SigningKey::from_bytes(raw[..32].try_into().unwrap());
        let public = secret.verifying_key();

        // Verify the embedded public key matches (bytes 32..64)
        let embedded_pub: [u8; 32] = raw[32..64].try_into().unwrap();
        if embedded_pub != public.to_bytes() {
            tracing::warn!("secret key file's embedded public key does not match derived key — using derived key");
        }

        Ok(Self {
            keyname: keyname.to_string(),
            secret,
            public,
        })
    }

    /// Sign a fingerprint and return a `NarInfoSignature` ready for the builder.
    pub fn sign_fingerprint(&self, fingerprint: &[u8]) -> NarInfoSignature {
        let sig = self.secret.sign(fingerprint);
        NarInfoSignature {
            key_name: self.keyname.clone(),
            encoded: BASE64.encode(sig.to_bytes()),
        }
    }

    /// Render the public key in Nix's `keyname:base64` format for advertising
    /// in the Nostr event's `nixSigKey` tag.
    pub fn public_key_string(&self) -> String {
        format!("{}:{}", self.keyname, BASE64.encode(self.public.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn random_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn nix_format_key(signing_key: &SigningKey) -> String {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&signing_key.to_bytes());
        raw[32..].copy_from_slice(&signing_key.verifying_key().to_bytes());
        format!("test-cache-1:{}", BASE64.encode(&raw))
    }

    #[test]
    fn load_and_sign_roundtrip() {
        let signing_key = random_signing_key();
        let verifying_key = signing_key.verifying_key();
        let nix_key = nix_format_key(&signing_key);

        let pair = SigningKeyPair::from_secret_str(&nix_key).unwrap();
        assert_eq!(pair.keyname, "test-cache-1");
        assert_eq!(pair.public.to_bytes(), verifying_key.to_bytes());

        // Sign something and verify
        let msg = b"test fingerprint bytes";
        let sig = pair.sign_fingerprint(msg);

        assert_eq!(sig.key_name, "test-cache-1");
        assert!(!sig.encoded.is_empty());

        // Verify the signature cryptographically
        let sig_bytes = BASE64.decode(&sig.encoded).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(msg, &ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap()))
            .expect("signature must verify");
    }

    #[test]
    fn public_key_string_format() {
        let signing_key = random_signing_key();
        let nix_key = nix_format_key(&signing_key);

        let pair = SigningKeyPair::from_secret_str(&nix_key).unwrap();
        let pub_str = pair.public_key_string();

        assert!(pub_str.starts_with("test-cache-1:"));
        // Public key is 32 bytes → base64 is 44 chars
        let b64_part = &pub_str["test-cache-1:".len()..];
        assert_eq!(b64_part.len(), 44);
    }

    #[test]
    fn load_from_file() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("secret-key");

        let signing_key = random_signing_key();
        let nix_key = nix_format_key(&signing_key);

        std::fs::write(&key_path, &nix_key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let pair = SigningKeyPair::from_secret_file(&key_path).unwrap();
        assert_eq!(pair.keyname, "test-cache-1");
    }

    #[cfg(unix)]
    #[test]
    fn load_from_file_rejects_weak_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("secret-key");

        let signing_key = random_signing_key();
        std::fs::write(&key_path, nix_format_key(&signing_key)).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = SigningKeyPair::from_secret_file(&key_path).err().expect("weak perms must be refused");
        assert!(err.to_string().contains("group/world-accessible"), "unexpected: {err}");
    }

    #[test]
    fn reject_bad_key_format() {
        assert!(SigningKeyPair::from_secret_str("no-colon-here").is_err());
        assert!(SigningKeyPair::from_secret_str("name:!!invalidbase64!!").is_err());
        assert!(SigningKeyPair::from_secret_str("name:AAAA").is_err()); // too short
    }
}
