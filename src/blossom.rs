//! Blossom blob upload with NIP-98 authentication.
//!
//! BUD-02 defines PUT /upload for blob upload.
//! BUD-01 defines GET /<sha256> and HEAD /<sha256> for retrieval.
//! BUD-06 defines HEAD /upload for preflight checks.
//!
//! Authentication uses NIP-98 (kind 24242 event) as an
//! `Authorization: Nostr <base64-json>` header.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use nostr::prelude::*;
use reqwest::Client;
use sha2::{Digest, Sha256};

/// Preflight threshold: HEAD /upload is only used for blobs > 2MB.
const PREFLIGHT_SIZE_THRESHOLD: usize = 2 * 1024 * 1024;

/// A single server rejection reason.
struct ServerError {
    server: String,
    status: reqwest::StatusCode,
    reason: Option<String>,
}

impl ServerError {
    fn description(&self) -> String {
        let reason = self
            .reason
            .as_deref()
            .unwrap_or("no reason given");
        format!("{}: {} {}", self.server, self.status, reason)
    }
}

/// A Blossom client that uploads blobs to one or more servers.
pub struct BlossomUploader {
    keys: Keys,
    servers: Vec<String>,
    http: Client,
}

impl BlossomUploader {
    pub fn new(keys: Keys, servers: Vec<String>) -> Self {
        Self {
            keys,
            servers,
            http: Client::new(),
        }
    }

    /// Compute SHA256 of data, returning hex string.
    pub fn hash_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Build a NIP-98 upload auth event and return the Authorization header value.
    async fn create_auth_header(&self, hash: &str) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let expiration = now + 300; // 5 minutes

        let tags = vec![
            Tag::custom(TagKind::custom("t"), vec!["upload"]),
            Tag::custom(TagKind::custom("x"), vec![hash.to_string()]),
            Tag::custom(TagKind::custom("expiration"), vec![expiration.to_string()]),
        ];

        let event = EventBuilder::new(Kind::Custom(24242), "Upload")
            .tags(tags)
            .sign_with_keys(&self.keys)?;

        let json = event.as_json();
        let encoded = BASE64.encode(json);
        Ok(format!("Nostr {}", encoded))
    }

    /// Check if a server already has the blob via HEAD /<sha256> (BUD-01).
    async fn check_exists(&self, server: &str, hash: &str) -> Result<bool> {
        let url = format!("{}/{}", server.trim_end_matches('/'), hash);
        let resp = match self.http.head(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("HEAD existence check to {} failed: {}", server, e);
                return Ok(false);
            }
        };
        Ok(resp.status().is_success())
    }

    /// Preflight upload via HEAD /upload (BUD-06).
    /// Returns Ok(true) if the server should accept the upload.
    /// Returns Ok(false) if we should skip this server (413, etc.).
    /// Returns Err for unexpected/network errors.
    async fn preflight_upload(
        &self,
        server: &str,
        hash: &str,
        size: usize,
    ) -> Result<(bool, Option<String>)> {
        let url = format!("{}/upload", server.trim_end_matches('/'));
        let resp = match self
            .http
            .head(&url)
            .header("X-SHA-256", hash)
            .header("X-Content-Length", size.to_string())
            .header("X-Content-Type", "application/octet-stream")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("HEAD /upload preflight to {} failed: {}", server, e);
                return Ok((false, Some(format!("network error: {}", e))));
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::OK {
            return Ok((true, None));
        }

        let reason = resp
            .headers()
            .get("X-Reason")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            // 413 — skip this server permanently for this blob
            tracing::warn!(
                "server {} rejected preflight: 413 Content Too Large (size: {} bytes){}",
                server,
                size,
                reason.as_ref().map(|r| format!(" — {}", r)).unwrap_or_default()
            );
            return Ok((false, reason));
        }

        // Any other error: log it but still try the PUT (server state may change)
        tracing::debug!(
            "HEAD /upload to {} returned {} — will attempt PUT anyway{}",
            server,
            status,
            reason.as_ref().map(|r| format!(" ({})", r)).unwrap_or_default()
        );
        Ok((true, reason))
    }

    /// Upload a blob to a specific server.
    ///
    /// Returns Ok(()) on success (201 Created or 200 OK = already exists).
    /// Returns Err for 413 or other fatal errors.
    async fn upload_to_server(&self, server: &str, data: &[u8], hash: &str) -> Result<()> {
        let auth_header = self.create_auth_header(hash).await?;
        let url = format!("{}/upload", server.trim_end_matches('/'));

        let resp = self
            .http
            .put(&url)
            .header("Authorization", &auth_header)
            .header("Content-Type", "application/octet-stream")
            .header("X-SHA-256", hash)
            .body(data.to_vec())
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            tracing::debug!("uploaded {} to {} (status {})", &hash[..12], server, status);
            Ok(())
        } else {
            let reason = resp
                .headers()
                .get("X-Reason")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let text = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
                return Err(anyhow!(
                    "413 Content Too Large{}",
                    reason.map(|r| format!(" — {}", r)).unwrap_or_default()
                ));
            }

            Err(anyhow!(
                "{} {}{}",
                status,
                text,
                reason.map(|r| format!(" ({})", r)).unwrap_or_default()
            ))
        }
    }

    /// Upload a blob to all configured servers (redundant replication).
    ///
    /// For each server:
    /// 1. HEAD /<sha256> — skip if already exists.
    /// 2. If data > 2MB: HEAD /upload (BUD-06) preflight — skip on 413.
    /// 3. PUT /upload — try the upload.
    /// 4. On 413 from PUT: skip to next server.
    ///
    /// Uploads to ALL servers for redundancy — does not stop at first success.
    /// Returns Ok(hash) if at least one server has the blob after all attempts.
    /// Returns Err only if every server failed.
    pub async fn upload(&self, data: &[u8]) -> Result<String> {
        let hash = Self::hash_hex(data);
        let size = data.len();
        let should_preflight = size > PREFLIGHT_SIZE_THRESHOLD;

        let mut errors: Vec<ServerError> = Vec::new();
        let mut success_count = 0usize;

        for server in &self.servers {
            // 1. Existence check (BUD-01)
            match self.check_exists(server, &hash).await {
                Ok(true) => {
                    tracing::debug!("blob {} already exists on {}", &hash[..12], server);
                    success_count += 1;
                    continue; // try next server for redundancy
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::debug!("existence check to {} failed: {}", server, e);
                }
            }

            // 2. Preflight for large blobs (BUD-06)
            if should_preflight {
                match self.preflight_upload(server, &hash, size).await {
                    Ok((true, _)) => {} // proceed with upload
                    Ok((false, reason)) => {
                        errors.push(ServerError {
                            server: server.clone(),
                            status: reqwest::StatusCode::PAYLOAD_TOO_LARGE,
                            reason,
                        });
                        continue; // skip this server
                    }
                    Err(e) => {
                        tracing::debug!("preflight to {} failed: {}", server, e);
                    }
                }
            }

            // 3. Upload (BUD-02)
            match self.upload_to_server(server, data, &hash).await {
                Ok(()) => {
                    success_count += 1;
                    tracing::debug!("uploaded {} to {}", &hash[..12], server);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    let status = if err_str.starts_with("413") {
                        reqwest::StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        reqwest::StatusCode::BAD_REQUEST
                    };
                    let reason = if err_str.starts_with("413 Content Too Large") {
                        err_str.strip_prefix("413 Content Too Large").map(|s| s.trim().to_string())
                    } else {
                        Some(err_str.clone())
                    };
                    errors.push(ServerError {
                        server: server.clone(),
                        status,
                        reason,
                    });
                    tracing::warn!("upload to {} failed: {}", server, err_str);
                }
            }
        }

        if success_count > 0 {
            tracing::info!(
                "blob {} ({} bytes): {}/{} servers have it",
                &hash[..12],
                size,
                success_count,
                self.servers.len(),
            );
            return Ok(hash);
        }

        // All servers failed — build comprehensive error
        let mut msg = format!(
            "Blob {} ({} bytes) rejected by all {} Blossom server(s):\n",
            &hash[..16],
            size,
            self.servers.len()
        );
        for err in &errors {
            msg.push_str("  - ");
            msg.push_str(&err.description());
            msg.push('\n');
        }
        if errors.is_empty() {
            msg.push_str("  (no servers configured or all preflight checks failed)\n");
        }

        Err(anyhow!(msg.trim_end().to_string()))
    }

    /// Upload a blob, trying all servers. Returns the hash.
    pub async fn upload_bytes(&self, data: &[u8]) -> Result<String> {
        self.upload(data).await
    }
}
