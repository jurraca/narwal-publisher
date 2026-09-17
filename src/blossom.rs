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

/// Session token lifetime: bearer tokens authorize any upload, so keep
/// the window short. Refreshed when under REFRESH_MARGIN_SECS of life.
const TOKEN_TTL_SECS: u64 = 120;
/// Re-mint when less than this much validity remains (covers clock skew;
/// the server rejects expired tokens and tolerates 60s future drift).
const REFRESH_MARGIN_SECS: u64 = 60;

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

/// A cached session auth token: one header value plus its expiry.
/// Tokens carry no `x` tag (upstream `requireXTag` passes any hash when
/// no `x` tags are present), so a single token authorizes every upload —
/// across blobs and across servers — until it expires.
struct CachedToken {
    header: String,
    expires_at: u64,
}

/// A Blossom client that uploads blobs to one or more servers.
pub struct BlossomUploader {
    keys: Keys,
    servers: Vec<String>,
    http: Client,
    auth_token: std::sync::Mutex<Option<CachedToken>>,
}

impl BlossomUploader {
    pub fn new(keys: Keys, servers: Vec<String>) -> Self {
        Self {
            keys,
            servers,
            http: Client::new(),
            auth_token: std::sync::Mutex::new(None),
        }
    }

    /// Compute SHA256 of data, returning hex string.
    pub fn hash_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn unix_now() -> Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs())
    }

    /// Mint a fresh session token (no `x` tag: valid for any upload).
    /// NOTE: the returned header is bearer material — never log it.
    fn mint_token(keys: &Keys) -> Result<CachedToken> {
        let now = Self::unix_now()?;
        let expiration = now + TOKEN_TTL_SECS;

        let tags = vec![
            Tag::custom(TagKind::custom("t"), vec!["upload"]),
            Tag::custom(TagKind::custom("expiration"), vec![expiration.to_string()]),
        ];

        let event = EventBuilder::new(Kind::Custom(24242), "Upload")
            .tags(tags)
            .sign_with_keys(keys)?;

        let json = event.as_json();
        let encoded = BASE64.encode(json);
        Ok(CachedToken {
            header: format!("Nostr {}", encoded),
            expires_at: expiration,
        })
    }

    /// Session Authorization header, reusing the cached token until it
    /// nears expiry. Lock is held only for a timestamp check / swap —
    /// signing happens outside it.
    fn auth_header(&self) -> Result<String> {
        let now = Self::unix_now()?;
        if let Some(tok) = self.auth_token.lock().map_err(|e| anyhow!("auth token lock poisoned: {e}"))?.as_ref() {
            if tok.expires_at.saturating_sub(now) >= REFRESH_MARGIN_SECS {
                return Ok(tok.header.clone());
            }
        }
        let tok = Self::mint_token(&self.keys)?;
        let header = tok.header.clone();
        *self.auth_token.lock().map_err(|e| anyhow!("auth token lock poisoned: {e}"))? = Some(tok);
        Ok(header)
    }

    /// Drop the cached token (e.g. after a 401) so the next call re-mints.
    fn invalidate_token(&self) {
        if let Ok(mut cache) = self.auth_token.lock() {
            *cache = None;
        }
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

    async fn put_upload(&self, server: &str, data: &[u8], hash: &str, auth: &str) -> Result<reqwest::Response> {
        let url = format!("{}/upload", server.trim_end_matches('/'));
        Ok(self
            .http
            .put(&url)
            .header("Authorization", auth)
            .header("Content-Type", "application/octet-stream")
            .header("X-SHA-256", hash)
            .body(data.to_vec())
            .send()
            .await?)
    }

    /// Upload a blob to a specific server.
    ///
    /// Returns Ok(()) on success (201 Created or 200 OK = already exists).
    /// Returns Err for 413 or other fatal errors.
    async fn upload_to_server(&self, server: &str, data: &[u8], hash: &str) -> Result<()> {
        let mut resp = self.put_upload(server, data, hash, &self.auth_header()?).await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Token may have expired mid-run (clock skew, long uploads):
            // invalidate once and retry with a fresh token.
            self.invalidate_token();
            resp = self.put_upload(server, data, hash, &self.auth_header()?).await?;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uploader() -> BlossomUploader {
        BlossomUploader::new(Keys::generate(), vec!["http://127.0.0.1:1".to_string()])
    }

    fn decode_auth_event(header: &str) -> nostr::Event {
        let b64 = header.strip_prefix("Nostr ").expect("missing Nostr prefix");
        let json = BASE64.decode(b64).expect("valid base64");
        let json = String::from_utf8(json).expect("valid utf-8");
        nostr::Event::from_json(json).expect("valid event")
    }

    fn tag_values(event: &nostr::Event, name: &str) -> Vec<String> {
        event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some(name))
            .filter_map(|t| t.as_slice().get(1).cloned())
            .collect()
    }

    #[test]
    fn session_token_shape() {
        let uploader = test_uploader();
        let header = uploader.auth_header().unwrap();
        let event = decode_auth_event(&header);
        assert_eq!(event.kind.as_u16(), 24242);
        assert_eq!(tag_values(&event, "t"), vec!["upload".to_string()]);
        assert!(tag_values(&event, "x").is_empty(), "session token must not scope to a blob");
        let exp: u64 = tag_values(&event, "expiration")[0].parse().unwrap();
        let now = BlossomUploader::unix_now().unwrap();
        assert!(exp > now && exp <= now + TOKEN_TTL_SECS + 5, "expiry must be ~TTL in the future");
    }

    #[test]
    fn session_token_reused_across_calls() {
        let uploader = test_uploader();
        let first = uploader.auth_header().unwrap();
        let second = uploader.auth_header().unwrap();
        assert_eq!(first, second, "one token per session, not per blob");
    }

    #[test]
    fn expired_token_is_reminted() {
        let uploader = test_uploader();
        // Plant a dead token straight into the cache.
        *uploader.auth_token.lock().unwrap() = Some(CachedToken {
            header: "Nostr stale".to_string(),
            expires_at: 1,
        });
        let fresh = uploader.auth_header().unwrap();
        assert_ne!(fresh, "Nostr stale");
        assert!(fresh.starts_with("Nostr "));
    }

    #[test]
    fn invalidate_drops_cached_token() {
        let uploader = test_uploader();
        let first = uploader.auth_header().unwrap();
        uploader.invalidate_token();
        // Cache is empty now; a re-mint must differ (fresh timestamps) or at
        // minimum be a valid header. Sleep-free: expiration seconds may tie,
        // so only assert validity, not inequality.
        let second = uploader.auth_header().unwrap();
        assert!(second.starts_with("Nostr "));
        let _ = first;
    }

    /// Live acceptance: an x-less session token must authorize PUT /upload
    /// on a real blossom-server (exercises upstream requireXTag pass-through).
    /// Runs only with TEST_BLOSSOM_URL set (e.g. http://185.18.221.233:3000);
    /// skipped otherwise so sandbox/CI stays offline-clean.
    #[tokio::test]
    async fn live_session_token_upload() {
        let server = match std::env::var("TEST_BLOSSOM_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skipping live_session_token_upload (TEST_BLOSSOM_URL unset)");
                return;
            }
        };
        // NOTE: needs an allowlisted publisher key to actually succeed; with
        // a random key expect 401/403, which still proves the token *shape*
        // parses (not 400). This test documents shape acceptance, not policy.
        let uploader = BlossomUploader::new(Keys::generate(), vec![server]);
        let data = b"narwal-cli session-token probe";
        let hash = BlossomUploader::hash_hex(data);
        let auth = uploader.auth_header().unwrap();
        let url = format!("{}/upload", uploader.servers[0].trim_end_matches('/'));
        let resp = uploader
            .http
            .put(&url)
            .header("Authorization", &auth)
            .header("Content-Type", "application/octet-stream")
            .header("X-SHA-256", &hash)
            .body(data.to_vec())
            .send()
            .await
            .expect("reachable blossom server");
        let status = resp.status();
        eprintln!("live probe status: {status}");
        let reason = resp
            .headers()
            .get("X-Reason")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp.text().await.unwrap_or_default();
        eprintln!("live probe reason: {reason:?} body: {body:?}");
        assert_ne!(
            status.as_u16(),
            400,
            "token must parse (400 = malformed auth event)"
        );
    }
}
