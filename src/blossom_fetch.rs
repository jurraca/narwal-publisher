//! Blossom blob fetching (BUD-01 GET /<sha256>).
//!
//! Downloads blobs from Blossom servers by content hash. Used to fetch
//! existing hashtree nodes when incrementally updating a cache.

use anyhow::{anyhow, Result};
use reqwest::Client;

/// A Blossom client that fetches blobs from servers.
pub struct BlossomFetcher {
    servers: Vec<String>,
    http: Client,
}

impl BlossomFetcher {
    pub fn new(servers: Vec<String>) -> Self {
        Self {
            servers,
            http: Client::new(),
        }
    }

    /// Fetch a blob by its SHA-256 hex hash.
    ///
    /// Tries each server in order, returns the first successful response.
    pub async fn fetch(&self, hash_hex: &str) -> Result<Vec<u8>> {
        for server in &self.servers {
            let url = format!("{}/{}", server.trim_end_matches('/'), hash_hex);
            match self.http.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes().await?;
                    return Ok(bytes.to_vec());
                }
                Ok(resp) => {
                    tracing::debug!(
                        "fetch {} from {} returned {}",
                        &hash_hex[..12.min(hash_hex.len())],
                        server,
                        resp.status()
                    );
                }
                Err(e) => {
                    tracing::debug!("fetch {} from {} failed: {}", &hash_hex[..12.min(hash_hex.len())], server, e);
                }
            }
        }
        Err(anyhow!(
            "blob {} not found on any of {} server(s)",
            &hash_hex[..12.min(hash_hex.len())],
            self.servers.len()
        ))
    }
}
