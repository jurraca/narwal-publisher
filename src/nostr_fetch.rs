//! Nostr event fetching — query relays for the latest cache root event.
//!
//! Fetches kind 17091 (default cache) or 37091 (named cache) events
//! to find the current `htree` tag, which gives us the root hash
//! of the existing hashtree for incremental updates.

use anyhow::{anyhow, Result};
use nostr::prelude::*;
use nostr_sdk::Client;

/// Configuration for fetching a cache root event.
pub struct FetchConfig {
    /// Nostr secret key (for relay authentication if needed).
    pub keys: Keys,
    /// Relays to query.
    pub relays: Vec<String>,
    /// Named channel. If None, queries kind 17091 (default cache).
    /// If Some, queries kind 37091 with the given d-tag.
    pub channel: Option<String>,
    /// Publisher pubkey (hex) to filter events by.
    /// If None, queries all pubkeys (first match wins).
    pub author: Option<String>,
}

/// Result of fetching the latest root event.
pub struct RootEvent {
    /// The htree URI (e.g. "htree://nhash1qq...").
    pub htree_uri: String,
    /// Blossom server URLs from the event's blossom tags.
    pub blossom_servers: Vec<String>,
    /// Nix signing keys from the event's nixSigKey tags.
    pub nix_sig_keys: Vec<String>,
}

/// Fetch the latest cache root event from Nostr relays.
///
/// Returns Ok(Some(event)) if found, Ok(None) if no event exists yet
/// (first publish), or Err on network/relay errors.
pub async fn fetch_latest_root(config: FetchConfig) -> Result<Option<RootEvent>> {
    let client = Client::new(config.keys.clone());

    for relay in &config.relays {
        client.add_relay(relay).await?;
    }
    client.connect().await;

    let kind = if config.channel.is_some() {
        Kind::Custom(37091)
    } else {
        Kind::Custom(17091)
    };

    let mut filter = Filter::new().kind(kind).limit(1);

    if let Some(channel) = &config.channel {
        filter = filter.identifier(channel);
    }

    if let Some(author_hex) = &config.author {
        let pk: PublicKey = author_hex.parse().map_err(|e| anyhow!("invalid pubkey: {}", e))?;
        filter = filter.author(pk);
    }

    let events = client.fetch_events(filter, std::time::Duration::from_secs(10)).await?;

    // Get the latest event (fetch_events returns newest-first in practice,
    // but sort by created_at to be safe)
    let latest = events
        .into_iter()
        .max_by_key(|e| e.created_at);

    let Some(event) = latest else {
        client.disconnect().await;
        return Ok(None);
    };

    // Extract htree tag
    let htree_uri = event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::Custom("htree".into()))
        .and_then(|t| t.content())
        .ok_or_else(|| anyhow!("root event missing htree tag"))?
        .to_string();

    // Extract blossom server tags
    let blossom_servers: Vec<String> = event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::Custom("blossom".into()))
        .filter_map(|t| t.content())
        .map(|s| s.to_string())
        .collect();

    // Extract nixSigKey tags
    let nix_sig_keys: Vec<String> = event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::Custom("nixSigKey".into()))
        .filter_map(|t| t.content())
        .map(|s| s.to_string())
        .collect();

    client.disconnect().await;

    Ok(Some(RootEvent {
        htree_uri,
        blossom_servers,
        nix_sig_keys,
    }))
}
