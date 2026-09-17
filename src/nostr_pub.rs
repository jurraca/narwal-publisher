//! Nostr event publication.
//!
//! Publishes a kind 17091 (default cache) or 37091 (named cache) event
//! per NIP-XX, with tags:
//!   ["htree", "htree://<nhash>"]
//!   ["blossom", "<server-url>"]  (repeatable)
//!   ["nixSigKey", "<name:base64pubkey>"]  (repeatable, optional)
//!   ["d", "<channel-name>"]  (only for kind 37091)

use anyhow::Result;
use nostr::prelude::*;
use nostr::signer::NostrSigner;
use nostr_sdk::Client;
use std::sync::Arc;

/// Configuration for publishing a cache root event.
pub struct PublishConfig {
    /// Nostr signer (local keys or NIP-46 bunker).
    pub signer: Arc<dyn NostrSigner>,
    /// Relays to publish to.
    pub relays: Vec<String>,
    /// Named channel. If None, publishes kind 17091 (default cache).
    /// If Some, publishes kind 37091 (named cache) with a d-tag.
    pub channel: Option<String>,
    /// htree:// URI (e.g. "htree://nhash1qq...").
    pub htree_uri: String,
    /// Blossom server URLs to advertise.
    pub blossom_servers: Vec<String>,
    /// Nix signing keys to advertise (format: "name:base64pubkey").
    pub nix_sig_keys: Vec<String>,
}

/// Publish a cache root event to Nostr relays.
///
/// Returns Ok(()) if at least one relay accepted the event.
pub async fn publish_cache(config: PublishConfig) -> Result<()> {
    let client = Client::new(config.signer);

    for relay in &config.relays {
        client.add_relay(relay).await?;
    }
    client.connect().await;

    let kind = if config.channel.is_some() {
        Kind::Custom(37091)
    } else {
        Kind::Custom(17091)
    };

    let mut tags: Vec<Tag> = vec![Tag::custom(
        TagKind::Custom("htree".into()),
        vec![config.htree_uri.clone()],
    )];

    for server in &config.blossom_servers {
        tags.push(Tag::custom(
            TagKind::Custom("blossom".into()),
            vec![server.clone()],
        ));
    }

    for key in &config.nix_sig_keys {
        tags.push(Tag::custom(
            TagKind::Custom("nixSigKey".into()),
            vec![key.clone()],
        ));
    }

    if let Some(channel) = &config.channel {
        tags.push(Tag::identifier(channel.clone()));
    }

    let event = client
        .sign_event_builder(EventBuilder::new(kind, "").tags(tags))
        .await?;

    let output = client.send_event(&event).await?;

    tracing::info!(
        "published event {} to {} relay(s)",
        event.id.to_bech32().unwrap_or_default(),
        output.success.len()
    );

    if output.success.is_empty() {
        return Err(anyhow::anyhow!("no relay accepted the event"));
    }

    client.disconnect().await;
    Ok(())
}
