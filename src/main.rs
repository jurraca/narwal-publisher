mod blossom;
mod manifest;
mod nar;
mod nhash;
mod nostr_pub;
mod scan;
mod store_path;

use anyhow::{anyhow, Result};
use clap::Parser;
use nostr::prelude::Keys;
use std::path::PathBuf;

/// Publish a Nix binary cache to Blossom + Nostr.
#[derive(Parser)]
#[command(name = "nix-blossom-publish")]
struct Cli {
    /// Staging directory produced by `nix copy --to file:///staging`.
    staging_dir: PathBuf,

    /// Nostr secret key (nsec, hex, or ncryptsec).
    #[arg(long)]
    sec: String,

    /// Blossom server URL to upload to. Repeatable.
    #[arg(long = "blossom", required = true)]
    blossom_servers: Vec<String>,

    /// Nostr relay URL to publish to. Repeatable.
    #[arg(long = "relay", required = true)]
    relays: Vec<String>,

    /// Named cache channel (kind 37091). Omit for default cache (kind 17091).
    #[arg(long)]
    channel: Option<String>,

    /// Nix Ed25519 public key to advertise (format: name:base64pubkey). Repeatable.
    #[arg(long = "nix-sig-key")]
    nix_sig_keys: Vec<String>,

    /// Compute hashes and build manifest but skip upload and publish.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let keys = Keys::parse(&cli.sec)?;

    // Step 1: Scan staging directory.
    let staging = scan::scan(&cli.staging_dir)?;

    // Step 2: Upload NAR blobs to Blossom.
    tracing::info!("uploading {} NAR blobs", staging.nars.len());
    let mut nar_hashes = Vec::with_capacity(staging.nars.len());
    for nar_path in &staging.nars {
        let data = scan::read_bytes(nar_path)?;
        let hash = blossom::BlossomUploader::hash_hex(&data);
        tracing::info!("NAR {:?} hash={}", nar_path.file_name(), &hash[..16]);

        if !cli.dry_run {
            let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
            uploader.upload_bytes(&data).await?;
        }
        nar_hashes.push(hash);
    }

    // Step 3: Upload narinfo blobs + collect directory entries.
    tracing::info!("uploading {} narinfo blobs", staging.narinfos.len());
    let mut entries = Vec::with_capacity(staging.narinfos.len() + 1);

    for narinfo_path in &staging.narinfos {
        let data = scan::read_bytes(narinfo_path)?;
        let hash = manifest::sha256(&data);
        let name = narinfo_path
            .file_name()
            .ok_or_else(|| anyhow!("invalid narinfo path"))?
            .to_string_lossy()
            .to_string();

        tracing::info!("narinfo {} hash={}", name, &hex::encode(&hash)[..16]);

        if !cli.dry_run {
            let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
            uploader.upload_bytes(&data).await?;
        }

        entries.push(manifest::DirEntry {
            name,
            hash,
            size: data.len() as u64,
        });
    }

    // Step 4: Upload nix-cache-info + add to directory.
    {
        let data = scan::read_bytes(&staging.cache_info)?;
        let hash = manifest::sha256(&data);
        tracing::info!("nix-cache-info hash={}", &hex::encode(&hash)[..16]);

        if !cli.dry_run {
            let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
            uploader.upload_bytes(&data).await?;
        }

        entries.push(manifest::DirEntry {
            name: "nix-cache-info".into(),
            hash,
            size: data.len() as u64,
        });
    }

    // Step 5: Build directory manifest tree (chunked if > 174 entries).
    let (manifest_nodes, root_hash) = manifest::build_directory_tree(entries);
    tracing::info!(
        "manifest tree: {} nodes, root hash={}",
        manifest_nodes.len(),
        hex::encode(&root_hash)
    );

    if !cli.dry_run {
        // Upload all manifest nodes (leaves first, then parents).
        let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
        for (idx, (bytes, hash)) in manifest_nodes.iter().enumerate() {
            tracing::debug!("uploading manifest node {}/{} hash={}", idx + 1, manifest_nodes.len(), hex::encode(hash));
            uploader.upload_bytes(bytes).await?;
        }
    }

    // Step 6: Encode nhash and construct htree:// URI.
    let nhash = nhash::nhash_encode(&root_hash)?;
    let htree_uri = format!("htree://{}", nhash);
    tracing::info!("htree URI: {}", htree_uri);

    if cli.dry_run {
        tracing::info!("dry run complete — skipping publish");
        return Ok(());
    }

    // Step 7: Publish Nostr event.
    nostr_pub::publish_cache(nostr_pub::PublishConfig {
        keys,
        relays: cli.relays,
        channel: cli.channel,
        htree_uri,
        blossom_servers: cli.blossom_servers,
        nix_sig_keys: cli.nix_sig_keys,
    })
    .await?;

    tracing::info!("publish complete");
    Ok(())
}
