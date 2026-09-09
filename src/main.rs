mod blossom;
mod closure;
mod compress;
mod manifest;
mod nar;
mod narinfo;
mod nhash;
mod nostr_pub;
mod refscan;
mod scan;
mod signing;
mod store_path;

use anyhow::{anyhow, Result};
use clap::Parser;
use nix_derivation::{StoreDir, StorePath};
use nix_narinfo::Compression;
use nostr::prelude::Keys;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Publish a Nix binary cache to Blossom + Nostr.
#[derive(Parser)]
#[command(name = "nix-blossom-publish")]
struct Cli {
    /// Nix store paths to publish (closure is resolved automatically).
    store_paths: Vec<PathBuf>,

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

    /// Nix Ed25519 secret key file for signing narinfos (format: name:base64).
    /// The derived public key is advertised in the Nostr event's nixSigKey tag.
    /// Required for input-addressed paths; CA paths are self-certifying.
    #[arg(long = "nix-sig-key")]
    nix_sig_key: Option<PathBuf>,

    /// Compression format (xz or zstd). Default: xz.
    #[arg(long, default_value = "xz")]
    compression: String,

    /// Compute hashes and build manifest but skip upload and publish.
    #[arg(long)]
    dry_run: bool,

    /// Nix store directory. Default: /nix/store.
    #[arg(long, default_value = "/nix/store")]
    store_dir: PathBuf,
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

    if cli.store_paths.is_empty() {
        return Err(anyhow!("no store paths given"));
    }

    let keys = Keys::parse(&cli.sec)?;
    let store_dir = StoreDir::new(cli.store_dir.to_string_lossy().as_ref())?;

    // Load signing key if provided.
    let signing_key = match &cli.nix_sig_key {
        Some(path) => {
            tracing::info!("loading Nix signing key from {}", path.display());
            Some(signing::SigningKeyPair::from_secret_file(path)?)
        }
        None => {
            tracing::warn!("no --nix-sig-key provided; input-addressed paths will be rejected by stock Nix clients");
            None
        }
    };

    let compression = match cli.compression.as_str() {
        "xz" => Compression::Xz,
        "zstd" => Compression::Zstd,
        "none" => Compression::None,
        other => return Err(anyhow!("unknown compression: {}", other)),
    };

    // Step 1: Resolve closure (dependencies first, self-contained).
    tracing::info!("resolving closure of {} input paths", cli.store_paths.len());
    let closure_entries = closure::resolve(&cli.store_paths, &cli.store_dir)?;
    tracing::info!("closure: {} paths", closure_entries.len());

    // Step 2: Process each path — encode NAR, compress, build narinfo, sign.
    let mut manifest_entries = Vec::with_capacity(closure_entries.len() + 1);

    for entry in &closure_entries {
        let basename = entry
            .path
            .file_name()
            .ok_or_else(|| anyhow!("invalid path: {}", entry.path.display()))?
            .to_string_lossy()
            .to_string();

        tracing::info!("processing {}", basename);

        // 2a. Encode NAR (we already have hash+size from closure scan, but
        // we need the bytes for compression — unless we stream later).
        let nar_output = nar::encode_store_path(&entry.path)?;

        // Verify hash matches what closure scan found.
        if nar_output.nar_hash != entry.nar_hash {
            return Err(anyhow!(
                "NAR hash mismatch for {}: closure scan gave {:?}, encode gave {:?}",
                basename,
                &entry.nar_hash[..8],
                &nar_output.nar_hash[..8]
            ));
        }

        // 2b. Compress NAR.
        let compressed = compress::compress_xz(&nar_output.bytes)?;
        let url = compress::nar_url(&compressed.file_hash);

        tracing::info!(
            "  NAR: {} bytes → {} bytes compressed, url={}",
            nar_output.nar_size,
            compressed.file_size,
            url
        );

        // 2c. Parse store path for narinfo builder.
        let store_path = store_path::parse_basename(&basename)?;

        // 2d. Parse reference hashparts into StorePaths.
        let ref_paths: Vec<StorePath> = entry
            .references
            .iter()
            .filter_map(|hp| {
                // Reconstruct full basename from hashpart by looking it up
                // in the closure entries. If not found (shouldn't happen
                // since closure is complete), skip.
                closure_entries
                    .iter()
                    .find(|e| {
                        e.path
                            .file_name()
                            .map(|n| {
                                n.to_string_lossy()
                                    .split('-')
                                    .next()
                                    .unwrap_or("")
                                    == hp
                            })
                            .unwrap_or(false)
                    })
                    .and_then(|e| {
                        e.path
                            .file_name()
                            .and_then(|n| StorePath::from_basename(n.as_bytes()).ok())
                    })
            })
            .collect();

        // 2e. Build narinfo.
        let sigs: Vec<nix_narinfo::NarInfoSignature> = if let Some(ref sk) = signing_key {
            // Build unsigned narinfo first to get the fingerprint.
            let unsigned = narinfo::build_narinfo(
                &store_dir,
                &store_path,
                &url,
                entry.nar_hash,
                entry.nar_size,
                compression.clone(),
                compressed.file_hash,
                compressed.file_size,
                &ref_paths,
                &[],
            )?;
            vec![sk.sign_fingerprint(unsigned.fingerprint.as_bytes())]
        } else {
            vec![]
        };

        let narinfo_output = narinfo::build_narinfo(
            &store_dir,
            &store_path,
            &url,
            entry.nar_hash,
            entry.nar_size,
            compression.clone(),
            compressed.file_hash,
            compressed.file_size,
            &ref_paths,
            &sigs,
        )?;

        tracing::info!(
            "  narinfo: {} bytes",
            narinfo_output.bytes.len()
        );

        // 2f. Upload NAR blob + narinfo blob to Blossom.
        if !cli.dry_run {
            let uploader =
                blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
            uploader.upload_bytes(&compressed.bytes).await?;

            let uploader =
                blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
            uploader.upload_bytes(&narinfo_output.bytes).await?;
        }

        // 2g. Collect manifest entry for the narinfo blob.
        let narinfo_hash = compress::sha256(&narinfo_output.bytes);
        manifest_entries.push(manifest::DirEntry {
            name: format!("{}.narinfo", store_path::hash_part(&basename)),
            hash: narinfo_hash,
            size: narinfo_output.bytes.len() as u64,
        });
    }

    // Step 3: Synthesize nix-cache-info.
    let cache_info = synthesize_cache_info();
    let cache_info_hash = compress::sha256(&cache_info);
    tracing::info!("nix-cache-info: {} bytes", cache_info.len());

    if !cli.dry_run {
        let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
        uploader.upload_bytes(&cache_info).await?;
    }

    manifest_entries.push(manifest::DirEntry {
        name: "nix-cache-info".into(),
        hash: cache_info_hash,
        size: cache_info.len() as u64,
    });

    // Step 4: Build hashtree manifest.
    let (manifest_nodes, root_hash) = manifest::build_directory_tree(manifest_entries);
    tracing::info!(
        "manifest tree: {} nodes, root hash={}",
        manifest_nodes.len(),
        hex::encode(&root_hash)
    );

    if !cli.dry_run {
        let uploader = blossom::BlossomUploader::new(keys.clone(), cli.blossom_servers.clone());
        for (bytes, hash) in &manifest_nodes {
            tracing::debug!("uploading manifest node hash={}", hex::encode(hash));
            uploader.upload_bytes(bytes).await?;
        }
    }

    // Step 5: Encode nhash → htree URI.
    let nhash = nhash::nhash_encode(&root_hash)?;
    let htree_uri = format!("htree://{}", nhash);
    tracing::info!("htree URI: {}", htree_uri);

    if cli.dry_run {
        tracing::info!("dry run complete — skipping publish");
        return Ok(());
    }

    // Step 6: Publish Nostr event.
    // Derive public key string from signing key for nixSigKey tag.
    let nix_sig_keys: Vec<String> = signing_key
        .iter()
        .map(|sk| sk.public_key_string())
        .collect();

    nostr_pub::publish_cache(nostr_pub::PublishConfig {
        keys,
        relays: cli.relays,
        channel: cli.channel,
        htree_uri,
        blossom_servers: cli.blossom_servers,
        nix_sig_keys,
    })
    .await?;

    tracing::info!("publish complete");
    Ok(())
}

/// Synthesize a minimal nix-cache-info file.
fn synthesize_cache_info() -> Vec<u8> {
    b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n".to_vec()
}
