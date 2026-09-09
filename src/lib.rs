//! nix-blossom-publish library.
//!
//! Publish Nix binary caches to Blossom + Nostr. Fully self-contained —
//! no `nix`, `nix-store`, or `nix-daemon` required. NAR encoding, closure
//! resolution, compression, narinfo building, and Ed25519 signing are all
//! handled by the Cachix Rust crates (`nix-archive`, `nix-derivation`,
//! `nix-narinfo`).

pub mod blossom;
pub mod blossom_fetch;
pub mod closure;
pub mod compress;
pub mod manifest;
pub mod nar;
pub mod narinfo;
pub mod nhash;
pub mod nostr_fetch;
pub mod nostr_pub;
pub mod refscan;
pub mod signing;
pub mod store_path;
pub mod tree_reader;

use anyhow::{anyhow, Result};
use nix_derivation::{StoreDir, StorePath};
use nix_narinfo::Compression;
use nostr::prelude::Keys;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Configuration for a publish operation.
pub struct PublishConfig {
    /// Nix store paths to publish (closure is resolved automatically).
    pub store_paths: Vec<PathBuf>,
    /// Nostr secret key (nsec, hex, or ncryptsec).
    pub sec: String,
    /// Blossom server URLs to upload to.
    pub blossom_servers: Vec<String>,
    /// Nostr relay URLs to publish to.
    pub relays: Vec<String>,
    /// Named cache channel (kind 37091). Omit for default cache (kind 17091).
    pub channel: Option<String>,
    /// Nix Ed25519 secret key file for signing narinfos.
    pub nix_sig_key: Option<PathBuf>,
    /// Compression format: "xz", "zstd", or "none".
    pub compression: String,
    /// Compute hashes and build manifest but skip upload and publish.
    pub dry_run: bool,
    /// Nix store directory. Default: /nix/store.
    pub store_dir: PathBuf,
}

/// Run the full publish pipeline.
///
/// 1. Fetch latest root event from Nostr (atomic: abort if unreachable)
/// 2. Flatten existing tree from Blossom into an entry map
/// 3. Resolve closure of input paths (self-contained, no nix-store)
/// 4. For each path: encode NAR, compress, build narinfo, sign, upload
/// 5. Merge new entries with existing entries
/// 6. Rebuild hashtree, upload changed nodes
/// 7. Publish new root event to Nostr
pub async fn publish(config: PublishConfig) -> Result<()> {
    if config.store_paths.is_empty() {
        return Err(anyhow!("no store paths given"));
    }

    let keys = Keys::parse(&config.sec)?;
    let store_dir = StoreDir::new(config.store_dir.to_string_lossy().as_ref())?;

    // Load signing key if provided.
    let signing_key = match &config.nix_sig_key {
        Some(path) => {
            tracing::info!("loading Nix signing key from {}", path.display());
            Some(signing::SigningKeyPair::from_secret_file(path)?)
        }
        None => {
            tracing::warn!("no --nix-sig-key provided; input-addressed paths will be rejected by stock Nix clients");
            None
        }
    };

    let compression = match config.compression.as_str() {
        "xz" => Compression::Xz,
        "zstd" => Compression::Zstd,
        "none" => Compression::None,
        other => return Err(anyhow!("unknown compression: {}", other)),
    };

    // Step 1: Fetch the latest root event from Nostr (atomic update guarantee).
    tracing::info!("fetching latest root event from Nostr");
    let author_hex = keys.public_key().to_hex();
    let existing_root = nostr_fetch::fetch_latest_root(nostr_fetch::FetchConfig {
        keys: keys.clone(),
        relays: config.relays.clone(),
        channel: config.channel.clone(),
        author: Some(author_hex),
    })
    .await?;

    // Use servers from the Nostr event for fetching existing tree (if any),
    // falling back to CLI servers for new uploads.
    let fetch_servers = existing_root
        .as_ref()
        .filter(|r| !r.blossom_servers.is_empty())
        .map(|r| r.blossom_servers.clone())
        .unwrap_or_else(|| config.blossom_servers.clone());

    let fetcher = blossom_fetch::BlossomFetcher::new(fetch_servers);

    // Step 2: Flatten existing tree (if any) into an entry map.
    let mut existing_entries: HashMap<String, manifest::DirEntry> = HashMap::new();

    if let Some(ref root) = existing_root {
        tracing::info!("found existing cache: {}", root.htree_uri);
        let root_hash = tree_reader::parse_nhash_uri(&root.htree_uri)?;
        let entries = tree_reader::flatten_tree(&root_hash, &fetcher).await?;
        tracing::info!("existing tree: {} entries", entries.len());
        for entry in entries {
            existing_entries.insert(entry.name.clone(), entry);
        }
    } else {
        tracing::info!("no existing cache found — creating new");
    }

    // Step 3: Resolve closure of input paths.
    tracing::info!("resolving closure of {} input paths", config.store_paths.len());
    let closure_entries = closure::resolve(&config.store_paths, &config.store_dir)?;
    tracing::info!("closure: {} paths", closure_entries.len());

    // Step 4: Process each path — encode NAR, compress, build narinfo, sign, upload.
    let mut new_entries: Vec<manifest::DirEntry> = Vec::with_capacity(closure_entries.len());

    for entry in &closure_entries {
        let basename = entry
            .path
            .file_name()
            .ok_or_else(|| anyhow!("invalid path: {}", entry.path.display()))?
            .to_string_lossy()
            .to_string();

        let narinfo_name = format!("{}.narinfo", store_path::hash_part(&basename));

        // Skip if already in the tree (content-addressed = same name = same blob).
        if existing_entries.contains_key(&narinfo_name) {
            tracing::info!("skipping {} (already in cache)", basename);
            new_entries.push(existing_entries[&narinfo_name].clone());
            continue;
        }

        tracing::info!("processing {}", basename);

        // 4a. Encode NAR.
        let nar_output = nar::encode_store_path(&entry.path)?;

        // Verify hash matches closure scan.
        if nar_output.nar_hash != entry.nar_hash {
            return Err(anyhow!(
                "NAR hash mismatch for {}: closure scan gave {:?}, encode gave {:?}",
                basename,
                &entry.nar_hash[..8],
                &nar_output.nar_hash[..8]
            ));
        }

        // 4b. Compress NAR.
        let compressed = compress::compress(&nar_output.bytes, compression.clone())?;
        let url = compress::nar_url(&compressed.file_hash, compression.clone())?;

        tracing::info!(
            "  NAR: {} bytes → {} bytes compressed, url={}",
            nar_output.nar_size,
            compressed.file_size,
            url
        );

        // 4c. Parse store path for narinfo builder.
        let sp = store_path::parse_basename(&basename)?;

        // 4d. Parse reference hashparts into StorePaths.
        let ref_paths: Vec<StorePath> = entry
            .references
            .iter()
            .filter_map(|hp| {
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

        // 4e. Build narinfo.
        let sigs: Vec<nix_narinfo::NarInfoSignature> = if let Some(ref sk) = signing_key {
            let unsigned = narinfo::build_narinfo(
                &store_dir,
                &sp,
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
            &sp,
            &url,
            entry.nar_hash,
            entry.nar_size,
            compression.clone(),
            compressed.file_hash,
            compressed.file_size,
            &ref_paths,
            &sigs,
        )?;

        tracing::info!("  narinfo: {} bytes", narinfo_output.bytes.len());

        // 4f. Upload NAR blob + narinfo blob to Blossom.
        if !config.dry_run {
            let uploader =
                blossom::BlossomUploader::new(keys.clone(), config.blossom_servers.clone());
            uploader.upload_bytes(&compressed.bytes).await?;

            let uploader =
                blossom::BlossomUploader::new(keys.clone(), config.blossom_servers.clone());
            uploader.upload_bytes(&narinfo_output.bytes).await?;
        }

        // 4g. Collect manifest entry for the narinfo blob.
        let narinfo_hash = compress::sha256(&narinfo_output.bytes);
        new_entries.push(manifest::DirEntry {
            name: narinfo_name,
            hash: narinfo_hash,
            size: narinfo_output.bytes.len() as u64,
        });
    }

    // Step 5: Merge new entries with existing entries.
    for entry in new_entries {
        let name = entry.name.clone();
        existing_entries.insert(name, entry);
    }

    let all_entries: Vec<manifest::DirEntry> = existing_entries.into_values().collect();
    tracing::info!("total entries after merge: {}", all_entries.len());

    // Step 6: Synthesize nix-cache-info.
    let cache_info = synthesize_cache_info();
    let cache_info_hash = compress::sha256(&cache_info);
    tracing::info!("nix-cache-info: {} bytes", cache_info.len());

    if !config.dry_run {
        let uploader = blossom::BlossomUploader::new(keys.clone(), config.blossom_servers.clone());
        uploader.upload_bytes(&cache_info).await?;
    }

    let mut final_entries = all_entries;
    final_entries.push(manifest::DirEntry {
        name: "nix-cache-info".into(),
        hash: cache_info_hash,
        size: cache_info.len() as u64,
    });

    // Step 7: Build hashtree manifest.
    let (manifest_nodes, root_hash) = manifest::build_directory_tree(final_entries);
    tracing::info!(
        "manifest tree: {} nodes, root hash={}",
        manifest_nodes.len(),
        hex::encode(&root_hash)
    );

    if !config.dry_run {
        let uploader = blossom::BlossomUploader::new(keys.clone(), config.blossom_servers.clone());
        for (bytes, hash) in &manifest_nodes {
            tracing::debug!("uploading manifest node hash={}", hex::encode(hash));
            uploader.upload_bytes(bytes).await?;
        }
    }

    // Step 8: Encode nhash → htree URI.
    let nhash = nhash::nhash_encode(&root_hash)?;
    let htree_uri = format!("htree://{}", nhash);
    tracing::info!("htree URI: {}", htree_uri);

    if config.dry_run {
        tracing::info!("dry run complete — skipping publish");
        return Ok(());
    }

    // Step 9: Publish Nostr event (atomic: only after all blobs are uploaded).
    let nix_sig_keys: Vec<String> = signing_key
        .iter()
        .map(|sk| sk.public_key_string())
        .collect();

    nostr_pub::publish_cache(nostr_pub::PublishConfig {
        keys,
        relays: config.relays,
        channel: config.channel,
        htree_uri,
        blossom_servers: config.blossom_servers,
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
