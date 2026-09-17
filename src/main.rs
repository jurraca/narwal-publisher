use anyhow::Result;
use clap::Parser;
use narwal_cli::PublishConfig;
use std::path::PathBuf;

/// Publish a Nix binary cache to Blossom + Nostr.
#[derive(Parser)]
#[command(name = "narwal-cli")]
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

    narwal_cli::publish(PublishConfig {
        store_paths: cli.store_paths,
        sec: cli.sec,
        blossom_servers: cli.blossom_servers,
        relays: cli.relays,
        channel: cli.channel,
        nix_sig_key: cli.nix_sig_key,
        compression: cli.compression,
        dry_run: cli.dry_run,
        store_dir: cli.store_dir,
    })
    .await
}
