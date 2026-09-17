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

    /// Path to the file holding the Nostr secret key (nsec or hex).
    /// Key material is file-only by design: CLI args leak via ps/history.
    /// Also settable via NARWAL_SEC_FILE (a path, never key material).
    #[arg(long = "sec-file", env = "NARWAL_SEC_FILE")]
    sec_file: PathBuf,

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
        sec_file: cli.sec_file,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn base_args() -> Vec<&'static str> {
        vec![
            "narwal-cli",
            "--sec-file",
            "/run/secrets/nostr-sec",
            "--blossom",
            "http://blossom:3000",
            "--relay",
            "ws://relay:32847",
        ]
    }

    #[test]
    fn parses_sec_file() {
        let cli = Cli::try_parse_from(base_args()).unwrap();
        assert_eq!(cli.sec_file, PathBuf::from("/run/secrets/nostr-sec"));
    }

    #[test]
    fn rejects_inline_sec() {
        // Key material on the command line was removed by design: it leaks
        // via ps, shell history, and CI logs. Use --sec-file.
        let mut args = base_args();
        args.extend(["--sec", "nsec1deadbeef"]);
        let err = Cli::try_parse_from(args).err().expect("--sec must be rejected");
        assert!(err.to_string().contains("unexpected argument '--sec'"), "unexpected: {err}");
    }
}
