use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use narwal_cli::PublishConfig;
use std::path::PathBuf;

/// Publish a Nix binary cache to Blossom + Nostr.
///
/// Default (no subcommand): publish STORE_PATHS. Use the `pair` subcommand
/// for the interactive NIP-46 pairing ceremony on its own.
#[derive(Parser)]
#[command(name = "narwal-cli")]
struct Cli {
    /// Nix store paths to publish (closure is resolved automatically).
    store_paths: Vec<PathBuf>,

    /// Path to the file holding the Nostr secret key (nsec or hex).
    /// Key material is file-only by design: CLI args leak via ps/history.
    /// Also settable via NARWAL_SEC_FILE (a path, never key material).
    /// Exactly one of --sec-file / --bunker / --qr is required for publish.
    #[arg(long = "sec-file", env = "NARWAL_SEC_FILE", conflicts_with_all = ["bunker", "qr"])]
    sec_file: Option<PathBuf>,

    /// NIP-46 bunker URL (bunker://<pubkey>?relay=wss://...&secret=...).
    /// Remote signing: the identity key never touches this machine.
    /// Quote the URL: unquoted `&relay=` params are shell background jobs.
    /// Exactly one of --sec-file / --bunker / --qr is required for publish.
    #[arg(long, env = "NARWAL_BUNKER", conflicts_with_all = ["sec_file", "qr"])]
    bunker: Option<String>,

    /// Pair via nostrconnect:// QR code (Amber-style signer apps).
    /// Reuses the stored pairing when present, so the scan happens once.
    /// Exactly one of --sec-file / --bunker / --qr is required for publish.
    #[arg(long, conflicts_with_all = ["sec_file", "bunker"])]
    qr: bool,

    #[command(flatten)]
    pairing: PairingArgs,

    /// Blossom server URL to upload to. Repeatable. Required for publish.
    #[arg(long = "blossom")]
    blossom_servers: Vec<String>,

    /// Nostr relay URL to publish to. Repeatable. Required for publish.
    #[arg(long = "relay")]
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

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Standalone steps. `pair` runs the interactive NIP-46 pairing ceremony
/// on its own (scan QR, approve, save); publish runs take it from there.
#[derive(Subcommand)]
enum Commands {
    /// Pair with a signer app via nostrconnect:// QR code, then exit.
    /// Replaces any stored pairing (old user pubkey is logged first).
    Pair {
        #[command(flatten)]
        pairing: PairingArgs,
    },
}

/// Flags shared by `--qr` publishing and the `pair` subcommand.
#[derive(clap::Args)]
struct PairingArgs {
    /// Pairing file (default: ~/.local/share/narwal-cli/pairing.json).
    #[arg(long = "pairing-file")]
    pairing_file: Option<PathBuf>,

    /// Handshake relay for pairing (repeatable; defaults to public
    /// relays). Must be normal relays, not the cache relay: its kind
    /// allowlist would drop kind-24133 handshake traffic.
    #[arg(long = "bunker-relay")]
    bunker_relays: Vec<String>,
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

    // Standalone pairing ceremony: no key source, no blossom/relay needed.
    if let Some(Commands::Pair { pairing }) = cli.command {
        let relays = narwal_cli::nip46::pair::resolve_handshake_relays(&pairing.bunker_relays);
        let file = pairing_file_path(pairing.pairing_file)?;
        narwal_cli::nip46::pair::pair_fresh(&relays, &file).await?;
        return Ok(());
    }

    // Publish path: clap can't express "required unless a subcommand is
    // present", so the publish-time requirements are validated here.
    if let Err(msg) = validate_publish(&cli) {
        Cli::command()
            .error(clap::error::ErrorKind::MissingRequiredArgument, msg)
            .exit();
    }

    narwal_cli::publish(PublishConfig {
        store_paths: cli.store_paths,
        sec_file: cli.sec_file,
        bunker: cli.bunker,
        qr: cli.qr,
        pairing_file: cli.pairing.pairing_file,
        bunker_relays: cli.pairing.bunker_relays,
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

/// Publish-time requirements (checked only when no subcommand runs):
/// exactly one key source, plus blossom + relay endpoints.
fn validate_publish(cli: &Cli) -> Result<(), String> {
    let sources = [&cli.sec_file.is_some(), &cli.bunker.is_some(), &cli.qr]
        .iter()
        .filter(|b| ***b)
        .count();
    if sources != 1 {
        return Err(
            "exactly one of --sec-file, --bunker or --qr is required".to_string(),
        );
    }
    if cli.blossom_servers.is_empty() {
        return Err("missing --blossom <BLOSSOM_SERVERS>".to_string());
    }
    if cli.relays.is_empty() {
        return Err("missing --relay <RELAYS>".to_string());
    }
    if cli.store_paths.is_empty() {
        return Err("missing store paths to publish".to_string());
    }
    Ok(())
}

/// Resolve the pairing file (explicit path or ~/.local/share default).
fn pairing_file_path(flagged: Option<PathBuf>) -> Result<PathBuf> {
    match flagged {
        Some(p) => Ok(p),
        None => narwal_cli::nip46::session::default_pairing_file(),
    }
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
        assert_eq!(cli.sec_file, Some(PathBuf::from("/run/secrets/nostr-sec")));
        assert_eq!(cli.bunker, None);
    }

    #[test]
    fn parses_bunker() {
        let mut args = base_args();
        // swap --sec-file for --bunker
        args.remove(2);
        args.remove(1);
        args.extend([
            "--bunker",
            "bunker://79dff8f5cdb0a63b8678ad0ef2e2a3ff1e45ac1ff91b0b8c122a702c4c4?relay=wss://relay:32847",
        ]);
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.sec_file, None);
        assert!(cli.bunker.unwrap().starts_with("bunker://"));
    }

    #[test]
    fn rejects_sec_file_and_bunker_together() {
        let mut args = base_args();
        args.extend(["--bunker", "bunker://abc?relay=wss://relay:32847"]);
        let err = Cli::try_parse_from(args).err().expect("conflict must be rejected");
        assert!(err.to_string().contains("cannot be used with"), "unexpected: {err}");
    }

    #[test]
    fn parses_qr_without_key_sources() {
        let args = vec![
            "narwal-cli",
            "--qr",
            "--blossom",
            "http://blossom:3000",
            "--relay",
            "ws://relay:32847",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(cli.qr);
        assert_eq!(cli.sec_file, None);
        assert_eq!(cli.bunker, None);
    }

    #[test]
    fn rejects_qr_with_sec_file() {
        let mut args = base_args();
        args.push("--qr");
        let err = Cli::try_parse_from(args).err().expect("conflict must be rejected");
        assert!(err.to_string().contains("cannot be used with"), "unexpected: {err}");
    }

    #[test]
    fn rejects_no_key_source() {
        // No clap-level required flags anymore (a bare `pair` needs none),
        // so this is validated for the publish path instead.
        let args = vec![
            "narwal-cli",
            "--blossom",
            "http://blossom:3000",
            "--relay",
            "ws://relay:32847",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let err = validate_publish(&cli).expect_err("missing source must be rejected");
        assert!(err.contains("exactly one of"), "unexpected: {err}");
    }

    #[test]
    fn validate_publish_accepts_full_set() {
        let cli = Cli::try_parse_from(base_args()).unwrap();
        // base_args has no store paths — add one for the full check.
        let mut cli = cli;
        cli.store_paths = vec![PathBuf::from("/nix/store/abc-hello")];
        validate_publish(&cli).expect("full publish args must validate");
    }

    #[test]
    fn validate_publish_rejects_missing_blossom() {
        let args = vec!["narwal-cli", "--sec-file", "/run/secrets/x", "--relay", "ws://r"];
        let cli = Cli::try_parse_from(args).unwrap();
        let err = validate_publish(&cli).expect_err("must be rejected");
        assert!(err.contains("--blossom"), "unexpected: {err}");
    }

    #[test]
    fn pair_subcommand_parses_standalone() {
        // Bare `pair` needs no blossom/relay/key-source flags.
        let cli = Cli::try_parse_from(vec!["narwal-cli", "pair"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Pair { .. })));
        let Some(Commands::Pair { pairing }) = cli.command else {
            panic!("expected pair subcommand");
        };
        assert!(pairing.pairing_file.is_none());
        assert!(pairing.bunker_relays.is_empty());
    }

    #[test]
    fn pair_subcommand_takes_relays_and_file() {
        let cli = Cli::try_parse_from(vec![
            "narwal-cli",
            "pair",
            "--bunker-relay",
            "wss://relay.example.com",
            "--pairing-file",
            "/tmp/p.json",
        ])
        .unwrap();
        let Some(Commands::Pair { pairing }) = cli.command else {
            panic!("expected pair subcommand");
        };
        assert_eq!(pairing.bunker_relays, vec!["wss://relay.example.com".to_string()]);
        assert_eq!(pairing.pairing_file, Some(PathBuf::from("/tmp/p.json")));
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
