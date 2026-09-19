# narwal-cli

Publish Nix store paths to Blossom and announce them via Nostr.

A [Narwal](https://github.com/jurraca/narwal) cache can then
source and index packages, and serve as a Nix binary cache.

## What it does

Given one or more `/nix/store` paths, it resolves the closure and for
each path:

1. Encodes the NAR, computes `NarHash`/`NarSize`, scans references.
2. Compresses (`xz`/`zstd`) → `FileHash`/`FileSize`, builds and signs
   the narinfo with the Nix cache signing key.
3. Uploads the `.nar.xz` + `.narinfo` blobs to Blossom (BUD-11 auth).
4. Builds the narinfo manifest tree, uploads it, and publishes the
   hashtree root pointer to the relay (kind 17091 default cache,
   kind 37091 named channel).

Narwal subscribes to those root events, indexes the manifest, serves
narinfos itself, and 302-redirects NAR downloads straight to Blossom.
Nix clients only ever see a regular binary cache.

## Stack

Pure Rust, no Nix runtime dependency. Nix-format work (NAR
encode/hash, reference scanning, narinfo build/sign, derivation
parsing, nix base32) is handled by three [Cachix](https://github.com/cachix) crates:

- [`nix-archive`](https://crates.io/crates/nix-archive) — NAR encode/hash, reference scanning
- [`nix-narinfo`](https://crates.io/crates/nix-narinfo) — narinfo build/sign, fingerprint
- [`nix-derivation`](https://crates.io/crates/nix-derivation) — store path types, nix base32, `.drv` parsing

Plus `nostr`/`nostr-sdk` (relay publish), `reqwest` (rustls, Blossom
uploads), `ed25519-dalek` (narinfo signing), `xz2`/`zstd`
(compression; link system liblzma/libzstd), `clap`, `tokio`.

## Usage

You need two secrets: your Nostr signing key ("nsec") to sign the
event announcing the cache state and your Nix signing key to sign
the package builds. You can choose to omit the latter, but stock
Nix clients reject unsigned packages unless the client explicitly
opts out.

```bash
narwal-cli /nix/store/<hash>-hello-2.12.1 \
  --sec-file ./nostr.sec \
  --blossom http://<blossom-host>:3000 \
  --relay ws://<relay-host>:32847 \
  --channel test \
  --nix-sig-key ./mycache.sec \
  --dry-run # builds, but doesn't publish

# same, but signing via a NIP-46 bunker instead of a local key file:
narwal-cli /nix/store/<hash>-hello-2.12.1 \
  --bunker "bunker://<bunker-pubkey>?relay=wss://<relay>&secret=<token>" \
  --blossom http://<blossom-host>:3000 \
  --relay ws://<relay-host>:32847 \
  --channel test \
  --nix-sig-key ./mycache.sec \
  --dry-run

# or pair once with your phone signer (Amber) via QR, then sign per run:
narwal-cli pair   # prints a nostrconnect:// QR — scan it, approve, done
narwal-cli /nix/store/<hash>-hello-2.12.1 \
  --qr \
  --blossom http://<blossom-host>:3000 \
  --relay ws://<relay-host>:32847 \
  --channel test \
  --nix-sig-key ./mycache.sec \
  --dry-run

# for real: drop --dry-run
```

- `--sec-file` — path to the file holding the Nostr identity (`nsec`
  or hex). Also settable via `NARWAL_SEC_FILE` (a path, never key
  material). Must be allowlisted for uploads on Blossom and for
  writes on the relay.
- `--channel` — named cache channel (kind 37091). Omit for the
  default cache (kind 17091).
- `--nix-sig-key` — `name:base64` Ed25519 secret key file. Signs
  narinfos; the derived public key is advertised in the root event's
  `nixSigKey` tag so clients can add it to `trusted-public-keys`.
  Required for input-addressed paths.
- `--compression` — `xz` (default) or `zstd`.

## Security: key handling

Both publisher secrets can be provided by file.

- Nostr identity (`--sec-file`): file containing `nsec` or hex.
- Nix cache key (`--nix-sig-key`): `nix keygen-secret` format file.

Both files are refused at load time unless owner-only accessible
(`chmod 600`); group/world-readable key files are a hard error, not
a warning.

NIP-46 bunkers are supported as an alternative to `--sec-file`:
pass `--bunker "bunker://<pubkey>?relay=…&secret=…"` (or
`NARWAL_BUNKER`) and the identity key never touches the publisher
machine — signatures are requested from the signer app over Nostr.
Exactly one of `--sec-file` / `--bunker` / `--qr` is required.

Some signer apps (Amber) never export `bunker://` URLs — they scan a
`nostrconnect://` QR the client shows instead. Two ways to use it:

- `narwal-cli pair` — standalone ceremony: prints URI + terminal QR,
  waits up to 1 minute for the signer app, which answers with a
  `connect` *response* echoing our anti-spoofing secret (there is no
  ack-of-ack in NIP-46 — the response is the acknowledgement). The
  CLI takes the remote-signer key from the response author and learns
  the user key via `get_public_key` best-effort, adopts the signer's
  `switch_relays` answer if any, and saves the app key, signer key,
  user key **and the relays the signer is on** to
  `~/.local/share/narwal-cli/pairing.json` (0600). If the signer is
  not yet serving requests, the pairing is still saved and the user
  key is resolved lazily on first use. Re-running `pair` replaces the
  stored pairing (old user pubkey is logged).
- `--qr` on publish — same ceremony inline when no pairing is stored,
  straight to publishing afterwards.

Later runs reuse the stored app key **and the stored relays** — Amber
recognizes the app, no re-scan; each run just signs (subject to Amber's
own policy). Using the stored relays matters: re-deriving from CLI
defaults would talk to a relay the signer never checks, and the request
would silently never be seen. On each reuse the CLI also asks the signer
where it is now (`switch_relays`, short timeout) and updates the file, so
a signer that moved stays reachable. The app key is not the identity
key, but treat the file as a bearer credential anyway (written 0600).

Client side (fetching through Narwal):

```bash
nix-store -r /nix/store/<hash>-hello-2.12.1 \
  --option substituters http://<narwal-host>:8090 \
  --option trusted-public-keys "mycache:<base64-pubkey>"
```

## Development

```bash
nix develop   # rustc/cargo/clippy/rustfmt/rust-analyzer + liblzma/libzstd
cargo test    # 35 unit tests, no network
nix build .#default   # release binary via buildRustPackage
```
