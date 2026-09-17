# narwal-cli — publisher for the Narwal nix cache

CLI that publishes Nix store paths as a binary cache backed by
[Blossom](https://github.com/hzrd149/blossom) blobs + a Nostr
hashtree root, for consumption by the [Narwal](https://github.com/jurraca/narwal)
server. Mirrors the `narwal` server; the two are developed in lockstep
(`../narwal`, `../SPEC.md`).

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
parsing, nix base32) is handled by three Cachix crates:

- [`nix-archive`](https://crates.io/crates/nix-archive) — NAR encode/hash, reference scanning
- [`nix-narinfo`](https://crates.io/crates/nix-narinfo) — narinfo build/sign, fingerprint
- [`nix-derivation`](https://crates.io/crates/nix-derivation) — store path types, nix base32, `.drv` parsing

Plus `nostr`/`nostr-sdk` (relay publish), `reqwest` (rustls, Blossom
uploads), `ed25519-dalek` (narinfo signing), `xz2`/`zstd`
(compression; link system liblzma/libzstd), `clap`, `tokio`.

## Usage

```bash
# dry run first: hashes + manifest, no upload, no publish
narwal-cli /nix/store/<hash>-hello-2.12.1 \
  --sec-file ./nostr.sec \
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

Both publisher secrets are **file-only by design**. There is
deliberately no `--sec` flag: raw key material on a command line
leaks through the process table (`ps`), shell history, and CI logs.

- Nostr identity (`--sec-file`): file containing `nsec` or hex.
- Nix cache key (`--nix-sig-key`): `nix keygen-secret` format file.

Both files are refused at load time unless owner-only accessible
(`chmod 600`); group/world-readable key files are a hard error, not
a warning. Planned next step: NIP-46 bunker support so the Nostr key
never touches the publisher machine (note: Blossom upload auth needs
one signature per blob, so a bunker requires an auto-approve policy
for the publisher key to be usable).

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
