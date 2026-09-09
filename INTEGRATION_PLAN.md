# nix-archive Integration Plan

Replace the publisher's `nix copy --to file:///staging` → scan staging dir →
upload flow with direct store-path input using three Cachix Rust crates:
`nix-archive`, `nix-narinfo`, and `nix-derivation`. All three are pure Rust,
link no Nix code, and are tested differentially against Nix 2.34–2.36.

## Current flow

```
nix copy --to file:///staging /nix/store/48nhp...-coreutils-9.8
    ↓ Nix daemon builds NARs, narinfos, nix-cache-info on disk
nix-blossom-publish staging/ --blossom ... --relay ...
    ↓ scan.rs walks dir, reads each file into memory, uploads
```

Publisher is a file uploader. Nix does all the real work (NAR serialization,
hashing, reference scanning, narinfo building, signing). Publisher reads
pre-built artifacts and pushes bytes.

## Target flow

```
nix-blossom-publish /nix/store/48nhp...-coreutils-9.8 --blossom ... --relay ...
    ↓
for each store path in closure (topological order):
    encode NAR from filesystem path (nix-archive, streaming)
    compute NarHash + NarSize (same pass)
    scan references (same pass, nix-archive ReferencePattern)
    compress NAR (xz/zstd) → FileHash + FileSize
    build narinfo (nix-narinfo builder, canonical field order)
    sign fingerprint (nix-narinfo fingerprint + ed25519-dalek)
    upload NAR blob + narinfo blob to Blossom
build manifest tree, publish Nostr event
```

No `nix` binary, no daemon, no staging directory. All Nix-format work is
handled by the three Cachix crates.

## Crate dependencies

| Crate | Version | Role | Replaces |
|---|---|---|---|
| `nix-archive` | 0.4 | NAR encode/decode/hash, reference scanning | `nix-store --dump`, NAR reading from staging |
| `nix-narinfo` | latest | Narinfo parse/build/sign, fingerprint computation | Hand-rolled narinfo format + fingerprint |
| `nix-derivation` | 0.6 | Nix base32, StorePath/StoreDir types, .drv parsing | Stage 2 (nix32 module), Deriver/System fields |
| `ed25519-dalek` | 2.x | Ed25519 sign operation | N/A (nix-narinfo computes the fingerprint; this signs it) |
| `xz2` or `zstd` | latest | NAR compression | N/A |

All three Cachix crates are Apache-2.0, `#![forbid(unsafe_code)]`, and have
no Nix runtime dependency. They're designed to compose: `nix-narinfo` uses
`nix-derivation` types (`StorePath`, `StoreDir`, `NixHash`, `DrvOutput`),
and `nix-archive` handles the NAR bytes that `nix-narinfo`'s `NarHash`/
`FileHash` fields point to.

## What the crates provide

### nix-archive

| API | Returns | Replaces |
|---|---|---|
| `encode_path(w, path, case_hack)` | NAR bytes streamed to writer | `nix-store --dump` / reading .nar from staging |
| `hash_path(path, case_hack)` | `NarHash { size, sha256 }` | NarHash/NarSize from narinfo |
| `ReferencePattern::scan_path(path, case_hack)` | `ReferenceScan { nar_size, nar_sha256, matches }` | References field from narinfo |
| `ReferencePattern::writer(inner)` | `Write` decorator that scans while writing | combined hash + reference pass |

### nix-narinfo

| API | Returns | Replaces |
|---|---|---|
| `NarInfo::builder_in(store_dir, path, url, nar_hash, nar_size)` | Builder for constructing narinfo | Hand-rolled narinfo text format |
| `.compression()`, `.file_size()`, `.references()`, `.deriver()`, `.system()` | Builder methods for optional fields | Manual field assembly |
| `.to_canonical_bytes()` | Deterministic narinfo text (Nix field order) | Manual format string |
| `NarInfo::fingerprint()` | Exact Nix binary-cache fingerprint string | Hand-rolled fingerprint (was a risk item) |
| `TrustedPublicKey` | Parse `keyname:base64-pubkey` format | Manual key parsing |
| `NarInfo::is_content_addressed()` | Whether path needs signing | Manual CA detection |
| `UnkeyedRealisation`, `realisation_cache_path()` | `.doi` realisation documents | SPEC section 12.3 future work (now available) |

### nix-derivation

| API | Returns | Replaces |
|---|---|---|
| `StorePath`, `StoreDir` | Typed store path parsing/validation/rendering | Stage 2 (nix32 module) — **eliminated** |
| Nix base32 encode/decode | `nixbase32` for hashpart encoding | Custom nix32 implementation |
| `Derivation::parse()` | Parse `.drv` files (ATerm + JSON v4) | Shell-out to nix-store for Deriver/System |
| `Derivation::system`, `Derivation::outputs` | Extract `system` and output info from .drv | Omitted fields in narinfo |
| `hash_input_derivation_modulo()` | Derivation-modulo hash for closure resolution | Enables self-contained Approach B |
| `DrvOutput` | Derivation output identity | Realisation support |

### What none of the crates provide

- **Closure resolution** — nix-derivation provides the building blocks (.drv
  parsing, derivation-modulo hashing) but not the full graph walk. Still needs
  implementation (Stage 3).
- **Compression** — nix-archive produces uncompressed NAR bytes. Publisher
  must compress (xz/zstd) and compute FileHash over compressed bytes.
- **Ed25519 signing operation** — nix-narinfo computes the correct fingerprint
  bytes to sign, but the actual `sign(secret_key, fingerprint)` call needs
  `ed25519-dalek`.
- **Blossom upload, manifest tree, Nostr publishing** — unchanged from
  current publisher code.

---

## Stages

### Stage 1: NAR encoding module (nix-archive)

**Goal**: encode a NAR from a store path and get its hash, without Nix.

**Changes**:
- `publisher/Cargo.toml`: add `nix-archive = "0.4"`
- New `publisher/src/nar.rs`:
  ```rust
  pub struct NarOutput {
      pub bytes: Vec<u8>,           // uncompressed NAR (buffered for now)
      pub nar_hash: [u8; 32],      // SHA256 of NAR bytes
      pub nar_size: u64,           // byte length
  }

  pub fn encode_store_path(path: &Path) -> Result<NarOutput> {
      let nar_hash = hash_path(path, CaseHack::native())?;
      let mut bytes = Vec::new();
      encode_path(&mut bytes, path, CaseHack::native())?;
      Ok(NarOutput { bytes, nar_hash: nar_hash.sha256, nar_hash.size })
  }
  ```

**Testing**: byte-exact parity with `nix-store --dump` on a known store path
(e.g. coreutils). `sha256sum` of encoded NAR must equal `hash_path` result
must equal `nix-store --dump | sha256sum`.

**No changes to existing flow yet** — this is a standalone module.

---

### Stage 2: Store path types (nix-derivation)

**Goal**: typed store path parsing, Nix base32 encoding, and .drv access.

**Replaces the former Stage 2 (Nix32 encoding from scratch).** nix-derivation
provides `StorePath`, `StoreDir`, and Nix base32 encode/decode — no custom
implementation needed.

**Changes**:
- `publisher/Cargo.toml`: add `nix-derivation = "0.6"`
- Use `StorePath::from_basename()` to parse hashparts from store path names.
- Use `StoreDir::default()` (`/nix/store`) for path rendering.
- Nix base32 encoding/decoding via nix-derivation's API (used in narinfo
  fields, URL construction, reference candidate preparation).
- Optional: parse `.drv` files with `Derivation::parse()` to extract
  `Deriver:` and `System:` for the narinfo (both were previously omitted).

**Testing**: parse a known store path, verify hashpart extraction. Roundtrip
Nix base32 encode/decode against known narinfo hash vectors.

---

### Stage 3: Closure resolution (self-contained)

**Goal**: given input store paths, produce the full ordered list of paths to
publish (dependencies first) — without shelling out to `nix-store`.

**Approach**: reference-scan-based closure resolution using nix-archive.

The insight: a store path's references are other store path hashparts that
appear literally in its NAR byte stream. nix-archive's `ReferencePattern`
scans for exactly these. So we can discover the full closure by scanning
references recursively, starting from the input paths.

The challenge: `ReferencePattern` needs a candidate set (hashparts to look
for). We don't know the closure yet — that's what we're trying to discover.
Solution: use *all* paths in `/nix/store` as the candidate set. A `readdir`
of the store directory gives us every hashpart on the machine. The scanner
does O(1) HashMap lookups per position with an alphabet check that skips
non-base32 bytes quickly, so a large candidate set is fine.

**Flow**:
```
1. readdir(/nix/store) → HashSet of all hashparts (all_candidates)
2. worklist = input store paths
3. closure = {} (empty graph)
4. while worklist not empty:
   a. pop path P
   b. if P in closure: skip
   c. ReferencePattern::scan_path(P, all_candidates) → {nar_hash, nar_size, refs}
   d. closure[P] = {nar_hash, nar_size, refs}
   e. for each ref in refs: add to worklist if not in closure
5. topological sort closure (dependencies first)
```

Step 4c encodes the NAR to scan references. This NAR encoding is work we'd
do anyway for uploading — so we cache the encoded NAR (or its hash + size
+ references) to avoid re-encoding in Stage 8's upload loop.

**Why not .drv-based?** nix-derivation can parse `.drv` files and compute
derivation-modulo hashes, which would give the closure without encoding
NARs. But finding the `.drv` file for a given output store path is not
possible without the Nix database — the .drv hash is derived from the
derivation content, not the output content. We'd need to either scan all
`.drv` files and compute their output paths (expensive) or query the Nix
database (defeats the purpose). The reference-scan approach works from the
actual store contents and needs no database.

**When topo order matters**: for batch publish (all paths → one root event),
topo order is a correctness nicety — all narinfos are uploaded before the
root event, so the tree is complete when clients see it. For incremental
publish (root updated after each path), topo order is required so referenced
narinfos exist before referencing ones are announced.

**Changes**:
- New `publisher/src/closure.rs`:
  ```rust
  use std::collections::{HashMap, HashSet};
  use std::path::PathBuf;
  use nix_archive::nar::{ReferencePattern, ReferenceScan, CaseHack};

  pub struct ClosureEntry {
      pub path: PathBuf,
      pub nar_hash: [u8; 32],
      pub nar_size: u64,
      pub references: Vec<PathBuf>,  // resolved store paths
  }

  pub fn resolve(input_paths: &[PathBuf]) -> Result<Vec<ClosureEntry>> {
      // 1. readdir /nix/store → all hashparts
      let all_candidates = read_store_hashparts()?;

      // 2. BFS reference scan
      let mut closure: HashMap<PathBuf, ClosureEntry> = HashMap::new();
      let mut worklist: Vec<PathBuf> = input_paths.to_vec();

      while let Some(path) = worklist.pop() {
          if closure.contains_key(&path) {
              continue;
          }

          let pattern = ReferencePattern::new(&all_candidates)?;
          let scan = pattern.scan_path(&path, CaseHack::native())?;

          // Map matched candidate indices back to store paths
          let references = scan.matches
              .iter()
              .map(|&i| store_path_for_hashpart(&all_candidates[i]))
              .collect();

          closure.insert(path.clone(), ClosureEntry {
              path,
              nar_hash: scan.nar_sha256,
              nar_size: scan.nar_size,
              references,
          });

          // Add new references to worklist
          for ref_path in &closure[&path].references {
              if !closure.contains_key(ref_path) {
                  worklist.push(ref_path.clone());
              }
          }
      }

      // 3. Topological sort (dependencies first)
      Ok(topo_sort(closure)?)
  }
  ```
- `read_store_hashparts()`: readdir `/nix/store`, extract 32-char hashpart
  from each entry name. Returns `Vec<String>` of nix-base32 hashparts plus
  a mapping back to full store paths.

**Testing**: compare resolved closure against `nix-store --query
--requisites --include-outputs` for a known path. Verify all references
match `nix-store --query --references` per-path.

---

### Stage 4: Reference scanning (nix-archive)

**Goal**: for each store path, compute the `References:` field from NAR bytes.

**Changes**:
- New `publisher/src/refscan.rs`:
  ```rust
  pub fn scan_references(
      path: &Path,
      candidates: &[String],  // nix32 hashparts of all paths in closure
  ) -> Result<ReferenceScan> {
      let pattern = ReferencePattern::new(candidates)?;
      pattern.scan_path(path, CaseHack::native())
  }
  ```
- `ReferencePattern::scan_path` returns nar_hash + nar_size + matched
  candidate indices in a single pass. This can replace the separate
  `hash_path` call from Stage 1 — one pass gives hash, size, AND references.
- Map candidate indices back to store path hashparts (via nix-derivation
  `StorePath`) for the `References:` field.

**Testing**: compare references against `nix-store --query --references` for
a known path.

---

### Stage 5: Compression + FileHash

**Goal**: compress NAR bytes and compute the Blossom blob address.

**Changes**:
- Add `xz2` or `zstd` crate to `publisher/Cargo.toml`.
- In the NAR pipeline:
  ```rust
  let mut compressor = XzEncoder::new(Vec::new(), 6);
  compressor.write_all(&nar.bytes)?;
  let compressed = compressor.finish()?;

  let file_hash = sha256(&compressed);   // = Blossom blob address
  let file_size = compressed.len() as u64;
  ```
- URL field: `nar/<nixbase32(file_hash)>.nar.xz` (using nix-derivation's
  base32 encoder).

**Testing**: FileHash matches the `.nar.xz` hash from `nix copy --to` staging
dir for the same store path. NAR bytes decompress to identical content.

**Optimization (deferred)**: chain `encode_path` → compressor → hash sink →
Blossom upload in a single streaming pass. See Stage 9.

---

### Stage 6: Narinfo builder (nix-narinfo)

**Goal**: assemble narinfo text from computed fields, with correct Nix field
order and canonical encoding.

**Replaces the former hand-rolled narinfo struct and format string.**
nix-narinfo's builder API handles deterministic field order, canonical hash
encodings, sorted references, and store-aware absolute paths.

**Changes**:
- `publisher/Cargo.toml`: add `nix-narinfo` (latest)
- New `publisher/src/narinfo.rs`:
  ```rust
  use nix_derivation::{NixHash, StoreDir, StorePath};
  use nix_narinfo::{Compression, NarInfo};

  pub fn build_narinfo(
      store_path: &StorePath,
      store_dir: &StoreDir,
      url: &str,                    // nar/<nixbase32(filehash)>.nar.xz
      nar_hash: [u8; 32],
      nar_size: u64,
      file_size: u64,
      compression: Compression,
      references: &[String],         // sorted store path hashparts
      deriver: Option<&str>,        // from .drv parsing (Stage 2)
      system: Option<&str>,         // from .drv parsing (Stage 2)
  ) -> Result<Vec<u8>> {
      let info = NarInfo::builder_in(
          store_dir.clone(),
          store_path.clone(),
          url,
          NixHash::Sha256(nar_hash),
          nar_size,
      )
      .compression(compression)
      .file_size(Some(file_size))
      .references(references)
      .deriver(deriver)
      .system(system)
      .build()?;

      Ok(info.to_canonical_bytes())
  }
  ```
- nix-narinfo handles: field order, newline conventions, canonical hash
  encodings, sorted references, store-aware paths. All previously manual
  and error-prone.

**Testing**: parse output with `NarInfo::parse_in()` (roundtrip). Compare
canonical bytes against a known narinfo from `nix copy --to` for the same
store path.

---

### Stage 7: Ed25519 signing

**Goal**: sign narinfo fingerprints so stock Nix clients can verify them.

#### Why this is mandatory for a general-purpose cache

Nix's `require-sigs` is `true` by default and is a **global** setting — there
is no per-substituter toggle in `nix.conf`. An unsigned cache serving
input-addressed paths (the vast majority of nixpkgs) will be rejected by
every stock Nix client unless the user sets `require-sigs = false`, which
disables signature verification for *all* caches including cache.nixos.org.

The only per-cache escape hatch is the `trusted` store parameter, but that's
set by the store operator in local store config, not by the client in their
`nix.conf` substituters line. It doesn't apply to remote HTTP substituters
like Narwal.

Exceptions (no signature needed): fixed-output derivations (fetchurl,
fetchgit, etc.) are content-addressed and self-certifying — Nix verifies by
hashing the NAR. Floating CA paths (experimental `ca-derivations` feature)
are also self-certifying. But neither covers regular built packages.

**Bottom line**: if the publisher wants to serve built packages (coreutils,
gcc, glibc, user applications) to stock Nix clients, Ed25519 signing is
required. The user experience is one line in `nix.conf`:

```
trusted-public-keys = cache-name:base64-ed25519-pubkey
```

alongside the substituter URL — identical to adding any other Nix binary
cache. The publisher generates the key pair, signs all narinfos, and
advertises the public key in the Nostr root event's `nixSigKey` tag so
clients can discover it.

#### What nix-narinfo provides

The fingerprint computation was the primary risk item — the signed bytes must
match Nix's `ValidPathInfo::fingerprint` exactly. nix-narinfo computes this
internally and correctly (tested against Nix 2.34–2.36). The publisher no
longer hand-assembles the fingerprint string.

nix-narinfo also provides:
- `TrustedPublicKey` — parse the `keyname:base64-pubkey` format for
  advertising in the Nostr event's `nixSigKey` tag.
- `NarInfo::is_content_addressed()` — detect CA paths that don't need
  signing, allowing the publisher to skip signatures for self-certifying
  paths.

#### Changes

- Add `ed25519-dalek = "2"` to `publisher/Cargo.toml`.
- New `publisher/src/signing.rs`:
  ```rust
  pub struct SigningKey {
      pub keyname: String,
      pub secret: ed25519_dalek::SigningKey,
      pub public: ed25519_dalek::VerifyingKey,
  }

  impl SigningKey {
      pub fn from_secret_file(path: &Path) -> Result<Self> { ... }

      /// Sign the fingerprint bytes that nix-narinfo computed.
      pub fn sign_fingerprint(&self, fingerprint: &[u8]) -> String {
          let sig = self.secret.sign(fingerprint);
          format!("{}:{}", self.keyname, BASE64.encode(sig.to_bytes()))
      }
  }
  ```
- Nix key format: `nix keygen-secret` → secret key file; `nix keygen-public`
  → `keyname:base64-pubkey`. Publisher accepts the same secret key file
  format so users can reuse existing keys.
- The signed fingerprint comes from nix-narinfo's `NarInfo::fingerprint()`
  method — correct by construction, not by manual assembly.
- Sig line: `Sig: <keyname>:<base64(signature)>` appended to the narinfo
  text.

#### CLI changes
- Add `--secret-key-file <path>` flag (Nix secret key format).
- Publish the public key in the Nostr event's `nixSigKey` tag.
- If `--secret-key-file` is omitted, the publisher should refuse to publish
  input-addressed paths (or warn loudly) since the resulting cache will be
  unusable by stock Nix clients. CA paths can still be published unsigned.

#### Testing
Generate a key pair, sign a narinfo, verify with `nix-store --verify-path`
or `nix path-info --sigs`. Cross-check that nix-narinfo's fingerprint matches
what Nix computes internally.

---

### Stage 8: CLI rework — store path input

**Goal**: change publisher input from staging directory to store paths.

**Changes**:
- `publisher/src/main.rs`:
  ```rust
  struct Cli {
      /// Nix store paths to publish.
      store_paths: Vec<PathBuf>,

      #[arg(long, required = true)]
      blossom_servers: Vec<String>,

      #[arg(long, required = true)]
      relays: Vec<String>,

      #[arg(long)]
      channel: Option<String>,

      #[arg(long)]
      secret_key_file: Option<PathBuf>,

      #[arg(long, default_value = "xz")]
      compression: String,

      #[arg(long)]
      dry_run: bool,
  }
  ```
- New main loop:
  ```
  1. closure::resolve(&cli.store_paths) → Vec<PathBuf>
  2. Collect all hashparts as reference candidates (via nix-derivation)
  3. For each path (topological order):
     a. scan_references(path, candidates) → nar_hash, nar_size, refs
     b. encode_store_path(path) → nar_bytes (or stream)
     c. compress(nar_bytes) → compressed, file_hash, file_size
     d. build narinfo (nix-narinfo builder)
     e. compute fingerprint (nix-narinfo)
     f. sign fingerprint (ed25519-dalek)
     g. append Sig: line to narinfo text
     h. upload NAR blob (by file_hash) to Blossom
     i. upload narinfo blob (by SHA256(narinfo_text)) to Blossom
     j. collect manifest entry
  4. Synthesize nix-cache-info
  5. build_directory_tree(entries) → manifest nodes + root hash
  6. Upload manifest nodes
  7. Publish Nostr event (with nixSigKey tag from signing key)
  ```
- Remove or deprecate `scan.rs` (staging dir scanner).

**Testing**: end-to-end: publish a small store path, point Narwal at the
Nostr event, `nix-build --substituters https://narwal/` and verify the
package substitutes correctly.

**Migration**: keep `--from-staging <dir>` as a hidden compat flag that uses
the old scan.rs path, so existing workflows don't break during transition.

---

### Stage 9: Streaming upload (optimization)

**Goal**: eliminate buffering large NARs in memory.

**Problem**: `encode_path` writes to `std::io::Write` (sync). Blossom upload
is async (`reqwest`). Current `BlossomUploader::upload_bytes` takes `&[u8]`.

**Approach**: 
- Add `BlossomUploader::upload_stream(reader, hash, size)` using
  `reqwest::Body::wrap_stream` with an async channel.
- Bridge: `encode_path` writes sync → `tokio::sync::mpsc` channel →
  `reqwest` streaming body reads async.
- Pipeline: `encode_path` → `ReferenceWriter` → `HashSink` → xz encoder →
  channel → Blossom PUT with streaming body.
- One pass, zero buffering of full NAR, references and hashes computed inline.

**Alternative**: write compressed NAR to a temp file, then stream-upload the
temp file with `reqwest::Body::wrap_stream(fs::File)`. Simpler, trades
memory for disk I/O. Acceptable given NARs are typically small.

**Testing**: upload a large NAR (>100MB), verify memory usage stays flat.
Verify SHA256 of uploaded blob matches FileHash.

---

## Dependency graph between stages

```
Stage 1 (NAR encoding, nix-archive) ──────────┐
Stage 2 (Store path types, nix-derivation) ───┤
Stage 3 (closure resolution) ─────────────────►│
Stage 4 (reference scanning, nix-archive) ────►├── Stage 6 (narinfo builder, nix-narinfo)
Stage 5 (compression + FileHash) ─────────────►│          │
Stage 7 (Ed25519 signing) ───────────────────►│          │
                                               └──────────┴── Stage 8 (CLI rework) ──► Stage 9 (streaming)
```

Stages 1-5 and 7 can be developed in parallel (independent modules). Stage 6
depends on all of them. Stage 8 integrates everything. Stage 9 is pure
optimization.

## What stays unchanged

- `blossom.rs` — BlossomUploader works as-is for `&[u8]` uploads. Stage 9
  adds streaming variant.
- `manifest.rs` — hashtree Dir tree builder is unaffected. Narinfo entries
  still map `name → hash + size`.
- `nhash.rs` — nhash encoding of root hash is unaffected.
- `nostr_pub.rs` — Nostr event publishing is unaffected (gains
  `nixSigKey` tag population from signing key).

## What gets removed

- `scan.rs` — staging directory scanner. Replaced by direct store path input.
- The `nix copy --to file:///staging` prerequisite step.
- Dependency on `nix` binary for NAR serialization, narinfo building, and
  closure resolution. The publisher is fully self-contained — no `nix`,
  `nix-store`, or `nix-daemon` required.
- Former Stage 2 (custom nix32 module) — replaced by nix-derivation.
- Hand-rolled narinfo format string and fingerprint assembly — replaced by
  nix-narinfo.

## Risk notes

- **NAR parity**: nix-archive is tested differentially against `nix-store
  --dump`, but the publisher should have its own parity test on at least one
  real store path before relying on it.
- **Reference scanning correctness**: `ReferencePattern::scan_path` scans for
  32-byte nix32 hashparts in the NAR byte stream. This matches Nix's own
  reference scanner. Edge cases: hashparts split across chunk boundaries
  (handled by the scanner's tail buffer), false positives (handled by Nix's
  alphabet check, which nix-archive replicates).
- **Signing format**: ~~the fingerprint string must match Nix's exactly~~
  — resolved by nix-narinfo, which computes the fingerprint internally and
  is tested against Nix 2.34–2.36. Remaining risk: the ed25519-dalek sign
  output must match Nix's libsodium `crypto_sign_detached` format. Both use
  RFC 8032 Ed25519, so this should be compatible, but verify with a
  known-key + known-narinfo test vector.
- **macOS case hack**: `CaseHack::native()` matches Nix's compiled default.
  If the store was built on macOS with a different setting, hashes won't
  match. Not a concern on Linux.
- **Crate maturity**: nix-narinfo is new (created Aug 2026, 7 commits). The
  API may change. nix-derivation (0.6.1) and nix-archive (0.3) are more
  established. Pin versions and watch for breaking changes.
