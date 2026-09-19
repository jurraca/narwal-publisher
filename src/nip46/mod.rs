//! NIP-46 (Nostr remote signing) support.
//!
//! Split into three layers with one-way dependencies:
//!
//! - [`session`] — persisted pairing state (no dependency on the others),
//! - [`signer`]  — the `BunkerSigner` transport + `NostrSigner` impl,
//! - [`pair`]    — the `nostrconnect://` QR ceremony.
//!
//! `signer` and `pair` both depend on `session`; `pair` also depends on
//! `signer`. Neither `session` nor `signer` depends on `pair`, so there is
//! no module cycle.

pub mod pair;
pub mod session;
pub mod signer;
