//! NIP-46 pairing via `nostrconnect://` QR code (Amber-style signer apps).
//!
//! This module is the ceremony only; persisted state lives in
//! [`super::session`] and the transport in [`super::signer`].
//!
//! Some signer apps never export `bunker://` URLs — instead they scan a
//! connection URI the *client* shows. Flow:
//!
//! 1. Generate an ephemeral app keypair (or load the stored pairing).
//! 2. Connect to the handshake relays and open a *persistent* kind-24133
//!    subscription BEFORE showing the QR.
//!    24133 is in NIP-01's ephemeral range, so relays never store it — a
//!    response published before we are subscribed is lost permanently.
//! 3. Wait on that live subscription for the signer's `connect` response
//!    (whose `result` echoes our `secret`). The scan itself is the
//!    approval: pairing is single-use and stops at the first valid
//!    response (or the ceremony timeout).
//! 4. Persist `{app secret, bunker pubkey, user pubkey}` (0600) so later
//!    runs skip the scan: the app key is stable, Amber recognizes the
//!    app, and each run just signs (subject to Amber's own policy). The
//!    user pubkey is verified best-effort via a `get_public_key` RPC; if
//!    the signer is slow to start serving requests the pairing is still
//!    saved and the key is resolved lazily on first use.
//!
//! The app key is NOT the identity key: worst case, whoever holds the
//! pairing file can *request* signatures, but the signer app still
//! approves each one. The identity key itself never touches disk here.
//!
//! NOTE: handshake relays must be normal public relays. Our cache relay
//! allowlists event kinds (17091/37091) and would drop kind-24133
//! handshake traffic.

use super::session::{load_pairing, save_pairing, Pairing};
use super::signer::{wait_for_any_connection, BunkerSigner};
use anyhow::{anyhow, Result};
use nostr::prelude::*;
use nostr::signer::NostrSigner;
use nostr_sdk::prelude::RelayPoolNotification;
use nostr_sdk::Client;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Default handshake relays: public, signer-reachable, writable, unfiltered.
/// Overridable per run via `--bunker-relay`.
///
/// A short curated list rather than one relay: the signer may only be able
/// to publish to some of them, so we subscribe on all reachable ones. The
/// rendezvous is kept together by the *persistent* subscription below (we
/// listen continuously from before the QR until a response lands), not by
/// narrowing to a single relay.
pub const DEFAULT_HANDSHAKE_RELAYS: [&str; 2] = [
    "wss://nos.lol",
    "wss://nostr.oxtr.dev"
];

/// How long to wait for the user to scan the QR and approve.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for the first handshake relay to connect before showing
/// the QR anyway (the rest keep connecting in the background).
const FIRST_CONNECT_BUDGET: Duration = Duration::from_secs(4);
/// Best-effort `get_public_key` verification after the signer accepts.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(20);

/// Resolve handshake relays: explicit flags win, empty means defaults.
pub fn resolve_handshake_relays(requested: &[String]) -> Vec<String> {
    if requested.is_empty() {
        DEFAULT_HANDSHAKE_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        requested.to_vec()
    }
}

/// Render a QR code for the terminal, two modules per row using half
/// blocks (▀▄█), low error-correction level, and a 1-module quiet zone.
/// Roughly a third of the lines of naive full-block rendering.
pub fn render_qr(data: &str) -> Result<String> {
    use qrcode::{EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .map_err(|e| anyhow!("QR encode failed: {e}"))?;
    let w = code.width();
    let dark = |x: usize, y: usize| code[(x, y)] == qrcode::Color::Dark;
    let mut out = String::new();
    out.push_str(&" ".repeat(w + 2));
    out.push('\n');
    for y in (0..w).step_by(2) {
        out.push(' ');
        for x in 0..w {
            let top = dark(x, y);
            let bottom = y + 1 < w && dark(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str(" \n");
    }
    out.push_str(&" ".repeat(w + 2));
    out.push('\n');
    Ok(out)
}

/// Build the `nostrconnect://` pairing URI with correct percent-encoding.
///
/// Per NIP-46 the client-initiated URI carries `relay` (repeatable),
/// `secret` (required — echoed back in the signer's connect response so
/// the client can verify it and reject spoofed pairings), plus display
/// hints (`name`) and the requested `perms` (least-privilege: exactly
/// the event kinds this publisher signs).
///
/// (The SDK's `Display` for the client URI instead emits an unencoded
/// `metadata={...}` blob first, which strict signer-app parsers such
/// as Amber's reject — hence hand-rolled here.)
pub fn pairing_uri(app_pubkey: &PublicKey, relays: &[String], secret: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    // Unreserved characters stay readable; everything else encodes.
    const QUERY_SET: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let pct = |s: &str| utf8_percent_encode(s, QUERY_SET).to_string();
    let mut q = String::new();
    for r in relays {
        if !q.is_empty() {
            q.push('&');
        }
        q.push_str("relay=");
        q.push_str(&pct(r));
    }
    q.push_str("&secret=");
    q.push_str(&pct(secret));
    q.push_str("&name=narwal-cli&perms=");
    q.push_str(&pct(
        "sign_event:24242,sign_event:17091,sign_event:37091",
    ));
    format!("nostrconnect://{}?{}", app_pubkey.to_hex(), q)
}

/// Fresh random pairing secret (anti-spoofing token, not key material).
fn fresh_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Pair (or re-use a stored pairing) and return a ready signer.
///
/// Stored pairing: rebuilds the signer from the app secret on the relays the
/// signer was reachable on when paired (persisted in the file, merged with
/// any explicitly requested relays), verifies the user pubkey still matches
/// (warns loudly on change — possible device swap), and returns without any
/// QR ceremony.
/// Fresh pairing: see [`pair_fresh`].
pub async fn pair_via_qr(
    requested_relays: &[String],
    pairing_file: &Path,
) -> Result<BunkerSigner> {
    if let Some(mut pairing) = load_pairing(pairing_file)? {
        println!("Pairing: reusing stored pairing from {}", pairing_file.display());
        // Use the relays the signer is actually on (stored at pairing time),
        // merged with any explicitly requested ones. Re-deriving from CLI
        // defaults here was the bug: the signer never sees those relays.
        let mut relays = pairing.relays.clone();
        for r in requested_relays {
            if !relays.contains(r) {
                relays.push(r.clone());
            }
        }
        if relays.is_empty() {
            relays = resolve_handshake_relays(requested_relays);
        }
        tracing::info!(
            "reusing stored bunker pairing from {} (relays: {})",
            pairing_file.display(),
            relays.join(", ")
        );
        let signer = BunkerSigner::paired(&pairing, relays.clone())?;

        // Best-effort: ask the signer where it is now and persist that, so a
        // signer that moved relays stays reachable on later runs. Short
        // timeout so an unreachable signer does not stall startup.
        match tokio::time::timeout(Duration::from_secs(5), signer.refresh_relays()).await {
            Ok(Ok(extra)) if !extra.is_empty() => {
                tracing::info!("signer relay list: {}", extra.join(", "));
                signer.add_relays(&extra).await;
                let mut changed = false;
                for r in extra {
                    if !pairing.relays.contains(&r) {
                        pairing.relays.push(r);
                        changed = true;
                    }
                }
                if changed {
                    if let Err(e) = save_pairing(pairing_file, &pairing) {
                        tracing::warn!("could not persist updated signer relays: {e}");
                    }
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::debug!("switch_relays unsupported/failed ({e})"),
            Err(_) => tracing::debug!("switch_relays timed out; keeping stored relays"),
        }

        if pairing.user_pubkey_hex.is_empty() {
            // Saved before the user key could be resolved (signer was slow
            // to serve get_public_key). Resolve it now; still non-fatal.
            match signer.get_public_key().await {
                Ok(pk) => tracing::info!("resolved paired user pubkey: {}", pk.to_hex()),
                Err(e) => tracing::warn!(
                    "stored pairing has no user key and lookup failed ({e}); will retry on use"
                ),
            }
            return Ok(signer);
        }
        // Verify the pairing still resolves to the same user.
        match signer.get_public_key().await {
            Ok(pk) if pk.to_hex() == pairing.user_pubkey_hex => return Ok(signer),
            Ok(pk) => tracing::warn!(
                "paired user pubkey changed (stored {}, bunker says {}) — continuing; delete {} to re-pair from scratch",
                pairing.user_pubkey_hex,
                pk.to_hex(),
                pairing_file.display()
            ),
            Err(e) => {
                return Err(anyhow!(
                    "stored pairing failed ({e}); delete {} to re-pair, or check bunker reachability \
                     (relays: {})",
                    pairing_file.display(),
                    relays.join(", ")
                ))
            }
        }
        return Ok(signer);
    }

    pair_fresh(requested_relays, pairing_file).await
}

/// Run the full pairing ceremony from scratch and persist the result.
///
/// The kind-24133 subscription is opened *before*
/// the QR is displayed. Kind 24133 is ephemeral, so a signer response
/// published while we are not subscribed is lost forever. If a pairing file
/// already exists it is replaced (the old user pubkey is logged first).
pub async fn pair_fresh(
    requested_relays: &[String],
    pairing_file: &Path,
) -> Result<BunkerSigner> {
    if let Some(old) = load_pairing(pairing_file)? {
        tracing::warn!(
            "replacing stored pairing for {} (file {})",
            old.user_pubkey_hex,
            pairing_file.display()
        );
    }
    // Print before any network so the ceremony never looks hung.
    println!("Pairing: checking handshake relays…");
    let using_defaults = requested_relays.is_empty();
    let candidates = resolve_handshake_relays(requested_relays);
    for r in &candidates {
        RelayUrl::parse(r).map_err(|e| anyhow!("bad handshake relay {r:?}: {e}"))?;
    }

    // One client, all candidate relays, connect, then wait only for the
    // *first* connection (a dead relay must not stall the QR for seconds).
    let client = Client::default();
    for relay in &candidates {
        client
            .add_relay(relay)
            .await
            .map_err(|e| anyhow!("handshake relay {relay}: {e}"))?;
    }
    client.connect().await;
    let connected = wait_for_any_connection(&client, FIRST_CONNECT_BUDGET).await;

    // Health-gate the QR: only advertise relays that are up. Explicit
    // requests are kept regardless (operator intent wins) but flagged.
    let mut effective: Vec<String> = Vec::new();
    for r in &candidates {
        if connected.contains(r) {
            println!("✓ handshake relay reachable: {r}");
            effective.push(r.clone());
        } else if using_defaults {
            println!("✗ handshake relay unreachable, excluded from QR: {r}");
        } else {
            println!("✗ handshake relay unreachable, keeping (explicitly requested): {r}");
            effective.push(r.clone());
        }
    }
    if effective.is_empty() {
        println!("WARNING: no handshake relay is reachable — showing the QR anyway;");
        println!("pairing will likely fail until one recovers. Re-run pair for a fresh check.");
        effective = candidates;
    }
    let handshake_relays = &effective;
    let app_keys = Keys::generate();
    // Anti-spoofing token: the signer must echo it in its connect response.
    let secret = fresh_secret();

    // The subscription is opened BEFORE showing the QR (kind 24133 is
    // ephemeral) and stays live for the whole ceremony, so late-connecting
    // relays and late signer responses are still caught.
    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(app_keys.public_key())
        .limit(0);
    client
        .subscribe(filter, None)
        .await
        .map_err(|e| anyhow!("handshake subscribe failed: {e}"))?;
    println!("✓ kind-24133 subscription open (before QR display)");

    // Forward every kind-24133 event into a channel; the persistent
    // subscription plus this forwarder remove the fetch_events EOSE gaps
    // that dropped ephemeral signer responses.
    let (tx, rx) = mpsc::channel::<Event>(64);
    let task_client = client.clone();
    tokio::spawn(async move {
        let _ = task_client
            .handle_notifications(move |notif| {
                let tx = tx.clone();
                async move {
                    if let RelayPoolNotification::Event { event, .. } = notif {
                        let _ = tx.send(*event).await;
                    }
                    // `Ok(false)` = keep handling; `Ok(true)` would exit the
                    // loop and drop the channel after the first event.
                    Ok(false)
                }
            })
            .await;
    });

    let uri_string = pairing_uri(&app_keys.public_key(), handshake_relays, &secret);
    println!("Scan this pairing code with your signer app (Amber):\n");
    println!("{}", render_qr(&uri_string)?);
    println!("{uri_string}\n");
    println!("Waiting up to 1 minute for approval (Ctrl-C to abort)…");
    println!("(app pubkey for debugging: {})", app_keys.public_key().to_hex());

    let deadline = Instant::now() + PAIRING_TIMEOUT;
    let remote_signer_pubkey = await_connect_response(&app_keys, &secret, rx, deadline)
        .await
        .map_err(|e| {
            anyhow!(
                "{e} (relays used: {}; re-run `pair` for a fresh health check, or add --bunker-relay)",
                handshake_relays.join(",")
            )
        })?;
    println!("✓ signer connected: {}", remote_signer_pubkey.to_hex());

    // The signer's connect response IS the acknowledgement — NIP-46 defines
    // no ack-of-ack. Its author is the remote signer; the user key is
    // resolved next, best-effort.
    let transport = BunkerSigner::transport_only(
        app_keys.clone(),
        remote_signer_pubkey,
        handshake_relays.to_vec(),
    );

    // Best-effort: a brand-new signer connection may not be serving
    // requests yet. Do not fail the pairing — an empty user_pubkey_hex is
    // resolved lazily on first use instead.
    let user_pubkey = match tokio::time::timeout(VERIFY_TIMEOUT, transport.user_public_key()).await {
        Ok(Ok(pk)) => Some(pk),
        Ok(Err(e)) => {
            println!("! could not resolve user key yet ({e}); saving pairing anyway");
            None
        }
        Err(_) => {
            println!("! user key lookup timed out; saving pairing anyway");
            None
        }
    };

    // Let the signer steer us to healthy relays (NIP-46 switch_relays);
    // adopt whatever it returns, keep ours too. Best-effort.
    let mut signer_relays: Vec<String> = handshake_relays.to_vec();
    match transport.refresh_relays().await {
        Ok(extra) if !extra.is_empty() => {
            tracing::info!("signer suggested relays: {}", extra.join(", "));
            transport.add_relays(&extra).await;
            for r in extra {
                if !signer_relays.contains(&r) {
                    signer_relays.push(r);
                }
            }
        }
        Ok(_) => {}
        Err(e) => tracing::debug!("switch_relays unsupported/failed ({e}) — keeping handshake relays"),
    }

    let pairing = Pairing {
        app_secret_hex: app_keys.secret_key().to_secret_hex(),
        bunker_pubkey_hex: remote_signer_pubkey.to_hex(),
        user_pubkey_hex: user_pubkey.map(|pk| pk.to_hex()).unwrap_or_default(),
        relays: signer_relays.clone(),
    };
    save_pairing(pairing_file, &pairing)?;
    tracing::info!(
        "pairing saved to {} (signer relays: {})",
        pairing_file.display(),
        signer_relays.join(", ")
    );

    let signer = BunkerSigner::paired(&pairing, signer_relays)?;
    match user_pubkey {
        Some(pk) => println!(
            "\nPaired as {} (saved to {})\nPublishing will now sign via your signer app.",
            pk.to_bech32().unwrap_or_else(|_| pk.to_hex()),
            pairing_file.display()
        ),
        None => println!(
            "\nPaired (saved to {}); user key will be resolved on first use.",
            pairing_file.display()
        ),
    }
    Ok(signer)
}

/// Wait for the signer's connect response on a live event stream.
///
/// Returns the remote signer pubkey once a response echoing `secret`
/// arrives, or an error if the stream closes or the deadline passes.
/// Extracted from [`pair_fresh`] so the accept path is testable without a
/// network or a real relay.
async fn await_connect_response(
    app_keys: &Keys,
    secret: &str,
    mut rx: mpsc::Receiver<Event>,
    deadline: Instant,
) -> Result<PublicKey> {
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) => d,
            None => return Err(anyhow!("pairing timed out — no signer connected within 1 minute")),
        };
        let event = match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) => event,
            // Sender dropped (notification task ended): no more events.
            Ok(None) => return Err(anyhow!("pairing event stream closed before a signer connected")),
            Err(_) => return Err(anyhow!("pairing timed out — no signer connected within 1 minute")),
        };
        tracing::info!(
            "pairing candidate: id={} author={} kind={:?}",
            event.id.to_hex(),
            event.pubkey.to_hex(),
            event.kind
        );
        if let Some(pk) = try_accept_response(app_keys, secret, &event)? {
            return Ok(pk);
        }
    }
}

/// Try to interpret an event as the signer's `connect` response.
///
/// In the `nostrconnect://` direction the signer speaks first, and it
/// speaks in responses, not requests: a kind-24133 event authored by the
/// (still unknown) remote signer, p-tagged to our app key, whose
/// decrypted body is `{"id": ..., "result": "<our-secret>"}`. Accepts
/// only responses echoing this run's secret (anti-spoofing) and returns
/// the response author as the remote signer pubkey. Everything else —
/// undecryptable traffic, requests, wrong secrets — is Ok(None) with an
/// info breadcrumb, so a stuck ceremony is diagnosable rather than silent.
fn try_accept_response(
    app_keys: &Keys,
    expected_secret: &str,
    event: &Event,
) -> Result<Option<PublicKey>> {
    let short = |id: &EventId| id.to_hex()[..12].to_string();
    let plaintext = match super::signer::decrypt_from(app_keys, &event.pubkey, &event.content) {
        Ok(p) => p,
        Err(e) => {
            tracing::info!("pairing: event {} not for us (decrypt failed: {e})", short(&event.id));
            return Ok(None);
        }
    };
    let body: serde_json::Value = match serde_json::from_str(&plaintext) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!("pairing: event {} not JSON ({e})", short(&event.id));
            return Ok(None);
        }
    };
    match body.get("result").and_then(|r| r.as_str()) {
        Some(s) if s == expected_secret => Ok(Some(event.pubkey)),
        Some(_) => {
            tracing::info!("pairing: event {} response secret mismatch", short(&event.id));
            Ok(None)
        }
        None => {
            tracing::info!("pairing: event {} has no result field", short(&event.id));
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip46::{NostrConnectMessage, NostrConnectRequest};

    /// Signer side of a `connect` response echoing `secret`, p-tagged to the
    /// app. Used by the offline pairing tests.
    fn connect_response_event(signer: &Keys, app: &PublicKey, secret: &str) -> Event {
        let body = serde_json::json!({"id": "r1", "result": secret}).to_string();
        let ct = crate::nip46::signer::encrypt_to(signer, app, &body).unwrap();
        EventBuilder::new(Kind::NostrConnect, ct)
            .tag(Tag::public_key(*app))
            .sign_with_keys(signer)
            .unwrap()
    }

    #[test]
    fn pairing_uri_round_trip() {
        let app = Keys::generate();
        let relays = vec![
            "wss://relay.ditto.pub".to_string(),
            "wss://nos.lol".to_string(),
        ];
        let secret = "test-secret-abc123";
        let s = pairing_uri(&app.public_key(), &relays, secret);
        assert!(s.starts_with("nostrconnect://"), "unexpected: {s}");
        assert!(s.contains(&app.public_key().to_hex()), "unexpected: {s}");
        assert!(s.contains("secret=test-secret-abc123"), "secret missing: {s}");
        // Relays first, metadata last, everything encoded: no raw JSON
        // punctuation that strict signer-app parsers choke on.
        assert!(!s.contains('"') && !s.contains('{') && !s.contains('}'), "unencoded: {s}");
        assert!(s.contains("relay=wss%3A%2F%2Frelay.ditto.pub"), "unexpected: {s}");
        // The SDK's own parser predates the current spec (it requires the
        // legacy `metadata` blob and ignores secret/name/perms), so verify
        // structure manually instead of round-tripping through it.
        let query = s.split_once('?').expect("query").1;
        let mut pairs: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for kv in query.split('&') {
            let (k, v) = kv.split_once('=').expect("k=v");
            let v = percent_encoding::percent_decode_str(v)
                .decode_utf8()
                .expect("decodable")
                .into_owned();
            pairs.entry(k.to_string()).or_default().push(v);
        }
        assert_eq!(
            pairs["relay"],
            vec![
                "wss://relay.ditto.pub".to_string(),
                "wss://nos.lol".to_string()
            ]
        );
        assert_eq!(pairs["secret"], vec!["test-secret-abc123".to_string()]);
        assert_eq!(pairs["name"], vec!["narwal-cli".to_string()]);
        assert_eq!(
            pairs["perms"],
            vec!["sign_event:24242,sign_event:17091,sign_event:37091".to_string()]
        );
    }

    /// Full pairing handshake offline, per NIP-46's client-initiated
    /// direction: "signer" answers with a connect *response* echoing our
    /// secret, "app" accepts it via try_accept_response. Two local keys,
    /// no network.
    #[test]
    fn connect_response_accept_envelope() {
        let app = Keys::generate();
        let signer = Keys::generate();
        let secret = "s3cr3t-test-value";

        // Signer side: connect response echoing our secret, p-tagged to us.
        let body = serde_json::json!({"id": "r1", "result": secret}).to_string();
        let ct = crate::nip46::signer::encrypt_to(&signer, &app.public_key(), &body).unwrap();
        let response_event = EventBuilder::new(Kind::NostrConnect, ct)
            .tag(Tag::public_key(app.public_key()))
            .sign_with_keys(&signer)
            .unwrap();

        // App side: accept iff the secret matches.
        let accepted = try_accept_response(&app, secret, &response_event)
            .unwrap()
            .expect("must accept");
        assert_eq!(accepted, signer.public_key());

        // Wrong secret: rejected (spoofing protection).
        assert!(try_accept_response(&app, "wrong-secret", &response_event)
            .unwrap()
            .is_none());

        // Non-response traffic ignored: a request envelope must not pair us.
        let req = NostrConnectRequest::Ping;
        let req_msg = NostrConnectMessage::request(&req);
        let req_ct =
            crate::nip46::signer::encrypt_to(&signer, &app.public_key(), &req_msg.as_json())
                .unwrap();
        let request_event = EventBuilder::new(Kind::NostrConnect, req_ct)
            .tag(Tag::public_key(app.public_key()))
            .sign_with_keys(&signer)
            .unwrap();
        assert!(try_accept_response(&app, secret, &request_event)
            .unwrap()
            .is_none());
    }

    /// Regression for the live hang: kind 24133 is ephemeral, so the connect
    /// response only ever exists on a live stream. The channel-driven wait
    /// must accept it even after unrelated traffic and a wrong-secret spoof,
    /// with a gap in between (no EOSE, no polling).
    #[tokio::test]
    async fn await_accepts_live_response_after_noise() {
        let app = Keys::generate();
        let signer = Keys::generate();
        let secret = "live-secret";
        let app_pk = app.public_key();
        let (tx, rx) = mpsc::channel(8);

        // Unrelated request that must not pair us.
        let ping_msg = NostrConnectMessage::request(&NostrConnectRequest::Ping);
        let ping_ct =
            crate::nip46::signer::encrypt_to(&signer, &app_pk, &ping_msg.as_json()).unwrap();
        let ping_ev = EventBuilder::new(Kind::NostrConnect, ping_ct)
            .tag(Tag::public_key(app_pk))
            .sign_with_keys(&signer)
            .unwrap();
        tx.send(ping_ev).await.unwrap();

        // Spoofed response with the wrong secret.
        tx.send(connect_response_event(&signer, &app_pk, "wrong"))
            .await
            .unwrap();

        // A gap, then the real response — this is the window that the old
        // fetch_events polling dropped.
        let real = connect_response_event(&signer, &app_pk, secret);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(real).await;
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let got = await_connect_response(&app, secret, rx, deadline)
            .await
            .expect("must accept the live response");
        assert_eq!(got, signer.public_key());
    }

    #[tokio::test]
    async fn await_times_out_without_a_signer() {
        let app = Keys::generate();
        // Sender kept alive: the stream is open but silent.
        let (_tx, rx) = mpsc::channel(8);
        let deadline = Instant::now() + Duration::from_millis(50);
        let err = await_connect_response(&app, "s", rx, deadline)
            .await
            .expect_err("must time out");
        assert!(err.to_string().contains("timed out"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn await_errors_when_stream_closes() {
        let app = Keys::generate();
        let (tx, rx) = mpsc::channel(8);
        drop(tx);
        let deadline = Instant::now() + Duration::from_secs(5);
        let err = await_connect_response(&app, "s", rx, deadline)
            .await
            .expect_err("must fail on closed stream");
        assert!(err.to_string().contains("closed"), "unexpected: {err}");
    }

    #[test]
    fn qr_render_smoke() {
        let out = render_qr("nostrconnect://deadbeef?relay=wss://x").unwrap();
        // Half-block mode: two modules per row, so these must appear.
        assert!(
            out.contains('▀') || out.contains('▄'),
            "QR must use half-block rows"
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() > 10, "QR must be multi-line");
        assert!(lines.len() < 30, "QR must stay compact, got {} lines", lines.len());
    }

    #[test]
    fn resolve_defaults_is_curated_list() {
        // A short list of signer-friendly writable relays, not one indexer:
        // the persistent subscription keeps the rendezvous together.
        let defaults = resolve_handshake_relays(&[]);
        let expected: Vec<String> = DEFAULT_HANDSHAKE_RELAYS.iter().map(|s| s.to_string()).collect();
        assert_eq!(defaults, expected);
        assert!(defaults.len() >= 2, "want several relays: {defaults:?}");
    }

    #[test]
    fn resolve_passes_explicit_through() {
        let custom = vec!["wss://example.com".to_string()];
        assert_eq!(resolve_handshake_relays(&custom), custom);
    }

    /// With only an unreachable relay, the first-connection wait returns
    /// empty within its budget instead of hanging. Offline-safe (refused
    /// port, no network).
    #[tokio::test]
    async fn wait_for_any_connection_times_out_offline() {
        let client = Client::default();
        client.add_relay("ws://127.0.0.1:1").await.unwrap();
        client.connect().await;
        let start = Instant::now();
        let connected = wait_for_any_connection(&client, Duration::from_millis(800)).await;
        assert!(connected.is_empty(), "expected none, got {connected:?}");
        assert!(start.elapsed() < Duration::from_secs(3), "took too long");
    }
}
