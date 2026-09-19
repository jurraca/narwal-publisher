//! NIP-46 remote signing (nostr bunker / `bunker://` URLs).
//!
//! Lets the publisher operate without holding the Nostr identity key:
//! signatures are requested from a remote signer app over Nostr itself.
//! The app holds only an ephemeral local keypair (used for the NIP-46
//! transport encryption); the identity key never touches this machine.
//!
//! Per-run cost is tiny: with session-scoped upload auth the publisher
//! needs ~2 signatures per run (root event + auth token), i.e. ~2 bunker
//! round trips. Interactive approval in the signer app is therefore
//! tolerable; an auto-approve policy for the app key is still nicer.
//!
//! Bunker URL format (NIP-46):
//! `bunker://<bunker-pubkey-hex>?relay=wss://...&secret=<app-token>`
//! The `secret` is an app connection token, not key material.

use anyhow::{anyhow, Result};
use nostr::nips::nip44::{self, Version};
use nostr::nips::nip46::{
    NostrConnectMessage, NostrConnectMethod, NostrConnectRequest, NostrConnectURI,
    ResponseResult,
};
use nostr::prelude::*;
use nostr_sdk::prelude::RelayPoolNotification;
use nostr_sdk::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex, OnceCell};

/// How long to wait for a bunker response (covers interactive approval).
const RPC_TIMEOUT: Duration = Duration::from_secs(90);

/// Poll until at least one pool relay is connected or `budget` elapses.
///
/// Returns the relays connected at that instant (empty on timeout). Used
/// instead of `Client::wait_for_connection`, which waits for *all* relays —
/// a single dead relay then stalls startup for the full timeout even though
/// the subscription is already live on a working one.
pub(crate) async fn wait_for_any_connection(client: &Client, budget: Duration) -> Vec<String> {
    let deadline = Instant::now() + budget;
    loop {
        let connected: Vec<String> = client
            .relays()
            .await
            .into_iter()
            .filter(|(_, r)| r.is_connected())
            .map(|(u, _)| u.to_string())
            .collect();
        if !connected.is_empty() || Instant::now() >= deadline {
            return connected;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// NIP-44 encrypt a JSON payload for the recipient.
pub(crate) fn encrypt_to(
    sender: &Keys,
    recipient: &PublicKey,
    payload: &str,
) -> Result<String> {
    nip44::encrypt(sender.secret_key(), recipient, payload, Version::V2)
        .map_err(|e| anyhow!("nip44 encrypt failed: {e}"))
}

/// NIP-44 decrypt a payload from the sender.
pub(crate) fn decrypt_from(
    recipient: &Keys,
    sender: &PublicKey,
    payload: &str,
) -> Result<String> {
    nip44::decrypt(recipient.secret_key(), sender, payload)
        .map_err(|e| anyhow!("nip44 decrypt failed: {e}"))
}

/// A NIP-46 remote signer implementing [`NostrSigner`].
///
/// Transport: one persistent kind-24133 subscription (`#p=[app]`) plus a
/// background notification forwarder that completes pending requests by
/// message id. Exactly one relay subscription per process, no polling.
pub struct BunkerSigner {
    app_keys: Keys,
    bunker_pubkey: PublicKey,
    relays: Vec<String>,
    app_secret: Option<String>,
    client: Client,
    started: OnceCell<()>,
    handshook: OnceCell<()>,
    user_pubkey: OnceCell<PublicKey>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<NostrConnectMessage>>>>,
}

// Manual Debug: app_keys holds secret material — never print it.
impl std::fmt::Debug for BunkerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BunkerSigner")
            .field("bunker_pubkey", &self.bunker_pubkey)
            .field("relays", &self.relays)
            .field("has_app_secret", &self.app_secret.is_some())
            .finish_non_exhaustive()
    }
}

impl BunkerSigner {
    /// Parse a `bunker://` URL. The app keypair is generated fresh per
    /// process (ephemeral): nothing identifying persists on disk. No
    /// network happens here — connection is lazy on first use.
    pub fn new(url: &str) -> Result<Self> {
        let uri = NostrConnectURI::parse(url)
            .map_err(|e| anyhow!("invalid bunker URL: {e}"))?;
        if !uri.is_bunker() {
            return Err(anyhow!("not a bunker:// URL"));
        }
        let bunker_pubkey = uri
            .remote_signer_public_key()
            .ok_or_else(|| anyhow!("bunker URL has no signer pubkey"))?
            .to_owned();
        let relays: Vec<String> = uri.relays().iter().map(|r| r.to_string()).collect();
        if relays.is_empty() {
            return Err(anyhow!("bunker URL lists no relays (?relay=wss://...)"));
        }
        let app_secret = uri.secret().map(|s| s.to_string());
        if app_secret.is_none() {
            tracing::warn!(
                "bunker URL has no `&secret=`: signers such as Amber register no client for it \
                 and will answer get_public_key/sign_event with \"no permission\". Copy the URL \
                 including its secret, or use `--qr` pairing instead."
            );
        }
        Ok(Self {
            app_keys: Keys::generate(),
            bunker_pubkey,
            relays,
            app_secret,
            client: Client::default(),
            started: OnceCell::new(),
            handshook: OnceCell::new(),
            user_pubkey: OnceCell::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Bare transport to a remote signer: app identity + where to reach
    /// it. No user key yet — call [`BunkerSigner::user_public_key`] (or a
    /// successful pairing handshake) to learn it. The connect handshake is
    /// skipped: in flows that use this constructor, approval happened
    /// elsewhere (QR scan) or is per-request policy.
    pub(crate) fn transport_only(
        app_keys: Keys,
        remote_signer_pubkey: PublicKey,
        relays: Vec<String>,
    ) -> Self {
        let this = Self {
            app_keys,
            bunker_pubkey: remote_signer_pubkey,
            relays,
            app_secret: None,
            client: Client::default(),
            started: OnceCell::new(),
            handshook: OnceCell::new(),
            user_pubkey: OnceCell::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = this.handshook.set(());
        this
    }

    /// Build from an already-paired identity (QR flow): the app keypair
    /// is stable across runs, the user pubkey is known, and the QR scan
    /// itself was the approval — so the cached pubkey is pre-seeded.
    /// Relays come from CLI/defaults each run (never go stale in the file).
    pub(crate) fn paired(pairing: &super::session::Pairing, relays: Vec<String>) -> Result<Self> {
        let app_keys = Keys::parse(&pairing.app_secret_hex).map_err(|e| {
            anyhow!("stored pairing has unusable app secret (delete it to re-pair): {e}")
        })?;
        let bunker_pubkey: PublicKey = pairing
            .bunker_pubkey_hex
            .parse()
            .map_err(|e| anyhow!("stored pairing has bad bunker pubkey: {e}"))?;
        let this = Self::transport_only(app_keys, bunker_pubkey, relays);
        // Pre-seed the verified user pubkey when known. An empty value means
        // pairing finished before the signer served get_public_key; the key
        // is then resolved lazily by user_public_key().
        if !pairing.user_pubkey_hex.is_empty() {
            let user_pubkey: PublicKey = pairing
                .user_pubkey_hex
                .parse()
                .map_err(|e| anyhow!("stored pairing has bad user pubkey: {e}"))?;
            let _ = this.user_pubkey.set(user_pubkey);
        }
        Ok(this)
    }

    /// Connect transport + subscribe for responses, exactly once.
    async fn ensure_started(&self) -> Result<()> {
        self.started
            .get_or_try_init(|| async {
                for relay in &self.relays {
                    // Duplicate adds are harmless (bool return); surface real errors.
                    self.client.add_relay(relay).await.map_err(|e| anyhow!("bunker relay {relay}: {e}"))?;
                }
                self.client.connect().await;
                // Proceed on the first live relay: the subscription below is
                // queued on the whole pool, so one working path is enough.
                let connected = wait_for_any_connection(&self.client, Duration::from_secs(5)).await;
                if connected.is_empty() {
                    tracing::warn!(
                        "bunker transport: no relay connected yet ({}); requests may not reach the signer",
                        self.relays.join(", ")
                    );
                } else {
                    tracing::info!("bunker transport connected on: {}", connected.join(", "));
                }

                // No author filter: signers may answer with the per-connection
                // key or the account key. Decryption against the event author
                // (below) authenticates whichever it is; the #p tag keeps the
                // subscription scoped to this app's private key.
                let filter = Filter::new()
                    .kind(Kind::NostrConnect)
                    .pubkey(self.app_keys.public_key())
                    .limit(0);
                self.client
                    .subscribe(filter, None)
                    .await
                    .map_err(|e| anyhow!("bunker response subscribe failed: {e}"))?;
                tracing::info!(
                    "bunker transport listening for responses (app key {})",
                    self.app_keys.public_key().to_hex()
                );

                let client = self.client.clone();
                let app_keys = self.app_keys.clone();
                let pending = Arc::clone(&self.pending);
                tokio::spawn(async move {
                    let _ = client
                        .handle_notifications(|notif| {
                            let pending = Arc::clone(&pending);
                            let app_keys = app_keys.clone();
                            async move {
                                if let RelayPoolNotification::Event { event, .. } = notif {
                                    Self::dispatch_response(&pending, &app_keys, &event).await;
                                }
                                // `Ok(false)` = keep handling; `Ok(true)`
                                // would exit after the first event.
                                Ok(false)
                            }
                        })
                        .await;
                });
                Ok(())
            })
            .await
            .map(|_| ())
    }

    /// Try to complete a pending request from one incoming event.
    /// Unknown ids, undecryptable content, and non-responses are ignored
    /// (other traffic may share the subscription).
    async fn dispatch_response(
        pending: &Mutex<HashMap<String, oneshot::Sender<NostrConnectMessage>>>,
        app_keys: &Keys,
        event: &Event,
    ) {
        // Decrypt against the event author: that is whoever actually signed
        // (signer's per-connection key or the account key). NIP-44's key is
        // symmetric between the app secret and that author.
        let plaintext = match decrypt_from(app_keys, &event.pubkey, &event.content) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "bunker: ignoring kind-24133 from {} (decrypt failed: {e})",
                    event.pubkey.to_hex()
                );
                return;
            }
        };
        let msg: NostrConnectMessage = match NostrConnectMessage::from_json(&plaintext) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("bunker: ignoring undecodable response ({e})");
                return;
            }
        };
        if !msg.is_response() {
            return;
        }
        let sender = pending.lock().await.remove(msg.id());
        if let Some(tx) = sender {
            tracing::debug!("bunker: completing request id={} from {}", msg.id(), event.pubkey.to_hex());
            let _ = tx.send(msg);
        } else {
            tracing::debug!("bunker: response id={} has no pending request", msg.id());
        }
    }

    /// One NIP-46 round trip: encrypt, publish kind 24133, await the
    /// correlated response.
    async fn rpc(&self, req: NostrConnectRequest) -> Result<(NostrConnectMethod, NostrConnectMessage)> {
        let method = req.method();
        let msg = NostrConnectMessage::request(&req);
        tracing::info!("bunker: sending {method} (id={})", msg.id());
        let resp = self.rpc_raw(msg.id(), &msg.as_json()).await?;
        tracing::info!("bunker: {method} response received");
        Ok((method, resp))
    }

    /// Raw round trip for an already-serialized request payload under a
    /// caller-chosen id (used for methods like `switch_relays` that have
    /// no typed request variant).
    async fn rpc_raw(&self, id: &str, payload_json: &str) -> Result<NostrConnectMessage> {
        self.ensure_started().await?;
        let ciphertext = encrypt_to(&self.app_keys, &self.bunker_pubkey, payload_json)?;
        let event = EventBuilder::new(Kind::NostrConnect, ciphertext)
            .tag(Tag::public_key(self.bunker_pubkey))
            .sign_with_keys(&self.app_keys)
            .map_err(|e| anyhow!("signing bunker request failed: {e}"))?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id.to_string(), tx);
        let output = self
            .client
            .send_event(&event)
            .await
            .map_err(|e| anyhow!("sending bunker request failed: {e}"))?;
        for (url, err) in &output.failed {
            tracing::debug!("bunker request {id} rejected by {url}: {err}");
        }
        if output.success.is_empty() {
            return Err(anyhow!(
                "bunker request {id} reached no relay (attempted: {}); the signer cannot \
                 see it — check the handshake relays are reachable from this host",
                self.relays.join(", ")
            ));
        }
        tracing::info!(
            "bunker request {id} published ({} relay(s), {} failed)",
            output.success.len(),
            output.failed.len()
        );

        tokio::time::timeout(RPC_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow!("bunker timed out waiting for response (approve the request in your signer app?)"))?
            .map_err(|_| anyhow!("bunker response handler dropped"))
    }

    /// Ask the signer for its current relay list (NIP-46 `switch_relays`)
    /// and adopt any new relays into the transport pool. Returns the
    /// signer's list (empty = nothing to change).
    pub(crate) async fn refresh_relays(&self) -> Result<Vec<String>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = format!(
            "sw-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let payload = serde_json::json!({"id": id, "method": "switch_relays", "params": []}).to_string();
        let msg = self.rpc_raw(&id, &payload).await?;
        if !msg.is_response() || msg.id() != id {
            return Err(anyhow!("bad switch_relays response"));
        }
        let body: serde_json::Value = serde_json::from_str(&msg.as_json())
            .map_err(|e| anyhow!("bad switch_relays envelope: {e}"))?;
        let result = body.get("result");
        match result {
            None | Some(serde_json::Value::Null) => Ok(vec![]),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| anyhow!("bad switch_relays entry: {v}"))
                })
                .collect(),
            Some(other) => Err(anyhow!("unexpected switch_relays result: {other}")),
        }
    }

    /// Add relays to the transport pool (best effort; duplicates ignored).
    /// Recorded subscriptions replay on each new handshake automatically.
    pub(crate) async fn add_relays(&self, relays: &[String]) {
        for relay in relays {
            match self.client.add_relay(relay).await {
                Ok(_) => tracing::info!("bunker transport: added relay {relay}"),
                Err(e) => tracing::debug!("bunker transport: relay {relay} not added ({e})"),
            }
        }
        self.client.connect().await;
    }

    /// Run the NIP-46 connect handshake once (only meaningful when the
    /// URL carries a `secret` app token).
    async fn ensure_handshake(&self) -> Result<()> {
        let Some(secret) = self.app_secret.clone() else {
            return Ok(());
        };
        self.handshook
            .get_or_try_init(|| async {
                let req = NostrConnectRequest::Connect {
                    remote_signer_public_key: self.bunker_pubkey,
                    secret: Some(secret),
                };
                let (method, msg) = self.rpc(req).await?;
                match response_to_result(msg, method)? {
                    ResponseResult::Ack => Ok(()),
                    other => Err(anyhow!("unexpected bunker connect response: {other:?}")),
                }
            })
            .await
            .map(|_| ())
    }

    /// Authoritative user pubkey, fetched once via RPC and cached.
    pub(crate) async fn user_public_key(&self) -> Result<PublicKey> {
        if let Some(pk) = self.user_pubkey.get() {
            return Ok(*pk);
        }
        self.ensure_handshake().await?;
        let (method, msg) = self.rpc(NostrConnectRequest::GetPublicKey).await?;
        let pk = match response_to_result(msg, method)? {
            ResponseResult::GetPublicKey(pk) => pk,
            other => return Err(anyhow!("unexpected bunker get_public_key response: {other:?}")),
        };
        let _ = self.user_pubkey.set(pk);
        Ok(pk)
    }
}

/// Unwrap a correlated bunker response into a [`ResponseResult`].
///
/// Surfaces the signer's `error` field *before* parsing `result`, because
/// `to_response()` parses `result` eagerly and error responses commonly
/// carry `result: ""` (Amber does), which fails hex/JSON parsing and would
/// otherwise mask the real message ("no permission", "user rejected", …).
/// Auth challenges are exempt: they legitimately pair `result: "auth_url"`
/// with a URL in `error`, and [`ok_result`] special-cases them.
pub(crate) fn response_to_result(
    msg: NostrConnectMessage,
    method: NostrConnectMethod,
) -> Result<ResponseResult> {
    let what = method.to_string();
    if let NostrConnectMessage::Response { result, error, .. } = &msg {
        let is_auth_url = result.as_deref() == Some("auth_url");
        if !is_auth_url {
            if let Some(err) = error {
                if !err.is_empty() {
                    return Err(anyhow!("bunker {what} failed: {err}"));
                }
            }
        }
    }
    let res = msg
        .to_response(method)
        .map_err(|e| anyhow!("bad bunker response for {what}: {e}"))?;
    ok_result(res, &what)
}

/// Unwrap a correlated bunker response: surface approval requests and
/// bunker-side errors before the caller matches on the result payload.
pub(crate) fn ok_result(res: NostrConnectResponse, what: &str) -> Result<ResponseResult> {
    if res.is_auth_url() {
        return Err(anyhow!(
            "bunker requests approval in your signer app ({what})"
        ));
    }
    if let Some(err) = res.error {
        return Err(anyhow!("bunker {what} failed: {err}"));
    }
    res.result
        .ok_or_else(|| anyhow!("bunker {what} returned an empty response"))
}

/// Map any displayable error into a [`SignerError`].
fn se(e: impl std::fmt::Display) -> SignerError {
    SignerError::from(e.to_string())
}

#[allow(mismatched_lifetime_syntaxes)]
impl NostrSigner for BunkerSigner {
    fn backend(&self) -> SignerBackend {
        SignerBackend::NostrConnect
    }

    fn get_public_key(&self) -> BoxedFuture<Result<PublicKey, SignerError>> {
        Box::pin(async move { self.user_public_key().await.map_err(se) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> BoxedFuture<Result<Event, SignerError>> {
        Box::pin(async move {
            self.ensure_handshake().await.map_err(se)?;
            let (method, msg) = self
                .rpc(NostrConnectRequest::SignEvent(unsigned))
                .await
                .map_err(se)?;
            match response_to_result(msg, method).map_err(se)? {
                ResponseResult::SignEvent(event) => Ok(*event),
                other => Err(se(format!("unexpected bunker sign_event response: {other:?}"))),
            }
        })
    }

    // NIP-04 is deprecated/unauthenticated. NIP-46 defines nip04_* methods,
    // but the publisher only ever signs events, so we never forward NIP-04
    // to the signer: these fail fast instead. (NIP-46 transport itself is
    // NIP-44 v2 — see encrypt_to/decrypt_from.)
    fn nip04_encrypt<'a>(
        &'a self,
        _public_key: &'a PublicKey,
        _content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move { Err(se("NIP-04 is deprecated and not supported")) })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        _public_key: &'a PublicKey,
        _encrypted_content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move { Err(se("NIP-04 is deprecated and not supported")) })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            self.ensure_handshake().await.map_err(se)?;
            let (method, msg) = self
                .rpc(NostrConnectRequest::Nip44Encrypt {
                    public_key: *public_key,
                    text: content.to_string(),
                })
                .await
                .map_err(se)?;
            let res = response_to_result(msg, method).map_err(se)?;
            match res {
                ResponseResult::Nip44Encrypt { ciphertext } => Ok(ciphertext),
                other => Err(se(format!("unexpected bunker nip44_encrypt response: {other:?}"))),
            }
        })
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            self.ensure_handshake().await.map_err(se)?;
            let (method, msg) = self
                .rpc(NostrConnectRequest::Nip44Decrypt {
                    public_key: *public_key,
                    ciphertext: payload.to_string(),
                })
                .await
                .map_err(se)?;
            let res = response_to_result(msg, method).map_err(se)?;
            match res {
                ResponseResult::Nip44Decrypt { plaintext } => Ok(plaintext),
                other => Err(se(format!("unexpected bunker nip44_decrypt response: {other:?}"))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bunker_url(secret: Option<&str>) -> (Keys, String) {
        let bunker_keys = Keys::generate();
        let mut url = format!(
            "bunker://{}?relay=wss://relay.example.com",
            bunker_keys.public_key().to_hex()
        );
        if let Some(s) = secret {
            url.push_str(&format!("&secret={s}"));
        }
        (bunker_keys, url)
    }

    #[test]
    fn parses_bunker_url() {
        let (bunker_keys, url) = bunker_url(Some("tok123"));
        let signer = BunkerSigner::new(&url).expect("valid bunker url");
        assert_eq!(signer.bunker_pubkey, bunker_keys.public_key());
        assert_eq!(signer.relays, vec!["wss://relay.example.com".to_string()]);
        assert_eq!(signer.app_secret.as_deref(), Some("tok123"));
        // App identity is ephemeral and distinct from the bunker key.
        assert_ne!(signer.app_keys.public_key(), bunker_keys.public_key());
    }

    #[test]
    fn rejects_non_bunker_url() {
        assert!(BunkerSigner::new("wss://relay.example.com").is_err());
        assert!(BunkerSigner::new("nostrconnect://deadbeef?relay=wss://r").is_err());
    }

    #[test]
    fn rejects_bunker_url_without_relays() {
        let bunker_keys = Keys::generate();
        let url = format!("bunker://{}", bunker_keys.public_key().to_hex());
        assert!(BunkerSigner::new(&url).is_err());
    }

    /// App side encrypts a SignEvent request; bunker side decrypts and
    /// parses it. Offline — two local keys, no network.
    #[test]
    fn request_envelope_round_trip() {
        let app = Keys::generate();
        let bunk = Keys::generate();
        let author = Keys::generate().public_key();
        let unsigned = EventBuilder::new(Kind::Custom(24242), "Upload")
            .tags(vec![Tag::custom(
                TagKind::Custom("t".into()),
                vec!["upload"],
            )])
            .build(author);

        let req = NostrConnectRequest::SignEvent(unsigned);
        let msg = NostrConnectMessage::request(&req);
        let ct = nip44::encrypt(
            app.secret_key(),
            &bunk.public_key(),
            msg.as_json(),
            Version::V2,
        )
        .unwrap();

        // Bunker side: decrypt + parse.
        let pt = nip44::decrypt(bunk.secret_key(), &app.public_key(), &ct).unwrap();
        let back = NostrConnectMessage::from_json(&pt).unwrap();
        assert!(back.is_request());
        assert_eq!(back.id(), msg.id());
        let req2 = back.to_request().unwrap();
        assert_eq!(req2.method(), NostrConnectMethod::SignEvent);
    }

    /// Bunker side encrypts a connect-ack response; app side decrypts,
    /// parses, and unwraps it via the same ok_result path rpc() uses.
    #[test]
    fn response_envelope_round_trip() {
        let app = Keys::generate();
        let bunk = Keys::generate();

        let res = NostrConnectResponse::with_result(ResponseResult::Ack);
        let msg = NostrConnectMessage::response("42", res);
        let ct = nip44::encrypt(
            bunk.secret_key(),
            &app.public_key(),
            msg.as_json(),
            Version::V2,
        )
        .unwrap();

        // App side: decrypt + parse + unwrap.
        let pt = nip44::decrypt(app.secret_key(), &bunk.public_key(), &ct).unwrap();
        let back = NostrConnectMessage::from_json(&pt).unwrap();
        assert!(back.is_response());
        assert_eq!(back.id(), "42");
        let res = back.to_response(NostrConnectMethod::Connect).unwrap();
        match ok_result(res, "connect").unwrap() {
            ResponseResult::Ack => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Error responses surface (not silently unwrapped).
    #[test]
    fn error_response_surfaces() {
        let res = NostrConnectResponse::with_error("denied");
        let err = ok_result(res, "sign_event").unwrap_err();
        assert!(err.to_string().contains("denied"), "unexpected: {err}");
    }

    /// Regression: Amber's error convention is `{result: "", error: "…"}`.
    /// `to_response()` parses the empty result as a pubkey and fails with
    /// "Invalid string length", hiding the reason. `response_to_result`
    /// must surface the signer's message instead.
    #[test]
    fn error_response_surfaces_before_result_parse() {
        let msg = NostrConnectMessage::Response {
            id: "1".into(),
            result: Some(String::new()),
            error: Some("no permission".into()),
        };
        let err = response_to_result(msg, NostrConnectMethod::GetPublicKey)
            .expect_err("must surface the signer error");
        assert!(err.to_string().contains("no permission"), "unexpected: {err}");
        assert!(
            !err.to_string().contains("Invalid string length"),
            "masked error leaked: {err}"
        );
    }

    /// Auth challenges use `result: "auth_url"` with the URL in `error`;
    /// they must keep the dedicated "approve in your app" message.
    #[test]
    fn auth_url_is_not_misreported_as_error() {
        let msg = NostrConnectMessage::Response {
            id: "1".into(),
            result: Some("auth_url".into()),
            error: Some("https://example.com/auth".into()),
        };
        let err = response_to_result(msg, NostrConnectMethod::GetPublicKey)
            .expect_err("auth url is still an error condition");
        assert!(err.to_string().contains("approval"), "unexpected: {err}");
        assert!(!err.to_string().contains("auth_url failed"), "unexpected: {err}");
    }

    #[test]
    fn successful_get_public_key_response_parses() {
        let pk = Keys::generate().public_key();
        let msg = NostrConnectMessage::Response {
            id: "1".into(),
            result: Some(pk.to_hex()),
            error: None,
        };
        match response_to_result(msg, NostrConnectMethod::GetPublicKey).unwrap() {
            ResponseResult::GetPublicKey(got) => assert_eq!(got, pk),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// NIP-04 is deliberately not forwarded to the signer (deprecated).
    #[tokio::test]
    async fn nip04_is_not_forwarded() {
        use nostr::signer::NostrSigner;
        let (_, url) = bunker_url(Some("tok"));
        let signer = BunkerSigner::new(&url).unwrap();
        let pk = Keys::generate().public_key();
        assert!(signer.nip04_encrypt(&pk, "hi").await.is_err());
        assert!(signer.nip04_decrypt(&pk, "ct").await.is_err());
    }
}
