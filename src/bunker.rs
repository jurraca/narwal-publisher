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
use std::time::Duration;
use tokio::sync::{oneshot, Mutex, OnceCell};

/// How long to wait for a bunker response (covers interactive approval).
const RPC_TIMEOUT: Duration = Duration::from_secs(90);

/// A NIP-46 remote signer implementing [`NostrSigner`].
///
/// Transport: one persistent kind-24133 subscription (authors=[bunker],
/// #p=[app]) plus a background notification forwarder that completes
/// pending requests by message id. Exactly one relay subscription per
/// process, no polling.
pub struct BunkerSigner {
    app_keys: Keys,
    bunker_pubkey: PublicKey,
    relays: Vec<String>,
    app_secret: Option<String>,
    client: Client,
    started: OnceCell<()>,
    handshook: OnceCell<()>,
    user_pubkey: OnceCell<PublicKey>,
    pending: Arc<Mutex<HashMap<String, (NostrConnectMethod, oneshot::Sender<(NostrConnectMethod, NostrConnectMessage)>)>>>,
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
        Ok(Self {
            app_keys: Keys::generate(),
            bunker_pubkey,
            relays,
            app_secret: uri.secret().map(|s| s.to_string()),
            client: Client::default(),
            started: OnceCell::new(),
            handshook: OnceCell::new(),
            user_pubkey: OnceCell::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
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

                let filter = Filter::new()
                    .author(self.bunker_pubkey)
                    .kind(Kind::NostrConnect)
                    .pubkey(self.app_keys.public_key())
                    .limit(0);
                self.client
                    .subscribe(filter, None)
                    .await
                    .map_err(|e| anyhow!("bunker response subscribe failed: {e}"))?;

                let client = self.client.clone();
                let app_keys = self.app_keys.clone();
                let bunker_pubkey = self.bunker_pubkey;
                let pending = Arc::clone(&self.pending);
                tokio::spawn(async move {
                    let _ = client
                        .handle_notifications(|notif| {
                            let pending = Arc::clone(&pending);
                            let app_keys = app_keys.clone();
                            async move {
                                if let RelayPoolNotification::Event { event, .. } = notif {
                                    Self::dispatch_response(
                                        &pending,
                                        &app_keys,
                                        &bunker_pubkey,
                                        &event,
                                    )
                                    .await;
                                }
                                Ok(true)
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
        pending: &Mutex<HashMap<String, (NostrConnectMethod, oneshot::Sender<(NostrConnectMethod, NostrConnectMessage)>)>>,
        app_keys: &Keys,
        bunker_pubkey: &PublicKey,
        event: &Event,
    ) {
        let plaintext = match nip44::decrypt(
            app_keys.secret_key(),
            bunker_pubkey,
            &event.content,
        ) {
            Ok(p) => p,
            Err(_) => return,
        };
        let msg: NostrConnectMessage = match NostrConnectMessage::from_json(&plaintext) {
            Ok(m) => m,
            Err(_) => return,
        };
        if !msg.is_response() {
            return;
        }
        let sender = pending.lock().await.remove(msg.id());
        if let Some((method, tx)) = sender {
            let _ = tx.send((method, msg));
        }
    }

    /// One NIP-46 round trip: encrypt, publish kind 24133, await the
    /// correlated response.
    async fn rpc(&self, req: NostrConnectRequest) -> Result<(NostrConnectMethod, NostrConnectMessage)> {
        self.ensure_started().await?;
        let msg = NostrConnectMessage::request(&req);
        let method = req.method();
        let id = msg.id().to_string();
        let payload = msg.as_json();
        let ciphertext = nip44::encrypt(
            self.app_keys.secret_key(),
            &self.bunker_pubkey,
            payload,
            Version::V2,
        )
        .map_err(|e| anyhow!("nip44 encrypt for bunker failed: {e}"))?;
        let event = EventBuilder::new(Kind::NostrConnect, ciphertext)
            .tag(Tag::public_key(self.bunker_pubkey))
            .sign_with_keys(&self.app_keys)
            .map_err(|e| anyhow!("signing bunker request failed: {e}"))?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), (method, tx));
        self.client
            .send_event(&event)
            .await
            .map_err(|e| anyhow!("sending bunker request failed: {e}"))?;

        let (method, msg) = tokio::time::timeout(RPC_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow!("bunker timed out waiting for response (approve the request in your signer app?)"))?
            .map_err(|_| anyhow!("bunker response handler dropped"))?;
        Ok((method, msg))
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
                let res = msg
                    .to_response(method)
                    .map_err(|e| anyhow!("bad bunker connect response: {e}"))?;
                match ok_result(res, "connect")? {
                    ResponseResult::Ack => Ok(()),
                    other => Err(anyhow!("unexpected bunker connect response: {other:?}")),
                }
            })
            .await
            .map(|_| ())
    }

    /// Authoritative user pubkey, fetched once via RPC and cached.
    async fn user_public_key(&self) -> Result<PublicKey> {
        if let Some(pk) = self.user_pubkey.get() {
            return Ok(*pk);
        }
        self.ensure_handshake().await?;
        let (method, msg) = self.rpc(NostrConnectRequest::GetPublicKey).await?;
        let res = msg
            .to_response(method)
            .map_err(|e| anyhow!("bad bunker response: {e}"))?;
        let pk = match ok_result(res, "get_public_key")? {
            ResponseResult::GetPublicKey(pk) => pk,
            other => return Err(anyhow!("unexpected bunker get_public_key response: {other:?}")),
        };
        let _ = self.user_pubkey.set(pk);
        Ok(pk)
    }
}

/// Unwrap a correlated bunker response: surface approval requests and
/// bunker-side errors before the caller matches on the result payload.
fn ok_result(res: NostrConnectResponse, what: &str) -> Result<ResponseResult> {
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
            let res = msg
                .to_response(method)
                .map_err(|e| se(format!("bad bunker response: {e}")))?;
            match ok_result(res, "sign_event").map_err(se)? {
                ResponseResult::SignEvent(event) => Ok(*event),
                other => Err(se(format!("unexpected bunker sign_event response: {other:?}"))),
            }
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            self.ensure_handshake().await.map_err(se)?;
            let (method, msg) = self
                .rpc(NostrConnectRequest::Nip04Encrypt {
                    public_key: *public_key,
                    text: content.to_string(),
                })
                .await
                .map_err(se)?;
            let res = msg
                .to_response(method)
                .map_err(|e| se(format!("bad bunker response: {e}")))?;
            match ok_result(res, "nip04_encrypt").map_err(se)? {
                ResponseResult::Nip04Encrypt { ciphertext } => Ok(ciphertext),
                other => Err(se(format!("unexpected bunker nip04_encrypt response: {other:?}"))),
            }
        })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            self.ensure_handshake().await.map_err(se)?;
            let (method, msg) = self
                .rpc(NostrConnectRequest::Nip04Decrypt {
                    public_key: *public_key,
                    ciphertext: encrypted_content.to_string(),
                })
                .await
                .map_err(se)?;
            let res = msg
                .to_response(method)
                .map_err(|e| se(format!("bad bunker response: {e}")))?;
            match ok_result(res, "nip04_decrypt").map_err(se)? {
                ResponseResult::Nip04Decrypt { plaintext } => Ok(plaintext),
                other => Err(se(format!("unexpected bunker nip04_decrypt response: {other:?}"))),
            }
        })
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
            let res = msg
                .to_response(method)
                .map_err(|e| se(format!("bad bunker response: {e}")))?;
            match ok_result(res, "nip44_encrypt").map_err(se)? {
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
            let res = msg
                .to_response(method)
                .map_err(|e| se(format!("bad bunker response: {e}")))?;
            match ok_result(res, "nip44_decrypt").map_err(se)? {
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
}
