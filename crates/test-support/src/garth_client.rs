//! Garth driven as a client, in-process, so a TypeScript suite can select it.
//!
//! This is the half that makes a `GarthClient` honest. `provisioning` founds a
//! principal using Garth's *builders*; that is not the client runtime. What
//! runs here is `ArkretClient` over `NativeExecutor` and the durable
//! `FileStore` — Garth's own subscription engine, transport loop and cursor
//! store — so a test that selects `--client-kind=garth` is exercising Garth
//! rather than the harness agreeing with itself.
//!
//! It lives on the light build edge with the rest of test-support, so the
//! browserless lane can drive it without building Inkson.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use arkret_http_client::{Auth, Client as SdkClient, DpopAuth};
use arkret_identifiers::{DeviceId, DidCoreId};
use ed25519_dalek::SigningKey;
use garth::{ArkretClient, CursorScope, CursorStore, FileStore, NativeExecutor, SyncLoopControl};

/// A Garth client bound to one founded principal.
///
/// The store path is stable for the life of this handle, which is what lets a
/// caller ask for a restart: the same path reopened is a new process's view of
/// the same durable state.
pub struct GarthClientHandle {
    sdk: SdkClient,
    actor_id: DidCoreId,
    device_id: DeviceId,
    store_path: PathBuf,
}

/// What one account-sync round did.
#[derive(Debug)]
pub struct SyncOutcome {
    /// Sync requests Garth's engine actually issued.
    pub rounds: usize,
    /// The cursor Garth committed to its durable store, if any.
    pub cursor: Option<String>,
    /// Why the loop stopped. `cancelled` is the expected answer for a bounded
    /// round; anything else means the Station or the session ended it.
    pub stop_reason: String,
}

impl GarthClientHandle {
    /// Build a client for a principal the canonical chain already founded.
    ///
    /// The session is DPoP-bound: the grant plus a proof over each request's
    /// own method and URL, signed by the device key the grant was issued to.
    /// Both halves are required, and minting the proof per request is Garth's
    /// transport doing it, not a pre-baked header.
    /// `http` must already trust the run-scoped CA.
    ///
    /// Building a fresh client here instead was the first thing that broke: the
    /// harness terminates TLS with a per-run authority, so a default client
    /// cannot reach the Station at all — and the failure did not look like one.
    /// Garth's loop treats a transport error as retryable, so it backed off and
    /// retried until the bridge's call timeout, which reads as a hang rather
    /// than as "this client cannot connect".
    pub fn new(
        http: reqwest::Client,
        station_base_url: &str,
        session_grant: String,
        signing_key: SigningKey,
        actor_id: &str,
        device_id: &str,
        store_root: &Path,
    ) -> Result<Self> {
        let signing_key = Arc::new(signing_key);
        let auth = Auth::Dpop(DpopAuth::with_dpop_token(session_grant, move |request| {
            garth::session::dpop::build_http_dpop_proof(request, &signing_key).map_err(|error| {
                arkret_http_client::Error::Protocol(format!("build DPoP proof: {error}"))
            })
        }));
        let sdk = SdkClient::builder(
            url::Url::parse(station_base_url).context("parse the Station base URL")?,
        )
        .auth(auth)
        .http_client(http)
        .build()
        .context("build the Garth client's Station transport")?;

        std::fs::create_dir_all(store_root).context("create the Garth store directory")?;
        Ok(Self {
            sdk,
            actor_id: DidCoreId::new(actor_id.to_owned()).map_err(anyhow::Error::msg)?,
            device_id: DeviceId::new(device_id.to_owned()).map_err(anyhow::Error::msg)?,
            store_path: store_root.join("account.json"),
        })
    }

    fn scope(&self) -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: self.actor_id.clone(),
            device_id: self.device_id.clone(),
        }
    }

    /// Run one bounded account-subscribe round through Garth's engine.
    ///
    /// Bounded because the engine's job after the first response is to
    /// long-poll; a caller that waited for the second round would be measuring
    /// the Station's wait window rather than Garth.
    pub async fn sync_account_once(&self) -> Result<SyncOutcome> {
        let store = FileStore::open(&self.store_path).map_err(anyhow::Error::msg)?;
        let control = SyncLoopControl::new();
        let rounds = Arc::new(AtomicUsize::new(0));
        let failure: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let transport = {
            let sdk = self.sdk.clone();
            let control = control.clone();
            let rounds = Arc::clone(&rounds);
            let failure = Arc::clone(&failure);
            move |request, options| {
                let sdk = sdk.clone();
                let control = control.clone();
                let rounds = Arc::clone(&rounds);
                let failure = Arc::clone(&failure);
                async move {
                    // Counted before the call, and the loop is cancelled after
                    // the first attempt whatever its outcome. Cancelling only
                    // on success is what turned an unreachable Station into a
                    // retry loop that outlived the caller's timeout: a client
                    // that cannot connect must report that, not hang.
                    let first = rounds.fetch_add(1, Ordering::SeqCst) == 0;
                    let outcome = sdk
                        .account_subscribe_batch_with_options(&request, &options)
                        .await
                        .map_err(|error| garth::Error::Http(error.to_string()));
                    if first {
                        control.cancel();
                    }
                    if let Err(error) = &outcome {
                        *failure.lock().expect("transport failure lock") = Some(error.to_string());
                    }
                    outcome
                }
            }
        };

        let host = ArkretClient::new(NativeExecutor, store.clone(), store.clone());
        let stop = host
            .subscription_engine()
            .with_control(control)
            .run_account_to_inbox(self.actor_id.clone(), self.device_id.clone(), &transport)
            .await
            .map_err(anyhow::Error::msg)?;

        if let Some(error) = failure.lock().expect("transport failure lock").take() {
            anyhow::bail!("Garth's transport could not reach the Station: {error}");
        }

        let cursor = store
            .load(self.scope())
            .await
            .map_err(anyhow::Error::msg)?
            .map(|cursor| cursor.to_string());
        Ok(SyncOutcome {
            rounds: rounds.load(Ordering::SeqCst),
            cursor,
            stop_reason: format!("{stop:?}").to_lowercase(),
        })
    }

    /// The cursor a freshly reopened store reports.
    ///
    /// Reopening from the same path is what a restarted process sees, so this
    /// is the question "did the state actually survive" rather than "is it
    /// still in memory".
    pub async fn cursor_after_restart(&self) -> Result<Option<String>> {
        let reopened = FileStore::open(&self.store_path).map_err(anyhow::Error::msg)?;
        Ok(reopened
            .load(self.scope())
            .await
            .map_err(anyhow::Error::msg)?
            .map(|cursor| cursor.to_string()))
    }
}
