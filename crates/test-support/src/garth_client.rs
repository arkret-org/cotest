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
use std::time::Duration;

use anyhow::{Context, Result};
use arkret_http_client::{Auth, Client as SdkClient, DpopAuth};
use arkret_identifiers::DeviceId;
use arkret_wire::{AccountId, ActorId};
use ed25519_dalek::SigningKey;
use garth::{
    AccountRunner, ClientEvent, ClientProjector, CursorScope, CursorStore, FileStore,
    NativeExecutor, RunOptions, SyncLoopControl, TransportProvider,
};

/// A Garth client bound to one founded principal.
///
/// The store path is stable for the life of this handle, which is what lets a
/// caller ask for a restart: the same path reopened is a new process's view of
/// the same durable state.
pub struct GarthClientHandle {
    sdk: SdkClient,
    actor_id: ActorId,
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
        account_id: AccountId,
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
            actor_id: ActorId::account(account_id),
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
        let provider = BoundedProvider {
            sdk: self.sdk.clone(),
            control: control.clone(),
            rounds: Arc::new(AtomicUsize::new(0)),
        };
        let projector = CountingProjector::default();

        let stop = AccountRunner::new(NativeExecutor, store.clone())
            .with_control(control)
            .run(
                &provider,
                &projector,
                self.scope(),
                RunOptions {
                    beat: Duration::from_millis(1),
                    ..RunOptions::default()
                },
            )
            .await;
        let rounds = provider.rounds.load(Ordering::SeqCst);
        let stop = match stop {
            Ok(stop) => stop,
            // The engine classifies an unreachable Station as retryable and
            // would otherwise back off past the caller's timeout, which reads
            // as a hang rather than as the connection failure it is.
            Err(error) => anyhow::bail!("Garth's transport could not reach the Station: {}", error),
        };

        let cursor = store
            .load(self.scope())
            .await
            .map_err(anyhow::Error::msg)?
            .map(|cursor| cursor.to_string());
        Ok(SyncOutcome {
            rounds,
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

/// Hands the engine the harness's own CA-trusting Station client, and closes
/// the loop after the first attempt whatever its outcome.
struct BoundedProvider {
    sdk: SdkClient,
    control: SyncLoopControl,
    rounds: Arc<AtomicUsize>,
}

impl TransportProvider for BoundedProvider {
    type Transport = SdkClient;

    async fn provide(&self) -> garth::Result<SdkClient> {
        self.rounds.fetch_add(1, Ordering::SeqCst);
        self.control.cancel();
        Ok(self.sdk.clone())
    }
}

/// Counts what the engine decoded, so a round that returned nothing is
/// distinguishable from one that never ran.
#[derive(Debug, Default)]
struct CountingProjector {
    projected: AtomicUsize,
}

impl ClientProjector for CountingProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        self.projected.fetch_add(batch.len(), Ordering::SeqCst);
        Ok(())
    }
}
