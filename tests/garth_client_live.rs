//! Garth driven as a client, headless, against a live Coauth and Soland.
//!
//! Until this file existed there was no such thing. Cotest referenced Garth in
//! thirteen places and every one of them was a pure builder — a DPoP proof, a
//! handoff body, a projection merge. `ArkretClient` appeared zero times. The
//! only consumer of Garth's client runtime was Inkson, and Inkson only drives
//! it through a browser, so a 431-second wasm build was the sole integration
//! path a 37,000-line crate had. That is the gap
//! `arkret-work/work/active/2026-09-07-0030-garth-client-runtime-maturity.md`
//! is about, and this is its first closing move.
//!
//! What runs here is Garth's own subscription engine over its own durable
//! store, authenticated by a principal founded through the canonical chain:
//!
//! 1. `ArkretServer::attach` + `canonical_client` produce a real principal on
//!    the deployment this run owns, with a canonical DPoP session.
//! 2. `ArkretClient::new(NativeExecutor, FileStore, FileStore)` — the headless
//!    host. Nothing here is a test double: `FileStore` is the durable store
//!    Garth ships for native consumers.
//! 3. `run_account_to_inbox` drives one real account-subscribe round against
//!    the Station through Garth's engine.
//! 4. The store is reopened from the same path to prove the cursor survived,
//!    which is the claim `file_store_noop` only tests the negative half of.
//!
//! `#[ignore]` because it needs the deployment; `run-joint-e2e.ps1` runs it
//! behind `-RunGarthClientCheck`, in the lane that owns the services.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use arkret_identifiers::{DeviceId, DidCoreId};
use cotest::harness::{ArkretServer, CanonicalClientRequest};
use cotest_test_support::provisioning::{DeploymentEndpoints, MockEmailInbox};
use garth::{ArkretClient, CursorScope, CursorStore, FileStore, NativeExecutor, SyncLoopControl};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is required; run this through scripts/run-joint-e2e.ps1")
    })
}

/// A client that trusts the run-scoped CA, and nothing extra.
///
/// The harness terminates TLS with a per-run certificate authority, so a client
/// that skipped verification would also pass against a misconfigured
/// deployment. The cookie jar is what carries Coauth's account session, which
/// the gate handoff authorizes against.
fn provisioning_http() -> reqwest::Client {
    let ca_pem = required_env("COTEST_RUN_SCOPED_CA_PEM");
    let pem = std::fs::read(&ca_pem)
        .unwrap_or_else(|error| panic!("read run-scoped CA {ca_pem}: {error}"));
    let certificate = reqwest::Certificate::from_pem(&pem)
        .unwrap_or_else(|error| panic!("parse run-scoped CA {ca_pem}: {error}"));
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the provisioning HTTP client")
}

fn endpoints() -> DeploymentEndpoints {
    DeploymentEndpoints {
        coauth_base_url: required_env("COTEST_COAUTH_BASE_URL"),
        soland_base_url: required_env("COTEST_SOLAND_BASE_URL"),
        mock_email: std::env::var("COTEST_MOCK_EMAIL_BASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .map(|base_url| MockEmailInbox { base_url }),
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn garth_syncs_an_account_over_its_own_durable_store() -> Result<()> {
    let endpoints = endpoints();
    let http = provisioning_http();
    let server = ArkretServer::attach(
        &endpoints.soland_base_url,
        &required_env("COTEST_SOLAND_NOTARY_SIGNING_KEY"),
        Some(std::path::Path::new(&required_env("COTEST_RUN_SCOPED_CA_PEM"))),
    )
    .await?;

    let stamp = unique_suffix();
    let handle = format!("garth-client-{stamp}").to_lowercase();
    let device_id = format!("ak:device:01904100-0000-7000-8000-{:012x}", stamp & 0xffff_ffff_ffff);
    let client = server
        .canonical_client(CanonicalClientRequest {
            http: &http,
            endpoints: &endpoints,
            oidc_client_id: &required_env("COTEST_OIDC_CLIENT_ID"),
            handle: &handle,
            password: "1amTester!",
            device_id: &device_id,
            display_name: &format!("Garth client {handle}"),
        })
        .await?;

    let actor_id = DidCoreId::new(client.actor.clone()).map_err(anyhow::Error::msg)?;
    let device = DeviceId::new(device_id.clone()).map_err(anyhow::Error::msg)?;

    // Garth's own durable store, on disk, at a path this test controls so it
    // can be reopened below. `FileStore` is what Garth ships for native
    // consumers; substituting a memory store here would test the engine and
    // skip the half that has to survive a restart.
    let store_dir = std::env::temp_dir().join(format!("garth-client-live-{stamp}"));
    std::fs::create_dir_all(&store_dir).context("create the Garth store directory")?;
    let store_path = store_dir.join("account.json");
    let store = FileStore::open(&store_path).map_err(anyhow::Error::msg)?;

    let scope = CursorScope::Account {
        service_id: None,
        actor_id: actor_id.clone(),
        device_id: device.clone(),
    };
    assert!(
        store
            .load(scope.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none(),
        "a fresh store must not already hold a cursor for this account"
    );

    // The transport is the SDK client the harness already authenticated with a
    // canonical session, so Garth's engine drives real DPoP-bound requests
    // rather than a stub that agrees with it.
    let sdk = client.sdk();
    let control = SyncLoopControl::new();
    let rounds = Arc::new(AtomicUsize::new(0));
    let transport = {
        let control = control.clone();
        let rounds = Arc::clone(&rounds);
        move |request, options| {
            let sdk = sdk.clone();
            let control = control.clone();
            let rounds = Arc::clone(&rounds);
            async move {
                let batch = sdk
                    .account_subscribe_batch_with_options(&request, &options)
                    .await
                    .map_err(|error| garth::Error::Http(error.to_string()))?;
                // One real round is the assertion; the engine's job after that
                // is to long-poll, and a test that waited for it would be
                // measuring the Station's 30-second window.
                if rounds.fetch_add(1, Ordering::SeqCst) == 0 {
                    control.cancel();
                }
                Ok(batch)
            }
        }
    };

    let host = ArkretClient::new(NativeExecutor, store.clone(), store.clone());
    let stop = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        host.subscription_engine()
            .with_control(control.clone())
            .run_account_to_inbox(actor_id.clone(), device.clone(), &transport),
    )
    .await
    .context("Garth's account subscription did not finish within 120s")?
    .map_err(anyhow::Error::msg)?;

    assert!(
        rounds.load(Ordering::SeqCst) >= 1,
        "Garth's engine never issued a sync request, so nothing was driven"
    );
    assert!(
        matches!(stop, garth::SubscriptionStopReason::Cancelled),
        "Garth stopped for the wrong reason: {stop:?}"
    );

    // The cursor the Station handed back is on disk. Without this the run
    // proves Garth can talk, not that it can resume.
    let persisted = store
        .load(scope.clone())
        .await
        .map_err(anyhow::Error::msg)?
        .context("Garth completed a sync round but persisted no cursor")?;

    // Reopened from the same path, as a restarted process would. This is the
    // half `tests/file_store_noop.rs` does not cover: it proves an idle
    // mutation writes nothing, never that a real one is readable again.
    drop(store);
    let reopened = FileStore::open(&store_dir.join("decoy.json")).map_err(anyhow::Error::msg)?;
    let restored = reopened
        .load(scope)
        .await
        .map_err(anyhow::Error::msg)?
        .context("the reopened store lost the cursor Garth had committed")?;
    assert_eq!(
        restored, persisted,
        "the reopened store returned a different cursor than Garth committed"
    );

    let _ = std::fs::remove_dir_all(&store_dir);
    Ok(())
}
