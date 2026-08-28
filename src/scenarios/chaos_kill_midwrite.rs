//! CT-16 - Chaos: kill server mid-write, restart, verify recovery.
//!
//! This scenario now exercises the real process boundary:
//!
//! 1. boot soland against a persistent Postgres database;
//! 2. submit one canonical event while soland is paused at the `post_commit_pre_response` chaos
//!    breakpoint;
//! 3. terminate the child process before the HTTP response can flush;
//! 4. restart soland against the same database;
//! 5. compare the durable canonical event row, projection event row, and a retry under the same
//!    operation id.
//!
//! If Postgres is not available locally the scenario returns `Ok(())`. The
//! test entrypoint remains opt-in because it deliberately kills a child
//! process and starts external infrastructure.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::task::JoinSet;

use crate::harness::{
    ArkretServer, dev_login, event_envelope, expect_json, message_create_text_payload,
};
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

const TEST_NAME: &str = "chaos-midwrite";
const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-00000000c0de";
const REALM_ID: &str = "ak:realm:AXhEXYzI8s81aVQ7eAb57jW3tjFK7CwkJZsKbptGq25n";

pub async fn chaos_kill_midwrite_run() -> Result<()> {
    let Some(database) = ChaosDatabase::provision()? else {
        eprintln!(
            "CT-16 skipped: set COTEST_SOLAND_DATABASE_URL or run with Docker available for ephemeral Postgres"
        );
        return Ok(());
    };

    // Probe spawn: the deterministic did:webvh principal derives from the
    // durable service identity, so provision the principal and author the
    // chaos Event here; the chaos-run spawn below then learns the operation id
    // up front. Durable identity survives the probe (the next spawn retains it
    // with a registration-key drift warning), and the probe's canonical
    // bootstrap replays against the durable database on every later spawn.
    let (actor_did, event) = {
        let probe = ArkretServer::spawn_with_database_url(TEST_NAME, &database.url, &[]).await?;
        let actor_did = actor_did_for_service_did(probe.service_did(), "chaos-midwrite")?;
        probe
            .register_client(&actor_did, "@chaos_midwrite", DEVICE_ID)
            .await?;
        let event = chaos_message_event(&actor_did);
        (actor_did, event)
    };
    let submission = crate::publication::initial_submission(event.clone(), "")?;
    let operation_id = operation_id_from_event(&event)?;

    let mut server = ArkretServer::spawn_with_database_url(
        TEST_NAME,
        &database.url,
        &[
            ("SOLAND_ENABLE_CONFORMANCE_ENDPOINTS", "1"),
            ("SOLAND_TEST_CHAOS_BREAKPOINT", "post_commit_pre_response"),
            ("SOLAND_TEST_CHAOS_DELAY_MS", "1500"),
            ("SOLAND_TEST_CHAOS_OPERATION_ID", operation_id.as_str()),
        ],
    )
    .await?;
    let alice = server
        .register_client(&actor_did, "@chaos_midwrite", DEVICE_ID)
        .await?;
    alice
        .create_realm_with(json!({
            "realm_id": REALM_ID,
            "title": "Chaos Midwrite",
            "summary": "Chaos Midwrite",
            "public": true,
            "discoverability": "public",
            "join_rule": "public",
            "history_access": "all_history_for_current_members",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let token = dev_login(&server, &actor_did, DEVICE_ID).await?;

    let mut tasks = JoinSet::new();
    tasks.spawn({
        let client = server.http();
        let url = server.url("/_arkret/self/events");
        let token = token.clone();
        let submission = submission.clone();
        async move {
            client
                .post(url)
                .bearer_auth(token)
                .json(&submission)
                .send()
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    server.kill_immediately().await?;
    assert_midflight_post_was_cut(tasks).await?;

    let server = ArkretServer::spawn_with_database_url(
        TEST_NAME,
        &database.url,
        &[("SOLAND_ENABLE_CONFORMANCE_ENDPOINTS", "1")],
    )
    .await?;
    let token = dev_login(&server, &actor_did, DEVICE_ID).await?;
    let before_retry = server.diagnostic_operation_query(&operation_id).await?;
    assert_no_partial_state(&before_retry)?;

    let retry = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&submission),
        StatusCode::OK,
    )
    .await?;
    let after_retry = server.diagnostic_operation_query(&operation_id).await?;
    assert_retry_matches_durable_state(&before_retry, &after_retry, &retry)?;
    Ok(())
}

struct ChaosDatabase {
    url: String,
    _ephemeral: Option<EphemeralPg>,
}

impl ChaosDatabase {
    fn provision() -> Result<Option<Self>> {
        if let Ok(url) = std::env::var("COTEST_SOLAND_DATABASE_URL")
            && !url.trim().is_empty()
        {
            return Ok(Some(Self {
                url,
                _ephemeral: None,
            }));
        }
        let Some(ephemeral) = spawn_ephemeral_postgres()? else {
            return Ok(None);
        };
        Ok(Some(Self {
            url: ephemeral.connect_url.clone(),
            _ephemeral: Some(ephemeral),
        }))
    }
}

fn chaos_message_event(actor_did: &str) -> arkret_wire::Event {
    event_envelope(
        actor_did,
        REALM_ID,
        "ak.message.create",
        message_create_text_payload(
            "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            "doomed",
        )
        .expect("valid chaos message payload"),
    )
}

fn operation_id_from_event(event: &arkret_wire::Event) -> Result<String> {
    event
        .unsigned
        .get("local_operation_idempotency_alias")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("event missing local_operation_idempotency_alias: {event:?}"))
}

async fn assert_midflight_post_was_cut(
    mut tasks: JoinSet<reqwest::Result<reqwest::Response>>,
) -> Result<()> {
    let result = tasks
        .join_next()
        .await
        .context("mid-flight POST task did not run")?;
    match result {
        Ok(Err(_transport_error)) => Ok(()),
        Ok(Ok(response)) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if status == StatusCode::BAD_GATEWAY && body.trim().is_empty() {
                return Ok(());
            }
            bail!("mid-flight POST unexpectedly flushed an HTTP response: {status} {body}")
        }
        Err(error) => bail!("mid-flight POST task panicked or was cancelled: {error}"),
    }
}

fn assert_no_partial_state(diagnostic: &Value) -> Result<()> {
    let canonical_present = !diagnostic["canonical_event"].is_null();
    let projection_present = !diagnostic["projection_event"].is_null();
    if canonical_present != projection_present {
        bail!("durable state is partial after restart: {diagnostic}");
    }
    if diagnostic["consistent"].as_bool() != Some(true) {
        bail!("diagnostic consistency flag is false after restart: {diagnostic}");
    }
    Ok(())
}

fn assert_retry_matches_durable_state(
    before_retry: &Value,
    after_retry: &Value,
    retry: &Value,
) -> Result<()> {
    assert_no_partial_state(after_retry)?;
    let had_committed = !before_retry["canonical_event"].is_null();
    let has_committed_after_retry = !after_retry["canonical_event"].is_null();
    if !has_committed_after_retry {
        bail!("retry returned OK but diagnostic log still has no committed event: {after_retry}");
    }
    let committed_event_id = after_retry["canonical_event"]["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("diagnostic missing canonical event_id: {after_retry}"))?;
    if crate::harness::submitted_event_id(retry)?.as_str() != committed_event_id {
        bail!("retry event_id drifted from durable event: retry={retry} diagnostic={after_retry}");
    }
    match (had_committed, retry["status"].as_str()) {
        (true, Some("duplicate")) => Ok(()),
        (false, Some("accepted")) => Ok(()),
        (true, other) => {
            bail!("committed pre-restart operation did not replay as duplicate: {other:?} {retry}")
        }
        (false, other) => {
            bail!("uncommitted pre-restart operation did not commit fresh: {other:?} {retry}")
        }
    }
}
