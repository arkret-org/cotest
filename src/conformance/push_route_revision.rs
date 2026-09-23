//! Production SDK runner for the device push-route revision-CAS fixture.

use anyhow::{Context, Result, bail};
use arkret_models_identity::device_push_route::{
    DevicePushRoutePayload, ServerRevisionCasDecision, decide_server_revision_cas,
};
pub use cotest_push_registration_handoff_runner::{
    PUSH_REGISTRATION_HANDOFF_VECTOR_ID, PushRegistrationHandoffExecution,
    run_push_registration_handoff_lifecycle_vector,
    run_push_registration_handoff_lifecycle_with_database_url,
};
use serde::Deserialize;
use serde_json::Value;

use super::load_artifact_json;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushNotifyOutcomeFixture {
    suite: String,
    fixture_kind: String,
    profile: String,
    covers_vectors: Vec<Value>,
    version: String,
    spec_anchor: String,
    source_refs: Vec<Value>,
    description: String,
    runner: Value,
    request_context: Value,
    /// Free-form instances validated by their referenced JSON Schemas.
    schema_validation_cases: Vec<Value>,
    /// Trusted public push-gateway registration handoff lifecycle.
    #[serde(rename = "registration_handoff_lifecycle_cases")]
    _registration_handoff_lifecycle_cases: Vec<Value>,
    device_push_route_revision_cases: Vec<Value>,
}

pub fn run_push_route_revision_suite() -> Result<()> {
    let fixture: PushNotifyOutcomeFixture = serde_json::from_value(load_artifact_json(
        "fixtures/push-notify-outcome-fixture.json",
    )?)?;
    if fixture.suite.trim().is_empty()
        || fixture.fixture_kind.trim().is_empty()
        || fixture.profile.trim().is_empty()
        || fixture.covers_vectors.is_empty()
        || fixture.version.trim().is_empty()
        || fixture.spec_anchor.trim().is_empty()
        || fixture.source_refs.is_empty()
        || fixture.description.trim().is_empty()
        || fixture.runner.is_null()
        || fixture.request_context.is_null()
    {
        bail!("push notification fixture metadata drifted");
    }
    verify_closed_sdk_payloads(&fixture)?;
    let cases = &fixture.device_push_route_revision_cases;

    let lifecycle = cases
        .iter()
        .find(|case| case["name"] == "create_rotate_revoke")
        .context("push fixture omits create_rotate_revoke")?;
    let mut current_revision = None;
    let mut current_value = None;
    let mut accepted = 0_u64;
    for write in lifecycle["writes"]
        .as_array()
        .context("writes is not an array")?
    {
        let expected = write["expected_revision"]
            .as_u64()
            .context("write omits expected_revision")?;
        match decide_server_revision_cas(current_revision, expected) {
            ServerRevisionCasDecision::Accepted { next_revision } => {
                current_revision = Some(next_revision);
                current_value = Some(write);
                accepted += 1;
            }
            other => bail!("conformant push-route lifecycle write was rejected: {other:?}"),
        }
    }
    let final_value = current_value.context("push-route lifecycle produced no state")?;
    if accepted
        != lifecycle["expected"]["accepted_writes"]
            .as_u64()
            .unwrap_or_default()
        || current_revision != lifecycle["expected"]["final_revision"].as_u64()
        || final_value["shape"] != lifecycle["expected"]["final_state"]
    {
        bail!("push-route create/rotate/revoke revision fixture drifted");
    }

    let conflict = cases
        .iter()
        .find(|case| case["name"] == "stale_sibling_and_replay_fail_closed")
        .context("push fixture omits stale_sibling_and_replay_fail_closed")?;
    let initial_revision = conflict["initial_revision"].as_u64().unwrap_or_default();
    let mut current_revision = Some(initial_revision);
    for write in conflict["writes"]
        .as_array()
        .context("writes is not an array")?
    {
        let expected_revision = write["expected_revision"]
            .as_u64()
            .context("conflict write omits expected_revision")?;
        let outcome = decide_server_revision_cas(current_revision, expected_revision);
        match (write["expected"].as_str(), outcome) {
            (Some("accepted"), ServerRevisionCasDecision::Accepted { next_revision }) => {
                current_revision = Some(next_revision)
            }
            (Some("cas_conflict"), ServerRevisionCasDecision::Conflict) => {}
            (expected, observed) => {
                bail!("push-route conflict case expected {expected:?}, got {observed:?}");
            }
        }
    }
    if current_revision != conflict["expected"]["final_revision"].as_u64()
        || conflict["expected"]["rejected_write_side_effects"].as_u64() != Some(0)
    {
        bail!("push-route sibling/replay conflict fixture drifted");
    }

    let gc = cases
        .iter()
        .find(|case| case["name"] == "privacy_gc_keeps_revision_high_water")
        .context("push fixture omits privacy_gc_keeps_revision_high_water")?;
    let revision = gc["initial"]["revision"].as_u64().unwrap_or_default();
    let stale_expected = gc["stale_write_expected_revision"]
        .as_u64()
        .unwrap_or_default();
    if !matches!(
        decide_server_revision_cas(Some(revision), stale_expected),
        ServerRevisionCasDecision::Conflict
    ) || Some(revision) != gc["expected"]["final_revision"].as_u64()
    {
        bail!("push-route privacy GC lost its revision high-water mark");
    }
    Ok(())
}

fn verify_closed_sdk_payloads(fixture: &PushNotifyOutcomeFixture) -> Result<()> {
    for case in fixture.schema_validation_cases.iter().filter(|case| {
        case["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("device_push_route_"))
    }) {
        let accepted =
            serde_json::from_value::<DevicePushRoutePayload>(case["instance"].clone()).is_ok();
        if accepted != case["expect_valid"].as_bool().unwrap_or(false) {
            bail!(
                "SDK device push-route DTO disagrees with schema case {}",
                case["name"]
            );
        }
    }
    Ok(())
}
