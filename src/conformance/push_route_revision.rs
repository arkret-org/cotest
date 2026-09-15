//! Production SDK runner for the device push-route revision-CAS fixture.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use arkret_lattice_registry::{
    ActorPrivateCandidate, ActorPrivateMergeOutcome, build_actor_private_registry,
};
use arkret_models_identity::device_push_route::DevicePushRoutePayload;
use serde::Deserialize;
use serde_json::{Value, json};

use super::load_artifact_json;

const FAMILY: &str = "ak.private.device.push_route.v1";

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
    registration_handoff_lifecycle_cases: Vec<Value>,
    device_push_route_revision_cases: Vec<Value>,
}

/// The closed registration-handoff lifecycle set.
///
/// Every entry describes a behaviour that only a real Station/gateway pair can
/// exhibit -- a durable commit whose response was lost, a delayed install
/// racing a tombstone, two tenants that must not share an index. None of that
/// is decidable from artifacts, so this runner deliberately does **not** claim
/// to verify it. What it does claim is narrower and still worth having: the set
/// is closed, so a seventh case cannot arrive without someone deciding where it
/// executes, and each case's declared outcome is checked against the generated
/// constant it names rather than against a second spelling of it.
const REGISTRATION_HANDOFF_LIFECYCLE_CASES: [&str; 6] = [
    "exact_replay_after_lost_response",
    "revoke_wins_over_delayed_install",
    "same_registration_id_different_body_conflicts",
    "source_destination_and_device_are_exact",
    "successor_tombstones_predecessor_atomically",
    "tenant_isolation",
];

fn verify_registration_handoff_lifecycle_closure(fixture: &PushNotifyOutcomeFixture) -> Result<()> {
    let published = fixture
        .registration_handoff_lifecycle_cases
        .iter()
        .map(|case| {
            case.get("name")
                .and_then(Value::as_str)
                .context("registration handoff case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if published != BTreeSet::from(REGISTRATION_HANDOFF_LIFECYCLE_CASES) {
        bail!("registration handoff lifecycle is not the closed six-case set: {published:?}");
    }
    for case in &fixture.registration_handoff_lifecycle_cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .context("registration handoff case name")?;
        // A case describes either an ordered lifecycle or a set of rejection
        // variants. One of the two has to be there, or the row names an
        // outcome without naming what produces it.
        let steps = case.get("steps").and_then(Value::as_array);
        let variants = case.get("variants").and_then(Value::as_array);
        let described = steps.is_some_and(|rows| !rows.is_empty())
            || variants.is_some_and(|rows| !rows.is_empty());
        if !described {
            bail!("registration handoff case {name} declares no steps and no variants");
        }
        let expected = case
            .get("expected")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("registration handoff case {name} declares no outcome"))?;
        // The one outcome that names a wire code takes it from the generated
        // constant, so a rename in the registry cannot leave this fixture
        // asserting a code that no longer exists.
        if name == "same_registration_id_different_body_conflicts"
            && !expected.contains(arkret_wire::ErrorCode::DUPLICATE_CONFLICT)
        {
            bail!("registration handoff replay conflict no longer names the registered code");
        }
    }
    Ok(())
}

fn candidate(value: Value, expected_revision: u64) -> ActorPrivateCandidate {
    ActorPrivateCandidate {
        value,
        revision: Some(expected_revision + 1),
        expected_revision: Some(expected_revision),
        causal_order: None,
        hlc: None,
        device_id: None,
    }
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
    verify_registration_handoff_lifecycle_closure(&fixture)?;
    let registry = build_actor_private_registry()?;
    let cases = &fixture.device_push_route_revision_cases;

    let lifecycle = cases
        .iter()
        .find(|case| case["name"] == "create_rotate_revoke")
        .context("push fixture omits create_rotate_revoke")?;
    let mut current = None;
    let mut accepted = 0_u64;
    for write in lifecycle["writes"]
        .as_array()
        .context("writes is not an array")?
    {
        let expected = write["expected_revision"]
            .as_u64()
            .context("write omits expected_revision")?;
        let incoming = candidate(write.clone(), expected);
        match registry.apply(FAMILY, current.as_ref(), incoming)? {
            ActorPrivateMergeOutcome::Accepted(next) => {
                current = Some(next);
                accepted += 1;
            }
            other => bail!("conformant push-route lifecycle write was rejected: {other:?}"),
        }
    }
    let final_value = current.context("push-route lifecycle produced no state")?;
    if accepted
        != lifecycle["expected"]["accepted_writes"]
            .as_u64()
            .unwrap_or_default()
        || final_value.revision != lifecycle["expected"]["final_revision"].as_u64()
        || final_value.value["shape"] != lifecycle["expected"]["final_state"]
    {
        bail!("push-route create/rotate/revoke revision fixture drifted");
    }

    let conflict = cases
        .iter()
        .find(|case| case["name"] == "stale_sibling_and_replay_fail_closed")
        .context("push fixture omits stale_sibling_and_replay_fail_closed")?;
    let initial_revision = conflict["initial_revision"].as_u64().unwrap_or_default();
    let mut current = Some(candidate(json!({"name": "initial"}), initial_revision - 1));
    for write in conflict["writes"]
        .as_array()
        .context("writes is not an array")?
    {
        let expected_revision = write["expected_revision"]
            .as_u64()
            .context("conflict write omits expected_revision")?;
        let outcome = registry.apply(
            FAMILY,
            current.as_ref(),
            candidate(write.clone(), expected_revision),
        )?;
        match (write["expected"].as_str(), outcome) {
            (Some("accepted"), ActorPrivateMergeOutcome::Accepted(next)) => current = Some(next),
            (Some("cas_conflict"), ActorPrivateMergeOutcome::Conflict) => {}
            (expected, observed) => {
                bail!("push-route conflict case expected {expected:?}, got {observed:?}");
            }
        }
    }
    if current.as_ref().and_then(|value| value.revision)
        != conflict["expected"]["final_revision"].as_u64()
        || conflict["expected"]["rejected_write_side_effects"].as_u64() != Some(0)
    {
        bail!("push-route sibling/replay conflict fixture drifted");
    }

    let gc = cases
        .iter()
        .find(|case| case["name"] == "privacy_gc_keeps_revision_high_water")
        .context("push fixture omits privacy_gc_keeps_revision_high_water")?;
    let revision = gc["initial"]["revision"].as_u64().unwrap_or_default();
    let current = candidate(json!({"shape": "revoked"}), revision - 1);
    let stale_expected = gc["stale_write_expected_revision"]
        .as_u64()
        .unwrap_or_default();
    if !matches!(
        registry.apply(
            FAMILY,
            Some(&current),
            candidate(json!({"shape": "active"}), stale_expected),
        )?,
        ActorPrivateMergeOutcome::Conflict
    ) || current.revision != gc["expected"]["final_revision"].as_u64()
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
