//! Current MLS activation and Circle directory-visibility vectors.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use arkret_models_collaboration::governance::circle::{
    CircleDirectoryVisibility, CircleScopeError, validate_mls_activation_is_irreversible,
    validate_scope_mls_activation,
};
use serde_json::{Value, json};

const FIXTURE: &str = "visibility-policy-fixture.json";
const VECTOR_IDS: &[&str] = &[
    "ak.vector.e2ee.mls_activation_irreversible.v1",
    "ak.vector.e2ee.plaintext_write_after_activation_rejected.v1",
    "ak.vector.e2ee.ciphertext_write_before_activation_rejected.v1",
    "ak.vector.circle.activation_independent_of_realm.v1",
    "ak.vector.circle.directory_visibility_members_indistinguishable.v1",
    "ak.vector.circle.directory_visibility_realm_members_indistinguishable.v1",
    "ak.vector.history_access.since_join_prejoin_denied.v1",
    "ak.vector.preview.token_scoped_stripped_state.v1",
];

fn fixture() -> Result<Value> {
    let value = super::load_fixture_value(FIXTURE)?;
    if value["profile"] != "ak.profile.circle_conformance.v1"
        || value["suite"] != "visibility_policy"
        || value["runner"]["entrypoint"] != "ak.suite.visibility.policy.v1"
    {
        bail!("visibility policy fixture identity drifted");
    }
    let covered = value["covers_vectors"]
        .as_array()
        .context("visibility fixture missing covers_vectors")?
        .iter()
        .map(|id| id.as_str().context("vector id must be a string"))
        .collect::<Result<BTreeSet<_>>>()?;
    if covered != VECTOR_IDS.iter().copied().collect() {
        bail!("visibility policy fixture vector set drifted");
    }
    Ok(value)
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture["cases"]
        .as_array()
        .context("visibility fixture missing cases")?
        .iter()
        .find(|case| case["vector_id"] == vector_id)
        .with_context(|| format!("visibility fixture missing {vector_id}"))
}

fn assert_activation() -> Result<()> {
    let active = Some("ak:mls_group:active");
    if validate_mls_activation_is_irreversible(None, active).is_err()
        || validate_mls_activation_is_irreversible(active, active).is_err()
        || !matches!(
            validate_mls_activation_is_irreversible(active, None),
            Err(CircleScopeError::MlsActivationIrreversible)
        )
        || !matches!(
            validate_mls_activation_is_irreversible(active, Some("ak:mls_group:other")),
            Err(CircleScopeError::MlsActivationIrreversible)
        )
    {
        bail!("MLS activation irreversibility drifted");
    }
    if validate_scope_mls_activation(None, false).is_err()
        || validate_scope_mls_activation(active, true).is_err()
        || !matches!(
            validate_scope_mls_activation(active, false),
            Err(CircleScopeError::MlsActivationRequired)
        )
    {
        bail!("activated scope plaintext-write gate drifted");
    }
    // A definitely inactive scope refuses ciphertext as a generic
    // failed_precondition that names no reason code.
    match validate_scope_mls_activation(None, true) {
        Err(error @ CircleScopeError::MlsScopeInactive)
            if !error.to_string().contains("reason=") => {}
        _ => bail!("inactive scope ciphertext-write gate drifted"),
    }
    // The selected Circle scope is evaluated independently of the parent Realm.
    if validate_scope_mls_activation(None, false).is_err()
        || validate_scope_mls_activation(active, false).is_ok()
    {
        bail!("Circle MLS activation inherited the Realm default state");
    }
    Ok(())
}

fn key_set(value: &Value) -> Result<BTreeSet<&str>> {
    Ok(value
        .as_object()
        .context("visibility projection must be an object")?
        .keys()
        .map(String::as_str)
        .collect())
}

fn expected_keys<'a>(case: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    case["expected"][field]
        .as_array()
        .with_context(|| format!("missing expected {field}"))?
        .iter()
        .map(|value| value.as_str().context("expected key must be a string"))
        .collect()
}

fn reject_forbidden(value: &Value, names: &BTreeSet<&str>) -> Result<()> {
    for name in names {
        if value.get(*name).is_some() {
            bail!("visibility projection leaked {name}");
        }
    }
    Ok(())
}

fn assert_directory_visibility(fixture: &Value) -> Result<()> {
    let members = case(
        fixture,
        "ak.vector.circle.directory_visibility_members_indistinguishable.v1",
    )?;
    let realm_members = case(
        fixture,
        "ak.vector.circle.directory_visibility_realm_members_indistinguishable.v1",
    )?;
    if serde_json::from_value::<CircleDirectoryVisibility>(json!("members"))?
        != CircleDirectoryVisibility::Members
        || serde_json::from_value::<CircleDirectoryVisibility>(json!("realm_members"))?
            != CircleDirectoryVisibility::RealmMembers
        || serde_json::from_value::<CircleDirectoryVisibility>(json!("public")).is_ok()
    {
        bail!("Circle directory visibility closed set drifted");
    }
    if members["expected"]["non_member_projection"] != "not_found"
        || members["expected"]["absent_projection"] != "not_found"
        || realm_members["expected"]["non_realm_projection"] != "not_found"
        || members["expected"]["timing_bucket"] != realm_members["expected"]["timing_bucket"]
    {
        bail!("Circle non-member and absent projections differ");
    }
    let preview = json!({
        "circle_id": "ak:circle:AUSenBRnepSegLPN_3QRmalt393LbZ9xTHIOK-qXDnHw",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "visibility": "realm_members",
        "display": {"color_token": "indigo", "symbol": {"glyph": "shield"}},
        "member_count_bucket": "10_49",
        "join_rule": "knock",
        "opaque_commitment": format!("sha256:{}", "1".repeat(64)),
    });
    if key_set(&preview)? != expected_keys(realm_members, "preview_keys")? {
        bail!("Realm-member preview key whitelist drifted");
    }
    reject_forbidden(&preview, &expected_keys(realm_members, "forbidden_fields")?)?;
    Ok(())
}

pub fn run_visibility_policy_fixture_suite() -> Result<()> {
    let fixture = fixture()?;
    for vector_id in VECTOR_IDS {
        let _ = case(&fixture, vector_id)?;
    }
    assert_activation()?;
    let inactive = case(
        &fixture,
        "ak.vector.e2ee.ciphertext_write_before_activation_rejected.v1",
    )?;
    if inactive["expected"]["outcome"] != "failed_precondition"
        || inactive["expected"].get("reason").is_some()
        || inactive["expected"]["durable_writes"] != 0
    {
        bail!("inactive scope ciphertext refusal contract drifted");
    }
    assert_directory_visibility(&fixture)?;
    let history = case(
        &fixture,
        "ak.vector.history_access.since_join_prejoin_denied.v1",
    )?;
    let join_epoch = history["viewer"]["join_epoch"]
        .as_u64()
        .context("history vector missing join epoch")?;
    for event in history["events"]
        .as_array()
        .context("history events missing")?
    {
        if event["expected_visible"].as_bool() != event["epoch"].as_u64().map(|e| e >= join_epoch) {
            bail!("since_join history projection drifted");
        }
    }
    let preview = case(&fixture, "ak.vector.preview.token_scoped_stripped_state.v1")?;
    if preview["expected"]["history_events"] != json!([])
        || preview["expected"]["exporter_secrets"] != json!([])
    {
        bail!("preview projection leaked history or exporter secrets");
    }
    Ok(())
}
